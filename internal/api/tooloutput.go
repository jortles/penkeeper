package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// -------------------------------------------------------------------
// ListToolOutputs – GET /hosts/:hid/outputs
// -------------------------------------------------------------------
func ListToolOutputs(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var outputs []model.ToolOutput
		if err := db.Where("host_id = ?", hid).Order("created_at DESC").Find(&outputs).Error; err != nil {
			log.Printf("ListToolOutputs DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch tool outputs"})
			return
		}
		c.JSON(http.StatusOK, outputs)
	}
}

// maxToolOutput is the most tool output stored in one entry. The request
// body may be larger (JSON escaping), so the limit is checked here, on the
// decoded text.
const maxToolOutput = 20 << 20

// outputTooLarge answers 413 and returns true when output is over
// maxToolOutput.
func outputTooLarge(c *gin.Context, output string) bool {
	if len(output) <= maxToolOutput {
		return false
	}
	c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("output too large: %d bytes (max %d MB)", len(output), maxToolOutput>>20)})
	return true
}

// -------------------------------------------------------------------
// AddToolOutput – POST /hosts/:hid/outputs
// -------------------------------------------------------------------
func AddToolOutput(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload struct {
			Tool    string `json:"tool"`
			Command string `json:"command"`
			Output  string `json:"output"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if outputTooLarge(c, payload.Output) {
			return
		}
		if payload.Tool == "" {
			payload.Tool = "unknown"
		}

		out := model.ToolOutput{
			ID:      uuid.New(),
			HostID:  hid,
			Tool:    payload.Tool,
			Command: payload.Command,
			Output:  payload.Output,
		}
		if err := db.Create(&out).Error; err != nil {
			log.Printf("AddToolOutput DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save tool output"})
			return
		}
		c.JSON(http.StatusCreated, out)
	}
}

// -------------------------------------------------------------------
// DeleteToolOutput – DELETE /hosts/:hid/outputs/:oid
// -------------------------------------------------------------------
func DeleteToolOutput(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		oid, err := uuid.Parse(c.Param("oid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid output id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		result := db.Where("id = ? AND host_id = ?", oid, hid).Delete(&model.ToolOutput{})
		if result.Error != nil {
			log.Printf("DeleteToolOutput DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete tool output"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "output not found"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// pipeHost is a host a /pipe target can name.
type pipeHost struct {
	HostID         uuid.UUID `gorm:"column:host_id" json:"host_id"`
	HostIdentifier string    `gorm:"column:host_identifier" json:"host_identifier"`
	AssessmentID   uuid.UUID `gorm:"column:assessment_id" json:"assessment_id"`
	AssessmentName string    `gorm:"column:assessment_name" json:"assessment_name"`
}

// pickPipeHost picks the host a /pipe target names among the hosts whose
// identifier equals it ignoring case, newest first. Identifiers written
// exactly like the target come first, as they always have; the others count
// only when there are none. Hosts in several assessments are ambiguous (the
// same private address often appears for several clients), so ok is false
// and the caller asks for the assessment rather than guess. Within one
// assessment the newest host wins.
func pickPipeHost(matches []pipeHost, target string) (host pipeHost, ok bool) {
	var exact []pipeHost
	for _, m := range matches {
		if m.HostIdentifier == target {
			exact = append(exact, m)
		}
	}
	if len(exact) > 0 {
		matches = exact
	}
	if len(matches) == 0 {
		return pipeHost{}, false
	}
	host = matches[0]
	for _, m := range matches {
		if m.AssessmentID != host.AssessmentID {
			return pipeHost{}, false
		}
	}
	return host, true
}

// pipeHostNames lists hosts for a message (at most five).
func pipeHostNames(hosts []pipeHost) string {
	var names []string
	for i, h := range hosts {
		if i == 5 {
			names = append(names, fmt.Sprintf("and %d more", len(hosts)-5))
			break
		}
		names = append(names, fmt.Sprintf("%s (%s)", h.HostIdentifier, h.AssessmentName))
	}
	return strings.Join(names, ", ")
}

// -------------------------------------------------------------------
// PipeInput – POST /pipe
// Accepts piped tool output and attaches it to a host by identifier.
// Body: { target, assessment, tool, command, output }; assessment is
// optional (an assessment id or exact name) and limits the hosts searched.
// -------------------------------------------------------------------
func PipeInput(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		var payload struct {
			Target     string `json:"target"`
			Assessment string `json:"assessment"`
			Tool       string `json:"tool"`
			Command    string `json:"command"`
			Output     string `json:"output"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if outputTooLarge(c, payload.Output) {
			return
		}
		if payload.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
			return
		}
		if payload.Tool == "" {
			// Derive tool name from first word of command
			if fields := strings.Fields(payload.Command); len(fields) > 0 {
				payload.Tool = fields[0]
			} else {
				payload.Tool = "unknown"
			}
		}

		// Find the host whose identifier is the target (ignoring case, never
		// a part of it) in this user's assessments, or only in the one the
		// payload names.
		scope, args := "", []any{userID, payload.Target}
		if aid, err := uuid.Parse(payload.Assessment); err == nil {
			scope, args = " AND (a.id = ? OR a.name = ?)", append(args, aid, payload.Assessment)
		} else if payload.Assessment != "" {
			scope, args = " AND a.name = ?", append(args, payload.Assessment)
		}
		var matches []pipeHost
		if err := db.Raw(`
			SELECT h.id AS host_id, h.identifier AS host_identifier,
			       a.id AS assessment_id, a.name AS assessment_name
			FROM hosts h
			JOIN assessments a ON a.id = h.assessment_id
			WHERE a.owner_id = ? AND lower(h.identifier) = lower(?)`+scope+`
			ORDER BY a.name, a.id, h.created_at DESC`, args...).Scan(&matches).Error; err != nil {
			log.Printf("PipeInput DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up target"})
			return
		}
		if len(matches) == 0 {
			msg := "no host found matching target \"" + payload.Target + "\""
			if payload.Assessment != "" {
				msg += " in assessment \"" + payload.Assessment + "\""
			}
			c.JSON(http.StatusNotFound, gin.H{"error": msg})
			return
		}
		row, ok := pickPipeHost(matches, payload.Target)
		if !ok {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("target %q is a host in several assessments: %s; choose one with pk --assessment <name or id>",
					payload.Target, pipeHostNames(matches)),
				"candidates": matches,
			})
			return
		}

		out := model.ToolOutput{
			ID:      uuid.New(),
			HostID:  row.HostID,
			Tool:    payload.Tool,
			Command: payload.Command,
			Output:  payload.Output,
		}
		if err := db.Create(&out).Error; err != nil {
			log.Printf("PipeInput DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save output"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"output_id":       out.ID,
			"host_id":         row.HostID,
			"host_identifier": row.HostIdentifier,
			"assessment_id":   row.AssessmentID,
			"assessment_name": row.AssessmentName,
			"bytes":           len(payload.Output),
		})
	}
}
