package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// decryptCreds decrypts credential passwords and hashes for a single
// assessment's hosts. A value that fails to decrypt is blanked (never the
// ciphertext); the credential endpoints report such values.
func decryptCreds(eng *model.Assessment) {
	for j := range eng.Hosts {
		for k := range eng.Hosts[j].Creds {
			eng.Hosts[j].Creds[k] = decryptCredential(eng.Hosts[j].Creds[k]).Credential
		}
	}
}

// rowFound maps the error of a single-row lookup: nil means found,
// gorm.ErrRecordNotFound means not found, and any other error (the database
// failed) is returned as such.
func rowFound(err error) (bool, error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ownedAssessment is verifyAssessmentOwner for the paths an editor saves
// and reads through (scratch pad, notes): (false, nil) when the assessment
// doesn't exist or isn't the user's, and the error when the lookup failed.
// Those handlers answer 500 for an error, so a database hiccup is reported
// as a failed save (which the editor retries), never as "not found".
func ownedAssessment(db *storage.DB, engID, userID uuid.UUID) (bool, error) {
	var eng model.Assessment
	return rowFound(db.Select("id").First(&eng, "id = ? AND owner_id = ?", engID, userID).Error)
}

// -------------------------------------------------------------------
// Payload for creating an assessment
// -------------------------------------------------------------------
type createAssessmentReq struct {
	Name string `json:"name" binding:"required,min=3,max=200"`
}

// -------------------------------------------------------------------
// CreateAssessment – POST /assessments
// -------------------------------------------------------------------
func CreateAssessment(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		var req createAssessmentReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Set sort_order to max + 1 for this user's assessments
		var maxOrder int
		db.Model(&model.Assessment{}).Where("owner_id = ?", userID).Select("COALESCE(MAX(sort_order), 0)").Scan(&maxOrder)
		eng := model.Assessment{
			ID:        uuid.New(),
			OwnerID:   userID,
			Name:      req.Name,
			SortOrder: maxOrder + 1,
		}
		if err := db.Create(&eng).Error; err != nil {
			log.Printf("CreateAssessment DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store assessment"})
			return
		}
		c.JSON(http.StatusCreated, eng)
	}
}

// -------------------------------------------------------------------
// ListAssessments – GET /assessments
// Only returns assessments owned by the authenticated user.
// -------------------------------------------------------------------
func ListAssessments(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		var engs []model.Assessment
		if err := db.Select("id", "owner_id", "name", "sort_order", "created_at", "updated_at").
			Where("owner_id = ?", userID).
			Order("sort_order ASC, created_at ASC").Find(&engs).Error; err != nil {
			log.Printf("ListAssessments DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch assessments"})
			return
		}
		var hostRows []hostPortCount
		if err := db.Raw(`SELECT h.id, h.assessment_id, COUNT(p.id) AS ports
			FROM hosts h
			JOIN assessments a ON a.id = h.assessment_id
			LEFT JOIN ports p ON p.host_id = h.id
			WHERE a.owner_id = ?
			GROUP BY h.id
			ORDER BY h.created_at, h.id`, userID).Scan(&hostRows).Error; err != nil {
			log.Printf("ListAssessments DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch assessments"})
			return
		}
		c.JSON(http.StatusOK, assessmentSummaries(engs, hostRows))
	}
}

// -------------------------------------------------------------------
// GetAssessment – GET /assessments/:eid
// Returns the assessment with all its hosts and each host's ports.
// -------------------------------------------------------------------
func GetAssessment(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		var eng model.Assessment
		if err := db.Preload("Hosts").
			Preload("Hosts.Ports").
			Preload("Hosts.Creds").
			Preload("Hosts.Notes", func(tx *gorm.DB) *gorm.DB {
				return tx.Order("sort_order ASC, created_at ASC")
			}).
			Preload("Hosts.ToolOutputs").
			First(&eng, "id = ? AND owner_id = ?", engID, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
				return
			}
			log.Printf("GetAssessment DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch assessment"})
			return
		}
		decryptCreds(&eng)
		c.JSON(http.StatusOK, eng)
	}
}

// -------------------------------------------------------------------
// DeleteAssessment – DELETE /assessments/:eid
// Cascades delete to hosts, ports, etc.
// -------------------------------------------------------------------
func DeleteAssessment(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, engID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		if err := db.Delete(&model.Assessment{}, "id = ?", engID).Error; err != nil {
			log.Printf("DeleteAssessment DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete assessment"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// updateScratchPadReq is the body of PUT /assessments/:eid/scratchpad.
// Content is required (an empty string clears the scratch pad). Version is
// the scratch_pad_version the client loaded: when it is present the save
// only applies if the scratch pad is still at that version. Without it the
// save overwrites unconditionally (older clients). SaveID and BaseSaveIDs
// work as for notes (see updateNoteReq).
type updateScratchPadReq struct {
	Content     *string  `json:"content"`
	Version     *int     `json:"version"`
	SaveID      string   `json:"save_id" binding:"max=64"`
	BaseSaveIDs []string `json:"base_save_ids" binding:"max=16,dive,min=1,max=64"`
}

// columns returns the column updates for the request, or nil when it has no
// content (so a body like {} or {"version": 3} can't wipe the scratch pad).
func (r updateScratchPadReq) columns() map[string]interface{} {
	if r.Content == nil {
		return nil
	}
	return map[string]interface{}{
		"scratch_pad":         *r.Content,
		"scratch_pad_version": gorm.Expr("scratch_pad_version + 1"),
		"scratch_pad_save_id": r.SaveID,
	}
}

// scratchPadConflictBody is the 409 response for a save based on an old
// version: it carries the current text and version, and the id of the save
// that wrote it.
func scratchPadConflictBody(a model.Assessment) gin.H {
	return gin.H{
		"error":               "scratch pad changed elsewhere",
		"scratch_pad":         a.ScratchPad,
		"scratch_pad_version": a.ScratchPadVersion,
		"scratch_pad_save_id": a.ScratchPadSaveID,
	}
}

// -------------------------------------------------------------------
// UpdateScratchPad – PUT /assessments/:eid/scratchpad
// Saves the free-form scratch pad text for an assessment.
// Body: { content, version?, save_id?, base_save_ids? } →
// 200 { scratch_pad_version }, or 409 with the current text when version is
// given and the scratch pad has changed since (other than by the saves in
// base_save_ids).
// -------------------------------------------------------------------
func UpdateScratchPad(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		owned, err := ownedAssessment(db, engID, userID)
		if err != nil {
			log.Printf("UpdateScratchPad DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update scratch pad"})
			return
		}
		if !owned {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var payload updateScratchPadReq
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		cols := payload.columns()
		if cols == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "content required"})
			return
		}

		q := db.Where("id = ? AND owner_id = ?", engID, userID)
		if guard, args, ok := scratchPadSaveGuard.where(payload.Version, payload.BaseSaveIDs); ok {
			q = q.Where(guard, args...)
		}
		// RETURNING hands back the bumped version from the same statement.
		var updated model.Assessment
		result := q.Model(&updated).
			Clauses(clause.Returning{Columns: []clause.Column{{Name: "scratch_pad_version"}}}).
			Updates(cols)
		if result.Error != nil {
			log.Printf("UpdateScratchPad DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update scratch pad"})
			return
		}
		if result.RowsAffected == 0 {
			if payload.Version == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
				return
			}
			// The scratch pad has moved past the version the client edited.
			var current model.Assessment
			if err := db.First(&current, "id = ? AND owner_id = ?", engID, userID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
					return
				}
				log.Printf("UpdateScratchPad DB error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update scratch pad"})
				return
			}
			c.JSON(http.StatusConflict, scratchPadConflictBody(current))
			return
		}
		c.JSON(http.StatusOK, gin.H{"scratch_pad_version": updated.ScratchPadVersion})
	}
}

// -------------------------------------------------------------------
// UpdateAssessmentOrder – PUT /assessments/:eid/order
// Updates the sort_order of an assessment for drag-and-drop reordering.
// Body: { sort_order: int }
// -------------------------------------------------------------------
func UpdateAssessmentOrder(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, engID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var payload struct {
			SortOrder int `json:"sort_order"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := db.Model(&model.Assessment{}).
			Where("id = ? AND owner_id = ?", engID, userID).
			Update("sort_order", payload.SortOrder).Error; err != nil {
			log.Printf("UpdateAssessmentOrder DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update order"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}
