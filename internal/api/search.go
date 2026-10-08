package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"penkeeper/internal/storage"
)

// Search – GET /api/v1/search?q=<term>
// Returns up to 10 matches each from assessments, hosts, credentials, notes, and commands.
func Search(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		q := strings.TrimSpace(c.Query("q"))
		if len(q) < 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query must be at least 2 characters"})
			return
		}
		// Escape LIKE wildcards so user input is treated as literal text.
		// Escape the backslash first so it doesn't neutralize the escapes below.
		escaped := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q)
		like := "%" + escaped + "%"

		type AssessmentResult struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		}
		type HostResult struct {
			ID             uuid.UUID `json:"id"`
			Identifier     string    `json:"identifier"`
			Label          string    `json:"label"`
			AssessmentID   uuid.UUID `json:"assessment_id"`
			AssessmentName string    `json:"assessment_name"`
		}
		type CredResult struct {
			ID             uuid.UUID `json:"id"`
			Username       string    `json:"username"`
			Source         string    `json:"source"`
			HostID         uuid.UUID `json:"host_id"`
			HostIdentifier string    `json:"host_identifier"`
			AssessmentID   uuid.UUID `json:"assessment_id"`
			AssessmentName string    `json:"assessment_name"`
		}
		type NoteResult struct {
			ID             uuid.UUID `json:"id"`
			Title          string    `json:"title"`
			Snippet        string    `json:"snippet"`
			HostID         uuid.UUID `json:"host_id"`
			HostIdentifier string    `json:"host_identifier"`
			AssessmentID   uuid.UUID `json:"assessment_id"`
			AssessmentName string    `json:"assessment_name"`
		}
		type CommandResult struct {
			ID      uuid.UUID `json:"id"`
			Name    string    `json:"name"`
			OS      string    `json:"os"`
			Command string    `json:"command"`
		}

		var assessments []AssessmentResult
		if err := db.Raw(`
			SELECT id, name FROM assessments
			WHERE owner_id = ? AND name ILIKE ?
			LIMIT 10`, userID, like).Scan(&assessments).Error; err != nil {
			log.Printf("Search assessments error: %v", err)
		}

		var hosts []HostResult
		if err := db.Raw(`
			SELECT h.id, h.identifier, h.label, h.assessment_id, a.name AS assessment_name
			FROM hosts h JOIN assessments a ON a.id = h.assessment_id
			WHERE a.owner_id = ? AND (h.identifier ILIKE ? OR h.label ILIKE ?)
			LIMIT 10`, userID, like, like).Scan(&hosts).Error; err != nil {
			log.Printf("Search hosts error: %v", err)
		}

		var creds []CredResult
		if err := db.Raw(`
			SELECT c.id, c.username, c.source, c.host_id,
			       h.identifier AS host_identifier, h.assessment_id,
			       a.name AS assessment_name
			FROM credentials c
			JOIN hosts h ON h.id = c.host_id
			JOIN assessments a ON a.id = h.assessment_id
			WHERE a.owner_id = ? AND (c.username ILIKE ? OR c.source ILIKE ?)
			LIMIT 10`, userID, like, like).Scan(&creds).Error; err != nil {
			log.Printf("Search creds error: %v", err)
		}

		var notes []NoteResult
		if err := db.Raw(`
			SELECT n.id, n.title,
			       SUBSTRING(REGEXP_REPLACE(n.content, '<[^>]+>', '', 'g'), 1, 200) AS snippet,
			       n.host_id,
			       h.identifier AS host_identifier, h.assessment_id,
			       a.name AS assessment_name
			FROM notes n
			JOIN hosts h ON h.id = n.host_id
			JOIN assessments a ON a.id = h.assessment_id
			WHERE a.owner_id = ? AND (n.title ILIKE ? OR n.content ILIKE ?)
			LIMIT 10`, userID, like, like).Scan(&notes).Error; err != nil {
			log.Printf("Search notes error: %v", err)
		}

		var commands []CommandResult
		if err := db.Raw(`
			SELECT id, name, os, command FROM commands
			WHERE user_id = ? AND (name ILIKE ? OR command ILIKE ?)
			LIMIT 10`, userID, like, like).Scan(&commands).Error; err != nil {
			log.Printf("Search commands error: %v", err)
		}

		// Nil-safe: return empty slices rather than null in JSON
		if assessments == nil {
			assessments = []AssessmentResult{}
		}
		if hosts == nil {
			hosts = []HostResult{}
		}
		if creds == nil {
			creds = []CredResult{}
		}
		if notes == nil {
			notes = []NoteResult{}
		}
		if commands == nil {
			commands = []CommandResult{}
		}

		c.JSON(http.StatusOK, gin.H{
			"assessments": assessments,
			"hosts":       hosts,
			"credentials": creds,
			"notes":       notes,
			"commands":    commands,
		})
	}
}
