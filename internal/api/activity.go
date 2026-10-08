package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// RecordActivity logs an action against an assessment. Fire-and-forget:
// errors are logged but never returned to the caller.
func RecordActivity(db *storage.DB, assessmentID, userID uuid.UUID, action, detail string) {
	// Look up actor email for display — best effort
	var user model.User
	email := "unknown"
	if err := db.Select("email").First(&user, "id = ?", userID).Error; err == nil {
		email = user.Email
	}

	entry := model.ActivityLog{
		ID:           uuid.New(),
		AssessmentID: assessmentID,
		ActorEmail:   email,
		Action:       action,
		Detail:       detail,
	}
	if err := db.Create(&entry).Error; err != nil {
		log.Printf("RecordActivity error: %v", err)
	}
}

// ListActivity – GET /assessments/:eid/activity
// Returns the 50 most recent activity log entries for the assessment.
func ListActivity(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		eid, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, eid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var entries []model.ActivityLog
		if err := db.Where("assessment_id = ?", eid).
			Order("created_at DESC").
			Limit(50).
			Find(&entries).Error; err != nil {
			log.Printf("ListActivity DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch activity"})
			return
		}
		c.JSON(http.StatusOK, entries)
	}
}
