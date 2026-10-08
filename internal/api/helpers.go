package api

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// getUserID extracts the authenticated user's UUID from the Gin context.
// Returns uuid.Nil and false if the value is missing or unparseable.
func getUserID(c *gin.Context) (uuid.UUID, bool) {
	raw, exists := c.Get("userID")
	if !exists {
		return uuid.Nil, false
	}
	str, ok := raw.(string)
	if !ok {
		return uuid.Nil, false
	}
	uid, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

// verifyAssessmentOwner checks that the assessment exists and belongs to the
// given user. Returns nil if not found or not owned.
func verifyAssessmentOwner(db *storage.DB, engID, userID uuid.UUID) *model.Assessment {
	var eng model.Assessment
	if err := db.First(&eng, "id = ? AND owner_id = ?", engID, userID).Error; err != nil {
		return nil
	}
	return &eng
}

// verifyHostOwner checks that the host exists and its parent assessment
// belongs to the given user.
func verifyHostOwner(db *storage.DB, hostID, userID uuid.UUID) *model.Host {
	var host model.Host
	if err := db.First(&host, "id = ?", hostID).Error; err != nil {
		return nil
	}
	if verifyAssessmentOwner(db, host.AssessmentID, userID) == nil {
		return nil
	}
	return &host
}

// verifyPortOwner checks that the port exists and its parent host's assessment
// belongs to the given user.
func verifyPortOwner(db *storage.DB, portID, userID uuid.UUID) *model.Port {
	var port model.Port
	if err := db.First(&port, "id = ?", portID).Error; err != nil {
		return nil
	}
	if verifyHostOwner(db, port.HostID, userID) == nil {
		return nil
	}
	return &port
}

// verifyCommandOwner checks that the command exists and belongs to the given user.
func verifyCommandOwner(db *storage.DB, cmdID, userID uuid.UUID) *model.Command {
	var cmd model.Command
	if err := db.First(&cmd, "id = ? AND user_id = ?", cmdID, userID).Error; err != nil {
		return nil
	}
	return &cmd
}

// verifyNoteOwner checks that the note exists and its parent host's
// assessment belongs to the given user.
func verifyNoteOwner(db *storage.DB, noteID, userID uuid.UUID) *model.Note {
	var note model.Note
	if err := db.First(&note, "id = ?", noteID).Error; err != nil {
		return nil
	}
	if verifyHostOwner(db, note.HostID, userID) == nil {
		return nil
	}
	return &note
}

// verifyCredentialOwner checks that the credential exists and its parent host's
// assessment belongs to the given user.
func verifyCredentialOwner(db *storage.DB, credID, userID uuid.UUID) *model.Credential {
	var cred model.Credential
	if err := db.First(&cred, "id = ?", credID).Error; err != nil {
		return nil
	}
	if verifyHostOwner(db, cred.HostID, userID) == nil {
		return nil
	}
	return &cred
}
