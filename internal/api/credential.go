package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	appcrypto "penkeeper/internal/crypto"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// -------------------------------------------------------------------
// Request payload
// -------------------------------------------------------------------
type addCredentialReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Source   string `json:"source"`
}

// -------------------------------------------------------------------
// AddCredential – POST /hosts/:hid/credentials
// -------------------------------------------------------------------
func AddCredential(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		credHost := verifyHostOwner(db, hostID, userID)
		if credHost == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var req addCredentialReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if (req.Password != "" || req.Hash != "") && refuseWhileKeyMismatch(c) {
			return
		}
		encPass, encHash, err := encryptCredentialSecrets(req.Password, req.Hash)
		if err != nil {
			log.Printf("AddCredential encrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credential"})
			return
		}

		cred := model.Credential{
			ID:       uuid.New(),
			HostID:   hostID,
			Username: req.Username,
			Password: encPass,
			Hash:     encHash,
			Source:   req.Source,
		}

		if err := db.Create(&cred).Error; err != nil {
			log.Printf("AddCredential DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store credential"})
			return
		}
		go RecordActivity(db, credHost.AssessmentID, userID, "credential_added",
			"Added credential "+req.Username+" on "+credHost.Identifier)
		// Return the decrypted values in the response for the UI.
		cred.Password, cred.Hash = req.Password, req.Hash
		c.JSON(http.StatusCreated, cred)
	}
}

// -------------------------------------------------------------------
// ListCredentials – GET /hosts/:hid/credentials
// -------------------------------------------------------------------
func ListCredentials(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var creds []model.Credential
		if err := db.Where("host_id = ?", hostID).Find(&creds).Error; err != nil {
			log.Printf("ListCredentials DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch credentials"})
			return
		}
		views := make([]credentialView, len(creds))
		for i := range creds {
			views[i] = decryptCredential(creds[i])
		}
		c.JSON(http.StatusOK, views)
	}
}

// -------------------------------------------------------------------
// GetCredential – GET /credentials/:cid
// -------------------------------------------------------------------
func GetCredential(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		credID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
			return
		}

		cred := verifyCredentialOwner(db, credID, userID)
		if cred == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
			return
		}

		c.JSON(http.StatusOK, decryptCredential(*cred))
	}
}

// -------------------------------------------------------------------
// UpdateCredential – PUT /hosts/:hid/credentials/:cid
// -------------------------------------------------------------------
func UpdateCredential(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		credID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		// Password and Hash are only changed when present, so a client that
		// sends just the fields the user edited never overwrites a stored
		// value it could not read (see credentialView).
		var payload struct {
			Username string  `json:"username"`
			Password *string `json:"password"`
			Hash     *string `json:"hash"`
			Source   string  `json:"source"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Username is required (as on create) so a partial update can't blank it.
		if payload.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
			return
		}

		// Older clients send every field: the unchanged value, "" for a value
		// that could not be decrypted, or the stored ciphertext itself where a
		// read did not decrypt it (hashes, before they were encrypted). None
		// of them replaces the stored value, so an unchanged value is never
		// re-encrypted (with a wrong key it would become unreadable).
		var stored model.Credential
		if err := db.Select("password", "hash").
			First(&stored, "id = ? AND host_id = ?", credID, hostID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
				return
			}
			log.Printf("UpdateCredential DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update credential"})
			return
		}
		view := decryptCredential(stored)

		cols := map[string]interface{}{
			"username": payload.Username,
			"source":   payload.Source,
		}
		for _, f := range []struct {
			col    string
			val    *string
			stored string
			plain  string // "" when unreadable
		}{
			{"password", payload.Password, stored.Password, view.Password},
			{"hash", payload.Hash, stored.Hash, view.Hash},
		} {
			if f.val == nil || *f.val == f.plain ||
				(*f.val == f.stored && appcrypto.IsEncrypted(f.stored)) {
				continue
			}
			if refuseWhileKeyMismatch(c) {
				return
			}
			enc, err := appcrypto.Encrypt(*f.val)
			if err != nil {
				log.Printf("UpdateCredential encrypt error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credential"})
				return
			}
			cols[f.col] = enc
		}

		result := db.Model(&model.Credential{}).
			Where("id = ? AND host_id = ?", credID, hostID).
			Updates(cols)

		if result.Error != nil {
			log.Printf("UpdateCredential DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update credential"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// DeleteCredential – DELETE /hosts/:hid/credentials/:cid
// -------------------------------------------------------------------
func DeleteCredential(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		credID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		result := db.Where("id = ? AND host_id = ?", credID, hostID).Delete(&model.Credential{})
		if result.Error != nil {
			log.Printf("DeleteCredential DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete credential"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}
