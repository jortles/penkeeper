package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"penkeeper/internal/email"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// hashToken returns the hex-encoded SHA-256 hash of a raw token string.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// generateRawToken returns a cryptographically random 32-byte hex string (64 chars).
func generateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ForgotPassword – POST /api/auth/forgot-password
// Always returns 200 to prevent user enumeration.
func ForgotPassword(db *storage.DB, emailCfg email.Config, appURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
		successMsg := gin.H{"message": "If that email is registered, a reset link has been sent."}

		if err := c.ShouldBindJSON(&req); err != nil {
			// Still return success to prevent enumeration
			c.JSON(http.StatusOK, successMsg)
			return
		}

		// Look up user — bail silently if not found
		var user model.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusOK, successMsg)
			return
		}

		// Delete any existing unused tokens for this user
		db.Where("user_id = ? AND used_at IS NULL", user.ID).Delete(&model.PasswordResetToken{})

		// Generate raw token and store only its hash
		rawToken, err := generateRawToken()
		if err != nil {
			log.Printf("ForgotPassword: failed to generate token: %v", err)
			c.JSON(http.StatusOK, successMsg)
			return
		}

		prt := model.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    user.ID,
			TokenHash: hashToken(rawToken),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := db.Create(&prt).Error; err != nil {
			log.Printf("ForgotPassword: failed to store token: %v", err)
			c.JSON(http.StatusOK, successMsg)
			return
		}

		// Send email asynchronously so the response is not delayed by SMTP.
		// The token goes in the URL fragment, which browsers never send to
		// the server, so it stays out of access logs and Referer headers.
		resetURL := strings.TrimSuffix(appURL, "/") + "/#reset_token=" + rawToken
		go func() {
			if !emailCfg.Enabled() {
				log.Printf("ForgotPassword: SMTP not configured — reset URL for %s: %s", user.Email, resetURL)
				return
			}
			if err := email.SendPasswordReset(emailCfg, user.Email, resetURL); err != nil {
				log.Printf("ForgotPassword: failed to send email to %s: %v", user.Email, err)
			}
		}()

		c.JSON(http.StatusOK, successMsg)
	}
}

// ValidateResetToken – POST /api/auth/reset-password/validate {"token": "xxx"}
// (or GET /api/auth/reset-password?token=xxx, from pages loaded before the
// token moved out of URLs).
// Checks whether a raw token is valid (not expired, not used).
func ValidateResetToken(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken := c.Query("token")
		if c.Request.Method == http.MethodPost {
			var req struct {
				Token string `json:"token"`
			}
			_ = c.ShouldBindJSON(&req)
			rawToken = req.Token
		}
		if rawToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "token is required"})
			return
		}

		var prt model.PasswordResetToken
		err := db.Where(
			"token_hash = ? AND used_at IS NULL AND expires_at > ?",
			hashToken(rawToken), time.Now(),
		).First(&prt).Error

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "invalid or expired token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"valid": true})
	}
}

// errResetTokenSpent rolls back a reset whose token another request used
// (or that expired) after it was looked up.
var errResetTokenSpent = errors.New("reset token already used or expired")

// ResetPassword – POST /api/auth/reset-password
// Validates the token and updates the user's password.
func ResetPassword(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Token    string `json:"token" binding:"required"`
			Password string `json:"password" binding:"required,min=8"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}

		tokenHash := hashToken(req.Token)

		// Look up a valid, unused, unexpired token
		var prt model.PasswordResetToken
		err := db.Where(
			"token_hash = ? AND used_at IS NULL AND expires_at > ?",
			tokenHash, time.Now(),
		).First(&prt).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired reset token"})
			return
		}

		// Hash the new password
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("ResetPassword: bcrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set new password"})
			return
		}

		now := time.Now()

		// Mark the token as used and update the password in a transaction. Bump
		// token_version so any sessions issued before the reset are invalidated.
		// The token is consumed first, by a conditional UPDATE: of overlapping
		// requests with one token only one can mark it, the others roll back.
		txErr := db.Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&model.PasswordResetToken{}).
				Where("id = ? AND used_at IS NULL AND expires_at > ?", prt.ID, now).
				Update("used_at", now)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return errResetTokenSpent
			}
			return tx.Model(&model.User{}).
				Where("id = ?", prt.UserID).
				Updates(map[string]interface{}{
					"password":      string(hash),
					"token_version": gorm.Expr("token_version + 1"),
				}).Error
		})
		if errors.Is(txErr, errResetTokenSpent) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired reset token"})
			return
		}
		if txErr != nil {
			log.Printf("ResetPassword: transaction error: %v", txErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}
