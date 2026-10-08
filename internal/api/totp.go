package api

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"

	appcrypto "penkeeper/internal/crypto"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// totpPeriod is the TOTP time-step in seconds (pquerna's default).
const totpPeriod = 30

// validateTOTPCounter validates a code and, on success, returns the time-step
// counter it matched. It mirrors totp.Validate's default ±1 period skew but
// exposes the counter so callers can reject replay of an already-used code.
func validateTOTPCounter(code, secret string) (bool, int64, error) {
	now := time.Now()
	for _, delta := range []time.Duration{-totpPeriod * time.Second, 0, totpPeriod * time.Second} {
		t := now.Add(delta)
		expected, err := totp.GenerateCode(secret, t)
		if err != nil {
			return false, 0, err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true, t.Unix() / totpPeriod, nil
		}
	}
	return false, 0, nil
}

var (
	errTOTPInvalid = errors.New("invalid 2FA code")
	errTOTPUsed    = errors.New("2FA code already used — wait for the next one")
)

// consumeTOTPCode checks code against user's 2FA secret and records the
// time-step it matched, so each code works only once across login and
// enabling or disabling 2FA. updates are further columns to set in the same
// statement. The UPDATE only applies while totp_last_counter is still below
// that step and the secret is unchanged, so of two requests racing with one
// code only one succeeds; the other gets errTOTPUsed.
func consumeTOTPCode(db *storage.DB, user *model.User, code string, updates map[string]interface{}) error {
	secret, err := appcrypto.Decrypt(user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("read 2FA secret: %w", err)
	}
	valid, counter, err := validateTOTPCounter(code, secret)
	if err != nil {
		return fmt.Errorf("validate 2FA code: %w", err)
	}
	if !valid {
		return errTOTPInvalid
	}
	set := map[string]interface{}{"totp_last_counter": counter}
	for k, v := range updates {
		set[k] = v
	}
	res := db.Model(&model.User{}).
		Where("id = ? AND totp_secret = ? AND totp_last_counter < ?",
			user.ID, user.TOTPSecret, counter).
		Updates(set)
	if res.Error != nil {
		return fmt.Errorf("record 2FA code: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return errTOTPUsed
	}
	return nil
}

// SetupTOTP generates a new TOTP secret for the authenticated user, stores it
// encrypted (but does not yet enable it), and returns a QR code PNG as a base64 data URL.
// While 2FA is enabled it answers 409: replacing the secret needs a code, so
// 2FA has to be disabled (which asks for one) first.
func SetupTOTP(db *storage.DB, issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			return
		}

		var user model.User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}
		if user.TOTPEnabled {
			c.JSON(http.StatusConflict, gin.H{"error": "2FA is already enabled — disable it first"})
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: user.Email,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate TOTP secret"})
			return
		}

		// Encrypt the secret before persisting.
		encSecret, err := appcrypto.Encrypt(key.Secret())
		if err != nil {
			log.Printf("SetupTOTP encrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt TOTP secret"})
			return
		}

		// Persist the encrypted secret but leave totp_enabled = false until user verifies.
		// The condition keeps a setup that raced an enable from replacing the
		// secret that was just enabled. The replay counter starts over: no
		// code of the new secret has been used yet.
		res := db.Model(&model.User{}).Where("id = ? AND totp_enabled IS NOT TRUE", uid).
			Updates(map[string]interface{}{"totp_secret": encSecret, "totp_last_counter": 0})
		if res.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save TOTP secret"})
			return
		}
		if res.RowsAffected == 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "2FA is already enabled — disable it first"})
			return
		}

		// Generate a QR code PNG and encode as a base64 data URL.
		png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate QR code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"secret":  key.Secret(),
			"qr_code": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		})
	}
}

// EnableTOTP verifies a 6-digit TOTP code against the stored (encrypted) secret
// and, if valid, marks totp_enabled = true for the authenticated user. The
// code is consumed (it cannot be replayed at login) and token_version bumped
// in the same statement, which signs out the account's other sessions; the
// caller gets a new session cookie and stays signed in.
func EnableTOTP(db *storage.DB, jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)

	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			return
		}

		var req struct {
			Code string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
			return
		}

		var user model.User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		if user.TOTPEnabled {
			c.JSON(http.StatusConflict, gin.H{"error": "2FA is already enabled"})
			return
		}
		if user.TOTPSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "run setup first"})
			return
		}

		err = consumeTOTPCode(db, &user, req.Code, map[string]interface{}{
			"totp_enabled":  true,
			"token_version": user.TokenVersion + 1,
		})
		switch {
		case errors.Is(err, errTOTPInvalid):
			// 400, not 401: a mistyped code must not look like an expired session.
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code — check your authenticator app"})
			return
		case errors.Is(err, errTOTPUsed):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		case err != nil:
			log.Printf("EnableTOTP: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable 2FA"})
			return
		}

		user.TokenVersion++
		if _, err := startSession(c, key, user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "2FA is enabled, but the session could not be renewed — sign in again"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"totp_enabled": true})
	}
}

// DisableTOTP clears the TOTP secret and marks totp_enabled = false. Like
// EnableTOTP it consumes the code and bumps token_version, signing out the
// account's other sessions while the caller gets a new session cookie.
func DisableTOTP(db *storage.DB, jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)

	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			return
		}

		var req struct {
			Code string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "a current 2FA code is required to disable"})
			return
		}

		var user model.User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		if !user.TOTPEnabled {
			// Nothing to re-authenticate: drop a secret left by an unfinished
			// setup. The condition keeps this from clearing 2FA enabled meanwhile.
			res := db.Model(&model.User{}).Where("id = ? AND totp_enabled IS NOT TRUE", uid).Update("totp_secret", "")
			if res.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable 2FA"})
				return
			}
			if res.RowsAffected == 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "2FA was just enabled — reload and enter a current code to disable it"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"totp_enabled": false})
			return
		}

		// Re-authenticate: require a valid current TOTP code before removing the
		// second factor, so a hijacked session cannot silently strip 2FA.
		err = consumeTOTPCode(db, &user, req.Code, map[string]interface{}{
			"totp_enabled":  false,
			"totp_secret":   "",
			"token_version": user.TokenVersion + 1,
		})
		switch {
		case errors.Is(err, errTOTPInvalid), errors.Is(err, errTOTPUsed):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		case err != nil:
			log.Printf("DisableTOTP: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable 2FA"})
			return
		}

		user.TokenVersion++
		if _, err := startSession(c, key, user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "2FA is disabled, but the session could not be renewed — sign in again"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"totp_enabled": false})
	}
}
