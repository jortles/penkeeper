package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// JWTAuth validates the JWT signature and expiry using the provided HMAC
// secret. It checks for the token in this order:
//  1. The "pk_session" HttpOnly cookie (browser sessions)
//  2. The "Authorization: Bearer <token>" header (CLI / programmatic access)
//
// On success it stores the "sub" claim (user UUID) in the Gin context
// under the key "userID".
//
// It answers 401 only when the session is over: an invalid, expired or
// revoked token, or an unknown user. When the database cannot be asked
// (restarting, out of connections) it answers 503 with Retry-After, so
// clients retry instead of signing the user out.
func JWTAuth(db *storage.DB, secret string) gin.HandlerFunc {
	key := []byte(secret)

	return func(c *gin.Context) {
		var tokenStr string

		// 1. Try HttpOnly cookie first.
		if cookie, err := c.Cookie("pk_session"); err == nil && cookie != "" {
			tokenStr = cookie
		}

		// 2. Fall back to Authorization header (for CLI tool).
		if tokenStr == "" {
			auth := c.GetHeader("Authorization")
			if auth != "" && strings.HasPrefix(auth, "Bearer ") {
				tokenStr = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return key, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
			return
		}

		sub, err := claims.GetSubject()
		if err != nil || sub == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing subject in token"})
			return
		}

		// Reject partial tokens issued during the TOTP challenge step.
		if pending, _ := claims["pending"].(bool); pending {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "2FA required"})
			return
		}

		// Verify the token version against the user's current version so that a
		// password reset (which bumps the version) invalidates older sessions.
		uid, err := uuid.Parse(sub)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject in token"})
			return
		}
		var user model.User
		if err := db.Select("id", "token_version").First(&user, "id = ?", uid).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
				return
			}
			unavailable(c)
			return
		}
		// Missing "tv" claim (tokens issued before versioning) is treated as 0.
		var tokenVer int
		if raw, ok := claims["tv"]; ok {
			if f, ok := raw.(float64); ok {
				tokenVer = int(f)
			}
		}
		if tokenVer != user.TokenVersion {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired, please log in again"})
			return
		}

		// Reject a token ended by Logout (tokens issued before session tokens
		// carried a jti cannot be revoked this way and stay valid until exp).
		if jti, _ := claims["jti"].(string); jti != "" {
			var revoked int64
			if err := db.Model(&model.RevokedToken{}).Where("jti = ?", jti).Count(&revoked).Error; err != nil {
				unavailable(c)
				return
			}
			if revoked > 0 {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "logged out, please log in again"})
				return
			}
		}

		c.Set("userID", sub)
		c.Next()
	}
}

// unavailable answers a request whose session could not be checked because
// the database failed. The request was not run, so it can be retried.
func unavailable(c *gin.Context) {
	c.Header("Retry-After", "2")
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "server temporarily unavailable, please retry"})
}
