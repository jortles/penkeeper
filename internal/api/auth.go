package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm/clause"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

const cookieName = "pk_session"
const cookieFlag = "pk_logged_in"
const cookieMaxAge = 86400 // 24 hours

// dummyBcryptHash is a valid bcrypt hash used to run a comparison even when the
// email is unknown, so login response time does not reveal whether an account
// exists (bcrypt cost 10, of the string "invalid").
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// setAuthCookies writes an HttpOnly session cookie (holding the JWT) and
// a non-HttpOnly flag cookie so JavaScript can check login state.
func setAuthCookies(c *gin.Context, token string) {
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, token, cookieMaxAge, "/", "", secure, true) // HttpOnly
	c.SetCookie(cookieFlag, "1", cookieMaxAge, "/", "", secure, false)  // readable by JS
}

// clearAuthCookies removes both session cookies.
func clearAuthCookies(c *gin.Context) {
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, "/", "", secure, true)
	c.SetCookie(cookieFlag, "", -1, "/", "", secure, false)
}

// MigrateAuth creates the auth tables that storage.NewPostgres does not
// migrate: the list of logged-out session tokens.
func MigrateAuth(db *storage.DB) error {
	return db.AutoMigrate(&model.RevokedToken{})
}

// newSessionToken signs a full 24-hour session token for user. Each token
// gets a random jti, so Logout can revoke the one presented without ending
// the user's other sessions.
func newSessionToken(key []byte, user model.User) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID.String(),
		"tv":  user.TokenVersion,
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
		"jti": uuid.NewString(),
	})
	return token.SignedString(key)
}

// startSession issues a session token for user and sets the session cookies.
func startSession(c *gin.Context, key []byte, user model.User) (string, error) {
	tokenStr, err := newSessionToken(key, user)
	if err != nil {
		return "", err
	}
	setAuthCookies(c, tokenStr)
	return tokenStr, nil
}

// presentedToken returns the token a request carries, read as JWTAuth reads
// it: the pk_session cookie, else an Authorization Bearer token.
func presentedToken(c *gin.Context) string {
	if cookie, err := c.Cookie(cookieName); err == nil && cookie != "" {
		return cookie
	}
	if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// revocableTokenID returns the jti and expiry of tokenStr when it is a valid
// session token signed with key. ok is false for anything else: no token, a
// bad or expired one, a 2FA challenge token, or a token issued before
// session tokens carried a jti (those stay valid until they expire).
func revocableTokenID(tokenStr string, key []byte) (jti string, exp time.Time, ok bool) {
	if tokenStr == "" {
		return "", time.Time{}, false
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		return "", time.Time{}, false
	}
	claims, isMap := token.Claims.(jwt.MapClaims)
	if !isMap {
		return "", time.Time{}, false
	}
	if pending, _ := claims["pending"].(bool); pending {
		return "", time.Time{}, false
	}
	jti, _ = claims["jti"].(string)
	expAt, err := claims.GetExpirationTime()
	if jti == "" || len(jti) > 64 || err != nil || expAt == nil {
		return "", time.Time{}, false
	}
	return jti, expAt.Time, true
}

// Logout ends the presented session: its jti is recorded until the token
// would have expired, so JWTAuth refuses it from then on (other sessions of
// the account are kept), and the session cookies are cleared. The cookies
// are cleared even if the revocation cannot be stored (e.g. the database is
// down): the answer then says "revoked": false, as the token itself keeps
// working until it expires. A body of {"revoke": false} only clears the
// cookies: the SPA sends it when it signs out after a 401, which can come
// from a request sent with a cookie that was just replaced (enabling or
// disabling 2FA re-issues it), and revoking would end the new session.
func Logout(db *storage.DB, jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)

	return func(c *gin.Context) {
		var req struct {
			Revoke *bool `json:"revoke"`
		}
		_ = c.ShouldBindJSON(&req) // no body: revoke
		if req.Revoke != nil && !*req.Revoke {
			clearAuthCookies(c)
			c.JSON(http.StatusOK, gin.H{"ok": true, "revoked": false})
			return
		}
		if jti, exp, ok := revocableTokenID(presentedToken(c), key); ok {
			revoked := model.RevokedToken{JTI: jti, ExpiresAt: exp}
			if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&revoked).Error; err != nil {
				log.Printf("Logout: failed to revoke session: %v", err)
				clearAuthCookies(c)
				c.JSON(http.StatusOK, gin.H{"ok": true, "revoked": false})
				return
			}
			// Purge revocations of tokens that have expired anyway.
			db.Where("expires_at < ?", time.Now()).Delete(&model.RevokedToken{})
		}
		clearAuthCookies(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

type loginReq struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ListUsers returns the total user count and a list of users (email, role, created_at).
// Restricted to admin users.
func ListUsers(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			return
		}
		var caller model.User
		if err := db.First(&caller, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}
		if caller.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}

		var users []model.User
		if err := db.Order("created_at asc").Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query users"})
			return
		}

		type userRow struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			Role        string `json:"role"`
			TOTPEnabled bool   `json:"totp_enabled"`
			CreatedAt   string `json:"created_at"`
		}
		rows := make([]userRow, len(users))
		for i, u := range users {
			rows[i] = userRow{
				ID:          u.ID.String(),
				Email:       u.Email,
				Role:        u.Role,
				TOTPEnabled: u.TOTPEnabled,
				CreatedAt:   u.CreatedAt.Format("2006-01-02 15:04:05"),
			}
		}
		c.JSON(http.StatusOK, gin.H{"count": len(rows), "users": rows})
	}
}

// GetMe returns the authenticated user's profile (email, role, totp_enabled).
func GetMe(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			return
		}
		var user model.User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"email":        user.Email,
			"role":         user.Role,
			"totp_enabled": user.TOTPEnabled,
		})
	}
}

// Login verifies credentials and returns a signed JWT.
// If the user has TOTP enabled, returns a short-lived partial token instead.
func Login(db *storage.DB, jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)

	return func(c *gin.Context) {
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		var user model.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			// Run a dummy compare so the response time matches the found-user
			// path, preventing account enumeration by timing.
			_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(req.Password))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		// If TOTP is enabled, issue a short-lived partial token requiring 2FA.
		if user.TOTPEnabled {
			partial := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":     user.ID.String(),
				"pending": true,
				"exp":     time.Now().Add(5 * time.Minute).Unix(),
			})
			partialStr, err := partial.SignedString(key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"requires_totp": true, "partial_token": partialStr})
			return
		}

		tokenStr, err := startSession(c, key, user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenStr})
	}
}

// TOTPLogin completes the two-step login by verifying a TOTP code against a partial token.
func TOTPLogin(db *storage.DB, jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)

	return func(c *gin.Context) {
		var req struct {
			PartialToken string `json:"partial_token" binding:"required"`
			Code         string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Parse and validate the partial token.
		token, err := jwt.Parse(req.PartialToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return key, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
			return
		}

		// Must be a pending (TOTP-challenge) token.
		if pending, _ := claims["pending"].(bool); !pending {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not a TOTP challenge token"})
			return
		}

		userIDStr, err := claims.GetSubject()
		if err != nil || userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject"})
			return
		}
		uid, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
			return
		}

		var user model.User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		// Validate the code and consume its time-step in one conditional
		// UPDATE, so a code (even one sent twice at once) logs in only once.
		if err := consumeTOTPCode(db, &user, req.Code, nil); err != nil {
			if errors.Is(err, errTOTPInvalid) || errors.Is(err, errTOTPUsed) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				return
			}
			log.Printf("TOTPLogin: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate 2FA code"})
			return
		}

		// Issue full 24-hour JWT.
		tokenStr, err := startSession(c, key, user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenStr})
	}
}
