// internal/middleware/cors.go
package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware sets CORS headers based on the ALLOWED_ORIGINS environment
// variable (comma-separated list of allowed origins).
//
// If ALLOWED_ORIGINS is not set, no CORS headers are added. This is the safe
// default for same-origin deployments where the frontend is served by this
// same server. Echoing back an arbitrary request Origin together with
// Access-Control-Allow-Credentials: true would allow any site to make
// credentialed cross-origin requests using the user's session cookie.
func CORSMiddleware() gin.HandlerFunc {
	rawOrigins := os.Getenv("ALLOWED_ORIGINS")

	// Build a set of explicitly allowed origins for O(1) lookup.
	allowedSet := make(map[string]struct{})
	if rawOrigins != "" {
		for _, o := range strings.Split(rawOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				allowedSet[strings.ToLower(trimmed)] = struct{}{}
			}
		}
	}

	setCORSHeaders := func(c *gin.Context) bool {
		origin := c.GetHeader("Origin")
		if _, ok := allowedSet[strings.ToLower(origin)]; ok {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			return true
		}
		return false
	}

	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			if len(allowedSet) > 0 && setCORSHeaders(c) {
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				c.Writer.Header().Set("Access-Control-Max-Age", "86400")
			}
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		if len(allowedSet) > 0 && setCORSHeaders(c) {
			c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Type")
		}

		c.Next()
	}
}
