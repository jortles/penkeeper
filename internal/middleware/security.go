package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "0") // disable legacy XSS auditor (can itself be exploited)
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Writer.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		// API responses carry decrypted credentials and exports; keep them out
		// of the browser's disk cache. Static assets stay cacheable.
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Writer.Header().Set("Cache-Control", "no-store")
		}
		c.Next()
	}
}
