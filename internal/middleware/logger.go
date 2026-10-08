// internal/middleware/logger.go
package middleware

import (
	"log"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger is a simple request‑logging middleware.
// It prints: [timestamp] METHOD PATH -> STATUS (latency)
// Example: 2025-11-12T15:04:05Z INFO GET /api/v1/assessments -> 200 (12.34ms)
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Record the start time.
		start := time.Now()

		// Process request.
		c.Next()

		// After the request is handled, compute latency.
		latency := time.Since(start)

		// Gather useful data.
		method := c.Request.Method
		path := c.Request.URL.Path
		if len(path) > 512 { // real routes are far shorter; keep each line bounded
			path = path[:512] + "..."
		}
		path = LogSafe(path)
		status := c.Writer.Status()

		// Log in a consistent, easy‑to‑parse format.
		log.Printf("%s %s %s -> %d (%v)", start.UTC().Format(time.RFC3339), method, path, status, latency)
	}
}

// LogSafe escapes control characters (CR, LF, ESC, ...), non-printable runes
// and invalid UTF-8 in a request-derived string, so it cannot forge log lines
// or send escape sequences to an operator's terminal.
func LogSafe(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
