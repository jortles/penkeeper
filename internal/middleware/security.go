package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecureCookiesKey is the gin context key under which SecureCookies records
// whether session cookies set on this request must carry the Secure flag.
const SecureCookiesKey = "secure_cookies"

// SecureCookies decides, for every request, whether session cookies must be
// marked Secure: when the connection itself is TLS, when the app is reached
// through an https APP_URL, or when a proxy gin trusts (TRUSTED_PROXIES)
// says it terminated TLS (X-Forwarded-Proto). The header is never taken from
// an untrusted peer: anyone could send it and get a cookie the browser then
// withholds on plain HTTP.
func SecureCookies(appURL string) gin.HandlerFunc {
	viaHTTPS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(appURL)), "https://")
	return func(c *gin.Context) {
		secure := viaHTTPS || c.Request.TLS != nil
		if !secure {
			proto, _, _ := strings.Cut(c.GetHeader("X-Forwarded-Proto"), ",")
			secure = strings.EqualFold(strings.TrimSpace(proto), "https") && fromTrustedProxy(c)
		}
		c.Set(SecureCookiesKey, secure)
		c.Next()
	}
}

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
