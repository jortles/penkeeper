package middleware

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CSRFProtect rejects cross-site state-changing requests to /api. SameSite=Lax
// does not cover pages on other ports of the same host or on sibling
// subdomains, and the login endpoints need protection without any cookie.
//
// An unsafe request (POST, PUT, PATCH, DELETE) is allowed when:
//   - it carries no pk_session cookie and authenticates with a Bearer token
//     (the pk CLI; browsers cannot attach that header cross-origin);
//   - Sec-Fetch-Site is "same-origin" or "none";
//   - its Origin (or, without Origin, its Referer) is this server's own
//     origin, the origin of appURL, an ALLOWED_ORIGINS entry, or, from a
//     peer gin trusts as a proxy (TRUSTED_PROXIES), the origin given by
//     X-Forwarded-Proto and X-Forwarded-Host;
//   - it carries none of Sec-Fetch-Site, Origin, Referer or the session
//     cookie: browsers always send Origin on unsafe requests, so this is a
//     non-browser client such as `pk login`.
func CSRFProtect(appURL string) gin.HandlerFunc {
	trusted := make(map[string]struct{})
	for _, o := range strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",") {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			trusted[o] = struct{}{}
		}
	}
	if o := originOf(appURL); o != "" {
		trusted[o] = struct{}{}
	}
	var (
		mu     sync.Mutex
		window time.Time // start of the current minute of block logging
		budget int       // block log lines left in that minute
	)

	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			c.Next()
			return
		}
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}
		fwd := ""
		if c.Request.Header.Get("X-Forwarded-Host") != "" && fromTrustedProxy(c) {
			fwd = forwardedOrigin(c.Request)
		}
		if crossSiteRequest(c.Request, trusted, fwd) {
			// A reverse proxy that rewrites Host makes every plain-HTTP
			// request look cross-site, so say how to fix that. Anyone can
			// trigger this line: log at most 10 a minute, with every
			// request-derived field cut short and escaped.
			r := c.Request
			origin := r.Header.Get("Origin")
			if origin == "" {
				origin = originOf(r.Header.Get("Referer"))
			}
			mu.Lock()
			if now := time.Now(); now.Sub(window) >= time.Minute {
				window, budget = now, 10
			}
			logIt := budget > 0
			if logIt {
				budget--
			}
			mu.Unlock()
			if logIt {
				log.Printf(`CSRF: blocked %s %s: origin "%s" does not match Host "%s" (Sec-Fetch-Site "%s"); `+
					"if users reach penkeeper at that origin through a reverse proxy, set APP_URL to it or add it to ALLOWED_ORIGINS",
					logField(r.Method), logField(r.URL.Path), logField(origin), logField(r.Host),
					logField(r.Header.Get("Sec-Fetch-Site")))
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-site request blocked; " +
				"if penkeeper is behind a reverse proxy, set APP_URL to the URL users open (see the server log)"})
			return
		}
		c.Next()
	}
}

// crossSiteRequest reports whether r must be refused. fwd is the origin a
// trusted proxy forwarded (see forwardedOrigin), or "".
func crossSiteRequest(r *http.Request, trusted map[string]struct{}, fwd string) bool {
	_, cookieErr := r.Cookie("pk_session")
	hasCookie := cookieErr == nil
	if !hasCookie && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}

	self := "http://" + strings.ToLower(r.Host)
	if r.TLS != nil {
		self = "https://" + strings.ToLower(r.Host)
	}
	allowed := func(origin string) bool {
		if origin == self || (fwd != "" && origin == fwd) {
			return true
		}
		_, ok := trusted[origin]
		return ok
	}

	origin := strings.ToLower(r.Header.Get("Origin"))
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return false
	case "":
	default:
		// same-site or cross-site: only an explicitly trusted origin passes.
		_, ok := trusted[origin]
		return !ok
	}
	if origin != "" {
		return !allowed(origin)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return !allowed(originOf(ref))
	}
	return hasCookie
}

// originOf returns the lower-cased scheme://host[:port] of a URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// fromTrustedProxy reports whether gin trusts the request's peer as a proxy
// (TRUSTED_PROXIES). gin does not export that check, so ask ClientIP whether
// it would take the client address from this peer's X-Forwarded-For.
func fromTrustedProxy(c *gin.Context) bool {
	const probe = "192.0.2.1" // TEST-NET-1
	cp := c.Copy()
	cp.Request = &http.Request{RemoteAddr: c.Request.RemoteAddr, Header: http.Header{"X-Forwarded-For": {probe}}}
	// A peer that really is the probe address would match without trust.
	return c.RemoteIP() != probe && cp.ClientIP() == probe
}

// forwardedOrigin returns the lower-cased X-Forwarded-Proto://X-Forwarded-Host
// (the first entry of each), or "" when either is missing.
func forwardedOrigin(r *http.Request) string {
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	host, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ",")
	proto, host = strings.TrimSpace(proto), strings.TrimSpace(host)
	if proto == "" || host == "" {
		return ""
	}
	return strings.ToLower(proto + "://" + host)
}

// logField bounds a request-derived string for a log line: at most 100
// bytes, with control characters and invalid UTF-8 escaped by LogSafe.
func logField(s string) string {
	if len(s) > 100 {
		return LogSafe(s[:100]) + "..."
	}
	return LogSafe(s)
}
