package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// readAllHandler mimics a JSON handler: a failed read becomes a 400.
func readAllHandler(c *gin.Context) {
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	c.String(http.StatusOK, "%d", len(b))
}

func bodyLimitRouter() *gin.Engine {
	r := gin.New()
	r.Use(BodyLimit(100, map[string]int64{
		"/api/auth/":     10,
		"/api/v1/import": 1000,
	}))
	r.POST("/api/v1/x", readAllHandler)
	r.POST("/api/v1/import", readAllHandler)
	r.POST("/api/auth/login", readAllHandler)
	return r
}

// chunkedReader hides its length so the request goes out without Content-Length.
type chunkedReader struct{ io.Reader }

func TestBodyLimit(t *testing.T) {
	r := bodyLimitRouter()
	cases := []struct {
		path    string
		n       int
		chunked bool
		want    int
	}{
		{"/api/v1/x", 100, false, 200},
		{"/api/v1/x", 101, false, 413},
		{"/api/v1/x", 101, true, 413},
		{"/api/v1/x", 100, true, 200},
		{"/api/v1/import", 1000, false, 200},
		{"/api/v1/import", 1001, true, 413},
		{"/api/auth/login", 11, false, 413},
		{"/api/auth/login", 10, true, 200},
	}
	for _, tc := range cases {
		var body io.Reader = bytes.NewReader(bytes.Repeat([]byte("a"), tc.n))
		req := httptest.NewRequest(http.MethodPost, tc.path, body)
		if tc.chunked {
			req.Body = io.NopCloser(chunkedReader{body})
			req.ContentLength = -1
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %d bytes chunked=%v: status %d, want %d (%s)", tc.path, tc.n, tc.chunked, w.Code, tc.want, w.Body)
		}
		if tc.want == 413 && !strings.Contains(w.Body.String(), `"error":"request body too large`) {
			t.Errorf("%s: 413 body %q", tc.path, w.Body)
		}
	}
}

func TestCSRFProtect(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://ui.example.com")
	r := gin.New()
	r.Use(CSRFProtect("https://pk.example.com/"))
	ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	r.POST("/api/v1/commands", ok)
	r.GET("/api/v1/commands", ok)
	r.POST("/api/auth/login", ok)
	r.POST("/other", ok)

	session := &http.Cookie{Name: "pk_session", Value: "jwt"}
	cases := []struct {
		name   string
		method string
		path   string
		hdr    map[string]string
		cookie bool
		want   int
	}{
		{"same-origin fetch", "POST", "/api/v1/commands", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://app:1338"}, true, 204},
		{"other port, same site", "POST", "/api/v1/commands", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://app:8080"}, true, 403},
		{"cross-site login form", "POST", "/api/auth/login", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, false, 403},
		{"no fetch metadata, own origin", "POST", "/api/v1/commands", map[string]string{"Origin": "http://app:1338"}, true, 204},
		{"no fetch metadata, other port", "POST", "/api/v1/commands", map[string]string{"Origin": "http://app:8080"}, true, 403},
		{"no fetch metadata, null origin", "POST", "/api/v1/commands", map[string]string{"Origin": "null"}, true, 403},
		{"referer only, own origin", "POST", "/api/v1/commands", map[string]string{"Referer": "http://app:1338/#x"}, true, 204},
		{"referer only, other port", "POST", "/api/v1/commands", map[string]string{"Referer": "http://app:8080/"}, true, 403},
		{"APP_URL origin behind proxy", "POST", "/api/v1/commands", map[string]string{"Origin": "https://pk.example.com"}, true, 204},
		{"ALLOWED_ORIGINS cross-site", "POST", "/api/v1/commands", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://ui.example.com"}, true, 204},
		{"cookie, no browser headers", "POST", "/api/v1/commands", nil, true, 403},
		{"pk CLI bearer", "POST", "/api/v1/commands", map[string]string{"Authorization": "Bearer x"}, false, 204},
		{"bearer with cookie and foreign origin", "POST", "/api/v1/commands", map[string]string{"Authorization": "Bearer x", "Origin": "http://app:8080"}, true, 403},
		{"pk login, no cookie", "POST", "/api/auth/login", nil, false, 204},
		{"GET is not checked", "GET", "/api/v1/commands", map[string]string{"Sec-Fetch-Site": "cross-site"}, true, 204},
		{"non-API path", "POST", "/other", map[string]string{"Sec-Fetch-Site": "cross-site"}, true, 204},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "http://app:1338"+tc.path, nil)
		for k, v := range tc.hdr {
			req.Header.Set(k, v)
		}
		if tc.cookie {
			req.AddCookie(session)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}

// A Host-rewriting reverse proxy without APP_URL: the 403 and the log say to
// set APP_URL. Anyone can trigger that log line, so it is short, escaped and
// written at most 10 times a minute.
func TestCSRFBlockExplainsAPPURL(t *testing.T) {
	var buf bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)
	r := gin.New()
	r.Use(CSRFProtect(""))
	r.POST("/api/auth/login", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "http://127.0.0.1:1338/api/auth/login", nil)
		req.Header.Set("Origin", "http://pk.lan")
		if i > 0 {
			req.Header.Set("Origin", "http://"+strings.Repeat("\xff\n", 5000))
			req.Host = strings.Repeat("h", 5000)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "set APP_URL") {
			t.Fatalf("status %d body %s", w.Code, w.Body)
		}
	}
	if n := strings.Count(buf.String(), "set APP_URL"); n != 10 {
		t.Fatalf("logged %d times, want 10: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), `origin "http://pk.lan" does not match Host "127.0.0.1:1338"`) {
		t.Fatalf("log line: %s", buf.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if len(line) > 1000 || strings.ContainsRune(line, 0xff) {
			t.Fatalf("log line not bounded/escaped (%d bytes): %.200q", len(line), line)
		}
	}
}

// Behind a Host-rewriting proxy that gin trusts (TRUSTED_PROXIES), the
// origin from X-Forwarded-Proto and X-Forwarded-Host is the app's own.
func TestCSRFForwardedOrigin(t *testing.T) {
	r := gin.New()
	if err := r.SetTrustedProxies([]string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	r.Use(CSRFProtect(""))
	r.POST("/api/auth/login", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	cases := []struct {
		name, peer, origin, xfh, xfp, site string
		want                               int
	}{
		{"trusted proxy, forwarded origin", "10.0.0.1:4000", "http://pk.lan", "pk.lan", "http", "", 204},
		{"trusted proxy, proxy chain", "10.0.0.1:4000", "http://pk.lan:8080", "pk.lan:8080, 10.0.0.1", "http, http", "", 204},
		{"trusted proxy, other origin", "10.0.0.1:4000", "http://evil.example", "pk.lan", "http", "", 403},
		{"trusted proxy, other scheme", "10.0.0.1:4000", "http://pk.lan", "pk.lan", "https", "", 403},
		{"trusted proxy, no X-Forwarded-Proto", "10.0.0.1:4000", "http://pk.lan", "pk.lan", "", "", 403},
		{"trusted proxy, cross-site fetch", "10.0.0.1:4000", "http://pk.lan", "pk.lan", "http", "cross-site", 403},
		{"untrusted peer", "10.0.0.2:4000", "http://pk.lan", "pk.lan", "http", "", 403},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "http://127.0.0.1:1338/api/auth/login", nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("X-Forwarded-For", "192.168.1.9")
		req.Header.Set("X-Forwarded-Host", tc.xfh)
		if tc.xfp != "" {
			req.Header.Set("X-Forwarded-Proto", tc.xfp)
		}
		if tc.site != "" {
			req.Header.Set("Sec-Fetch-Site", tc.site)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}

	// TRUSTED_PROXIES unset: main.go trusts no proxy.
	r2 := gin.New()
	if err := r2.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	r2.Use(CSRFProtect(""))
	r2.POST("/api/auth/login", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest("POST", "http://127.0.0.1:1338/api/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:4000"
	req.Header.Set("Origin", "http://pk.lan")
	req.Header.Set("X-Forwarded-Host", "pk.lan")
	req.Header.Set("X-Forwarded-Proto", "http")
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("no trusted proxies: status %d, want 403", w.Code)
	}
}

func TestSecurityHeadersNoStoreOnAPI(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/api/v1/assessments", func(c *gin.Context) { c.Status(200) })
	r.GET("/static/app.js", func(c *gin.Context) { c.Status(200) })
	for path, want := range map[string]string{"/api/v1/assessments": "no-store", "/static/app.js": ""} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if got := w.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}
}

func TestLogSafe(t *testing.T) {
	cases := map[string]string{
		"/api/v1/assessments":      "/api/v1/assessments",
		"/x\n2026/10/07 FORGED":    `/x\n2026/10/07 FORGED`,
		"/a\r\x1b[31mred":          `/a\r\x1b[31mred`,
		"nobody@example.com\u202e": `nobody@example.com\u202e`,
		"/caf\u00e9":               "/caf\u00e9",
	}
	for in, want := range cases {
		if got := LogSafe(in); got != want {
			t.Errorf("LogSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaxInFlight(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 3)
	r := gin.New()
	r.POST("/import", MaxInFlight(2), func(c *gin.Context) {
		started <- struct{}{}
		<-release
		c.Status(200)
	})
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("POST", "/import", nil))
			codes <- w.Code
		}()
	}
	<-started
	<-started
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/import", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent request: %d, want 429", w.Code)
	}
	close(release)
	for i := 0; i < 2; i++ {
		select {
		case c := <-codes:
			if c != 200 {
				t.Fatalf("in-flight request: %d", c)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/import", nil))
	if w.Code != 200 {
		t.Fatalf("after release: %d, want 200", w.Code)
	}
}

// The access log keeps each line bounded however long the request path is.
func TestLoggerBoundsPath(t *testing.T) {
	var buf bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)
	r := gin.New()
	r.Use(Logger())
	r.NoRoute(func(c *gin.Context) { c.Status(http.StatusNotFound) })
	req := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("%ff", 20000), nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	if n := buf.Len(); n == 0 || n > 2200 {
		t.Errorf("access log line is %d bytes for a 20000-byte path, want 1..2200", n)
	}
}

// A client connecting from the probe address itself is not a trusted proxy.
func TestFromTrustedProxyProbePeer(t *testing.T) {
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	var got bool
	r.POST("/x", func(c *gin.Context) { got = fromTrustedProxy(c) })
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "192.0.2.1:4000"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got {
		t.Error("peer 192.0.2.1 with no trusted proxies counted as a trusted proxy")
	}
}
