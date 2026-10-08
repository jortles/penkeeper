package middleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// BodyLimit caps the size of request bodies before any handler parses them
// (JSON binding, multipart forms, raw reads). limits maps a route pattern as
// returned by c.FullPath() to its cap; a key ending in "/" applies to every
// route under that prefix. Other routes get def.
//
// A body whose declared Content-Length exceeds the cap is refused with 413
// before the handler runs. A body of unknown length (chunked) is cut off at
// the cap by http.MaxBytesReader, and the handler's error response is then
// replaced by the same 413.
func BodyLimit(def int64, limits map[string]int64) gin.HandlerFunc {
	limitFor := func(route string) int64 {
		if n, ok := limits[route]; ok {
			return n
		}
		best, n := -1, def
		for k, v := range limits {
			if strings.HasSuffix(k, "/") && strings.HasPrefix(route, k) && len(k) > best {
				best, n = len(k), v
			}
		}
		return n
	}

	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		limit := limitFor(c.FullPath())
		msg := fmt.Sprintf("request body too large (max %s)", formatBytes(limit))
		if c.Request.ContentLength > limit {
			c.Header("Connection", "close")
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": msg})
			return
		}
		if c.Request.ContentLength < 0 {
			body := &limitedBody{ReadCloser: http.MaxBytesReader(c.Writer, c.Request.Body, limit)}
			c.Request.Body = body
			c.Writer = &tooLargeWriter{ResponseWriter: c.Writer, body: body, msg: msg}
		}
		c.Next()
	}
}

// limitedBody records whether the MaxBytesReader it wraps hit its cap.
type limitedBody struct {
	io.ReadCloser
	exceeded bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		b.exceeded = true
	}
	return n, err
}

// tooLargeWriter turns whatever the handler answers after its body hit the
// cap (usually a 400 from a failed bind) into the 413 JSON error.
type tooLargeWriter struct {
	gin.ResponseWriter
	body *limitedBody
	msg  string
	sent bool
}

func (w *tooLargeWriter) WriteHeader(code int) {
	if w.body.exceeded {
		code = http.StatusRequestEntityTooLarge
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *tooLargeWriter) Write(p []byte) (int, error) {
	if !w.body.exceeded {
		return w.ResponseWriter.Write(p)
	}
	if !w.sent {
		w.sent = true
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Connection", "close")
		w.ResponseWriter.WriteHeader(http.StatusRequestEntityTooLarge)
		if _, err := w.ResponseWriter.WriteString(fmt.Sprintf(`{"error":%q}`, w.msg)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *tooLargeWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}
