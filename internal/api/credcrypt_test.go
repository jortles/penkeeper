package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRefuseWhileKeyMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	defer keyMismatch.Store(false)
	for _, mismatch := range []bool{false, true} {
		keyMismatch.Store(mismatch)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		if refused := refuseWhileKeyMismatch(c); refused != mismatch {
			t.Errorf("keyMismatch %v: refused %v", mismatch, refused)
		}
		if mismatch && w.Code != http.StatusServiceUnavailable {
			t.Errorf("keyMismatch: status %d, want 503", w.Code)
		}
	}
}
