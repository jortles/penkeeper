package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"penkeeper/internal/model"
)

// TestSessionTokenRevocableID checks that every session token gets its own
// jti (so Logout can revoke one session) and that only valid session tokens
// yield an id to revoke.
func TestSessionTokenRevocableID(t *testing.T) {
	key := []byte("test-secret")
	user := model.User{ID: uuid.New(), TokenVersion: 3}

	a, err := newSessionToken(key, user)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSessionToken(key, user)
	if err != nil {
		t.Fatal(err)
	}
	jtiA, expA, ok := revocableTokenID(a, key)
	if !ok || jtiA == "" {
		t.Fatalf("session token not revocable: ok=%v jti=%q", ok, jtiA)
	}
	if d := time.Until(expA); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("expiry %v from now, want about 24h", d)
	}
	if jtiB, _, _ := revocableTokenID(b, key); jtiB == jtiA {
		t.Errorf("two sessions share jti %q", jtiA)
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(a, claims, func(*jwt.Token) (interface{}, error) { return key, nil }); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != user.ID.String() || claims["tv"] != float64(3) {
		t.Errorf("claims sub=%v tv=%v, want %v and 3", claims["sub"], claims["tv"], user.ID)
	}

	sign := func(c jwt.MapClaims, k []byte) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	exp := time.Now().Add(time.Hour).Unix()
	for name, tok := range map[string]string{
		"empty":              "",
		"garbage":            "not-a-jwt",
		"other key":          sign(jwt.MapClaims{"sub": "x", "jti": "j", "exp": exp}, []byte("other")),
		"expired":            sign(jwt.MapClaims{"sub": "x", "jti": "j", "exp": time.Now().Add(-time.Minute).Unix()}, key),
		"pre-upgrade no jti": sign(jwt.MapClaims{"sub": "x", "tv": 0, "exp": exp}, key),
		"2FA challenge":      sign(jwt.MapClaims{"sub": "x", "pending": true, "jti": "j", "exp": exp}, key),
		"no expiry":          sign(jwt.MapClaims{"sub": "x", "jti": "j"}, key),
	} {
		if jti, _, ok := revocableTokenID(tok, key); ok {
			t.Errorf("%s: got revocable id %q, want none", name, jti)
		}
	}
}

// TestPresentedToken checks that Logout reads the token the way JWTAuth
// does: the session cookie first, then a Bearer header.
func TestPresentedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		cookie, auth, want string
	}{
		{"", "", ""},
		{"cookie-tok", "", "cookie-tok"},
		{"", "Bearer cli-tok", "cli-tok"},
		{"cookie-tok", "Bearer cli-tok", "cookie-tok"},
		{"", "Basic abc", ""},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		if tc.cookie != "" {
			c.Request.AddCookie(&http.Cookie{Name: cookieName, Value: tc.cookie})
		}
		if tc.auth != "" {
			c.Request.Header.Set("Authorization", tc.auth)
		}
		if got := presentedToken(c); got != tc.want {
			t.Errorf("cookie=%q auth=%q: got %q, want %q", tc.cookie, tc.auth, got, tc.want)
		}
	}
}
