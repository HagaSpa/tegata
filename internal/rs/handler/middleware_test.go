package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
)

const (
	testIssuer     = "http://localhost:8000"
	testIdentifier = "http://localhost:9000"
)

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() faild: %v", err)
	}
	return key
}

func bearerToken(t *testing.T, key *rsa.PrivateKey, edit func(c *jwt.Claims)) string {
	t.Helper()
	now := time.Now()
	c := &jwt.Claims{
		Iss:   testIssuer,
		Sub:   "u-0001",
		Aud:   jwt.Audience{testIssuer + "/userinfo", testIdentifier},
		Iat:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
		Scope: "openid notes.read",
	}
	if edit != nil {
		edit(c)
	}
	token, err := jwt.Sign(key, "test-kid", c)
	if err != nil {
		t.Fatalf("jwt.Sign() failed: %v", err)
	}
	return "Bearer " + token.String()
}

func newTestMiddleware(key *rsa.PrivateKey) *AuthMiddleware {
	keyFor := func(kid string) (*rsa.PublicKey, error) {
		return &key.PublicKey, nil
	}
	return NewAuthMiddleware(keyFor, testIssuer, testIdentifier)
}

type recordingHandler struct {
	called bool
	claims *jwt.Claims
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.claims = contextClaims(r.Context())
}

func serve(m *AuthMiddleware, scope, authorization string) (*httptest.ResponseRecorder, *recordingHandler) {
	next := &recordingHandler{}
	req := httptest.NewRequest(http.MethodGet, "/notes", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	m.Require(scope, next).ServeHTTP(rec, req)
	return rec, next
}

func TestAuthMiddleware_Require_Errors(t *testing.T) {
	const invalidToken = `Bearer error="invalid_token"`
	key := newTestKey(t)
	otherKey := newTestKey(t)
	m := newTestMiddleware(key)

	tests := []struct {
		name          string
		authorization string
		scope         string
		wantStatus    int
		wantChallenge string
	}{
		{
			name:          "へっだなし",
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: "Bearer",
		},
		{
			name:          "JWT の形になってない",
			authorization: "Bearer x",
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name:          "期限切れ",
			authorization: bearerToken(t, key, func(c *jwt.Claims) { c.Exp = time.Now().Add(-time.Hour).Unix() }),
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name:          "別の鍵で署名",
			authorization: bearerToken(t, otherKey, nil),
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name:          "iss が違う",
			authorization: bearerToken(t, key, func(c *jwt.Claims) { c.Iss = "http://evil.example" }),
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name: "ID トークンの形 (aud が client_id で scope なし)",
			authorization: bearerToken(t, key, func(c *jwt.Claims) {
				c.Aud = jwt.Audience{"tegata-sample"}
				c.Scope = ""
			}),
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name: "aud が userinfo だけ",
			authorization: bearerToken(t, key, func(c *jwt.Claims) {
				c.Aud = jwt.Audience{testIssuer + "/userinfo"}
				c.Scope = "openid"
			}),
			scope:         "notes.read",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: invalidToken,
		},
		{
			name:          "notes.read のトークンで notes.write が必要",
			authorization: bearerToken(t, key, nil),
			scope:         "notes.write",
			wantStatus:    http.StatusForbidden,
			wantChallenge: `Bearer error="insufficient_scope", scope="notes.write"`,
		},
		{
			name:          "notes.readonly は notes.read は満たさない",
			authorization: bearerToken(t, key, func(c *jwt.Claims) { c.Scope = "openid notes.readonly" }),
			scope:         "notes.read",
			wantStatus:    http.StatusForbidden,
			wantChallenge: `Bearer error="insufficient_scope", scope="notes.read"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, next := serve(m, tt.scope, tt.authorization)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want = %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.wantChallenge)
			}
			if next.called {
				t.Errorf("next was called, want not called")
			}
		})
	}
}

func TestAuthMiddleware_Require_Success(t *testing.T) {
	key := newTestKey(t)
	m := newTestMiddleware(key)

	rec, next := serve(m, "notes.read", bearerToken(t, key, nil))
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty", got)
	}
	if !next.called {
		t.Fatalf("next wat not called")
	}
	if next.claims == nil {
		t.Fatalf("contextClaims() = nil, want claims")
	}
	if next.claims.Sub != "u-0001" {
		t.Errorf("claims.Sub = %q want = %q", next.claims.Sub, "u-0001")
	}
}
