package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/auth"
)

func newUserInfoHandler(t *testing.T) (*UserInfoHandler, *auth.KeyManager) {
	t.Helper()
	km, err := auth.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager() failed: %v", err)
	}
	us, err := auth.NewUserStore("username", "password", "u-0001", "Tegata User", "user@example.com")
	if err != nil {
		t.Fatalf("NewUserStore() failed: %v", err)
	}
	return NewUserInfofHandler(km, us, "testIssuer"), km
}

func signToken(t *testing.T, km auth.KeyManager, claim auth.Claim) string {
	t.Helper()
	jwt, err := km.Sign(&claim)
	if err != nil {
		t.Fatalf("KeyManager.Sign() failed: %v", err)
	}
	return jwt.String()
}

func getUserInfo(h UserInfoHandler, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rec := httptest.NewRecorder()
	if authorization != "" {
		req.Header.Set("authorization", authorization)
	}
	h.Get(rec, req)
	return rec
}

func accessClaims(scope string) *auth.Claim {
	now := time.Now()
	return &auth.Claim{
		Iss:   testIssuer,
		Sub:   "u-0001",
		Aud:   testIssuer + "/userinfo",
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Scope: scope,
	}
}
