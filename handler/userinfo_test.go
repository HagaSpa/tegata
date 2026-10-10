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

func signToken(t *testing.T, km *auth.KeyManager, claim *auth.Claim) string {
	t.Helper()
	jwt, err := km.Sign(claim)
	if err != nil {
		t.Fatalf("KeyManager.Sign() failed: %v", err)
	}
	return jwt.String()
}

func getUserInfo(h *UserInfoHandler, authorization string) *httptest.ResponseRecorder {
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

func TestUserInfoHandler_Get_Errors(t *testing.T) {
	h, km := newUserInfoHandler(t)
	now := time.Now()
	// valid := signToken(t, km, accessClaims("openid"))
	// full := signToken(t, km, accessClaims("openid profile email"))

	expiredClaims := accessClaims("openid")
	expiredClaims.Exp = now.Add(-time.Hour).Unix()
	expired := signToken(t, km, expiredClaims)

	cases := []struct {
		name         string
		authoriation string
		wantStatus   int
		wantWWWWAuth string
	}{
		{"ヘッダなし", "", 401, "Bearer"},
		{"schema 違い", "Basic dgVzdA==", 401, `Bearer error="invalid_token"`},
		{"形になっていない", "Bearer x", 401, `Bearer error="invalid_token"`},
		{"期限切れ", "Bearer " + expired, 401, `Bearer error="invalid_token"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := getUserInfo(h, tc.authoriation)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			wwwAuth := rec.Header().Get("WWW-Authenticate")
			if wwwAuth != tc.wantWWWWAuth {
				t.Fatalf("rec.header WWW-Authenticate = %s, wand = %s", wwwAuth, tc.wantWWWWAuth)
			}
		})
	}
}
