package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/keys"
	"github.com/HagaSpa/tegata/internal/op/registry"
)

func newUserInfoHandler(t *testing.T) (*UserInfoHandler, *keys.Manager) {
	t.Helper()
	km, err := keys.NewManager()
	if err != nil {
		t.Fatalf("keys.NewManager() failed: %v", err)
	}
	us, err := registry.NewUsers("username", "password", "u-0001", "Tegata User", "user@example.com")
	if err != nil {
		t.Fatalf("registry.NewUsers() failed: %v", err)
	}
	return NewUserInfofHandler(km, us, testIssuer), km
}

func signToken(t *testing.T, km *keys.Manager, claim *jwt.Claims) string {
	t.Helper()
	tok, err := km.Sign(claim)
	if err != nil {
		t.Fatalf("Manager.Sign() failed: %v", err)
	}
	return tok.String()
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

func accessClaims(scope string) *jwt.Claims {
	now := time.Now()
	return &jwt.Claims{
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

	invAudClaims := accessClaims("openid")
	invAudClaims.Aud = "tegata-sample"
	invAud := signToken(t, km, invAudClaims)

	invIssClaims := accessClaims("openid")
	invIssClaims.Iss = "http://evil"
	invIss := signToken(t, km, invIssClaims)

	invSubClaims := accessClaims("openid")
	invSubClaims.Sub = "u-9999"
	invSub := signToken(t, km, invSubClaims)

	cases := []struct {
		name         string
		authoriation string
		wantStatus   int
		wantWWWWAuth string
	}{
		{"ヘッダなし", "", 401, "Bearer"},
		{"schema 違い", "Basic dgVzdA==", 401, `Bearer`},
		{"形になっていない", "Bearer x", 401, `Bearer error="invalid_token"`},
		{"期限切れ", "Bearer " + expired, 401, `Bearer error="invalid_token"`},
		{"Aud が異なる", "Bearer " + invAud, 401, `Bearer error="invalid_token"`},
		{"Iss が異なる", "Bearer " + invIss, 401, `Bearer error="invalid_token"`},
		{"Sub が異なる", "Bearer " + invSub, 401, `Bearer error="invalid_token"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := getUserInfo(h, tc.authoriation)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			wwwAuth := rec.Header().Get("WWW-Authenticate")
			if wwwAuth != tc.wantWWWWAuth {
				t.Errorf("rec.header WWW-Authenticate = %s, wand = %s", wwwAuth, tc.wantWWWWAuth)
			}
		})
	}
}

func TestUserInfoHandler_Get_Success(t *testing.T) {
	h, km := newUserInfoHandler(t)
	valid := signToken(t, km, accessClaims("openid"))
	full := signToken(t, km, accessClaims("openid profile email"))

	t.Run("openid のみ", func(t *testing.T) {
		rec := getUserInfo(h, "Bearer "+valid)
		if rec.Code != 200 {
			t.Errorf("status = %d, want %d (body %q)", rec.Code, 200, rec.Body.String())
		}

		m := map[string]any{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("Decode failed: %v (Body: %s)", err, rec.Body.String())
		}
		if m["sub"] != "u-0001" {
			t.Errorf("valid.sub = %s, want %s", m["sub"], "u-0001")
		}
		if m["name"] != nil {
			t.Errorf("valid.name = %s", m["name"])
		}
		if m["preferred_username"] != nil {
			t.Errorf("valid.preferred_username = %s", m["preferred_username"])
		}
		if m["email"] != nil {
			t.Errorf("valid.email = %s", m["email"])
		}
		if m["email_verified"] != nil {
			t.Errorf("valid.email_verified = %s", m["email_verified"])
		}
	})

	t.Run("openid profile email", func(t *testing.T) {
		rec := getUserInfo(h, "Bearer "+full)
		if rec.Code != 200 {
			t.Errorf("status = %d, want %d (body %q)", rec.Code, 200, rec.Body.String())
		}

		m := map[string]any{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("Decode failed: %v (Body: %s)", err, rec.Body.String())
		}
		if m["sub"] != "u-0001" {
			t.Errorf("valid.sub = %s, want %s", m["sub"], "u-0001")
		}
		if m["name"] != "Tegata User" {
			t.Errorf("valid.name = %s", m["name"])
		}
		if m["preferred_username"] != "username" {
			t.Errorf("valid.preferred_username = %s", m["preferred_username"])
		}
		if m["email"] != "user@example.com" {
			t.Errorf("valid.email = %s", m["email"])
		}
		if m["email_verified"] != true {
			t.Errorf("valid.email_verified = %s", m["email_verified"])
		}
	})
}
