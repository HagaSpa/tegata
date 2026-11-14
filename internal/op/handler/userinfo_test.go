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

func getUserInfo(h *UserInfoHandler, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rec := httptest.NewRecorder()
	if authorization != "" {
		req.Header.Set("authorization", authorization)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func accessClaims(scope string) *jwt.Claims {
	now := time.Now()
	return &jwt.Claims{
		Iss:   testIssuer,
		Sub:   "u-0001",
		Aud:   jwt.Audience{testIssuer + "/userinfo"},
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Scope: scope,
	}
}

func TestUserInfoHandler_Get_Errors(t *testing.T) {
	const invalidToken = `Bearer error="invalid_token"`
	h, km := newUserInfoHandler(t)

	cases := []struct {
		name        string
		header      string
		editClaims  func(c *jwt.Claims)
		wantWWWAuth string
	}{
		{name: "ヘッダなし", wantWWWAuth: "Bearer"},
		{name: "scheme 違い", header: "Basic dGVzdA==", wantWWWAuth: "Bearer"},
		{name: "形になっていない", header: "Bearer x", wantWWWAuth: invalidToken},
		{name: "期限切れ", editClaims: func(c *jwt.Claims) { c.Exp = time.Now().Add(-time.Hour).Unix() }, wantWWWAuth: invalidToken},
		{name: "aud が client_id（ID トークンと同じ形）", editClaims: func(c *jwt.Claims) { c.Aud = jwt.Audience{"tegata-sample"} }, wantWWWAuth: invalidToken},
		{name: "aud が RS 宛てだけ", editClaims: func(c *jwt.Claims) { c.Aud = jwt.Audience{"http://localhost:9000"} }, wantWWWAuth: invalidToken},
		{name: "iss が異なる", editClaims: func(c *jwt.Claims) { c.Iss = "http://evil" }, wantWWWAuth: invalidToken},
		{name: "sub が存在しない", editClaims: func(c *jwt.Claims) { c.Sub = "u-9999" }, wantWWWAuth: invalidToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if tc.editClaims != nil {
				c := accessClaims("openid")
				tc.editClaims(c)
				header = "Bearer " + signToken(t, km, c)
			}

			rec := getUserInfo(h, header)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 (body %q)", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.wantWWWAuth {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.wantWWWAuth)
			}
		})
	}
}

func TestUserInfoHandler_Get_Success(t *testing.T) {
	h, km := newUserInfoHandler(t)
	valid := signToken(t, km, accessClaims("openid"))
	full := signToken(t, km, accessClaims("openid profile email"))
	multipleAudClaims := accessClaims("openid profile email")
	multipleAudClaims.Aud = jwt.Audience{testIssuer + "/userinfo", "http://localhost:9000"}
	multipleAud := signToken(t, km, multipleAudClaims)

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

	t.Run("aud が配列の場合でも通る", func(t *testing.T) {
		rec := getUserInfo(h, "Bearer "+multipleAud)
		if rec.Code != 200 {
			t.Errorf("status = %d, want %d (body: %s)", rec.Code, 200, rec.Body.String())
		}

		m := map[string]any{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("Decode failed: %v (Body: %s)", err, rec.Body.String())
		}
		if m["sub"] != "u-0001" {
			t.Errorf("valid.sub = %s, want %s", m["sub"], "u-0001")
		}
	})
}
