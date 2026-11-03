package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/op/keys"
	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const (
	testIssuer   = "http://localhost:8080"
	testVerifier = "verifier-1"
	testNonce    = "nonce-1"
)

func newTokenHandler(t *testing.T) (*TokenHandler, *store.Codes) {
	t.Helper()
	km, err := keys.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	co := store.NewCodes()
	ts := store.NewRefreshTokens()
	r := registry.NewResources()
	return NewTokenHandler(registry.NewClients(), ts, co, km, r, testIssuer), co
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func issueCode(t *testing.T, codes *store.Codes, scope, verifier, nonce string) string {
	t.Helper()
	code := codes.Issue("tegata-sample", "http://localhost:9999/callback", scope, challengeOf(verifier), nonce, "u-0001")
	return code
}

func validTokenForm(code string) url.Values {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", "http://localhost:9999/callback")
	f.Set("code_verifier", testVerifier)
	f.Set("client_id", "tegata-sample")
	f.Set("client_secret", "dummy-secret")
	return f
}

func postToken(h *TokenHandler, f url.Values, basic bool) *httptest.ResponseRecorder {
	clientID, secret := f.Get("client_id"), f.Get("client_secret")
	if basic {
		f = cloneValues(f)
		f.Del("client_id")
		f.Del("client_secret")
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(clientID, secret)
	}
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func cloneValues(v url.Values) url.Values {
	c := url.Values{}
	for k, vs := range v {
		c[k] = append([]string(nil), vs...)
	}
	return c
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	return body
}

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3: %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload is not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	return claims
}

func TestTokenHandler_Post(t *testing.T) {
	cases := []struct {
		name       string
		basic      bool
		editForm   func(f url.Values)
		wantStatus int
		wantError  string
	}{
		{"正常（本文で認証）", false, nil, http.StatusOK, ""},
		{"正常（Basic で認証）", true, nil, http.StatusOK, ""},
		{"client_secret 違いは invalid_client", false, func(f url.Values) { f.Set("client_secret", "x") }, http.StatusUnauthorized, "invalid_client"},
		{"client_secret 違い（Basic）も invalid_client", true, func(f url.Values) { f.Set("client_secret", "x") }, http.StatusUnauthorized, "invalid_client"},
		{"client_id 未登録は invalid_client", false, func(f url.Values) { f.Set("client_id", "unknown") }, http.StatusUnauthorized, "invalid_client"},
		{"grant_type 違いは unsupported_grant_type", false, func(f url.Values) { f.Set("grant_type", "password") }, http.StatusBadRequest, "unsupported_grant_type"},
		{"code 不明は invalid_grant", false, func(f url.Values) { f.Set("code", "nope") }, http.StatusBadRequest, "invalid_grant"},
		{"code_verifier 違いは invalid_grant", false, func(f url.Values) { f.Set("code_verifier", "wrong") }, http.StatusBadRequest, "invalid_grant"},
		{"redirect_uri 違いは invalid_grant", false, func(f url.Values) { f.Set("redirect_uri", "http://localhost:9999/callbacx") }, http.StatusBadRequest, "invalid_grant"},
	}

	h, codes := newTokenHandler(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validTokenForm(issueCode(t, codes, "openid", testVerifier, testNonce))
			if tc.editForm != nil {
				tc.editForm(f)
			}

			rec := postToken(h, f, tc.basic)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			body := decodeJSON(t, rec)

			if tc.wantError != "" {
				if got := body["error"]; got != tc.wantError {
					t.Errorf("error = %v, want %q", got, tc.wantError)
				}
				if tc.wantStatus == http.StatusUnauthorized && tc.basic && rec.Header().Get("WWW-Authenticate") == "" {
					t.Errorf("401 for Basic auth must carry WWW-Authenticate")
				}
				return
			}

			if body["token_type"] != "Bearer" {
				t.Errorf("token_type = %v, want Bearer", body["token_type"])
			}
			if body["expires_in"] != float64(3600) {
				t.Errorf("expires_in = %v, want 3600", body["expires_in"])
			}
			if body["scope"] != "openid" {
				t.Errorf("scope = %v, want openid", body["scope"])
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}

			idToken, _ := body["id_token"].(string)
			id := decodePayload(t, idToken)
			if id["iss"] != testIssuer || id["sub"] != "u-0001" || id["aud"] != "tegata-sample" || id["nonce"] != testNonce {
				t.Errorf("id_token claims = %v", id)
			}
			if _, ok := id["scope"]; ok {
				t.Errorf("id_token must not carry scope: %v", id)
			}

			accessToken, _ := body["access_token"].(string)
			at := decodePayload(t, accessToken)
			if at["iss"] != testIssuer || at["sub"] != "u-0001" || at["aud"] != testIssuer+"/userinfo" || at["scope"] != "openid" {
				t.Errorf("access_token claims = %v", at)
			}
			if _, ok := at["nonce"]; ok {
				t.Errorf("access_token must not carry nonce: %v", at)
			}
		})
	}
}

func TestTokenHandler_Post_CodeIsSingleUse(t *testing.T) {
	h, codes := newTokenHandler(t)
	code := issueCode(t, codes, "openid", testVerifier, testNonce)

	first := postToken(h, validTokenForm(code), false)
	second := postToken(h, validTokenForm(code), false)

	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200 (body %q)", first.Code, first.Body.String())
	}
	if second.Code != http.StatusBadRequest || decodeJSON(t, second)["error"] != "invalid_grant" {
		t.Errorf("second status = %d body = %q, want 400 invalid_grant", second.Code, second.Body.String())
	}
}

func TestTokenHandler_Post_WrongVerifierBurnsCode(t *testing.T) {
	h, codes := newTokenHandler(t)
	code := issueCode(t, codes, "openid", testVerifier, testNonce)

	wrong := validTokenForm(code)
	wrong.Set("code_verifier", "wrong")
	if rec := postToken(h, wrong, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier status = %d, want 400", rec.Code)
	}

	retry := postToken(h, validTokenForm(code), false)
	if retry.Code != http.StatusBadRequest || decodeJSON(t, retry)["error"] != "invalid_grant" {
		t.Errorf("retry status = %d body = %q, want 400 invalid_grant (code must be consumed)", retry.Code, retry.Body.String())
	}
}

func TestTokenHandler_Post_OmitsNonceWhenAbsent(t *testing.T) {
	h, codes := newTokenHandler(t)
	code := issueCode(t, codes, "openid", testVerifier, "")

	rec := postToken(h, validTokenForm(code), false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	idToken, _ := decodeJSON(t, rec)["id_token"].(string)
	if _, ok := decodePayload(t, idToken)["nonce"]; ok {
		t.Errorf("id_token must omit nonce when the request had none")
	}
}

func TestTokenHandler_Post_AccessTokenAudience(t *testing.T) {
	const rs = "http://localhost:9000"
	tests := []struct {
		name    string
		scope   string
		wantAud any
	}{
		{"openid だけなら文字列", "openid", testIssuer + "/userinfo"},
		{"notes.read なら文字列", "openid notes.read", []any{testIssuer + "/userinfo", rs}},
		{"read と write の両方でも RS は 1回", "openid notes.read notes.write", []any{testIssuer + "/userinfo", rs}},
	}

	h, codes := newTokenHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := issueCode(t, codes, tt.scope, testVerifier, testNonce)
			rec := postToken(h, validTokenForm(code), false)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
			}
			body := decodeJSON(t, rec)
			if body["scope"] != tt.scope {
				t.Errorf("scope = %v, want %q", body["scope"], tt.scope)
			}

			accessToken, _ := body["access_token"].(string)
			if got := decodePayload(t, accessToken)["aud"]; !reflect.DeepEqual(got, tt.wantAud) {
				t.Errorf("access_token aud = %#v, want %q", got, tt.wantAud)
			}

			idToken, _ := body["id_token"].(string)
			if got := decodePayload(t, idToken)["aud"]; got != "tegata-sample" {
				t.Errorf("id_token aud = %#v, want %q", got, "tegata-sample")
			}
		})
	}
}
