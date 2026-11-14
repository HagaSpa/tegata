package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/keys"
	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const testState = "state-1"

var hiddenIDPattern = regexp.MustCompile(`name="id" value="([A-Za-z0-9_-]{43})"`)

func validAuthorizeQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "tegata-sample")
	q.Set("redirect_uri", "http://localhost:9999/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", testState)
	q.Set("nonce", "n")
	q.Set("code_challenge", "x")
	q.Set("code_challenge_method", "S256")
	return q
}

func saveRequest(t *testing.T, reqs *store.AuthorizeRequests, editRequest func(r *store.AuthorizeRequest)) string {
	t.Helper()
	req := parseAuthorizeRequest(validAuthorizeQuery())
	if editRequest != nil {
		editRequest(req)
	}
	id := reqs.Save(req)
	return id
}

func loginForm(id string) url.Values {
	f := url.Values{}
	f.Set("id", id)
	f.Set("username", "username")
	f.Set("password", "password")
	f.Set("action", "approve")
	return f
}

func idFromBody(t *testing.T, body string) string {
	t.Helper()
	m := hiddenIDPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("body does not carry id as hidden input: %q", body)
	}
	return m[1]
}

func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", rec.Header().Get("Location"), err)
	}
	q := loc.Query()
	loc.RawQuery = ""
	if got, want := loc.String(), "http://localhost:9999/callback"; got != want {
		t.Errorf("redirect target = %q, want %q", got, want)
	}
	return q
}

func assertBadRequest(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty (must not redirect)", loc)
	}
}

func newLoginHandler(t *testing.T) (*LoginHandler, *store.AuthorizeRequests, *store.Codes) {
	t.Helper()
	cl := registry.NewClients()
	u, err := registry.NewUsers(
		"username",
		"password",
		"u-0001",
		"hagaspa",
		"justicesparrow13@gmail.com",
	)
	if err != nil {
		t.Fatal("failed initilize")
	}
	co := store.NewCodes()
	ar := store.NewAuthorizeRequests()
	ss := store.NewSessions()
	h := NewLoginHandler(cl, u, co, ar, ss)
	return h, ar, co
}

func postLogin(h *LoginHandler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func signToken(t *testing.T, km *keys.Manager, claim *jwt.Claims) string {
	t.Helper()
	tok, err := km.Sign(claim)
	if err != nil {
		t.Fatalf("Manager.Sign() failed: %v", err)
	}
	return tok.String()
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
