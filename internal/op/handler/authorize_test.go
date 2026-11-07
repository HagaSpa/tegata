package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const testState = "state-1"

var hiddenIDPattern = regexp.MustCompile(`name="id" value="([A-Za-z0-9_-]{43})"`)

func newAuthorizeHandler(t *testing.T) (*AuthorizeHandler, *store.AuthorizeRequests) {
	t.Helper()
	cl := registry.NewClients()
	ar := store.NewAuthorizeRequests()
	h := NewAuthorizeHandler(cl, ar)
	return h, ar
}

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

func getAuthorize(h *AuthorizeHandler, q url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postAuthorize(h *AuthorizeHandler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
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

var authorizeSenders = []struct {
	method string
	send   func(h *AuthorizeHandler, v url.Values) *httptest.ResponseRecorder
}{
	{http.MethodGet, getAuthorize},
	{http.MethodPost, postAuthorize},
}

func TestAuthorizeHandler(t *testing.T) {
	tests := []struct {
		name       string
		editQuery  func(q url.Values)
		wantStatus int
		wantError  string
	}{
		{"正常", nil, http.StatusOK, ""},
		{"redirect_uri 不一致", func(q url.Values) { q.Set("redirect_uri", "http://localhost:9999/callbacx") }, http.StatusBadRequest, ""},
		{"client_id 未登録", func(q url.Values) { q.Set("client_id", "unknown") }, http.StatusBadRequest, ""},
		{"response_type が token", func(q url.Values) { q.Set("response_type", "token") }, http.StatusFound, "unsupported_response_type"},
		{"scope に openid がない", func(q url.Values) { q.Set("scope", "profile") }, http.StatusFound, "invalid_scope"},
		{"scope が複数", func(q url.Values) { q.Set("scope", "openid profile email") }, http.StatusOK, ""},
		{"code_challenge なし", func(q url.Values) { q.Del("code_challenge") }, http.StatusOK, ""},
		{"method が plain", func(q url.Values) { q.Set("code_challenge_method", "plain") }, http.StatusFound, "invalid_request"},
		{"state なしで失敗", func(q url.Values) { q.Del("state"); q.Set("response_type", "token") }, http.StatusFound, "unsupported_response_type"},
		{"request をつけると失敗", func(q url.Values) { q.Set("request", "aaa") }, http.StatusFound, "request_not_supported"},
		{"request_uri をつけると失敗", func(q url.Values) { q.Set("request_uri", "aaa") }, http.StatusFound, "request_uri_not_supported"},
	}

	h, _ := newAuthorizeHandler(t)
	for _, s := range authorizeSenders {
		for _, tt := range tests {
			t.Run(s.method+" "+tt.name, func(t *testing.T) {
				q := validAuthorizeQuery()
				if tt.editQuery != nil {
					tt.editQuery(q)
				}
				rec := s.send(h, q)
				if rec.Code != tt.wantStatus {
					t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
				}
				switch tt.wantStatus {
				case http.StatusOK:
					body := rec.Body.String()
					if !strings.Contains(body, "<form") {
						t.Errorf("body does not contain a form: %q", body)
					}
					idFromBody(t, body)
					if strings.Count(body, `type="hidden"`) != 1 {
						t.Errorf("body must carry exactly one hidden input: %q", body)
					}
					if strings.Contains(body, `name="state"`) || strings.Contains(body, testState) {
						t.Errorf("body must not carry the request parameters: %q", body)
					}
					if strings.Contains(body, "invalid username or password") {
						t.Errorf("the login page must not show an error message: %q", body)
					}
				case http.StatusBadRequest:
					assertBadRequest(t, rec)
				case http.StatusFound:
					lq := redirectQuery(t, rec)
					if got := lq.Get("error"); got != tt.wantError {
						t.Errorf("error = %q, want %q", got, tt.wantError)
					}
					if lq.Get("error_description") == "" {
						t.Errorf("error_description is empty")
					}
					if want := q.Get("state"); want != "" && lq.Get("state") != want {
						t.Errorf("state = %q, want %q", lq.Get("state"), want)
					}
					if q.Get("state") == "" && lq.Has("state") {
						t.Errorf("Location must not contain state: %v", lq)
					}
				}
			})
		}
	}
}

func TestAuthorizeHandler_SavesRequest(t *testing.T) {
	for _, s := range authorizeSenders {
		t.Run(s.method, func(t *testing.T) {
			h, reqs := newAuthorizeHandler(t)
			q := validAuthorizeQuery()

			rec := s.send(h, q)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			got, err := reqs.Find(idFromBody(t, rec.Body.String()))
			if err != nil {
				t.Fatalf("Find() failed: %v", err)
			}
			want := parseAuthorizeRequest(q)
			want.ExpiresAt = got.ExpiresAt
			if *got != *want {
				t.Errorf("saved request = %+v, want %+v", *got, *want)
			}
		})
	}
}

func TestAuthorizeHandler_ThenLogin(t *testing.T) {
	for _, s := range authorizeSenders {
		t.Run(s.method, func(t *testing.T) {
			lh, reqs, _ := newLoginHandler(t)
			h := NewAuthorizeHandler(registry.NewClients(), reqs)

			page := s.send(h, validAuthorizeQuery())
			if page.Code != http.StatusOK {
				t.Fatalf("authorize status = %d, want 200", page.Code)
			}
			id := idFromBody(t, page.Body.String())

			q := redirectQuery(t, postLogin(lh, loginForm(id)))
			if !q.Has("code") || q.Get("state") != testState {
				t.Errorf("Location query = %v, want code and state=%s", q, testState)
			}
		})
	}
}
