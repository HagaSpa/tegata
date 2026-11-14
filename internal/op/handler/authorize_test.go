package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

func newAuthorizeHandler(t *testing.T) (*AuthorizeHandler, *store.AuthorizeRequests, *store.Sessions, *store.Codes) {
	t.Helper()
	cl := registry.NewClients()
	ar := store.NewAuthorizeRequests()
	ss := store.NewSessions()
	co := store.NewCodes()
	h := NewAuthorizeHandler(cl, ar, ss, co)
	return h, ar, ss, co
}

func getAuthorize(h *AuthorizeHandler, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postAuthorize(h *AuthorizeHandler, f url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var authorizeSenders = []struct {
	method string
	send   func(h *AuthorizeHandler, v url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder
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
		{"prompt=none でログインしていない", func(q url.Values) { q.Set("prompt", "none") }, http.StatusFound, "login_required"},
		{"prompt=none と login の併用", func(q url.Values) { q.Set("prompt", "none login") }, http.StatusFound, "invalid_request"},
		{"prompt=login はログイン画面", func(q url.Values) { q.Set("prompt", "login") }, http.StatusOK, ""},
		{"max_age=0 はログイン画面", func(q url.Values) { q.Set("max_age", "0") }, http.StatusOK, ""},
		{"max_age が数値でない", func(q url.Values) { q.Set("max_age", "abc") }, http.StatusFound, "invalid_request"},
		{"max_age が負", func(q url.Values) { q.Set("max_age", "-1") }, http.StatusFound, "invalid_request"},
	}

	h, _, _, _ := newAuthorizeHandler(t)
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
			h, reqs, _, _ := newAuthorizeHandler(t)
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

func TestAuthorizeHandler_Session(t *testing.T) {
	tests := []struct {
		name        string
		withSession bool
		cookieValue string
		loginAgo    time.Duration
		prompt      string
		maxAge      string
		wantStatus  int
		wantError   string
	}{
		{"prompt=none でログイン済みなら code", true, "", time.Minute, "none", "", http.StatusFound, ""},
		{"prompt=none で max_age 以内なら code", true, "", time.Minute, "none", "120", http.StatusFound, ""},
		{"prompt=none で max_age を過ぎたら login_required", true, "", 3 * time.Minute, "none", "120", http.StatusFound, "login_required"},
		{"prompt=none で max_age=0 は login_required", true, "", time.Minute, "none", "0", http.StatusFound, "login_required"},
		{"prompt=none でセッションが期限切れなら login_required", true, "", store.SessionTTL + time.Minute, "none", "", http.StatusFound, "login_required"},
		{"prompt=none で未知の cookie は login_required", false, "bogus", 0, "none", "", http.StatusFound, "login_required"},
		{"prompt なしならログイン済みでもログイン画面", true, "", time.Minute, "", "", http.StatusOK, ""},
		{"prompt なしで max_age を過ぎていればログイン画面", true, "", 3 * time.Minute, "", "120", http.StatusOK, ""},
	}

	for _, s := range authorizeSenders {
		for _, tt := range tests {
			t.Run(s.method+" "+tt.name, func(t *testing.T) {
				h, _, ss, codes := newAuthorizeHandler(t)
				authTime := time.Now().Add(-tt.loginAgo)
				cookie := &http.Cookie{Name: "session_id", Value: tt.cookieValue}
				if tt.withSession {
					cookie.Value = ss.Save("u-0001", authTime)
				}
				q := validAuthorizeQuery()
				if tt.prompt != "" {
					q.Set("prompt", tt.prompt)
				}
				if tt.maxAge != "" {
					q.Set("max_age", tt.maxAge)
				}

				rec := s.send(h, q, cookie)
				if rec.Code != tt.wantStatus {
					t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
				}
				if tt.wantStatus == http.StatusOK {
					idFromBody(t, rec.Body.String())
					return
				}

				lq := redirectQuery(t, rec)
				if got := lq.Get("error"); got != tt.wantError {
					t.Fatalf("error = %q, want %q", got, tt.wantError)
				}
				if got := lq.Get("state"); got != testState {
					t.Errorf("state = %q, want %q", got, testState)
				}
				if tt.wantError != "" {
					if lq.Has("code") {
						t.Errorf("an error response must not carry code: %v", lq)
					}
					return
				}

				got, err := codes.Consume(lq.Get("code"))
				if err != nil {
					t.Fatalf("Consume() failed: %v", err)
				}
				if got.ClientID != "tegata-sample" || got.RedirectURI != "http://localhost:9999/callback" ||
					got.Scope != "openid" || got.Nonce != "n" || got.CodeChallenge != "x" ||
					got.Sub != "u-0001" || !got.AuthTime.Equal(authTime) {
					t.Errorf("code = %+v, want the request values, sub u-0001 and auth time %v", *got, authTime)
				}
			})
		}
	}
}

func TestAuthorizeHandler_PromptNoneAfterLogin(t *testing.T) {
	lh, reqs, sessions, codes := newLoginHandler(t)
	h := NewAuthorizeHandler(registry.NewClients(), reqs, sessions, lh.code)

	id := idFromBody(t, getAuthorize(h, validAuthorizeQuery()).Body.String())
	login := postLogin(lh, loginForm(id))
	redirectQuery(t, login)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v, want only session_id", cookies)
	}
	session, err := sessions.Get(cookies[0].Value)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	q := validAuthorizeQuery()
	q.Set("prompt", "none")
	lq := redirectQuery(t, getAuthorize(h, q, cookies[0]))
	got, err := codes.Consume(lq.Get("code"))
	if err != nil {
		t.Fatalf("Consume() failed: %v (Location query %v)", err, lq)
	}
	if got.Sub != "u-0001" || !got.AuthTime.Equal(session.AuthTime) {
		t.Errorf("code = %+v, want sub u-0001 and the login time %v", *got, session.AuthTime)
	}
}

func TestAuthorizeHandler_ThenLogin(t *testing.T) {
	for _, s := range authorizeSenders {
		t.Run(s.method, func(t *testing.T) {
			lh, reqs, sessions, _ := newLoginHandler(t)
			h := NewAuthorizeHandler(registry.NewClients(), reqs, sessions, lh.code)

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
