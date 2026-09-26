package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/auth"
)

func TestAuthorizeHandler_Get(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(q url.Values)
		wantStatus int
		wantError  string
	}{
		{"正常", nil, http.StatusOK, ""},
		{"redirect_uri 不一致", func(q url.Values) { q.Set("redirect_uri", "http://localhost:9999/callbacx") }, http.StatusBadRequest, ""},
		{"client_id 未登録", func(q url.Values) { q.Set("client_id", "unknown") }, http.StatusBadRequest, ""},
		{"response_type が token", func(q url.Values) { q.Set("response_type", "token") }, http.StatusFound, "unsupported_response_type"},
		{"scope に openid がない", func(q url.Values) { q.Set("scope", "profile") }, http.StatusFound, "invalid_scope"},
		{"scope が複数", func(q url.Values) { q.Set("scope", "openid profile email") }, http.StatusOK, ""},
		{"code_challenge なし", func(q url.Values) { q.Del("code_challenge") }, http.StatusFound, "invalid_request"},
		{"method が plain", func(q url.Values) { q.Set("code_challenge_method", "plain") }, http.StatusFound, "invalid_request"},
		{"state なしで失敗", func(q url.Values) { q.Del("state"); q.Del("code_challenge") }, http.StatusFound, "invalid_request"},
	}

	h := NewAuthorizeHandler(auth.NewClientStore(), nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := validAuthorizeQuery()
			if tt.mutate != nil {
				tt.mutate(q)
			}
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
			rec := httptest.NewRecorder()
			h.Get(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			location := rec.Header().Get("Location")
			switch tt.wantStatus {
			case http.StatusOK:
				body := rec.Body.String()
				if !strings.Contains(body, "<form") {
					t.Errorf("body does not contain a form: %q", body)
				}
				if want := `name="state" value="abc"`; !strings.Contains(body, want) {
					t.Errorf("body does not carry state as hidden input: %q", body)
				}
				if strings.Contains(body, "invalid username or password") {
					t.Errorf("GET must not show an error message: %q", body)
				}
			case http.StatusBadRequest:
				if location != "" {
					t.Errorf("Location = %q, want empty (must not redirect)", location)
				}
			case http.StatusFound:
				loc, err := url.Parse(location)
				if err != nil {
					t.Fatalf("Location %q is not a URL: %v", location, err)
				}
				if got := loc.Query().Get("error"); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
				if loc.Query().Get("error_description") == "" {
					t.Errorf("error_description is empty")
				}
				if want := q.Get("state"); want != "" {
					if got := loc.Query().Get("state"); got != want {
						t.Errorf("state = %q, want %q", got, want)
					}
				}
				if q.Get("state") == "" && loc.Query().Has("state") {
					t.Errorf("Location %q must not contain state", location)
				}
				loc.RawQuery = ""
				if got := loc.String(); got != q.Get("redirect_uri") {
					t.Errorf("redirect target = %q, want %q", got, q.Get("redirect_uri"))
				}
			}
		})
	}
}

func validAuthorizeQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "tegata-sample")
	q.Set("redirect_uri", "http://localhost:9999/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", "abc")
	q.Set("nonce", "n")
	q.Set("code_challenge", "x")
	q.Set("code_challenge_method", "S256")
	return q
}

func validAuthorizeForm() url.Values {
	f := validAuthorizeQuery()
	f.Set("username", "username")
	f.Set("password", "password")
	f.Set("action", "approve")
	return f
}

func newPostHandler(t *testing.T) *AuthorizeHandler {
	t.Helper()
	users, err := auth.NewUserStore("username", "password", "u-0001")
	if err != nil {
		t.Fatalf("NewUserStore() failed: %v", err)
	}
	return NewAuthorizeHandler(auth.NewClientStore(), users, auth.NewCodeStore())
}

func postAuthorize(h *AuthorizeHandler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func TestAuthorizeHandler_Post(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(f url.Values)
		wantStatus int
		wantError  string
		wantCode   bool
	}{
		{"承認で code が返る", nil, http.StatusFound, "", true},
		{"拒否は access_denied", func(f url.Values) { f.Set("action", "deny") }, http.StatusFound, "access_denied", false},
		{"パスワード違いは再表示", func(f url.Values) { f.Set("password", "wrong") }, http.StatusOK, "", false},
		{"ユーザ不在も再表示", func(f url.Values) { f.Set("username", "nobody") }, http.StatusOK, "", false},
		{"hidden の redirect_uri 差し替えは 400", func(f url.Values) { f.Set("redirect_uri", "http://localhost:9999/callbacx") }, http.StatusBadRequest, "", false},
		{"hidden の client_id 差し替えは 400", func(f url.Values) { f.Set("client_id", "unknown") }, http.StatusBadRequest, "", false},
		{"hidden の code_challenge 削除は invalid_request", func(f url.Values) { f.Del("code_challenge") }, http.StatusFound, "invalid_request", false},
		{"action 不正は 400", func(f url.Values) { f.Set("action", "x") }, http.StatusBadRequest, "", false},
		{"action なしは 400", func(f url.Values) { f.Del("action") }, http.StatusBadRequest, "", false},
	}
	h := newPostHandler(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validAuthorizeForm()
			if tt.mutate != nil {
				tt.mutate(f)
			}
			rec := postAuthorize(h, f)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			location := rec.Header().Get("Location")

			switch tt.wantStatus {
			case http.StatusOK, http.StatusBadRequest:
				if location != "" {
					t.Errorf("Location = %q, want empty", location)
				}
				if tt.wantStatus == http.StatusOK && !strings.Contains(rec.Body.String(), "invalid username or password") {
					t.Errorf("re-rendered page must show the error: %q", rec.Body.String())
				}
			case http.StatusFound:
				loc, err := url.Parse(location)
				if err != nil {
					t.Fatalf("Location %q is not a URL: %v", location, err)
				}
				q := loc.Query()
				if got := q.Get("error"); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
				if !tt.wantCode && q.Has("code") {
					t.Errorf("code must not be issued: %q", q.Get("code"))
				}
				if got := q.Get("state"); got != f.Get("state") {
					t.Errorf("state = %q, want %q", got, f.Get("state"))
				}
				loc.RawQuery = ""
				if got := loc.String(); got != f.Get("redirect_uri") {
					t.Errorf("redirect target= %q, want %q", got, f.Get("redirect_uri"))
				}
			}
		})
	}
}

func TestAuthorizeHandler_Post_CodeIsUniquePerApproval(t *testing.T) {
	h := newPostHandler(t)
	first := postAuthorize(h, validAuthorizeForm())
	second := postAuthorize(h, validAuthorizeForm())
	c1, _ := url.Parse(first.Header().Get("Location"))
	c2, _ := url.Parse(second.Header().Get("Location"))
	if c1 == nil || c2 == nil || c1.Query().Get("code") == c2.Query().Get("code") {
		t.Errorf("code must differ: %q vs %q", first.Header().Get("Location"), second.Header().Get("Location"))
	}
}

func TestAuthorizeHandler_Post_OmitsStateWhenAbsent(t *testing.T) {
	f := validAuthorizeForm()
	f.Del("state")
	rec := postAuthorize(newPostHandler(t), f)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if loc.Query().Has("state") {
		t.Errorf("Location %q must not contain state", loc)
	}
}

func TestAuthorizeHandler_Get_EscapesReflectedValues(t *testing.T) {
	q := validAuthorizeQuery()
	q.Set("state", `"><script>alert(1)</script>`)
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()

	NewAuthorizeHandler(auth.NewClientStore(), nil, nil).Get(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("state was reflected without escaping: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") && !strings.Contains(body, "\u003cscript\u003e") {
		t.Errorf("escaped state not found in body: %q", body)
	}
}
