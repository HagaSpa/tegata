package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
				if got := rec.Body.String(); got != "login page" {
					t.Errorf("body = %q, want %q", got, "login page")
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
