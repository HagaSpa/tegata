package handler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/keys"
	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const testPostLogoutRedirectURI = "https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect"

func newLogoutHandler(t *testing.T) (*LogoutHandler, *keys.Manager, *store.Sessions) {
	t.Helper()
	km, err := keys.NewManager()
	if err != nil {
		t.Fatalf("keys.NewManager() failed: %v", err)
	}
	ss := store.NewSessions()
	return NewLogoutHandler(km, registry.NewClients(), ss, testIssuer), km, ss
}

func idTokenClaims(issuer string) *jwt.Claims {
	now := time.Now()
	return &jwt.Claims{
		Iss: issuer,
		Sub: "u-0001",
		Aud: jwt.Audience{"conformance"},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
	}
}

func newLogoutRequest(method string, params url.Values, sessionKey string) *http.Request {
	var req *http.Request
	if method == http.MethodPost {
		req = httptest.NewRequest(method, "/logout", strings.NewReader(params.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, "/logout?"+params.Encode(), nil)
	}
	if sessionKey != "" {
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionKey})
	}
	return req
}

func TestLogoutHandler_ServeHTTP_Redirect(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		state        string
		wantLocation string
	}{
		{"GET で state あり", http.MethodGet, testState, testPostLogoutRedirectURI + "?state=" + testState},
		{"GET で state なし", http.MethodGet, "", testPostLogoutRedirectURI},
		{"POST で state あり", http.MethodPost, testState, testPostLogoutRedirectURI + "?state=" + testState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, km, ss := newLogoutHandler(t)
			key := ss.Save("u-0001", time.Now())

			params := url.Values{}
			params.Set("id_token_hint", signToken(t, km, idTokenClaims(testIssuer)))
			params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
			if tt.state != "" {
				params.Set("state", tt.state)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newLogoutRequest(tt.method, params, key))

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d, body = %q", rec.Code, http.StatusFound, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			if _, err := ss.Get(key); !errors.Is(err, store.ErrInvalidSession) {
				t.Errorf("Sessions.Get() error = %v, want store.ErrInvalidSession", err)
			}

			var deleted *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == "session_id" {
					deleted = c
				}
			}
			if deleted == nil {
				t.Fatal("Set-Cookie for session_id is missing")
			}
			if deleted.MaxAge >= 0 || deleted.Path != "/" || deleted.Value != "" {
				t.Errorf("Set-Cookie = %q, want empty value, Path=/ and Max-Age=0", deleted.String())
			}
		})
	}
}

func TestLogoutHandler_ServeHTTP_WithoutRedirectURI(t *testing.T) {
	t.Run("正しい hint と保存されてる Cookie を受け取り、post_logout_redirect_uri がない場合", func(t *testing.T) {
		h, km, ss := newLogoutHandler(t)
		key := ss.Save("u-0001", time.Now())

		params := url.Values{}
		params.Set("id_token_hint", signToken(t, km, idTokenClaims(testIssuer)))
		params.Set("state", testState)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d, body = %q", rec.Code, http.StatusOK, rec.Body.String())
		}
		if got := rec.Header().Get("Location"); got != "" {
			t.Errorf("Location = %q, want empty", got)
		}
		if _, err := ss.Get(key); !errors.Is(err, store.ErrInvalidSession) {
			t.Errorf("Sessions.Get() error = %v, want store.ErrInvalidSession", err)
		}

		var deleted *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "session_id" {
				deleted = c
			}
		}
		if deleted == nil {
			t.Fatal("Set-Cookie for session_id is missing")
		}
		if deleted.MaxAge >= 0 || deleted.Path != "/" || deleted.Value != "" {
			t.Errorf("Set-Cookie = %q, want empty value, Path=/ and Max-Age=0", deleted.String())
		}

		// logout.html
		if !bytes.Contains(rec.Body.Bytes(), []byte("Logout Success.")) {
			t.Error("html element not found")
		}
	})
}

func TestLogoutHandler_ServeHTTP_Error(t *testing.T) {
	h, km, ss := newLogoutHandler(t)

	tests := []struct {
		name                  string
		idTokenHint           string
		clientID              string
		postLogoutRedirectURI string
	}{
		{
			name:                  "id_token_hint の検証に失敗",
			idTokenHint:           "unknown_id_token_hint",
			clientID:              "",
			postLogoutRedirectURI: testPostLogoutRedirectURI,
		},
		{
			name:                  "hint から復号した claims の iss と、issuer が一致しない",
			idTokenHint:           signToken(t, km, idTokenClaims("http://evil")),
			clientID:              "",
			postLogoutRedirectURI: testPostLogoutRedirectURI,
		},
		{
			name:                  "client_id が送られてきた時に、それが claims の aud に存在しない",
			idTokenHint:           signToken(t, km, idTokenClaims(testIssuer)),
			clientID:              "unknown_client_id",
			postLogoutRedirectURI: testPostLogoutRedirectURI,
		},
		{
			name:                  "post_logout_redirect_uri が送られてきた時に、それが Client に登録されていない",
			idTokenHint:           signToken(t, km, idTokenClaims(testIssuer)),
			clientID:              "",
			postLogoutRedirectURI: "unknown_post_logout_redirect_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := ss.Save("u-0001", time.Now())
			params := url.Values{}
			params.Set("state", testState)

			if tt.idTokenHint != "" {
				params.Set("id_token_hint", tt.idTokenHint)
			}
			if tt.clientID != "" {
				params.Set("client_id", tt.clientID)
			}
			if tt.postLogoutRedirectURI != "" {
				params.Set("post_logout_redirect_uri", tt.postLogoutRedirectURI)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := rec.Header().Get("Location"); got != "" {
				t.Errorf("Location = %q, want empty", got)
			}
			if _, err := ss.Get(key); err != nil {
				t.Errorf("Sessions.Get() error = %v", err)
			}

			// logout.html
			if !bytes.Contains(rec.Body.Bytes(), []byte("<title>Tegata Logout Executed</title>")) {
				t.Error("html element not found")
			}
		})
	}
}

func TestLogoutHandler_ServeHTTP_OK(t *testing.T) {
	h, km, ss := newLogoutHandler(t)
	key := ss.Save("u-0001", time.Now())
	key2 := ss.Save("u-0002", time.Now())

	tests := []struct {
		name        string
		idTokenHint string
		cookieKey   string
	}{
		{
			name:        "id_token_hint が空",
			idTokenHint: "",
			cookieKey:   key,
		},
		{
			name:        "Cookie が空",
			idTokenHint: signToken(t, km, idTokenClaims(testIssuer)),
			cookieKey:   "",
		},
		{
			name:        "Cookie のキーが store に存在しない",
			idTokenHint: signToken(t, km, idTokenClaims(testIssuer)),
			cookieKey:   "unknownCookieKey",
		},
		{
			name:        "別のユーザのセッションキー",
			idTokenHint: signToken(t, km, idTokenClaims(testIssuer)),
			cookieKey:   key2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			params.Set("state", testState)
			params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)

			if tt.idTokenHint != "" {
				params.Set("id_token_hint", tt.idTokenHint)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, tt.cookieKey))

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("Location"); got != "" {
				t.Errorf("Location = %q, want empty", got)
			}

			// Don't delete the session yet.
			if _, err := ss.Get(key); err != nil {
				t.Errorf("Sessions.Get() error = %v", err)
			}
			if _, err := ss.Get(key2); err != nil {
				t.Errorf("Sessions.Get() error = %v", err)
			}

			// logout_confirm.html
			if !bytes.Contains(rec.Body.Bytes(), []byte("<title>Tegata Logout Confirm</title>")) {
				t.Error("html element not found")
			}
		})
	}
}

func TestLogoutHandler_Post(t *testing.T) {
	h, _, ss := newLogoutHandler(t)
	key := ss.Save("u-0001", time.Now())

	tests := []struct {
		name      string
		cookieKey string
	}{
		{name: "Cookie あり", cookieKey: key},
		{name: "Cookie なし", cookieKey: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Post(rec, newLogoutRequest(http.MethodPost, nil, tt.cookieKey))

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			if tt.cookieKey != "" {
				if _, err := ss.Get(key); !errors.Is(err, store.ErrInvalidSession) {
					t.Errorf("Sessions.Get() error = %v, want store.ErrInvalidSession", err)
				}

				var deleted *http.Cookie
				cookies := rec.Result().Cookies()
				if len(cookies) != 1 {
					t.Fatal("Response.Cookies must be one sizes")
				}
				if cookies[0].Name != "session_id" {
					t.Fatal("Set-Cookie for session_id is missing")
				}
				deleted = cookies[0]
				if deleted.Value != "" {
					t.Errorf("Cookie[session_id] must be empty")
				}
			}
		})
	}
}
