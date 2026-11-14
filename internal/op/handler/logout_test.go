package handler

import (
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
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionKey})
	return req
}

func TestLogoutHandler_Redirect(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		state        string
		wantLocation string
	}{
		{"GET で state あり", http.MethodGet, testState, testPostLogoutRedirectURI + "?state=" + testState},
		{"GET で state なし", http.MethodGet, "", testPostLogoutRedirectURI},
		{"POST で state あり", http.MethodPost, testState, testPostLogoutRedirectURI + "?state=" + testState},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, km, ss := newLogoutHandler(t)
			key := ss.Save("u-0001", time.Now())

			params := url.Values{}
			params.Set("id_token_hint", signToken(t, km, idTokenClaims(testIssuer)))
			params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
			if tc.state != "" {
				params.Set("state", tc.state)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newLogoutRequest(tc.method, params, key))

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d, body = %q", rec.Code, http.StatusFound, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != tc.wantLocation {
				t.Errorf("Location = %q, want %q", got, tc.wantLocation)
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

func TestLogoutHandler_Post_Error(t *testing.T) {
	t.Run("id_token_hint の検証に失敗", func(t *testing.T) {
		h, km, ss := newLogoutHandler(t)
		key := ss.Save("u-0001", time.Now())
		_ = signToken(t, km, idTokenClaims(testIssuer))

		params := url.Values{}
		params.Set("id_token_hint", "unknown_id_token_hint")
		params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
		params.Set("state", testState)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("When get unknown id_token_hint, res.Code must be StatusBadRequest")
		}
	})

	t.Run("POST hint から復号した claims の iss と、issuer が一致しない", func(t *testing.T) {
		h, km, ss := newLogoutHandler(t)
		key := ss.Save("u-0001", time.Now())

		params := url.Values{}
		params.Set("id_token_hint", signToken(t, km, idTokenClaims("unkonwnIssuer")))
		params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
		params.Set("state", testState)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("When iss and issuer not matched, res.Code must be StatusBadRequest")
		}
	})

	t.Run("POST client_id が送られてきた時に、それが claims の aud に存在しない", func(t *testing.T) {
		h, km, ss := newLogoutHandler(t)
		key := ss.Save("u-0001", time.Now())

		params := url.Values{}
		params.Set("id_token_hint", signToken(t, km, idTokenClaims("testIssuer")))
		params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
		params.Set("state", testState)
		params.Set("client_id", "unknown_client_id")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("When get unknown client_id, res.Code must be StatusBadRequest")
		}
	})

	t.Run("POST post_logout_redirect_uri が送られてきた時に、それが Client に登録されていない ", func(t *testing.T) {
		h, km, ss := newLogoutHandler(t)
		key := ss.Save("u-0001", time.Now())

		params := url.Values{}
		params.Set("id_token_hint", signToken(t, km, idTokenClaims("testIssuer")))
		params.Set("post_logout_redirect_uri", testPostLogoutRedirectURI)
		params.Set("state", testState)
		params.Set("post_logout_redirect_uri", "unknown_post_logout_redirect_uri")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newLogoutRequest(http.MethodPost, params, key))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("When get unknown post_logout_redirect_uri, res.Code must be StatusBadRequest")
		}
	})
}
