package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

func revokeForm(token string) url.Values {
	f := url.Values{}
	f.Set("token", token)
	f.Set("client_id", "tegata-sample")
	f.Set("client_secret", "dummy-secret")
	return f
}

func postRevoke(h *RevokeHandler, f url.Values, basic bool) *httptest.ResponseRecorder {
	clientID, secret := f.Get("client_id"), f.Get("client_secret")
	if basic {
		f = cloneValues(f)
		f.Del("client_id")
		f.Del("client_secret")
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(clientID, secret)
	}
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func TestRevokeHandler_Post(t *testing.T) {
	tests := []struct {
		name        string
		basic       bool
		editForm    func(f url.Values)
		wantStatus  int
		wantError   string
		wantRevoked bool
	}{
		{"自分のトークンは失効する", false, nil, http.StatusOK, "", true},
		{"Basic で認証しても失効する", true, nil, http.StatusOK, "", true},
		{"別のクライアントのトークンは消さないが 200", false, func(f url.Values) {
			f.Set("client_id", "tegata-rp")
			f.Set("client_secret", "rp-secret")
		}, http.StatusOK, "", false},
		{"存在しない値も 200", false, func(f url.Values) { f.Set("token", "nope") }, http.StatusOK, "", false},
		{"token なしは invalid_request", false, func(f url.Values) { f.Del("token") }, http.StatusBadRequest, "invalid_request", false},
		{"client_secret 違いは invalid_client", false, func(f url.Values) { f.Set("client_secret", "x") }, http.StatusUnauthorized, "invalid_client", false},
		{"client_secret 違い（Basic）も invalid_client", true, func(f url.Values) { f.Set("client_secret", "x") }, http.StatusUnauthorized, "invalid_client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := store.NewRefreshTokens()
			h := NewRevokeHandler(registry.NewClients(), ts)
			key := ts.Issue("tegata-sample", "u-0001", "openid offline_access")

			f := revokeForm(key)
			if tt.editForm != nil {
				tt.editForm(f)
			}
			rec := postRevoke(h, f, tt.basic)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantError == "" && rec.Body.Len() != 0 {
				t.Errorf("body = %q, want empty", rec.Body.String())
			}
			if tt.wantError != "" {
				if got := decodeJSON(t, rec)["error"]; got != tt.wantError {
					t.Errorf("error = %v, want %q", got, tt.wantError)
				}
				if tt.wantStatus == http.StatusUnauthorized && tt.basic && rec.Header().Get("WWW-Authenticate") == "" {
					t.Errorf("401 for Basic auth must carry WWW-Authenticate")
				}
			}

			_, _, err := ts.Rotate(key, "tegata-sample")
			if revoked := err != nil; revoked != tt.wantRevoked {
				t.Errorf("revoked = %v, want %v", revoked, tt.wantRevoked)
			}
		})
	}
}
