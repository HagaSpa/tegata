package handler

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testEscapedClientID = "client:1"
	testEscapedSecret   = "s e+c%ret"
)

type fakeClientAuthenticator struct {
	calls int
}

func (c *fakeClientAuthenticator) Authenticate(clientID, secret string) bool {
	c.calls++
	return clientID == testEscapedClientID && secret == testEscapedSecret
}

func newBasicAuthRequest(userPass string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(userPass)))
	return req
}

func TestAuthenticateClient_Basic(t *testing.T) {
	encodedID := url.QueryEscape(testEscapedClientID)
	encodedSecret := url.QueryEscape(testEscapedSecret)

	tests := []struct {
		name      string
		userPass  string
		wantOK    bool
		wantID    string
		wantCalls int
	}{
		{"URL エンコードされた値はデコードしてから照合する", encodedID + ":" + encodedSecret, true, testEscapedClientID, 1},
		{"client_id のエンコードが壊れていたら照合せずに 401", "%zz:" + encodedSecret, false, "", 0},
		{"client_secret のエンコードが壊れていたら照合せずに 401", encodedID + ":%zz", false, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &fakeClientAuthenticator{}
			rec := httptest.NewRecorder()
			id, ok := authenticateClient(rec, newBasicAuthRequest(tt.userPass), c)

			if ok != tt.wantOK || id != tt.wantID {
				t.Errorf("authenticateClient() = (%q, %v), want (%q, %v)", id, ok, tt.wantID, tt.wantOK)
			}
			if c.calls != tt.wantCalls {
				t.Errorf("Authenticate calls = %d, want %d", c.calls, tt.wantCalls)
			}

			if tt.wantOK {
				if rec.Body.Len() != 0 {
					t.Errorf("body = %q, want empty", rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="tegata"` {
				t.Errorf("WWW-Authenticate = %q, want %q", got, `Basic realm="tegata"`)
			}
			if body := decodeJSON(t, rec); body["error"] != "invalid_client" {
				t.Errorf("error = %v, want invalid_client", body["error"])
			}
		})
	}
}

func TestAuthenticateClient_PostBodyIsNotDecodedAgain(t *testing.T) {
	form := url.Values{"client_id": {testEscapedClientID}, "client_secret": {testEscapedSecret}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &fakeClientAuthenticator{}

	id, ok := authenticateClient(httptest.NewRecorder(), req, c)

	if !ok || id != testEscapedClientID {
		t.Errorf("authenticateClient() = (%q, %v), want (%q, true)", id, ok, testEscapedClientID)
	}
}
