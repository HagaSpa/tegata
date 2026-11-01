package bearer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"Bearer", "Bearer abc", "abc", true},
		{"scheme は大文字小文字を区別しない", "bearer abc", "abc", true},
		{"ヘッダーなし", "", "", false},
		{"トークンなし", "Bearer", "", false},
		{"別の scheme", "Basic abc", "", false},
		{"要素が多すぎる", "Bearer abc def", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set(bearerHeader, tc.header)
			}
			got, ok := Token(r)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("Token() = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestWriteMissingToken(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteMissingToken(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get(challengeHeader); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
}

func TestWriteInvalidToken(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteInvalidToken(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got, want := rec.Header().Get(challengeHeader), `Bearer error="invalid_token"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestWriteInsufficientScope(t *testing.T) {
	rec := httptest.NewRecorder()
	scope := "openid notes.read"
	WriteInsufficientScope(rec, scope)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got, want := rec.Header().Get(challengeHeader), `Bearer error="insufficient_scope", scope="openid notes.read"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}
