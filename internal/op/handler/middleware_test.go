package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDenyFraming(t *testing.T) {
	tests := []struct {
		name       string
		next       http.HandlerFunc
		wantStatus int
	}{
		{
			name: "画面を返すハンドラにも付く",
			next: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				io.WriteString(w, "<p>page</p>")
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "http.Error で返すエラー画面にも付く",
			next: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			DenyFraming(tt.next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
			res := rec.Result()

			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
			}
			if got := res.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
				t.Errorf("Content-Security-Policy = %q, want %q", got, "frame-ancestors 'none'")
			}
		})
	}
}
