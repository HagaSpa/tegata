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

type stubUserRegister struct {
	err error
	got []registry.RegisterUserInfo
}

func (s *stubUserRegister) Register(info registry.RegisterUserInfo) error {
	s.got = append(s.got, info)
	return s.err
}

func registerForm(id string) url.Values {
	f := url.Values{}
	f.Set("id", id)
	f.Set("username", "alice")
	f.Set("password", "correct horse battery")
	f.Set("name", "Alice")
	f.Set("email", "alice@example.com")
	return f
}

func getRegister(h *RegisterHandler, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/register?id="+url.QueryEscape(id), nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	return rec
}

func postRegister(h *RegisterHandler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func assertPage(t *testing.T, rec *httptest.ResponseRecorder, action string, id string) {
	t.Helper()
	body := rec.Body.String()
	if !strings.Contains(body, `action="`+action+`"`) {
		t.Errorf("body is not the page posting to %s: %q", action, body)
	}
	if got := idFromBody(t, body); got != id {
		t.Errorf("id = %q, want %q", got, id)
	}
}

func TestRegisterHandler_Get(t *testing.T) {
	tests := []struct {
		name       string
		id         func(saved string) string
		wantStatus int
	}{
		{"保存済みの id は登録画面へ遷移", func(saved string) string { return saved }, http.StatusOK},
		{"存在しない id は 400", func(saved string) string { return "bogus" }, http.StatusBadRequest},
		{"id なしは 400", func(saved string) string { return "" }, http.StatusBadRequest},
	}

	reqs := store.NewAuthorizeRequests()
	h := NewRegisterHandler(reqs, &stubUserRegister{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saved := saveRequest(t, reqs, nil)
			rec := getRegister(h, tt.id(saved))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			switch tt.wantStatus {
			case http.StatusOK:
				assertPage(t, rec, "/register", saved)
			case http.StatusBadRequest:
				assertBadRequest(t, rec)
			}
		})
	}
}
