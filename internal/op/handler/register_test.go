package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"uuid"

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

func TestRegisterHandler_Post(t *testing.T) {
	password := func(p string) func(f url.Values) {
		return func(f url.Values) { f.Set("password", p) }
	}
	const (
		success   = "Sign Up is success."
		required  = "username is required"
		length    = "Please make your password 15-64 characters long"
		duplicate = "Username is already in use."
	)

	tests := []struct {
		name         string
		editForm     func(f url.Values)
		registerErr  error
		wantStatus   int
		wantRegister bool
		wantPage     string
		wantMessage  string
	}{
		{"登録できたらログイン画面に戻る", nil, nil, http.StatusOK, true, "/login", success},
		{"name と email は空でも許可", func(f url.Values) { f.Del("name"); f.Del("email") }, nil, http.StatusOK, true, "/login", success},
		{"username が空は再表示", func(f url.Values) { f.Set("username", "") }, nil, http.StatusOK, false, "/register", required},
		{"パスワード 14 文字は再表示", password(strings.Repeat("a", 14)), nil, http.StatusOK, false, "/register", length},
		{"パスワード 15 文字は登録できる", password(strings.Repeat("a", 15)), nil, http.StatusOK, true, "/login", success},
		{"パスワード 64 文字は登録できる", password(strings.Repeat("a", 64)), nil, http.StatusOK, true, "/login", success},
		{"パスワード 65 文字は再表示", password(strings.Repeat("a", 65)), nil, http.StatusOK, false, "/register", length},
		{"日本語 14 文字は再表示", password(strings.Repeat("あ", 14)), nil, http.StatusOK, false, "/register", length},
		{"日本語 64 文字は登録できる", password(strings.Repeat("あ", 64)), nil, http.StatusOK, true, "/login", success},
		{"同じ usename は再表示", nil, registry.ErrDuplicatedUsername, http.StatusOK, true, "/register", duplicate},
		{"Register の失敗は 500", nil, errors.New("boom"), http.StatusInternalServerError, true, "", ""},
		{"存在しない id は 400", func(f url.Values) { f.Set("id", "bogus") }, nil, http.StatusBadRequest, false, "", ""},
		{"id なしは 400", func(f url.Values) { f.Del("id") }, nil, http.StatusBadRequest, false, "", ""},
	}

	reqs := store.NewAuthorizeRequests()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubUserRegister{err: tt.registerErr}
			h := NewRegisterHandler(reqs, stub)
			id := saveRequest(t, reqs, nil)
			f := registerForm(id)
			if tt.editForm != nil {
				tt.editForm(f)
			}

			rec := postRegister(h, f)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}

			if !tt.wantRegister {
				if len(stub.got) != 0 {
					t.Errorf("Register() was called with %+v, want no call", stub.got)
				}
			} else {
				want := []registry.RegisterUserInfo{{
					Username: f.Get("username"),
					Password: f.Get("password"),
					Name:     f.Get("name"),
					Email:    f.Get("email"),
				}}
				if !reflect.DeepEqual(stub.got, want) {
					t.Errorf("Register() got %+v, want %+v", stub.got, want)
				}
			}

			switch tt.wantStatus {
			case http.StatusOK:
				assertPage(t, rec, tt.wantPage, id)
				if !strings.Contains(rec.Body.String(), tt.wantMessage) {
					t.Errorf("body does not contain %q: %q", tt.wantMessage, rec.Body.String())
				}
			case http.StatusBadRequest:
				assertBadRequest(t, rec)
			}
		})
	}
}

func TestRegisterHandler_PostThenLogin(t *testing.T) {
	u, err := registry.NewUsers("username", "password", "u-0001", "hagaspa", "justicesparrow13@gmail.com")
	if err != nil {
		t.Fatalf("could not construct users: %v", err)
	}
	reqs := store.NewAuthorizeRequests()
	codes := store.NewCodes()
	rh := NewRegisterHandler(reqs, u)
	lh := NewLoginHandler(registry.NewClients(), u, codes, reqs)

	id := idFromBody(t, getRegister(rh, saveRequest(t, reqs, nil)).Body.String())
	page := postRegister(rh, registerForm(id))
	if page.Code != http.StatusOK {
		t.Fatalf("register status = %d, want 200 (body %q)", page.Code, page.Body.String())
	}

	login := loginForm(idFromBody(t, page.Body.String()))
	login.Set("username", "alice")
	login.Set("password", "correct horse battery")
	q := redirectQuery(t, postLogin(lh, login))

	code, err := codes.Consume(q.Get("code"))
	if err != nil {
		t.Fatalf("Consume() failed: %v", err)
	}
	if _, err := uuid.Parse(code.Sub); err != nil {
		t.Errorf("code.Sub = %q, want the UUID of the registered user: %v", code.Sub, err)
	}
}
