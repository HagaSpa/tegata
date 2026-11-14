package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/op/store"
)

func assertNoCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a failed login must not set a cookie: %v", cookies)
	}
}

func TestLoginHandler_Post(t *testing.T) {
	tests := []struct {
		name       string
		editForm   func(f url.Values)
		wantStatus int
		wantError  string
	}{
		{"承認で code が返る", nil, http.StatusFound, ""},
		{"拒否は access_denied", func(f url.Values) { f.Set("action", "deny") }, http.StatusFound, "access_denied"},
		{"パスワード違いは再表示", func(f url.Values) { f.Set("password", "wrong") }, http.StatusOK, ""},
		{"ユーザ不在も再表示", func(f url.Values) { f.Set("username", "nobody") }, http.StatusOK, ""},
		{"action 不正は 400", func(f url.Values) { f.Set("action", "x") }, http.StatusBadRequest, ""},
		{"action なしは 400", func(f url.Values) { f.Del("action") }, http.StatusBadRequest, ""},
		{"存在しない id は 400", func(f url.Values) { f.Set("id", "bogus") }, http.StatusBadRequest, ""},
		{"id なしは 400", func(f url.Values) { f.Del("id") }, http.StatusBadRequest, ""},
		{"フォームの redirect_uri は無視する", func(f url.Values) { f.Set("redirect_uri", "http://evil/cb") }, http.StatusFound, ""},
	}

	h, reqs, sessions, _ := newLoginHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := saveRequest(t, reqs, nil)
			f := loginForm(id)
			if tt.editForm != nil {
				tt.editForm(f)
			}
			rec := postLogin(h, f)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}

			switch tt.wantStatus {
			case http.StatusOK:
				body := rec.Body.String()
				if !strings.Contains(body, "invalid username or password") {
					t.Errorf("re-rendered page must show the error: %q", body)
				}
				if got := idFromBody(t, body); got != id {
					t.Errorf("re-rendered id = %q, want %q", got, id)
				}
				assertNoCookie(t, rec)
			case http.StatusBadRequest:
				assertBadRequest(t, rec)
				assertNoCookie(t, rec)
			case http.StatusFound:
				cookies := rec.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != "session_id" {
					t.Fatalf("cookies = %v, want only session_id", cookies)
				}
				if !cookies[0].HttpOnly {
					t.Errorf("session_id must be HttpOnly: %v", cookies[0])
				}
				if cookies[0].MaxAge != int(store.SessionTTL.Seconds()) {
					t.Errorf("session.MaxAge must be store.SessionTTL.Seconds(), session.MaxAge: %d", cookies[0].MaxAge)
				}
				s, err := sessions.Get(cookies[0].Value)
				if err != nil {
					t.Fatalf("Get(%q) failed: %v", cookies[0].Value, err)
				}
				if s.Sub != "u-0001" || s.AuthTime.IsZero() {
					t.Errorf("session = %+v, want sub u-0001 and a login time", *s)
				}
				lq := redirectQuery(t, rec)
				if got := lq.Get("error"); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
				if wantCode := tt.wantError == ""; lq.Has("code") != wantCode {
					t.Errorf("code present = %v, want %v", lq.Has("code"), wantCode)
				}
				if got := lq.Get("state"); got != testState {
					t.Errorf("state = %q, want %q", got, testState)
				}
			}
		})
	}
}

func TestLoginHandler_Post_RetryAfterWrongPassword(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, nil)

	wrong := loginForm(id)
	wrong.Set("password", "wrong")
	if rec := postLogin(h, wrong); rec.Code != http.StatusOK {
		t.Fatalf("wrong password status = %d, want 200", rec.Code)
	}

	if q := redirectQuery(t, postLogin(h, loginForm(id))); !q.Has("code") {
		t.Errorf("retry must issue a code: %v", q)
	}
}

func TestLoginHandler_Post_ApproveIsSingleUse(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, nil)

	redirectQuery(t, postLogin(h, loginForm(id)))
	assertBadRequest(t, postLogin(h, loginForm(id)))
}

func TestLoginHandler_Post_DenyConsumesRequest(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, nil)

	deny := loginForm(id)
	deny.Set("action", "deny")
	redirectQuery(t, postLogin(h, deny))
	assertBadRequest(t, postLogin(h, loginForm(id)))
}

func TestLoginHandler_Post_InvalidActionKeepsRequest(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, nil)

	invalid := loginForm(id)
	invalid.Set("action", "x")
	assertBadRequest(t, postLogin(h, invalid))

	if q := redirectQuery(t, postLogin(h, loginForm(id))); !q.Has("code") {
		t.Errorf("approve after invalid action must issue a code: %v", q)
	}
}

func TestLoginHandler_Post_IssuesCodeFromSavedRequest(t *testing.T) {
	h, reqs, _, codes := newLoginHandler(t)
	id := saveRequest(t, reqs, func(r *store.AuthorizeRequest) {
		r.Scope = "openid profile"
		r.Nonce = "nonce-saved"
		r.CodeChallenge = "challenge-saved"
	})

	f := loginForm(id)
	f.Set("scope", "openid email")
	f.Set("nonce", "nonce-form")
	f.Set("code_challenge", "challenge-form")
	q := redirectQuery(t, postLogin(h, f))

	got, err := codes.Consume(q.Get("code"))
	if err != nil {
		t.Fatalf("Consume() failed: %v", err)
	}
	if got.ClientID != "tegata-sample" || got.RedirectURI != "http://localhost:9999/callback" ||
		got.Scope != "openid profile" || got.Nonce != "nonce-saved" ||
		got.CodeChallenge != "challenge-saved" || got.Sub != "u-0001" {
		t.Errorf("code = %+v, want values from the saved request", *got)
	}
}

func TestLoginHandler_Post_OmitsStateWhenAbsent(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, func(r *store.AuthorizeRequest) { r.State = "" })

	if q := redirectQuery(t, postLogin(h, loginForm(id))); q.Has("state") {
		t.Errorf("Location must not contain state: %v", q)
	}
}

func TestLoginHandler_Post_RejectsUnregisteredClient(t *testing.T) {
	h, reqs, _, _ := newLoginHandler(t)
	id := saveRequest(t, reqs, func(r *store.AuthorizeRequest) { r.ClientID = "unknown" })

	assertBadRequest(t, postLogin(h, loginForm(id)))
}
