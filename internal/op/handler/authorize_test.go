package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/op/auth"
)

const testState = "state-1"

var hiddenIDPattern = regexp.MustCompile(`name="id" value="([A-Za-z0-9_-]{43})"`)

func newAuthorizeHandler(t *testing.T) (*AuthorizeHandler, *auth.AuthorizeRequestStore, *auth.CodeStore) {
	t.Helper()
	cl := auth.NewClientStore()
	u, err := auth.NewUserStore(
		"username",
		"password",
		"u-0001",
		"hagaspa",
		"justicesparrow13@gmail.com",
	)
	if err != nil {
		t.Fatal("failed initilize")
	}
	co := auth.NewCodeStore()
	ar := auth.NewAuthorizeRequestStore()
	h := NewAuthorizeHandler(cl, u, co, ar)
	return h, ar, co
}

func validAuthorizeQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "tegata-sample")
	q.Set("redirect_uri", "http://localhost:9999/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", testState)
	q.Set("nonce", "n")
	q.Set("code_challenge", "x")
	q.Set("code_challenge_method", "S256")
	return q
}

func saveRequest(t *testing.T, store *auth.AuthorizeRequestStore, mutate func(r *auth.AuthorizeRequest)) string {
	t.Helper()
	req := parseAuthorizeRequest(validAuthorizeQuery())
	if mutate != nil {
		mutate(req)
	}
	id, err := store.Save(req)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}
	return id
}

func loginForm(id string) url.Values {
	f := url.Values{}
	f.Set("id", id)
	f.Set("username", "username")
	f.Set("password", "password")
	f.Set("action", "approve")
	return f
}

func getAuthorize(h *AuthorizeHandler, q url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	return rec
}

func postAuthorize(h *AuthorizeHandler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Post(rec, req)
	return rec
}

func idFromBody(t *testing.T, body string) string {
	t.Helper()
	m := hiddenIDPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("body does not carry id as hidden input: %q", body)
	}
	return m[1]
}

func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", rec.Header().Get("Location"), err)
	}
	q := loc.Query()
	loc.RawQuery = ""
	if got, want := loc.String(), "http://localhost:9999/callback"; got != want {
		t.Errorf("redirect target = %q, want %q", got, want)
	}
	return q
}

func assertBadRequest(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty (must not redirect)", loc)
	}
}

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

	h, _, _ := newAuthorizeHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := validAuthorizeQuery()
			if tt.mutate != nil {
				tt.mutate(q)
			}
			rec := getAuthorize(h, q)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			switch tt.wantStatus {
			case http.StatusOK:
				body := rec.Body.String()
				if !strings.Contains(body, "<form") {
					t.Errorf("body does not contain a form: %q", body)
				}
				idFromBody(t, body)
				if strings.Count(body, `type="hidden"`) != 1 {
					t.Errorf("body must carry exactly one hidden input: %q", body)
				}
				if strings.Contains(body, `name="state"`) || strings.Contains(body, testState) {
					t.Errorf("body must not carry the request parameters: %q", body)
				}
				if strings.Contains(body, "invalid username or password") {
					t.Errorf("GET must not show an error message: %q", body)
				}
			case http.StatusBadRequest:
				assertBadRequest(t, rec)
			case http.StatusFound:
				lq := redirectQuery(t, rec)
				if got := lq.Get("error"); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
				if lq.Get("error_description") == "" {
					t.Errorf("error_description is empty")
				}
				if want := q.Get("state"); want != "" && lq.Get("state") != want {
					t.Errorf("state = %q, want %q", lq.Get("state"), want)
				}
				if q.Get("state") == "" && lq.Has("state") {
					t.Errorf("Location must not contain state: %v", lq)
				}
			}
		})
	}
}

func TestAuthorizeHandler_Get_SavesRequest(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	q := validAuthorizeQuery()

	rec := getAuthorize(h, q)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got, err := store.Find(idFromBody(t, rec.Body.String()))
	if err != nil {
		t.Fatalf("Find() failed: %v", err)
	}
	want := parseAuthorizeRequest(q)
	want.ExpiresAt = got.ExpiresAt
	if *got != *want {
		t.Errorf("saved request = %+v, want %+v", *got, *want)
	}
}

func TestAuthorizeHandler_Post(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(f url.Values)
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

	h, store, _ := newAuthorizeHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := saveRequest(t, store, nil)
			f := loginForm(id)
			if tt.mutate != nil {
				tt.mutate(f)
			}
			rec := postAuthorize(h, f)
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
			case http.StatusBadRequest:
				assertBadRequest(t, rec)
			case http.StatusFound:
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

func TestAuthorizeHandler_Post_RetryAfterWrongPassword(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, nil)

	wrong := loginForm(id)
	wrong.Set("password", "wrong")
	if rec := postAuthorize(h, wrong); rec.Code != http.StatusOK {
		t.Fatalf("wrong password status = %d, want 200", rec.Code)
	}

	if q := redirectQuery(t, postAuthorize(h, loginForm(id))); !q.Has("code") {
		t.Errorf("retry must issue a code: %v", q)
	}
}

func TestAuthorizeHandler_Post_ApproveIsSingleUse(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, nil)

	redirectQuery(t, postAuthorize(h, loginForm(id)))
	assertBadRequest(t, postAuthorize(h, loginForm(id)))
}

func TestAuthorizeHandler_Post_DenyConsumesRequest(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, nil)

	deny := loginForm(id)
	deny.Set("action", "deny")
	redirectQuery(t, postAuthorize(h, deny))
	assertBadRequest(t, postAuthorize(h, loginForm(id)))
}

func TestAuthorizeHandler_Post_InvalidActionKeepsRequest(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, nil)

	invalid := loginForm(id)
	invalid.Set("action", "x")
	assertBadRequest(t, postAuthorize(h, invalid))

	if q := redirectQuery(t, postAuthorize(h, loginForm(id))); !q.Has("code") {
		t.Errorf("approve after invalid action must issue a code: %v", q)
	}
}

func TestAuthorizeHandler_Post_IssuesCodeFromSavedRequest(t *testing.T) {
	h, store, codes := newAuthorizeHandler(t)
	id := saveRequest(t, store, func(r *auth.AuthorizeRequest) {
		r.Scope = "openid profile"
		r.Nonce = "nonce-saved"
		r.CodeChallenge = "challenge-saved"
	})

	f := loginForm(id)
	f.Set("scope", "openid email")
	f.Set("nonce", "nonce-form")
	f.Set("code_challenge", "challenge-form")
	q := redirectQuery(t, postAuthorize(h, f))

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

func TestAuthorizeHandler_Post_OmitsStateWhenAbsent(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, func(r *auth.AuthorizeRequest) { r.State = "" })

	if q := redirectQuery(t, postAuthorize(h, loginForm(id))); q.Has("state") {
		t.Errorf("Location must not contain state: %v", q)
	}
}

func TestAuthorizeHandler_Post_RejectsUnregisteredClient(t *testing.T) {
	h, store, _ := newAuthorizeHandler(t)
	id := saveRequest(t, store, func(r *auth.AuthorizeRequest) { r.ClientID = "unknown" })

	assertBadRequest(t, postAuthorize(h, loginForm(id)))
}

func TestAuthorizeHandler_GetThenPost(t *testing.T) {
	h, _, _ := newAuthorizeHandler(t)

	page := getAuthorize(h, validAuthorizeQuery())
	if page.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", page.Code)
	}
	id := idFromBody(t, page.Body.String())

	q := redirectQuery(t, postAuthorize(h, loginForm(id)))
	if !q.Has("code") || q.Get("state") != testState {
		t.Errorf("Location query = %v, want code and state=%s", q, testState)
	}
}
