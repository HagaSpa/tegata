package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie     = "session"
	logoutStateCookie = "logout_state"
)

//go:embed *.html
var htmlFS embed.FS

//go:embed static
var staticFS embed.FS

var pages = template.Must(template.ParseFS(htmlFS, "*.html"))

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setShortCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, MaxAge: 300, HttpOnly: true, Path: "/"})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", MaxAge: -1, HttpOnly: true, Path: "/"})
}

func render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

type resultPage struct {
	Title string
	Body  string
	Back  string
}

func showResult(w http.ResponseWriter, status int, title, body, back string) {
	render(w, status, "result.html", resultPage{Title: title, Body: body, Back: back})
}

func indent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func fetchNotes(ctx context.Context, url string, token *oauth2.Token) (json.RawMessage, error) {
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s (WWW-Authenticate: %s) %s", resp.Status, resp.Header.Get("WWW-Authenticate"), body)
	}
	return body, nil
}

func revoke(ctx context.Context, endpoint string, config oauth2.Config, refreshToken string) (string, error) {
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Status, nil
}

func shorten(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "..."
}

type session struct {
	token    *oauth2.Token
	idToken  string
	idClaims json.RawMessage
	userInfo json.RawMessage
	notes    json.RawMessage
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

func (s *sessions) lookup(r *http.Request) (string, *session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil, false
	}
	sess, ok := s.m[c.Value]
	return c.Value, sess, ok
}

type indexPage struct {
	SignedIn bool
	Message  string
	Error    string
}

type homePage struct {
	IDTokenClaims     string
	UserInfo          string
	Notes             string
	AccessTokenExpiry string
	RefreshToken      string
}

func main() {
	ctx := context.Background()
	issuer := env("ISSUER", "http://localhost:8080")
	listen := env("LISTEN", "127.0.0.1:5556")
	redirectURL := env("REDIRECT_URL", "http://127.0.0.1:5556/callback")
	postLogoutRedirectURL := env("POST_LOGOUT_REDIRECT_URL", "http://127.0.0.1:5556/")
	notesURL := env("NOTES_URL", "http://localhost:9000/notes")

	unregisteredURL, err := url.JoinPath(postLogoutRedirectURL, "unregistered")
	if err != nil {
		log.Fatal(err)
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}
	var metadata struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		log.Fatal(err)
	}
	config := oauth2.Config{
		ClientID:     env("CLIENT_ID", "tegata-rp"),
		ClientSecret: env("CLIENT_SECRET", "rp-secret"),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "notes.read"},
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	store := &sessions{m: map[string]*session{}}

	http.Handle("GET /static/", http.FileServerFS(staticFS))

	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		var p indexPage
		store.mu.Lock()
		_, _, p.SignedIn = store.lookup(r)
		store.mu.Unlock()
		if returned := r.URL.Query().Get("state"); returned != "" {
			c, err := r.Cookie(logoutStateCookie)
			if err == nil && c.Value == returned {
				p.Message = "Signed out at the OP and redirected back here. The state matched."
			} else {
				p.Error = "Redirected back here with a state that does not match."
			}
			clearCookie(w, logoutStateCookie)
		}
		render(w, http.StatusOK, "index.html", p)
	})

	http.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		state, nonce := rand.Text(), rand.Text()
		pkce := oauth2.GenerateVerifier()
		setShortCookie(w, "state", state)
		setShortCookie(w, "nonce", nonce)
		setShortCookie(w, "verifier", pkce)
		opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)}
		if r.URL.Query().Get("prompt") == "none" {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
		}
		http.Redirect(w, r, config.AuthCodeURL(state, opts...), http.StatusFound)
	})

	http.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		state, err := r.Cookie("state")
		if err != nil || q.Get("state") != state.Value {
			showResult(w, http.StatusBadRequest, "Sign-in failed", "state did not match", "/")
			return
		}
		if e := q.Get("error"); e != "" {
			showResult(w, http.StatusBadRequest, "Sign-in failed", "error="+e+"\nerror_description="+q.Get("error_description"), "/")
			return
		}
		pkce, err := r.Cookie("verifier")
		if err != nil {
			showResult(w, http.StatusBadRequest, "Sign-in failed", "verifier not found", "/")
			return
		}
		token, err := config.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(pkce.Value))
		if err != nil {
			showResult(w, http.StatusInternalServerError, "Sign-in failed", "token exchange failed: "+err.Error(), "/")
			return
		}
		rawIDToken, _ := token.Extra("id_token").(string)
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			showResult(w, http.StatusInternalServerError, "Sign-in failed", "id_token verification failed: "+err.Error(), "/")
			return
		}
		nonce, err := r.Cookie("nonce")
		if err != nil || idToken.Nonce != nonce.Value {
			showResult(w, http.StatusBadRequest, "Sign-in failed", "nonce did not match", "/")
			return
		}
		userInfo, err := provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
		if err != nil {
			showResult(w, http.StatusInternalServerError, "Sign-in failed", "userinfo failed: "+err.Error(), "/")
			return
		}
		if userInfo.Subject != idToken.Subject {
			showResult(w, http.StatusInternalServerError, "Sign-in failed", "userinfo sub does not match id_token sub", "/")
			return
		}
		notes, err := fetchNotes(r.Context(), notesURL, token)
		if err != nil {
			showResult(w, http.StatusInternalServerError, "Sign-in failed", "notes failed: "+err.Error(), "/")
			return
		}

		sess := &session{token: token, idToken: rawIDToken, notes: notes}
		idToken.Claims(&sess.idClaims)
		userInfo.Claims(&sess.userInfo)
		sid := rand.Text()
		store.mu.Lock()
		if old, _, ok := store.lookup(r); ok {
			delete(store.m, old)
		}
		store.m[sid] = sess
		store.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, HttpOnly: true, Path: "/"})
		clearCookie(w, "state")
		clearCookie(w, "nonce")
		clearCookie(w, "verifier")
		http.Redirect(w, r, "/home", http.StatusFound)
	})

	http.HandleFunc("GET /home", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		_, sess, ok := store.lookup(r)
		var p homePage
		if ok {
			p = homePage{
				IDTokenClaims:     indent(sess.idClaims),
				UserInfo:          indent(sess.userInfo),
				Notes:             indent(sess.notes),
				AccessTokenExpiry: sess.token.Expiry.Format(time.RFC3339),
				RefreshToken:      shorten(sess.token.RefreshToken),
			}
		}
		store.mu.Unlock()
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		render(w, http.StatusOK, "home.html", p)
	})

	http.HandleFunc("GET /notes", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		sid, sess, ok := store.lookup(r)
		if !ok {
			showResult(w, http.StatusUnauthorized, "No session", "Sign in first.", "/")
			return
		}
		current := sess.token
		next, err := config.TokenSource(r.Context(), current).Token()
		if err != nil {
			delete(store.m, sid)
			clearCookie(w, sessionCookie)
			showResult(w, http.StatusUnauthorized, "Refresh failed", "Sign in again.\n\n"+err.Error(), "/")
			return
		}
		sess.token = next
		refreshed := next != current
		if refreshed {
			log.Printf("refreshed: refresh_token %s -> %s", shorten(current.RefreshToken), shorten(next.RefreshToken))
		}
		notes, err := fetchNotes(r.Context(), notesURL, next)
		if err != nil {
			showResult(w, http.StatusInternalServerError, "Resource server error", err.Error(), "/home")
			return
		}
		sess.notes = notes
		showResult(w, http.StatusOK, "Called the resource server", indent(struct {
			Refreshed          bool
			RefreshTokenBefore string
			RefreshTokenAfter  string
			AccessTokenExpiry  time.Time
			Notes              json.RawMessage
		}{refreshed, shorten(current.RefreshToken), shorten(next.RefreshToken), next.Expiry, notes}), "/home")
	})

	http.HandleFunc("POST /expire", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		_, sess, ok := store.lookup(r)
		if !ok {
			showResult(w, http.StatusUnauthorized, "No session", "Sign in first.", "/")
			return
		}
		expired := *sess.token
		expired.Expiry = time.Now().Add(-time.Minute)
		sess.token = &expired
		showResult(w, http.StatusOK, "Marked the access token as expired",
			"Only this RP treats the access token as expired. The OP and the resource server still accept it.\n"+
				"Call the resource server again to refresh it with the refresh token.\n\n"+
				"AccessTokenExpiry: "+expired.Expiry.Format(time.RFC3339), "/home")
	})

	http.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		_, sess, ok := store.lookup(r)
		if !ok {
			showResult(w, http.StatusUnauthorized, "No session", "Sign in first.", "/")
			return
		}
		status, err := revoke(r.Context(), metadata.RevocationEndpoint, config, sess.token.RefreshToken)
		if err != nil {
			showResult(w, http.StatusBadGateway, "Revoke failed", err.Error(), "/home")
			return
		}
		showResult(w, http.StatusOK, "Revoked the refresh token",
			"RevokeStatus: "+status+"\nRefreshToken: "+shorten(sess.token.RefreshToken)+"\n\n"+
				"The access token still works until it expires.\n"+
				"Expire the access token and call the resource server again to see the refresh fail.", "/home")
	})

	http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		sid, sess, ok := store.lookup(r)
		if !ok {
			showResult(w, http.StatusUnauthorized, "No session", "Sign in first.", "/")
			return
		}
		params := url.Values{}
		switch r.PostFormValue("variant") {
		case "redirect":
			state := rand.Text()
			setShortCookie(w, logoutStateCookie, state)
			params.Set("id_token_hint", sess.idToken)
			params.Set("post_logout_redirect_uri", postLogoutRedirectURL)
			params.Set("state", state)
		case "no-redirect-uri":
			params.Set("id_token_hint", sess.idToken)
		case "no-id-token-hint":
			params.Set("post_logout_redirect_uri", postLogoutRedirectURL)
		case "unregistered-uri":
			params.Set("id_token_hint", sess.idToken)
			params.Set("post_logout_redirect_uri", unregisteredURL)
		default:
			showResult(w, http.StatusBadRequest, "Unknown logout", "variant must be redirect, no-redirect-uri, no-id-token-hint or unregistered-uri", "/home")
			return
		}
		delete(store.m, sid)
		clearCookie(w, sessionCookie)
		http.Redirect(w, r, metadata.EndSessionEndpoint+"?"+params.Encode(), http.StatusFound)
	})

	log.Printf("RP listening on http://%s/  (issuer=%s client_id=%s redirect=%s post_logout_redirect=%s)", listen, issuer, config.ClientID, redirectURL, postLogoutRedirectURL)
	log.Fatal(http.ListenAndServe(listen, nil))
}
