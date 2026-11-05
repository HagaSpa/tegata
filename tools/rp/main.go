package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

const sessionCookie = "session"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setCallbackCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, MaxAge: 300, HttpOnly: true, Path: "/"})
}

func writeJSON(w http.ResponseWriter, v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
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

type sessions struct {
	mu     sync.Mutex
	tokens map[string]*oauth2.Token
}

func (s *sessions) lookup(r *http.Request) (string, *oauth2.Token, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil, false
	}
	t, ok := s.tokens[c.Value]
	return c.Value, t, ok
}

func main() {
	ctx := context.Background()
	issuer := env("ISSUER", "http://localhost:8080")
	listen := env("LISTEN", "127.0.0.1:5556")
	redirectURL := env("REDIRECT_URL", "http://127.0.0.1:5556/callback")
	notesURL := env("NOTES_URL", "http://localhost:9000/notes")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}
	var metadata struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
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
	store := &sessions{tokens: map[string]*oauth2.Token{}}

	http.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		state, nonce := rand.Text(), rand.Text()
		pkce := oauth2.GenerateVerifier()
		setCallbackCookie(w, "state", state)
		setCallbackCookie(w, "nonce", nonce)
		setCallbackCookie(w, "verifier", pkce)
		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)), http.StatusFound)
	})

	http.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil || r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		if e := r.URL.Query().Get("error"); e != "" {
			http.Error(w, "authorization failed: "+e+" "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
			return
		}
		pkce, err := r.Cookie("verifier")
		if err != nil {
			http.Error(w, "verifier not found", http.StatusBadRequest)
			return
		}
		token, err := config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkce.Value))
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, _ := token.Extra("id_token").(string)
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "id_token verification failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		nonce, err := r.Cookie("nonce")
		if err != nil || idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}
		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(w, "userinfo failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if userInfo.Subject != idToken.Subject {
			http.Error(w, "userinfo sub does not match id_token sub", http.StatusInternalServerError)
			return
		}

		notes, err := fetchNotes(ctx, notesURL, token)
		if err != nil {
			http.Error(w, "notes failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		sid := rand.Text()
		store.mu.Lock()
		store.tokens[sid] = token
		store.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, HttpOnly: true, Path: "/"})

		var idClaims, userClaims json.RawMessage
		idToken.Claims(&idClaims)
		userInfo.Claims(&userClaims)
		writeJSON(w, struct {
			Message       string
			IDTokenClaims json.RawMessage
			UserInfo      json.RawMessage
			Notes         json.RawMessage
			OAuth2Token   *oauth2.Token
			Next          map[string]string
		}{"login completed", idClaims, userClaims, notes, token, map[string]string{
			"/notes":  "call the resource server again (refreshes the access token only when it has expired)",
			"/expire": "mark the access token as expired on the RP side, then open /notes",
			"/logout": "revoke the refresh token at the OP and forget the session",
		}})
	})

	http.HandleFunc("GET /notes", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		sid, current, ok := store.lookup(r)
		if !ok {
			http.Error(w, "no session: log in at /", http.StatusUnauthorized)
			return
		}
		next, err := config.TokenSource(r.Context(), current).Token()
		if err != nil {
			delete(store.tokens, sid)
			http.Error(w, "refresh failed, log in again at /: "+err.Error(), http.StatusUnauthorized)
			return
		}
		store.tokens[sid] = next
		refreshed := next != current
		if refreshed {
			log.Printf("refreshed: refresh_token %s -> %s", shorten(current.RefreshToken), shorten(next.RefreshToken))
		}

		notes, err := fetchNotes(r.Context(), notesURL, next)
		if err != nil {
			http.Error(w, "notes failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, struct {
			Refreshed          bool
			RefreshTokenBefore string
			RefreshTokenAfter  string
			AccessTokenExpiry  time.Time
			Notes              json.RawMessage
		}{refreshed, shorten(current.RefreshToken), shorten(next.RefreshToken), next.Expiry, notes})
	})

	http.HandleFunc("GET /expire", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		sid, current, ok := store.lookup(r)
		if !ok {
			http.Error(w, "no session: log in at /", http.StatusUnauthorized)
			return
		}
		expired := *current
		expired.Expiry = time.Now().Add(-time.Minute)
		store.tokens[sid] = &expired
		writeJSON(w, struct {
			Message           string
			AccessTokenExpiry time.Time
		}{"access token marked as expired on the RP side; open /notes to refresh", expired.Expiry})
	})

	http.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		sid, current, ok := store.lookup(r)
		if !ok {
			http.Error(w, "no session: log in at /", http.StatusUnauthorized)
			return
		}
		delete(store.tokens, sid)
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", MaxAge: -1, Path: "/"})
		status, err := revoke(r.Context(), metadata.RevocationEndpoint, config, current.RefreshToken)
		if err != nil {
			http.Error(w, "revoke failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, struct {
			Message      string
			RevokeStatus string
			RefreshToken string
		}{"logged out", status, shorten(current.RefreshToken)})
	})

	log.Printf("RP listening on http://%s/  (issuer=%s client_id=%s redirect=%s)", listen, issuer, config.ClientID, redirectURL)
	log.Fatal(http.ListenAndServe(listen, nil))
}
