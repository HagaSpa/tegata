package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setCallbackCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, MaxAge: 300, HttpOnly: true, Path: "/"})
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
	config := oauth2.Config{
		ClientID:     env("CLIENT_ID", "tegata-rp"),
		ClientSecret: env("CLIENT_SECRET", "rp-secret"),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "notes.read"},
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

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

		var idClaims, userClaims json.RawMessage
		idToken.Claims(&idClaims)
		userInfo.Claims(&userClaims)
		resp := struct {
			Message       string
			IDTokenClaims json.RawMessage
			UserInfo      json.RawMessage
			Notes         json.RawMessage
			OAuth2Token   *oauth2.Token
		}{"login completed", idClaims, userClaims, notes, token}
		data, _ := json.MarshalIndent(resp, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	log.Printf("RP listening on http://%s/  (issuer=%s client_id=%s redirect=%s)", listen, issuer, config.ClientID, redirectURL)
	log.Fatal(http.ListenAndServe(listen, nil))
}
