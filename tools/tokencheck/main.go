package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: tokencheck <code> <code_verifier> [nonce] [issuer]")
		os.Exit(2)
	}
	code, verifier := os.Args[1], os.Args[2]
	nonce := ""
	if len(os.Args) > 3 {
		nonce = os.Args[3]
	}
	issuer := "http://localhost:8080"
	if len(os.Args) > 4 {
		issuer = os.Args[4]
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		fmt.Println("Discovery NG:", err)
		os.Exit(1)
	}
	conf := oauth2.Config{
		ClientID:     "tegata-sample",
		ClientSecret: "dummy-secret",
		RedirectURL:  "http://localhost:9999/callback",
		Endpoint:     provider.Endpoint(),
	}
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		fmt.Println("Exchange NG:", err)
		os.Exit(1)
	}
	fmt.Println("Exchange OK")
	fmt.Println("  token_type:  ", tok.TokenType)
	fmt.Println("  expires_in:  ", tok.ExpiresIn)
	fmt.Println("  scope:       ", tok.Extra("scope"))
	fmt.Println("  access_token:", tok.AccessToken)
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		fmt.Println("id_token NG: missing in token response")
		os.Exit(1)
	}
	fmt.Println("  id_token:    ", rawIDToken)

	idToken, err := provider.Verifier(&oidc.Config{ClientID: conf.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		fmt.Println("Verify NG:", err)
		os.Exit(1)
	}
	if nonce != "" && idToken.Nonce != nonce {
		fmt.Printf("Verify NG: nonce = %q, want %q\n", idToken.Nonce, nonce)
		os.Exit(1)
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		fmt.Println("Claims NG:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(claims, "  ", "  ")
	fmt.Println("Verify OK (signature / iss / aud / exp checked by go-oidc)")
	fmt.Println("  claims:", string(out))
}
