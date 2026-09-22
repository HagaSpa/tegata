package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	issuer := "http://localhost:8080"
	if len(os.Args) > 1 {
		issuer = os.Args[1]
	}
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		fmt.Println("Discovery NG:", err)
		os.Exit(1)
	}
	conf := oauth2.Config{
		ClientID:    "tegata-sample",
		RedirectURL: "http://localhost:9999/callback",
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID},
	}
	state := rand.Text()
	nonce := rand.Text()
	verifier := oauth2.GenerateVerifier()
	url := conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	fmt.Println("state:        ", state)
	fmt.Println("nonce:        ", nonce)
	fmt.Println("code_verifier:", verifier)
	fmt.Println("code_challenge:", oauth2.S256ChallengeFromVerifier(verifier))
	fmt.Println()
	fmt.Println(url)
}
