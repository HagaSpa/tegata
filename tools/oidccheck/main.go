package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func main() {
	issuer := "http://localhost:8080"
	if len(os.Args) > 1 {
		issuer = os.Args[1]
	}
	ctx := context.Background()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		fmt.Println("Discovery NG:", err)
		os.Exit(1)
	}
	fmt.Println("Discovery OK")
	fmt.Println("  authorization_endpoint:", p.Endpoint().AuthURL)
	fmt.Println("  token_endpoint:        ", p.Endpoint().TokenURL)
	fmt.Println("  userinfo_endpoint:     ", p.UserInfoEndpoint())

	var meta struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := p.Claims(&meta); err != nil || meta.JWKS == "" {
		fmt.Println("jwks_uri NG:", err)
		os.Exit(1)
	}
	resp, err := http.Get(meta.JWKS)
	if err != nil {
		fmt.Println("JWKS GET NG:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		fmt.Println("JWKS parse NG:", err)
		os.Exit(1)
	}
	for _, k := range set.Keys {
		pub, ok := k.Key.(*rsa.PublicKey)
		if !ok || !k.Valid() {
			fmt.Println("JWKS key NG: kid=", k.KeyID)
			os.Exit(1)
		}
		fmt.Printf("JWKS OK  kid=%s alg=%s use=%s bits=%d e=%d\n", k.KeyID, k.Algorithm, k.Use, pub.N.BitLen(), pub.E)
	}
}
