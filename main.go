package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/HagaSpa/tegata/auth"
	"github.com/HagaSpa/tegata/handler"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	km, err := auth.NewKeyManager()
	if err != nil {
		log.Fatalf("failed to init key manager: %v", err)
	}

	issuer, exists := os.LookupEnv("ISSUER")
	if !exists {
		issuer = "http://localhost:8080"
	}
	config := auth.NewOpenIdConfiguration(issuer)

	cl := auth.NewClientStore()
	u, err := auth.NewUserStore(
		"username",
		"password",
		"u-0001",
	)
	if err != nil {
		log.Fatalf("failed to init user store: %v", err)
	}

	co := auth.NewCodeStore()

	jwksHandler := handler.NewJWKHandler(km)
	metadataHandler := handler.NewMetadataHandler(config)
	authHandler := handler.NewAuthorizeHandler(cl, u, co)
	tokenHandler := handler.NewTokenHandler(cl, co, km, issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", pingHandler)
	mux.Handle("GET /.well-known/openid-configuration", metadataHandler)
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("GET /authorize", authHandler.Get)
	mux.HandleFunc("POST /authorize", authHandler.Post)
	mux.HandleFunc("POST /token", tokenHandler.Post)

	fmt.Println("Serving on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
