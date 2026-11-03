package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/HagaSpa/tegata/internal/op/handler"
	"github.com/HagaSpa/tegata/internal/op/keys"
	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	km, err := keys.NewManager()
	if err != nil {
		log.Fatalf("failed to init key manager: %v", err)
	}

	issuer, exists := os.LookupEnv("ISSUER")
	if !exists {
		issuer = "http://localhost:8080"
	}

	cl := registry.NewClients()
	u, err := registry.NewUsers(
		"username",
		"password",
		"u-0001",
		"hagaspa",
		"justicesparrow13@gmail.com",
	)
	if err != nil {
		log.Fatalf("failed to init user store: %v", err)
	}
	r := registry.NewResources()

	co := store.NewCodes()
	ar := store.NewAuthorizeRequests()
	ts := store.NewRefreshTokens()

	jwksHandler := handler.NewJWKHandler(km)
	metadataHandler := handler.NewMetadataHandler(issuer)
	authHandler := handler.NewAuthorizeHandler(cl, u, co, ar)
	tokenHandler := handler.NewTokenHandler(cl, ts, co, km, r, issuer)
	useinfoHandler := handler.NewUserInfofHandler(km, u, issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", pingHandler)
	mux.Handle("GET /.well-known/openid-configuration", metadataHandler)
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("GET /authorize", authHandler.Get)
	mux.HandleFunc("POST /authorize", authHandler.Post)
	mux.HandleFunc("POST /token", tokenHandler.Post)
	mux.HandleFunc("GET /userinfo", useinfoHandler.Get)

	fmt.Println("Serving on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
