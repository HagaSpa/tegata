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

	certFile, certExists := os.LookupEnv("TLS_CERT_FILE")
	keyFile, keyExists := os.LookupEnv("TLS_KEY_FILE")
	if certExists != keyExists {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be either set or unset.")
	}
	isTLS := certExists && keyExists

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
	ss := store.NewSessions()

	jwksHandler := handler.NewJWKHandler(km)
	metadataHandler := handler.NewMetadataHandler(issuer)
	authHandler := handler.NewAuthorizeHandler(cl, ar, ss, co)
	loginHandler := handler.NewLoginHandler(cl, u, co, ar, ss)
	logoutHandler := handler.NewLogoutHandler(km, cl, ss, issuer)
	tokenHandler := handler.NewTokenHandler(cl, ts, co, km, r, issuer)
	useinfoHandler := handler.NewUserInfofHandler(km, u, issuer)
	revokeHandler := handler.NewRevokeHandler(cl, ts)
	registerHandler := handler.NewRegisterHandler(ar, u)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", pingHandler)
	mux.Handle("GET /.well-known/openid-configuration", metadataHandler)
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	mux.Handle("GET /userinfo", useinfoHandler)
	mux.Handle("POST /userinfo", useinfoHandler)
	mux.Handle("GET /authorize", authHandler)
	mux.Handle("POST /authorize", authHandler)
	mux.Handle("GET /logout", logoutHandler)
	mux.Handle("POST /logout", logoutHandler)
	mux.HandleFunc("POST /login", loginHandler.Post)
	mux.HandleFunc("POST /token", tokenHandler.Post)
	mux.HandleFunc("POST /revoke", revokeHandler.Post)
	mux.HandleFunc("GET /register", registerHandler.Get)
	mux.HandleFunc("POST /register", registerHandler.Post)
	mux.HandleFunc("POST /logout/confirm", logoutHandler.Post)

	fmt.Println("Serving on :8080...")

	if isTLS {
		log.Fatal(http.ListenAndServeTLS(":8080", certFile, keyFile, mux))
	}
	log.Fatal(http.ListenAndServe(":8080", mux))
}
