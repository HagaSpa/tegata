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
	jwksHandler := handler.NewJWKHandler(km)

	issuer, exists := os.LookupEnv("ISSUER")
	if !exists {
		issuer = "http://localhost:8080"
	}
	config := auth.NewOpenIdConfiguration(issuer)
	metadataHandler := handler.NewMetadataHandler(config)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", pingHandler)
	mux.Handle("GET /.well-known/openid-configuration", metadataHandler)
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)

	fmt.Println("Serving on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
