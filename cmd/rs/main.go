package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/HagaSpa/tegata/internal/rs/handler"
	"github.com/HagaSpa/tegata/internal/rs/keyset"
	"github.com/HagaSpa/tegata/internal/rs/store"
)

func main() {
	issuer, exists := os.LookupEnv("ISSUER")
	if !exists {
		issuer = "http://localhost:8080"
	}

	c := &http.Client{
		Timeout: 5 * time.Second,
	}

	jwksURI, err := keyset.GetJWKSURI(c, issuer)
	if err != nil {
		log.Fatalf("failed to get JWKS URI: %v", err)
	}
	ks := keyset.NewKeySet(c, jwksURI)
	auth := handler.NewAuthMiddleware(ks.Key, issuer, "http://localhost:9000")

	ns := store.NewNotes()
	ns.Add("u-0001", store.Note{Text: "sample"})
	nh := handler.NewNotesHandler(ns)

	mux := http.NewServeMux()
	mux.Handle("GET /notes", auth.Require("notes.read", http.HandlerFunc(nh.Get)))
	mux.Handle("POST /notes", auth.Require("notes.write", http.HandlerFunc(nh.Post)))

	fmt.Println("Serving on :9000...")
	log.Fatal(http.ListenAndServe(":9000", mux))
}
