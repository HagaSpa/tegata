package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func openIdConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	issuer, exists := os.LookupEnv("issuer")
	if !exists {
		issuer = "http://localhost:8080"
	}
	config := OpenIdConfiguration{
		Issuer:                           issuer,
		AuthorizationEndpoint:            issuer + "/authorize",
		TokenEndpoint:                    issuer + "/token",
		UserinfoEndpoint:                 issuer + "/userinfo",
		JwksUri:                          issuer + "/.well-known/jwks.json",
		ResponseTypesSupport:             []string{"code"},
		SubjectTypesSupport:              []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		CodeChallengeMethodsSupported:    []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type OpenIdConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ResponseTypesSupport             []string `json:"response_types_support"`
	SubjectTypesSupport              []string `json:"subject_types_support"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	mux.HandleFunc("/.well-known/openid-configuration", openIdConfigurationHandler)
	fmt.Println("Serving on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
