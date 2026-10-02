package handler

import (
	"encoding/json"
	"net/http"

	"github.com/HagaSpa/tegata/auth"
)

type JWKSProvider interface {
	JWKS() auth.JWKS
}

type JWKHandler struct {
	provider JWKSProvider
}

func NewJWKHandler(provider JWKSProvider) *JWKHandler {
	return &JWKHandler{
		provider: provider,
	}
}

func (h *JWKHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	jwks := h.provider.JWKS()
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
