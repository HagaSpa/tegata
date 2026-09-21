package handler

import (
	"encoding/json"
	"net/http"

	"github.com/HagaSpa/tegata/auth"
)

type JWKProvider interface {
	GetJWKS() auth.JWKS
}

type JWKHandler struct {
	provider JWKProvider
}

func NewJWKHandler(provider JWKProvider) *JWKHandler {
	return &JWKHandler{
		provider: provider,
	}
}

func (h *JWKHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	jwks := h.provider.GetJWKS()
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
