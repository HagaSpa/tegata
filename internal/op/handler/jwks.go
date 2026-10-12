package handler

import (
	"net/http"

	"github.com/HagaSpa/tegata/internal/op/keys"
)

type JWKSProvider interface {
	JWKS() keys.JWKS
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
	writeJSON(w, http.StatusOK, h.provider.JWKS())
}
