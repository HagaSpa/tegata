package handler

import (
	"encoding/json"
	"net/http"

	"github.com/HagaSpa/tegata/auth"
)

type MetadataHandler struct {
	config *auth.OpenIdConfiguration
}

func NewMetadataHandler(config *auth.OpenIdConfiguration) *MetadataHandler {
	return &MetadataHandler{
		config: config,
	}
}

func (h *MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.config); err != nil {
		internalError(w)
	}
}
