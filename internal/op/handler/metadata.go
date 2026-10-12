package handler

import (
	"net/http"

	"github.com/HagaSpa/tegata/internal/op/auth"
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
	writeJSON(w, http.StatusOK, h.config)
}
