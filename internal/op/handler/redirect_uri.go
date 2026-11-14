package handler

import (
	"net/http"

	"github.com/HagaSpa/tegata/internal/op/store"
)

type RedirectURIValidator interface {
	ValidateRedirectURI(clientID string, uri string) bool
}

func validateRedirectURI(
	w http.ResponseWriter,
	v RedirectURIValidator,
	req *store.AuthorizeRequest,
) bool {
	if !v.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return false
	}
	return true
}
