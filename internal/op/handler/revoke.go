package handler

import "net/http"

type RefreshTokenRevoker interface {
	Revoke(key string, clientID string)
}

type RevokeHandler struct {
	client  ClientAuthenticator
	revoker RefreshTokenRevoker
}

func NewRevokeHandler(
	client ClientAuthenticator,
	revoker RefreshTokenRevoker,
) *RevokeHandler {
	return &RevokeHandler{
		client:  client,
		revoker: revoker,
	}
}

func (h *RevokeHandler) Post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, errInvalidRequest, "parse failed")
		return
	}

	clientID, authed := authenticateClient(w, r, h.client)
	if !authed {
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		writeTokenError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
		return
	}

	h.revoker.Revoke(token, clientID)

	w.WriteHeader(http.StatusOK)
}
