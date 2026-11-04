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

	user, pass, ok := r.BasicAuth()
	if !ok {
		user = r.PostFormValue("client_id")
		pass = r.PostFormValue("client_secret")
	}
	if !h.client.Authenticate(user, pass) {
		if ok {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"tegata\"")
		}
		writeTokenError(w, http.StatusUnauthorized, errInvalidClient, "client_id or client_secret is invalid")
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		writeTokenError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
		return
	}

	h.revoker.Revoke(token, user)

	w.WriteHeader(http.StatusOK)
}
