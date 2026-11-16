package handler

import (
	"net/http"
	"net/url"
)

type ClientAuthenticator interface {
	Authenticate(clientID, secret string) bool
}

func authenticateClient(
	w http.ResponseWriter,
	r *http.Request,
	c ClientAuthenticator,
) (string, bool) {
	clientID, secret, ok := r.BasicAuth()
	unescapedFailed := false

	if ok {
		ueClientID, err := url.QueryUnescape(clientID)
		if err != nil {
			unescapedFailed = true
		}
		ueSecret, err := url.QueryUnescape(secret)
		if err != nil {
			unescapedFailed = true
		}
		clientID = ueClientID
		secret = ueSecret
	} else {
		clientID = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}

	if unescapedFailed || !c.Authenticate(clientID, secret) {
		if ok {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"tegata\"")
		}
		writeTokenError(w, http.StatusUnauthorized, errInvalidClient, "client_id or client_secret is invalid")
		return "", false
	}
	return clientID, true
}
