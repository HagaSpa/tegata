package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/HagaSpa/tegata/auth"
)

type errorCode string

const (
	errInvalidRequest          errorCode = "invalid_request"
	errAccessDenied            errorCode = "access_denied"
	errUnsupportedResponseType errorCode = "unsupported_response_type"
	errInvalidScope            errorCode = "invalid_scope"
	errServerError             errorCode = "server_error"
	errInvalidClient           errorCode = "invalid_client"
	errInvalidGrant            errorCode = "invalid_grant"
	errUnsupportedGrantType    errorCode = "unsupported_grant_type"
	errInvalidToken            errorCode = "invalid_token"
)

func redirectAuthorizationError(
	w http.ResponseWriter,
	r *http.Request,
	req *auth.AuthorizeRequest,
	code errorCode,
	desc string,
) {
	values := url.Values{}
	values.Set("error", string(code))
	values.Set("error_description", desc)
	if req.State != "" {
		values.Set("state", req.State)
	}
	redirectToClient(w, r, req.RedirectURI, values)
}

func redirectToClient(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	values url.Values,
) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "registered redirect_uri is invalid", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	for k, vs := range values {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

type tokenErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func writeTokenError(
	w http.ResponseWriter,
	status int,
	code errorCode,
	desc string,
) {
	w.Header().Set("Cache-Control", "no-store")
	v := tokenErrorResponse{
		Error:       string(code),
		Description: desc,
	}
	writeJSON(w, status, v)
}

func writeBearerError(w http.ResponseWriter, code errorCode) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, code))
	http.Error(w, string(code), http.StatusUnauthorized)
}

func writeBearerChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func writeInternalError(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeInternalError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}
