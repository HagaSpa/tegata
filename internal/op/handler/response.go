package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/HagaSpa/tegata/internal/op/store"
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
	errNotSupportedRequest     errorCode = "request_not_supported"
	errNotSupportedRequestURI  errorCode = "request_uri_not_supported"
	errLoginRequired           errorCode = "login_required"
)

func redirectAuthorizationError(
	w http.ResponseWriter,
	r *http.Request,
	req *store.AuthorizeRequest,
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

type CodeIssuer interface {
	Issue(
		clientID string,
		redirectURI string,
		scope string,
		codeChallenge string,
		nonce string,
		sub string,
		authTime time.Time,
	) string
}

func redirectWithCode(
	w http.ResponseWriter,
	r *http.Request,
	c CodeIssuer,
	req *store.AuthorizeRequest,
	sub string,
	authTime time.Time,
) {
	code := c.Issue(req.ClientID, req.RedirectURI, req.Scope, req.CodeChallenge, req.Nonce, sub, authTime)
	values := url.Values{}
	values.Set("code", code)
	if req.State != "" {
		values.Set("state", req.State)
	}
	redirectToClient(w, r, req.RedirectURI, values)
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
