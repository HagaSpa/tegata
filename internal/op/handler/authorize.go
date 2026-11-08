package handler

import (
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/HagaSpa/tegata/internal/op/store"
)

type RedirectURIValidator interface {
	ValidateRedirectURI(clientID string, uri string) bool
}

type AuthorizeRequestOperator interface {
	Save(req *store.AuthorizeRequest) string
	Find(key string) (*store.AuthorizeRequest, error)
	FindAndDelete(key string) (*store.AuthorizeRequest, error)
}

type AuthorizeHandler struct {
	clients RedirectURIValidator
	file    *template.Template
	authReq AuthorizeRequestOperator
}

func NewAuthorizeHandler(
	clients RedirectURIValidator,
	authReq AuthorizeRequestOperator,
) *AuthorizeHandler {
	f := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &AuthorizeHandler{
		clients: clients,
		file:    f,
		authReq: authReq,
	}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}

	req := parseAuthorizeRequest(r.Form)
	if !h.clients.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if r.Form.Get("request") != "" {
		redirectAuthorizationError(w, r, req, errNotSupportedRequest, "request not supported")
		return
	}
	if r.Form.Get("request_uri") != "" {
		redirectAuthorizationError(w, r, req, errNotSupportedRequestURI, "request_uri not supported")
		return
	}
	if code, desc := validateAuthorizeRequest(req); code != "" {
		redirectAuthorizationError(w, r, req, code, desc)
		return
	}
	id := h.authReq.Save(req)
	param := templateParam{
		ID: id,
	}
	render(h.file, w, &param)
}

func parseAuthorizeRequest(v url.Values) *store.AuthorizeRequest {
	return &store.AuthorizeRequest{
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		ResponseType:        v.Get("response_type"),
		Scope:               v.Get("scope"),
		State:               v.Get("state"),
		Nonce:               v.Get("nonce"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
	}
}

func validateAuthorizeRequest(r *store.AuthorizeRequest) (errorCode, string) {
	if r.ResponseType != "code" {
		return errUnsupportedResponseType, "response_type needs code"
	}
	if !slices.Contains(strings.Fields(r.Scope), "openid") {
		return errInvalidScope, "scope must contain openid"
	}
	if r.CodeChallenge != "" && r.CodeChallengeMethod != "S256" {
		return errInvalidRequest, "code_challenge_method needs S256"
	}
	return "", ""
}
