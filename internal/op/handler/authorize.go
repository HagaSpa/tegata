package handler

import (
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

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
	session SessionOperator
	code    CodeIssuer
}

func NewAuthorizeHandler(
	clients RedirectURIValidator,
	authReq AuthorizeRequestOperator,
	session SessionOperator,
	code CodeIssuer,
) *AuthorizeHandler {
	f := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &AuthorizeHandler{
		clients: clients,
		file:    f,
		authReq: authReq,
		code:    code,
		session: session,
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
	if authReqErr := validateAuthorizeRequest(req); authReqErr != nil {
		redirectAuthorizationError(w, r, req, authReqErr.code, authReqErr.desc)
		return
	}

	hasMaxAge := false
	maxAge := 0
	if r.Form.Get("max_age") != "" {
		n, err := strconv.Atoi(r.Form.Get("max_age"))
		if err != nil || n < 0 {
			redirectAuthorizationError(w, r, req, errInvalidRequest, "max_age must be a non-negative integer")
			return
		}
		maxAge = n
		hasMaxAge = true
	}

	promptNone := false
	prompt := strings.Fields(r.Form.Get("prompt"))
	if slices.Contains(prompt, "none") {
		if len(prompt) != 1 {
			redirectAuthorizationError(w, r, req, errInvalidRequest, "prompt=none must not be combined with other values")
			return
		}
		promptNone = true
	}

	var s *store.Session
	if c, err := r.Cookie("session_id"); err == nil {
		s, _ = h.session.Get(c.Value)
	}
	loggedIn := s != nil
	if loggedIn && hasMaxAge && time.Since(s.AuthTime) > time.Duration(maxAge)*time.Second {
		loggedIn = false
	}

	if promptNone {
		if !loggedIn {
			redirectAuthorizationError(w, r, req, errLoginRequired, "login required")
			return
		}
		redirectWithCode(w, r, h.code, req, s.Sub, s.AuthTime)
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

type authorizeError struct {
	code errorCode
	desc string
}

func validateAuthorizeRequest(r *store.AuthorizeRequest) *authorizeError {
	if r.ResponseType != "code" {
		return &authorizeError{
			code: errUnsupportedResponseType,
			desc: "response_type needs code",
		}
	}
	if !slices.Contains(strings.Fields(r.Scope), "openid") {
		return &authorizeError{
			code: errInvalidScope,
			desc: "scope must contain openid",
		}
	}
	if r.CodeChallenge != "" && r.CodeChallengeMethod != "S256" {
		return &authorizeError{
			code: errInvalidRequest,
			desc: "code_challenge_method needs S256",
		}
	}
	return nil
}
