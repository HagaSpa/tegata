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

	opt, authReqErr := validateAuthorizeRequest(r.Form)
	if authReqErr != nil {
		redirectAuthorizationError(w, r, req, authReqErr.code, authReqErr.desc)
		return
	}

	s := h.authenticatedSession(r, opt)

	switch {
	case opt.promptNone && s == nil:
		redirectAuthorizationError(w, r, req, errLoginRequired, "login required")
	case opt.promptNone:
		redirectWithCode(w, r, h.code, req, s.Sub, s.AuthTime)
	default:
		id := h.authReq.Save(req)
		param := templateParam{
			ID: id,
		}
		render(h.file, w, &param)
	}
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

func validateAuthorizeRequest(v url.Values) (loginOptions, *authorizeError) {
	if v.Get("request") != "" {
		return loginOptions{}, &authorizeError{
			code: errNotSupportedRequest,
			desc: "request not supported",
		}
	}
	if v.Get("request_uri") != "" {
		return loginOptions{}, &authorizeError{
			code: errNotSupportedRequestURI,
			desc: "request_uri not supported",
		}
	}
	if v.Get("response_type") != "code" {
		return loginOptions{}, &authorizeError{
			code: errUnsupportedResponseType,
			desc: "response_type needs code",
		}
	}
	if !slices.Contains(strings.Fields(v.Get("scope")), "openid") {
		return loginOptions{}, &authorizeError{
			code: errInvalidScope,
			desc: "scope must contain openid",
		}
	}
	if v.Get("code_challenge") != "" && v.Get("code_challenge_method") != "S256" {
		return loginOptions{}, &authorizeError{
			code: errInvalidRequest,
			desc: "code_challenge_method needs S256",
		}
	}
	return parseLoginOptions(v)
}

type loginOptions struct {
	maxAge     int
	hasMaxAge  bool
	promptNone bool
}

func parseLoginOptions(v url.Values) (loginOptions, *authorizeError) {
	opt := loginOptions{}

	if v.Get("max_age") != "" {
		n, err := strconv.Atoi(v.Get("max_age"))
		if err != nil || n < 0 {
			return loginOptions{}, &authorizeError{
				code: errInvalidRequest,
				desc: "max_age must be a non-negative integer",
			}
		}
		opt.maxAge = n
		opt.hasMaxAge = true
	}

	prompt := strings.Fields(v.Get("prompt"))
	if slices.Contains(prompt, "none") {
		if len(prompt) != 1 {
			return loginOptions{}, &authorizeError{
				code: errInvalidRequest,
				desc: "prompt=none must not be combined with other values",
			}
		}
		opt.promptNone = true
	}

	return opt, nil
}

func (h *AuthorizeHandler) authenticatedSession(
	r *http.Request,
	opt loginOptions,
) *store.Session {
	var s *store.Session
	if c, err := r.Cookie("session_id"); err == nil {
		s, _ = h.session.Get(c.Value)
	}
	if s != nil && opt.hasMaxAge && time.Since(s.AuthTime) > time.Duration(opt.maxAge)*time.Second {
		return nil
	}
	return s
}
