package handler

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type ClientValidator interface {
	ValidateRedirectURI(clientID string, uri string) bool
}

type UserAuthenticator interface {
	Authenticate(username string, password string) (string, error)
}

type CodeIssuer interface {
	Issue(
		clientID string,
		redirectURI string,
		scope string,
		codeChallenge string,
		nonce string,
		sub string,
	) (string, error)
}

type AuthorizeHandler struct {
	clients ClientValidator
	user    UserAuthenticator
	code    CodeIssuer
}

func NewAuthorizeHandler(
	clients ClientValidator,
	user UserAuthenticator,
	code CodeIssuer,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		clients: clients,
		user:    user,
		code:    code,
	}
}

func (h *AuthorizeHandler) Get(w http.ResponseWriter, r *http.Request) {
	req := parseAuthorizeRequest(r.URL.Query())
	if !h.clients.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if code, desc := req.validate(); code != "" {
		redirectError(w, r, req.RedirectURI, code, desc, req.State)
		return
	}
	w.Write([]byte("login page"))
}

func (h *AuthorizeHandler) Post(w http.ResponseWriter, r *http.Request) {
}

type authorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func parseAuthorizeRequest(v url.Values) *authorizeRequest {
	return &authorizeRequest{
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

func (r *authorizeRequest) validate() (string, string) {
	if r.ResponseType != "code" {
		return "unsupported_response_type", "response_type needs code"
	}
	if !slices.Contains(strings.Fields(r.Scope), "openid") {
		return "invalid_scope", "scope must contain openid"
	}
	if r.CodeChallenge == "" {
		return "invalid_request", "code_challenge is required"
	}
	if r.CodeChallengeMethod != "S256" {
		return "invalid_request", "code_challenge_method needs S256"
	}
	return "", ""
}

func redirectError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	errCode string,
	desc string,
	state string,
) {
	values := url.Values{}
	values.Set("error", errCode)
	values.Set("error_description", desc)
	if state != "" {
		values.Set("state", state)
	}
	redirectWith(w, r, redirectURI, values)
}

func redirectWith(
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
