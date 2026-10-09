package handler

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

//go:embed index.html
var htmlFS embed.FS

type RedirectURIValidator interface {
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
	clients RedirectURIValidator
	user    UserAuthenticator
	code    CodeIssuer
	file    *template.Template
}

func NewAuthorizeHandler(
	clients RedirectURIValidator,
	user UserAuthenticator,
	code CodeIssuer,
) *AuthorizeHandler {
	f := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &AuthorizeHandler{
		clients: clients,
		user:    user,
		code:    code,
		file:    f,
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
	h.render(w, req)
}

func (h *AuthorizeHandler) Post(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}
	req := parseAuthorizeRequest(r.PostForm)
	if !h.clients.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if code, desc := req.validate(); code != "" {
		redirectError(w, r, req.RedirectURI, code, desc, req.State)
		return
	}
	// 認証
	sub, err := h.user.Authenticate(r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		req.Error = "invalid username or password"
		h.render(w, req)
		return
	}
	// 判断
	action := r.PostFormValue("action")
	switch action {
	case "deny":
		redirectError(w, r, req.RedirectURI, "access_denied", "the user denied the request", req.State)
		return
	case "approve":
		// approve のみ発行
		code, err := h.code.Issue(req.ClientID, req.RedirectURI, req.Scope, req.CodeChallenge, req.Nonce, sub)
		if err != nil {
			redirectError(w, r, req.RedirectURI, "server_error", "failed to issue code", req.State)
			return
		}
		values := url.Values{}
		values.Set("code", code)
		if req.State != "" {
			values.Set("state", req.State)
		}
		redirectWith(w, r, req.RedirectURI, values)
	default:
		http.Error(w, "unknown action result", http.StatusBadRequest)
		return
	}
}

func (h *AuthorizeHandler) render(w http.ResponseWriter, req *authorizeRequest) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.file.Execute(w, req); err != nil {
		internalError(w)
	}
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
	Error               string
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
