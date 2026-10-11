package handler

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/HagaSpa/tegata/auth"
)

//go:embed index.html
var htmlFS embed.FS

type RedirectURIValidator interface {
	ValidateRedirectURI(clientID string, uri string) bool
}

type UserAuthenticator interface {
	Authenticate(username string, password string) (string, error)
}

type AuthorizeRequestOperator interface {
	Save(req *auth.AuthorizeRequest) (string, error)
	Find(key string) (*auth.AuthorizeRequest, error)
	FindAndDelete(key string) (*auth.AuthorizeRequest, error)
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
	authReq AuthorizeRequestOperator
}

func NewAuthorizeHandler(
	clients RedirectURIValidator,
	user UserAuthenticator,
	code CodeIssuer,
	authReq AuthorizeRequestOperator,
) *AuthorizeHandler {
	f := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &AuthorizeHandler{
		clients: clients,
		user:    user,
		code:    code,
		file:    f,
		authReq: authReq,
	}
}

func (h *AuthorizeHandler) Get(w http.ResponseWriter, r *http.Request) {
	req := parseAuthorizeRequest(r.URL.Query())
	if !h.clients.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if code, desc := validateAuthorizeRequest(req); code != "" {
		redirectError(w, r, req.RedirectURI, code, desc, req.State)
		return
	}
	id, err := h.authReq.Save(req)
	if err != nil {
		redirectError(w, r, req.RedirectURI, "server_error", "faild to save authorize request", req.State)
		return
	}
	param := templateParam{
		ID: id,
	}
	h.render(w, &param)
}

func (h *AuthorizeHandler) Post(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}

	id := r.PostFormValue("id")
	req, err := h.authReq.Find(id)
	if err != nil {
		http.Error(w, "faild to get authorize request", http.StatusBadRequest)
		return
	}

	if !h.clients.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}

	sub, err := h.user.Authenticate(r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		param := templateParam{
			ID:    id,
			Error: "invalid username or password",
		}
		h.render(w, &param)
		return
	}

	action := r.PostFormValue("action")
	if action != "deny" && action != "approve" {
		http.Error(w, "invalid action result", http.StatusBadRequest)
		return
	}

	req, err = h.authReq.FindAndDelete(id)
	if err != nil {
		http.Error(w, "failed to get authorize request", http.StatusBadRequest)
		return
	}

	switch action {
	case "deny":
		redirectError(w, r, req.RedirectURI, "access_denied", "the user denied the request", req.State)
	case "approve":
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
	}
}

type templateParam struct {
	ID    string
	Error string
}

func (h *AuthorizeHandler) render(w http.ResponseWriter, p *templateParam) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.file.Execute(w, p); err != nil {
		internalError(w)
	}
}

func parseAuthorizeRequest(v url.Values) *auth.AuthorizeRequest {
	return &auth.AuthorizeRequest{
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

func validateAuthorizeRequest(r *auth.AuthorizeRequest) (string, string) {
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
