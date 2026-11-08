package handler

import (
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/HagaSpa/tegata/internal/op/store"
)

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
		authTime time.Time,
	) string
}

type SessionOperator interface {
	Save(sub string, authTime time.Time) string
	Get(key string) (*store.Session, error)
}

type LoginHandler struct {
	clients RedirectURIValidator
	user    UserAuthenticator
	code    CodeIssuer
	file    *template.Template
	authReq AuthorizeRequestOperator
	session SessionOperator
}

func NewLoginHandler(
	clients RedirectURIValidator,
	user UserAuthenticator,
	code CodeIssuer,
	authReq AuthorizeRequestOperator,
	session SessionOperator,
) *LoginHandler {
	f := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &LoginHandler{
		clients: clients,
		user:    user,
		code:    code,
		file:    f,
		authReq: authReq,
		session: session,
	}
}

func (h *LoginHandler) Post(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}

	id := r.PostFormValue("id")
	req, err := h.authReq.Find(id)
	if err != nil {
		http.Error(w, "failed to get authorize request", http.StatusBadRequest)
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
		render(h.file, w, &param)
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

	now := time.Now()
	key := h.session.Save(sub, now)
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: key, MaxAge: 300, HttpOnly: true, Path: "/"})

	switch action {
	case "deny":
		redirectAuthorizationError(w, r, req, errAccessDenied, "the user denied the request")
	case "approve":
		code := h.code.Issue(req.ClientID, req.RedirectURI, req.Scope, req.CodeChallenge, req.Nonce, sub, now)
		values := url.Values{}
		values.Set("code", code)
		if req.State != "" {
			values.Set("state", req.State)
		}
		redirectToClient(w, r, req.RedirectURI, values)
	}
}
