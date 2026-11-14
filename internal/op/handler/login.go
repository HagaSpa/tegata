package handler

import (
	"html/template"
	"net/http"
	"time"

	"github.com/HagaSpa/tegata/internal/op/store"
)

type UserAuthenticator interface {
	Authenticate(username string, password string) (string, error)
}

type AuthorizeRequestFindDeleter interface {
	Find(key string) (*store.AuthorizeRequest, error)
	FindAndDelete(key string) (*store.AuthorizeRequest, error)
}

type SessionSaver interface {
	Save(sub string, authTime time.Time) string
}

type LoginHandler struct {
	clients RedirectURIValidator
	user    UserAuthenticator
	code    CodeIssuer
	file    *template.Template
	authReq AuthorizeRequestFindDeleter
	session SessionSaver
}

func NewLoginHandler(
	clients RedirectURIValidator,
	user UserAuthenticator,
	code CodeIssuer,
	authReq AuthorizeRequestFindDeleter,
	session SessionSaver,
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

	if !validateRedirectURI(w, h.clients, req) {
		return
	}

	sub, err := h.user.Authenticate(r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		param := templateParam{
			ID:    id,
			Error: "invalid username or password",
		}
		render(h.file, w, &param, http.StatusOK)
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
	setSessionCookie(w, key)

	switch action {
	case "deny":
		redirectAuthorizationError(w, r, req, errAccessDenied, "the user denied the request")
	case "approve":
		redirectWithCode(w, r, h.code, req, sub, now)
	}
}
