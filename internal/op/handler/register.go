package handler

import (
	"errors"
	"html/template"
	"net/http"
	"unicode/utf8"

	"github.com/HagaSpa/tegata/internal/op/registry"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const (
	maxLength = 64
	minLength = 15
)

type AuthorizeRequestFinder interface {
	Find(key string) (*store.AuthorizeRequest, error)
}

type UserRegister interface {
	Register(info registry.RegisterUserInfo) error
}

type RegisterHandler struct {
	finder   AuthorizeRequestFinder
	register UserRegister
	regPage  *template.Template
	indPage  *template.Template
}

func NewRegisterHandler(
	finder AuthorizeRequestFinder,
	register UserRegister,
) *RegisterHandler {
	reg := template.Must(template.ParseFS(htmlFS, "register.html"))
	ind := template.Must(template.ParseFS(htmlFS, "index.html"))
	return &RegisterHandler{
		finder:   finder,
		register: register,
		regPage:  reg,
		indPage:  ind,
	}
}

func (h *RegisterHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, err := h.finder.Find(id)
	if err != nil {
		http.Error(w, "failed to get authorize request", http.StatusBadRequest)
		return
	}
	param := templateParam{
		ID: id,
	}
	render(h.regPage, w, &param)
}

func (h *RegisterHandler) Post(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}

	id := r.PostFormValue("id")
	_, err = h.finder.Find(id)
	if err != nil {
		http.Error(w, "failed to get authorize request", http.StatusBadRequest)
		return
	}

	un := r.PostFormValue("username")
	if un == "" {
		param := templateParam{
			ID:    id,
			Error: "username is required",
		}
		render(h.regPage, w, &param)
		return
	}

	pw := r.PostFormValue("password")
	pwl := utf8.RuneCountInString(pw)
	if pwl < minLength || pwl > maxLength {
		param := templateParam{
			ID:    id,
			Error: "Please make your password 15-64 characters long",
		}
		render(h.regPage, w, &param)
		return
	}

	info := registry.RegisterUserInfo{
		Username: un,
		Password: pw,
		Name:     r.PostFormValue("name"),
		Email:    r.PostFormValue("email"),
	}

	if err = h.register.Register(info); err != nil {
		if errors.Is(err, registry.ErrDuplicatedUsername) {
			param := templateParam{
				ID:    id,
				Error: "Username is already in use.",
			}
			render(h.regPage, w, &param)
		} else {
			writeInternalError(w)
		}
		return
	}

	param := templateParam{
		ID:      id,
		Message: "Sign Up is success.",
	}
	render(h.indPage, w, &param)
}
