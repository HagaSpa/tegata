package handler

import (
	"html/template"
	"net/http"

	"github.com/HagaSpa/tegata/internal/op/store"
)

type AuthorizeRequestFinder interface {
	Find(key string) (*store.AuthorizeRequest, error)
}

type UserRegister interface {
	Register(username string, password string, name string, email string) error
}

type RegisterHandler struct {
	finder   AuthorizeRequestFinder
	register UserRegister
	file     *template.Template
}

func NewRegisterHandler(
	finder AuthorizeRequestFinder,
	register UserRegister,
) *RegisterHandler {
	f := template.Must(template.ParseFS(htmlFS, "register.html"))
	return &RegisterHandler{
		finder:   finder,
		register: register,
		file:     f,
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
	render(h.file, w, &param)
}
