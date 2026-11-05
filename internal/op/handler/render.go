package handler

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed index.html
//go:embed register.html
var htmlFS embed.FS

type templateParam struct {
	ID    string
	Error string
}

func render(
	f *template.Template,
	w http.ResponseWriter,
	p *templateParam,
) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := f.Execute(w, p); err != nil {
		writeInternalError(w)
	}
}
