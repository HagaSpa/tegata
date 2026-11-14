package handler

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed index.html
//go:embed register.html
//go:embed logout.html
var htmlFS embed.FS

type templateParam struct {
	ID      string
	Error   string
	Message string
}

func render(
	f *template.Template,
	w http.ResponseWriter,
	p *templateParam,
	status int,
) {
	var buf bytes.Buffer
	if err := f.Execute(&buf, p); err != nil {
		writeInternalError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}
