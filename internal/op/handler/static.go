package handler

import (
	"embed"
	"net/http"
)

//go:embed static
var staticFS embed.FS

func NewStaticHandler() http.Handler {
	return http.FileServerFS(staticFS)
}
