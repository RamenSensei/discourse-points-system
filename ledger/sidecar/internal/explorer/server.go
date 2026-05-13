// Package explorer serves the public block-explorer SPA at /explorer/.
// It is read-only — all data flows in via the public /api/v1/log/* endpoints.
package explorer

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed static/*
var staticFS embed.FS

type Service struct{}

// Mount registers /explorer/* routes on the given router. Multiple deep-link
// paths all return the same SPA shell; the JS reads window.location to render.
func (s *Service) Mount(r chi.Router) {
	r.Mount("/explorer/static/", http.StripPrefix("/explorer/static/", staticHandler()))
	r.Get("/explorer/", s.indexHandler)
	r.Get("/explorer/tx/{hash}", s.indexHandler)
	r.Get("/explorer/leaf/{idx}", s.indexHandler)
	r.Get("/explorer/sth/{size}", s.indexHandler)
	r.Get("/explorer/account/{id}", s.indexHandler)
	r.Get("/explorer", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/wallet/explorer/", http.StatusFound)
	})
}

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || strings.HasPrefix(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, sub, name)
	})
}

func (s *Service) indexHandler(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "missing index", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}
