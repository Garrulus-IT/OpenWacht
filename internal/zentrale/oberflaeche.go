// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// uiHandler liefert die eingebettete SPA aus. Dateien unter /assets/ tragen
// einen Inhalts-Hash im Namen und dürfen lange gecacht werden; alle anderen
// Pfade ohne Dateiendung bekommen index.html (Routing im Browser).
func uiHandler(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "Methode nicht erlaubt.")
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" || p == "LIESMICH.txt" {
			p = "index.html"
		}
		f, err := files.Open(p)
		if errors.Is(err, fs.ErrNotExist) && path.Ext(p) == "" {
			p = "index.html"
			f, err = files.Open(p)
		}
		if err != nil {
			if p == "index.html" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				io.WriteString(w, "Die Web-Oberfläche ist nicht in dieses Programm eingebaut (go run ./tools/build). Die API läuft.\n")
				return
			}
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			http.Error(w, "Datei nicht lesbar", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, p, st.ModTime(), rs)
	})
}
