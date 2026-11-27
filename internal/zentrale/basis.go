// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Basis-Pfad: OpenWacht kann unter einem Unterpfad laufen, etwa
// https://firma.example/openwacht/ hinter einem vorhandenen Webserver. Der Pfad
// kommt aus BaseURL. Intern arbeitet alles ab „/“: Eingehende Anfragen
// verlieren den Basis-Pfad (stripBase), ausgehende Adressen bekommen ihn
// zurück: Location-Köpfe (baseWriter), index.html (indexWithBase) und Cookies
// (cookiePath, ck). Die Oberfläche im Browser liest den Pfad aus
// <meta name="basis">. Gleiches Vorgehen wie in OpenChronik und OpenPforte. Der Agent-Port
// läuft immer ohne Pfad.

// basePath: Basis-Pfad ohne Schrägstrich am Ende, "" für die Wurzel.
func basePath(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}

var basePathPattern = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*$`)

// validBasePath: nur einfache Pfade aus Buchstaben, Ziffern, „-“, „_“ und „/“.
func validBasePath(p string) bool { return basePathPattern.MatchString(p) }

func (s *Server) cookiePath() string {
	if s.base == "" {
		return "/"
	}
	return s.base + "/"
}

// ck: Name eines Cookies. „__Host-“ verlangt Path=/; unter einem Basis-Pfad
// gilt deshalb „__Secure-“ (ebenfalls nur über HTTPS, aber mit Pfad).
func (s *Server) ck(name string) string {
	if s.base != "" {
		return strings.Replace(name, "__Host-", "__Secure-", 1)
	}
	return name
}

// stripBase nimmt den Basis-Pfad von eingehenden Anfragen ab. Anfragen
// außerhalb davon gibt es nicht (404); „/openwacht“ ohne Schrägstrich leitet weiter.
func (s *Server) stripBase(next http.Handler) http.Handler {
	if s.base == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == s.base {
			http.Redirect(w, r, s.base+"/", http.StatusMovedPermanently)
			return
		}
		if !strings.HasPrefix(p, s.base+"/") {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(p, s.base)
		if u.RawPath != "" {
			u.RawPath = strings.TrimPrefix(u.RawPath, s.base)
		}
		r2.URL = &u
		r2.RequestURI = u.RequestURI()
		next.ServeHTTP(&baseWriter{ResponseWriter: w, base: s.base}, r2)
	})
}

// baseWriter setzt den Basis-Pfad vor Weiterleitungen auf eigene Pfade.
type baseWriter struct {
	http.ResponseWriter
	base string
}

func (b *baseWriter) WriteHeader(code int) {
	h := b.Header()
	if l := h.Get("Location"); strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "//") && !strings.HasPrefix(l, b.base+"/") {
		h.Set("Location", b.base+l)
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *baseWriter) Write(p []byte) (int, error) { return b.ResponseWriter.Write(p) }

// Unwrap für http.ResponseController.
func (b *baseWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

// indexWithBase: index.html der Oberfläche mit Adressen der Dateien unter dem
// Basis-Pfad (Vite baut relativ, damit es unter jedem Pfad passt) und dem
// Basis-Pfad als <meta name="basis">.
func indexWithBase(base string, html []byte) []byte {
	html = bytes.ReplaceAll(html, []byte(`="./`), []byte(`="`+base+`/`))
	meta := `<meta name="basis" content="` + strings.NewReplacer(`&`, "&amp;", `"`, "&quot;", "<", "&lt;").Replace(base) + `">`
	return bytes.Replace(html, []byte("<head>"), []byte("<head>"+meta), 1)
}
