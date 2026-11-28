// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStripBase(t *testing.T) {
	s := &Server{base: "/openwacht"}
	var gesehen string
	h := s.stripBase(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gesehen = r.URL.Path
		if r.URL.Path == "/weiter" {
			http.Redirect(w, r, "/anmelden", http.StatusSeeOther)
		}
	}))
	for _, f := range []struct {
		pfad, innen string
		code        int
		ort         string
	}{
		{"/openwacht/api/v1/ich", "/api/v1/ich", 200, ""},
		{"/openwacht", "", 301, "/openwacht/"},
		{"/anderes/api", "", 404, ""},
		{"/openwacht/weiter", "/weiter", 303, "/openwacht/anmelden"},
	} {
		gesehen = ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", f.pfad, nil))
		if rec.Code != f.code || gesehen != f.innen || rec.Header().Get("Location") != f.ort {
			t.Errorf("%s: Code %d, innen %q, Location %q", f.pfad, rec.Code, gesehen, rec.Header().Get("Location"))
		}
	}
}

func TestIndexWithBase(t *testing.T) {
	out := string(indexWithBase("/openwacht", []byte(`<html><head><script src="./assets/a.js"></script></head></html>`)))
	if !strings.Contains(out, `<meta name="basis" content="/openwacht">`) || !strings.Contains(out, `src="/openwacht/assets/a.js"`) {
		t.Fatal(out)
	}
	if s := (&Server{base: "/openwacht"}); s.ck(sessionCookie) != "__Secure-openwacht" || s.cookiePath() != "/openwacht/" {
		t.Fatal(s.ck(sessionCookie), s.cookiePath())
	}
	if s := (&Server{}); s.ck(sessionCookie) != sessionCookie || s.cookiePath() != "/" {
		t.Fatal("Wurzel")
	}
}
