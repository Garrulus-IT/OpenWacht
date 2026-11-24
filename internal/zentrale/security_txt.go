// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/version"
)

// security.txt (RFC 9116, Etappe 36): Meldeweg für Sicherheitslücken unter
// /.well-known/security.txt. Kontakte: zuerst der Betreiber der Installation
// (Startoption -sicherheitskontakt), dann der Hersteller (im Build). Ohne
// Kontakt oder mit -security-txt=false gibt es die Datei nicht (404).

// ParseSecurityContacts prüft die Startoption: kommagetrennt, je mailto: oder
// https://, ohne Steuerzeichen.
func ParseSecurityContacts(s string) ([]string, error) {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if len(c) > 200 || strings.ContainsFunc(c, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
			return nil, errors.New("Kontakt zu lang oder mit Leer-/Steuerzeichen")
		}
		u, err := url.Parse(c)
		switch {
		case err != nil:
			return nil, err
		case u.Scheme == "mailto" && strings.Contains(u.Opaque, "@"):
		case u.Scheme == "https" && u.Host != "":
		default:
			return nil, fmt.Errorf("%q: nur mailto:… oder https://… erlaubt", c)
		}
		out = append(out, c)
	}
	return out, nil
}

// securityContacts: Betreiber zuerst, dann Hersteller; ohne Doppel.
func (s *Server) securityContacts() []string {
	if s.cfg.SecurityTxtOff {
		return nil
	}
	out := append([]string(nil), s.cfg.SecurityContacts...)
	if v := version.SecurityContact(); v != "" {
		if vc, err := ParseSecurityContacts(v); err == nil {
			for _, c := range vc {
				dup := false
				for _, o := range out {
					dup = dup || strings.EqualFold(o, c)
				}
				if !dup {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	contacts := s.securityContacts()
	if len(contacts) == 0 {
		http.NotFound(w, r)
		return
	}
	var b strings.Builder
	b.WriteString("# Meldeweg für Sicherheitslücken dieser OpenWacht-Installation.\n")
	b.WriteString("# Bitte keine Zugangsdaten oder personenbezogenen Daten mitschicken.\n")
	for _, c := range contacts {
		b.WriteString("Contact: " + c + "\n")
	}
	// Die Datei entsteht bei jedem Abruf neu, Ablauf also immer in der Zukunft.
	fmt.Fprintf(&b, "Expires: %s\n", s.now().UTC().Add(180*24*time.Hour).Truncate(time.Second).Format(time.RFC3339))
	b.WriteString("Preferred-Languages: de, en\n")
	b.WriteString("Canonical: " + strings.TrimSuffix(s.cfg.BaseURL.String(), "/") + "/.well-known/security.txt\n")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=86400")
	w.Write([]byte(b.String()))
}
