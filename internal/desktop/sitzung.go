// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Anmeldung mit Konto wie im Browser: E-Mail und Passwort, danach der Code
// aus der Authenticator-App. Die App führt dieselbe Sitzung wie der Browser
// (Cookie __Host-openwacht, CSRF-Token bei Änderungen) und darf damit genau,
// was das Konto im Web darf; heikle Änderungen verlangen wie dort einen
// frischen Code. Die Sitzung lebt nur im Speicher: Nach einem Neustart der
// App oder nach Ablauf (Leerlauf bzw. Höchstdauer der Zentrale) meldet man
// sich neu an. Passkey und SSO gehen nur im Browser.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
)

const (
	sitzungsCookie = "__Host-openwacht"
	faktorCookie   = "__Host-openwacht-2fa"
)

// ErrSitzung: Sitzung abgelaufen oder beendet; neu anmelden.
var ErrSitzung = errors.New("Sitzung abgelaufen, bitte neu anmelden")

// ErrZweiFaktorEinrichten: Das Konto braucht erst die Zwei-Faktor-Anmeldung (im Browser einrichten).
var ErrZweiFaktorEinrichten = errors.New("Die Zwei-Faktor-Anmeldung ist für dieses Konto Pflicht. Bitte zuerst im Browser einrichten, dann hier anmelden.")

// Sitzung eines Kontos; sicher für mehrere Goroutinen.
type Sitzung struct {
	mu      sync.Mutex
	Email   string
	cookie  string // Sitzung
	faktor  string // Zwischenschritt bis zum Code
	csrf    string
	beendet bool
}

// Aktiv: angemeldet (Sitzung vorhanden und nicht abgelaufen).
func (s *Sitzung) Aktiv() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cookie != "" && s.csrf != "" && !s.beendet
}

func (s *Sitzung) anfrage(req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookie != "" {
		req.AddCookie(&http.Cookie{Name: sitzungsCookie, Value: s.cookie})
	}
	if s.faktor != "" && strings.HasPrefix(req.URL.Path, "/api/v1/sitzung") {
		req.AddCookie(&http.Cookie{Name: faktorCookie, Value: s.faktor})
	}
	if s.csrf != "" && req.Method != http.MethodGet && req.Method != http.MethodHead {
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
}

// antwort übernimmt neue oder gelöschte Cookies der Zentrale.
func (s *Sitzung) antwort(resp *http.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range resp.Cookies() {
		weg := c.MaxAge < 0 || c.Value == ""
		switch c.Name {
		case sitzungsCookie:
			if weg {
				s.cookie, s.csrf = "", ""
			} else {
				s.cookie, s.beendet = c.Value, false
			}
		case faktorCookie:
			if weg {
				s.faktor = ""
			} else {
				s.faktor = c.Value
			}
		}
	}
}

func (s *Sitzung) vergessen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookie, s.faktor, s.csrf, s.beendet = "", "", "", true
}

// Anmelden: Schritt 1, E-Mail und Passwort. code==true heißt: als Nächstes
// den Code aus der Authenticator-App mit ZweiterFaktor schicken.
func (c Client) Anmelden(ctx context.Context, email, passwort string) (code bool, err error) {
	if c.Sitzung == nil {
		return false, errors.New("keine Sitzung")
	}
	c.Sitzung.vergessen()
	var out struct {
		CSRF          string `json:"csrf"`
		ZweiterFaktor bool   `json:"zweiter_faktor"`
		Einrichten    bool   `json:"zwei_faktor_einrichten"`
	}
	if err := c.send(ctx, http.MethodPost, "/api/v1/sitzung", map[string]string{"email": email, "passwort": passwort}, &out); err != nil {
		return false, err
	}
	if out.ZweiterFaktor {
		return true, nil
	}
	return false, c.Sitzung.fertig(email, out.CSRF, out.Einrichten)
}

// ZweiterFaktor: Schritt 2, Code aus der Authenticator-App.
func (c Client) ZweiterFaktor(ctx context.Context, email, code string) error {
	if c.Sitzung == nil {
		return errors.New("keine Sitzung")
	}
	var out struct {
		CSRF       string `json:"csrf"`
		Einrichten bool   `json:"zwei_faktor_einrichten"`
	}
	if err := c.send(ctx, http.MethodPost, "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": strings.TrimSpace(code)}, &out); err != nil {
		return err
	}
	return c.Sitzung.fertig(email, out.CSRF, out.Einrichten)
}

func (s *Sitzung) fertig(email, csrf string, einrichten bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookie == "" || csrf == "" {
		return errors.New("Die Zentrale hat keine Sitzung angelegt.")
	}
	s.Email, s.csrf, s.beendet = email, csrf, false
	if einrichten {
		return ErrZweiFaktorEinrichten
	}
	return nil
}

// Abmelden beendet die Sitzung auch auf der Zentrale.
func (c Client) Abmelden(ctx context.Context) error {
	if c.Sitzung == nil || !c.Sitzung.Aktiv() {
		return nil
	}
	err := c.send(ctx, http.MethodDelete, "/api/v1/sitzung", nil, nil)
	c.Sitzung.vergessen()
	return err
}
