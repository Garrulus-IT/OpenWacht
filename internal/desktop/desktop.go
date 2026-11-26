// SPDX-License-Identifier: AGPL-3.0-only

// Package desktop enthält die Logik der Desktop-App (1.0.4): Einstellungen,
// Abfrage der Alarme mit einem API-Token, Vergleich zweier Stände und das
// Symbol im Infobereich. Die Oberfläche unter Windows steht in cmd/desktop;
// alles hier ist ohne Windows testbar.
//
// Die App fragt alle 30 Sekunden GET /api/v1/alarme ab (bei offenem Fenster
// auch Mandanten, Gruppen, Geräte, Sensoren und Checks) mit einem API-Token.
// Was sie darf, bestimmt dessen Rolle: Leser nur sehen, Operator auch Geräte
// und Sensoren pflegen (Entscheidung des Herausgebers 26.11.2026, vorher nur
// Leser). Das Token liegt in der Windows-Anmeldeinformationsverwaltung, nie in
// einer Datei.
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Config: was die App außer dem Token braucht (Datei desktop.json).
type Config struct {
	Zentrale    string `json:"zentrale"`              // https://openwacht.example
	Darstellung string `json:"darstellung,omitempty"` // "" = wie System, "hell", "dunkel"
	Mandant     string `json:"mandant,omitempty"`     // zuletzt gewählter Mandant
	OhneUnter   bool   `json:"ohne_unter,omitempty"`  // Untermandanten ausblenden
}

// ConfigPath: %APPDATA%\OpenWacht\desktop.json bzw. ~/.config/OpenWacht/desktop.json.
func ConfigPath() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "OpenWacht", "desktop.json"), nil
}

// CleanZentrale prüft die Adresse: nur https, ohne Pfad, Abfrage oder Zugangsdaten.
func CleanZentrale(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("Adresse der Zentrale: z. B. https://openwacht.firma.example (nur https, ohne Pfad)")
	}
	return "https://" + u.Host, nil
}

// LoadConfig liest die Einstellungen; fehlt die Datei, ist Zentrale leer.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Zentrale != "" {
		z, err := CleanZentrale(c.Zentrale)
		if err != nil {
			return Config{}, err
		}
		c.Zentrale = z
	}
	return c, nil
}

// SaveConfig schreibt die Einstellungen (nur für den eigenen Benutzer lesbar).
func SaveConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// CleanToken prüft das Format eines API-Tokens (owt1.<43 Zeichen base64url>).
func CleanToken(s string) (string, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, "owt1.")
	if !ok || len(rest) != 43 || strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return "", errors.New("API-Token: erwartet owt1.… (in OpenWacht unter Benutzer und Mandanten › API-Tokens, Rolle Leser oder Operator)")
	}
	return s, nil
}

// Alarm: die Felder aus GET /api/v1/alarme, die die App braucht.
type Alarm struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Gegenstand string     `json:"gegenstand"`
	Status     string     `json:"status"` // warn, crit, unknown
	Meldung    string     `json:"meldung"`
	Ende       *time.Time `json:"ende"`
	Bestaetigt *time.Time `json:"bestaetigt_am"`
}

// Client fragt die Zentrale ab.
type Client struct {
	Zentrale string
	Token    string
	HTTP     *http.Client
}

// ErrToken: Token ungültig, abgelaufen oder widerrufen.
var ErrToken = errors.New("API-Token ungültig, abgelaufen oder widerrufen")

// Alarme holt die Alarme der letzten 30 Tage (offene zuerst).
func (c Client) Alarme(ctx context.Context) ([]Alarm, error) {
	var out struct {
		Alarme []Alarm `json:"alarme"`
	}
	if err := c.get(ctx, "/api/v1/alarme?limit=500", &out); err != nil {
		return nil, err
	}
	return out.Alarme, nil
}

// get: GET mit dem Token, nur an die eingestellte Zentrale, Antwort ≤ 8 MiB.
func (c Client) get(ctx context.Context, pfad string, out any) error {
	return c.send(ctx, http.MethodGet, pfad, nil, out)
}

// FehlerZentrale: die Zentrale hat die Anfrage abgelehnt; Text ist ihre
// Meldung (für Menschen geschrieben, z. B. „Intervall: 30 Sekunden bis 1 Tag.“).
type FehlerZentrale struct {
	Code int
	Text string
}

func (e *FehlerZentrale) Error() string {
	if e.Text != "" {
		return e.Text
	}
	return fmt.Sprintf("Zentrale antwortet mit %d", e.Code)
}

// send: Anfrage mit dem Token, nur an die eingestellte Zentrale, Antwort ≤ 8 MiB.
// body (falls nicht nil) geht als JSON; out (falls nicht nil) nimmt die
// Antwort auf. Jede Antwort 2xx gilt als Erfolg.
func (c Client) send(ctx context.Context, method, pfad string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Zentrale+pfad, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	// Nie einer Weiterleitung folgen: das Token geht nur an die eingestellte Zentrale.
	hc2 := *hc
	hc2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc2.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrToken
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		var f struct {
			Fehler string `json:"fehler"`
		}
		_ = json.Unmarshal(data, &f)
		return &FehlerZentrale{Code: resp.StatusCode, Text: Kuerzen(strings.TrimSpace(f.Fehler), 400)}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("Antwort nicht lesbar: %w", err)
	}
	return nil
}

// Zustand fürs Symbol: schlimmster offener, nicht bestätigter Alarm.
type Zustand string

const (
	ZustandOK        Zustand = "ok"
	ZustandWarn      Zustand = "warn"
	ZustandKrit      Zustand = "crit"
	ZustandUnbekannt Zustand = "unknown"
	ZustandStoerung  Zustand = "stoerung" // Zentrale nicht erreichbar oder Token falsch
)

var rang = map[string]int{"unknown": 1, "warn": 2, "crit": 3}

// Zusammenfassung: Zustand, Zahlen und Text für den Tooltip.
type Zusammenfassung struct {
	Zustand   Zustand
	Kritisch  int
	Warnungen int
	Unbekannt int
}

func Zusammenfassen(alarme []Alarm) Zusammenfassung {
	z := Zusammenfassung{Zustand: ZustandOK}
	schlimmst := 0
	for _, a := range alarme {
		if a.Ende != nil || a.Bestaetigt != nil {
			continue
		}
		switch a.Status {
		case "crit":
			z.Kritisch++
		case "warn":
			z.Warnungen++
		case "unknown":
			z.Unbekannt++
		}
		if rang[a.Status] > schlimmst {
			schlimmst, z.Zustand = rang[a.Status], Zustand(a.Status)
		}
	}
	return z
}

// Tooltip: höchstens 127 Zeichen (Grenze des Infobereichs).
func (z Zusammenfassung) Tooltip() string {
	var teile []string
	if z.Kritisch > 0 {
		teile = append(teile, fmt.Sprintf("%d kritisch", z.Kritisch))
	}
	if z.Warnungen > 0 {
		teile = append(teile, fmt.Sprintf("%d %s", z.Warnungen, map[bool]string{true: "Warnung", false: "Warnungen"}[z.Warnungen == 1]))
	}
	if z.Unbekannt > 0 {
		teile = append(teile, fmt.Sprintf("%d unbekannt", z.Unbekannt))
	}
	if len(teile) == 0 {
		return "OpenWacht: alles in Ordnung"
	}
	return Kuerzen("OpenWacht: "+strings.Join(teile, ", "), 127)
}

// Ereignis: was die App meldet.
type Ereignis struct {
	Art   string // neu, schlimmer, entwarnung
	Alarm Alarm
}

// Titel der Benachrichtigung.
func (e Ereignis) Titel() string {
	text := map[string]string{"crit": "Kritisch", "warn": "Warnung", "unknown": "Unbekannt"}
	switch e.Art {
	case "entwarnung":
		return "Entwarnung"
	case "schlimmer":
		return "Jetzt " + text[e.Alarm.Status]
	}
	if t := text[e.Alarm.Status]; t != "" {
		return t
	}
	return "Alarm"
}

// Text der Benachrichtigung.
func (e Ereignis) Text() string {
	s := e.Alarm.Name
	// "check" (Sensor der Zentrale) sagt nichts; der Name nennt den Sensor schon.
	if e.Alarm.Gegenstand != "" && e.Alarm.Gegenstand != "check" {
		s += " · " + e.Alarm.Gegenstand
	}
	if e.Art != "entwarnung" && e.Alarm.Meldung != "" {
		s += "\n" + e.Alarm.Meldung
	}
	return Kuerzen(s, 255)
}

// Vergleichen: Ereignisse zwischen zwei Ständen, wie die Hinweise am Rand der
// Oberfläche: neuer Alarm, schlimmer geworden, Entwarnung. Bestätigte melden
// sich nicht. alt == nil (erster Stand): nichts.
func Vergleichen(alt, neu []Alarm) []Ereignis {
	if alt == nil {
		return nil
	}
	vorher := make(map[string]Alarm, len(alt))
	for _, a := range alt {
		vorher[a.ID] = a
	}
	var out []Ereignis
	for _, a := range neu {
		v, bekannt := vorher[a.ID]
		switch {
		case a.Ende != nil:
			if bekannt && v.Ende == nil {
				out = append(out, Ereignis{"entwarnung", a})
			}
		case a.Bestaetigt != nil:
		case !bekannt || v.Ende != nil:
			out = append(out, Ereignis{"neu", a})
		case rang[a.Status] > rang[v.Status]:
			out = append(out, Ereignis{"schlimmer", a})
		}
	}
	// Schlimmste zuerst, Entwarnungen zuletzt.
	sort.SliceStable(out, func(i, j int) bool { return gewicht(out[i]) > gewicht(out[j]) })
	return out
}

func gewicht(e Ereignis) int {
	if e.Art == "entwarnung" {
		return 0
	}
	return rang[e.Alarm.Status] + 1
}

// Kuerzen auf n Zeichen, Steuerzeichen außer Zeilenumbruch werden Leerzeichen.
func Kuerzen(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}
