// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Seite Berichte wie web/src/Berichte.tsx: Verfügbarkeit und SLA-Ziel je
// Mandant und Gerät, Alarme und Kapazität eines Monats, dazu das PDF.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Bericht aus GET /api/v1/berichte.
type Bericht struct {
	Mandant   string `json:"mandant"`
	Monat     string `json:"monat"`
	Mandanten []struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Geraete        int     `json:"geraete"`
		Verfuegbarkeit float64 `json:"verfuegbarkeit"`
		Ziel           float64 `json:"ziel"`
		Erfuellt       bool    `json:"erfuellt"`
	} `json:"mandanten"`
	Geraete []struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Mandant        string  `json:"mandant"`
		Verfuegbarkeit float64 `json:"verfuegbarkeit"`
		AusfallMinuten int     `json:"ausfall_minuten"`
		Ausfaelle      int     `json:"ausfaelle"`
		Ziel           float64 `json:"ziel"`
		Erfuellt       bool    `json:"erfuellt"`
	} `json:"geraete"`
	Alarme     int `json:"alarme"`
	Kritisch   int `json:"kritisch"`
	Warnungen  int `json:"warnungen"`
	Bestaetigt int `json:"bestaetigt"`
	Laengste   []struct {
		Name    string    `json:"name"`
		Mandant string    `json:"mandant"`
		Schwere string    `json:"schwere"`
		Beginn  time.Time `json:"beginn"`
		Minuten int       `json:"minuten"`
		Offen   bool      `json:"offen"`
	} `json:"laengste"`
	Prognose []struct {
		Geraet string  `json:"geraet"`
		Platte string  `json:"platte"`
		Belegt float64 `json:"belegt"`
		Tage   int     `json:"tage"`
	} `json:"prognose"`
}

// BerichtAbfrage: mandant=…&monat=…&untermandanten=1|0 wie im Web.
func BerichtAbfrage(mandant, monat string, mitUnter bool) string {
	q := url.Values{}
	q.Set("mandant", mandant)
	q.Set("monat", monat)
	q.Set("untermandanten", map[bool]string{true: "1", false: "0"}[mitUnter])
	return q.Encode()
}

// BerichtHolen: Bericht als Daten.
func (c Client) BerichtHolen(ctx context.Context, abfrage string) (Bericht, error) {
	var b Bericht
	err := c.get(ctx, "/api/v1/berichte?"+abfrage, &b)
	return b, err
}

// BerichtPDF: derselbe Bericht als PDF.
func (c Client) BerichtPDF(ctx context.Context, abfrage string) ([]byte, error) {
	var b []byte
	err := c.send(ctx, http.MethodGet, "/api/v1/berichte/pdf?"+abfrage, nil, &b)
	if err == nil && !strings.HasPrefix(string(b), "%PDF") {
		return nil, fmt.Errorf("Die Zentrale hat kein PDF geliefert.")
	}
	return b, err
}

// SLAZiel setzt das SLA-Ziel eines Mandanten in Prozent (nil = erben).
func (c Client) SLAZiel(ctx context.Context, mandant string, ziel *float64) error {
	return c.send(ctx, http.MethodPut, "/api/v1/mandanten/"+p(mandant)+"/sla", map[string]any{"ziel": ziel}, nil)
}

// Monate: aktueller und 12 vorige Monate als „2026-11“.
func Monate(jetzt time.Time) []string {
	out := make([]string, 0, 13)
	for i := 0; i < 13; i++ {
		x := time.Date(jetzt.Year(), jetzt.Month()-time.Month(i), 1, 0, 0, 0, 0, jetzt.Location())
		out = append(out, x.Format("2006-01"))
	}
	return out
}

var monatsNamen = [...]string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}

// MonatName: „2026-11“ → „November 2026“.
func MonatName(m string) string {
	t, err := time.Parse("2006-01", m)
	if err != nil {
		return m
	}
	return monatsNamen[t.Month()-1] + " " + strconv.Itoa(t.Year())
}

// Prozent: drei Nachkommastellen mit Komma wie im Web („99,950 %“).
func Prozent(f float64) string {
	return strings.Replace(strconv.FormatFloat(f, 'f', 3, 64), ".", ",", 1) + " %"
}

// Dauer: Minuten wie dauer() im Web („45 Min.“, „2:05 Std.“).
func Dauer(m int) string {
	if m < 60 {
		return fmt.Sprintf("%d Min.", m)
	}
	return fmt.Sprintf("%d:%02d Std.", m/60, m%60)
}

// ZielLesen: Eingabe „99,5“ → 99.5; leer = nil (erben).
func ZielLesen(s string) (*float64, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if s == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64)
	if err != nil {
		return nil, fmt.Errorf("SLA-Ziel: eine Zahl in Prozent, z. B. 99,5")
	}
	return &f, nil
}
