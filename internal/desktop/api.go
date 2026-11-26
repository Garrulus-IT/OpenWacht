// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // Zeitzonen der Wartungsfenster auch unter Windows
)

// Hier stehen die Abfragen und Änderungen des Hauptfensters (ab 1.0.6). Die
// Zentrale prüft jede Änderung selbst (Rolle des Tokens, Mandant, Eingaben);
// die App zeigt deren Meldung unverändert an.

// Mandant aus GET /api/v1/mandanten.
type Mandant struct {
	ID    string  `json:"id"`
	Ueber *string `json:"uebergeordnet_id"`
	Name  string  `json:"name"`
	Rolle string  `json:"rolle"` // leser | operator | admin | "" (nur über einen Untermandanten sichtbar)
}

// Gruppe aus GET /api/v1/gruppen.
type Gruppe struct {
	ID        string  `json:"id"`
	MandantID string  `json:"mandant_id"`
	ElternID  *string `json:"eltern_id"`
	Name      string  `json:"name"`
	Position  int     `json:"position"`
}

// Wartung eines Geräts oder Checks.
type Wartung struct {
	Seit        time.Time `json:"seit"`
	Bis         time.Time `json:"bis"`
	Grund       string    `json:"grund"`
	Von         *string   `json:"von"`
	UeberGeraet bool      `json:"ueber_geraet"`
}

// Geraet aus GET /api/v1/geraete.
type Geraet struct {
	ID        string   `json:"id"`
	MandantID string   `json:"mandant_id"`
	Name      string   `json:"name"`
	Adresse   *string  `json:"adresse"`
	GruppeID  *string  `json:"gruppe_id"`
	AgentID   *string  `json:"agent_id"`
	SNMPID    *string  `json:"snmp_id"`
	Checks    int      `json:"checks"`
	Wartung   *Wartung `json:"wartung"`
}

// Check aus GET /api/v1/checks (ein Sensor, den die Zentrale oder der Agent misst).
type Check struct {
	ID        string          `json:"id"`
	MandantID string          `json:"mandant_id"`
	GeraetID  string          `json:"geraet_id"`
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Aktiv     bool            `json:"aktiv"`
	Status    *string         `json:"status"`
	Meldung   *string         `json:"meldung"`
	Messwert  *string         `json:"messwert"`
	Seit      *time.Time      `json:"seit"`
	Zuletzt   *time.Time      `json:"zuletzt"`
	Naechste  time.Time       `json:"naechste"`
	Wartung   *Wartung        `json:"wartung"`
	Herkunft  *string         `json:"herkunft"`
	AmAgent   bool            `json:"am_agent"`
}

// Stand: alles, was das Hauptfenster zeigt, aus einem Durchgang.
type Stand struct {
	Mandanten []Mandant
	Gruppen   []Gruppe
	Geraete   []Geraet
	Sensoren  []Sensor
	Checks    []Check
	Zeit      time.Time
}

// StandHolen fragt nacheinander alles ab, was das Hauptfenster braucht.
func (c Client) StandHolen(ctx context.Context) (Stand, error) {
	var st Stand
	var m struct {
		Mandanten []Mandant `json:"mandanten"`
	}
	if err := c.get(ctx, "/api/v1/mandanten", &m); err != nil {
		return st, err
	}
	var g struct {
		Gruppen []Gruppe `json:"gruppen"`
	}
	if err := c.get(ctx, "/api/v1/gruppen", &g); err != nil {
		return st, err
	}
	var d struct {
		Geraete []Geraet `json:"geraete"`
	}
	if err := c.get(ctx, "/api/v1/geraete", &d); err != nil {
		return st, err
	}
	sensoren, err := c.Sensoren(ctx)
	if err != nil {
		return st, err
	}
	var ch struct {
		Checks []Check `json:"checks"`
	}
	if err := c.get(ctx, "/api/v1/checks", &ch); err != nil {
		return st, err
	}
	st.Mandanten, st.Gruppen, st.Geraete, st.Sensoren, st.Checks = m.Mandanten, g.Gruppen, d.Geraete, sensoren, ch.Checks
	st.Zeit = time.Now()
	return st, nil
}

// CheckEingabe: Anlegen und Ändern eines Checks (wie checkIn der Zentrale).
type CheckEingabe struct {
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Aktiv     *bool           `json:"aktiv,omitempty"`
}

func p(id string) string { return url.PathEscape(id) }

// CheckAnlegen legt am Gerät einen Sensor an.
func (c Client) CheckAnlegen(ctx context.Context, geraet string, in CheckEingabe) error {
	return c.send(ctx, http.MethodPost, "/api/v1/geraete/"+p(geraet)+"/checks", in, nil)
}

// CheckAendern ändert einen Sensor (alle Felder).
func (c Client) CheckAendern(ctx context.Context, id string, in CheckEingabe) error {
	return c.send(ctx, http.MethodPut, "/api/v1/checks/"+p(id), in, nil)
}

// CheckAktiv pausiert einen Sensor oder setzt ihn fort.
func (c Client) CheckAktiv(ctx context.Context, ch Check, aktiv bool) error {
	return c.CheckAendern(ctx, ch.ID, CheckEingabe{Name: ch.Name, Typ: ch.Typ, Ziel: ch.Ziel, Intervall: ch.Intervall, Aktiv: &aktiv})
}

// CheckLoeschen löscht einen Sensor samt Verlauf.
func (c Client) CheckLoeschen(ctx context.Context, id string) error {
	return c.send(ctx, http.MethodDelete, "/api/v1/checks/"+p(id), nil, nil)
}

// CheckJetzt stößt die Messung sofort an.
func (c Client) CheckJetzt(ctx context.Context, id string) error {
	return c.send(ctx, http.MethodPost, "/api/v1/checks/"+p(id)+"/jetzt", nil, nil)
}

// GeraetEingabe: Anlegen und Ändern eines Geräts.
type GeraetEingabe struct {
	Name     string  `json:"name"`
	Adresse  string  `json:"adresse"`
	GruppeID *string `json:"gruppe_id,omitempty"` // "" = keine Gruppe
}

// GeraetAnlegen legt im Mandanten ein Gerät an.
func (c Client) GeraetAnlegen(ctx context.Context, mandant string, in GeraetEingabe) error {
	return c.send(ctx, http.MethodPost, "/api/v1/mandanten/"+p(mandant)+"/geraete", in, nil)
}

// GeraetAendern ändert Name, Adresse und Gruppe eines Geräts.
func (c Client) GeraetAendern(ctx context.Context, id string, in GeraetEingabe) error {
	return c.send(ctx, http.MethodPut, "/api/v1/geraete/"+p(id), in, nil)
}

// GeraetLoeschen löscht ein Gerät. Hat es noch Inhalt, verlangt die Zentrale
// den Namen des Geräts als Bestätigung (leer = nur ein leeres Gerät löschen).
func (c Client) GeraetLoeschen(ctx context.Context, id, bestaetigung string) error {
	var body any
	if bestaetigung != "" {
		body = map[string]string{"bestaetigung": bestaetigung}
	}
	return c.send(ctx, http.MethodDelete, "/api/v1/geraete/"+p(id), body, nil)
}

// WartungSetzen: Wartung für ein Gerät (art "geraete") oder einen Check (art "checks").
func (c Client) WartungSetzen(ctx context.Context, art, id string, minuten int, grund string) error {
	return c.send(ctx, http.MethodPut, "/api/v1/"+art+"/"+p(id)+"/wartung",
		map[string]any{"minuten": minuten, "grund": grund}, nil)
}

// WartungBeenden beendet die Wartung vorzeitig.
func (c Client) WartungBeenden(ctx context.Context, art, id string) error {
	return c.send(ctx, http.MethodDelete, "/api/v1/"+art+"/"+p(id)+"/wartung", nil, nil)
}

// AlarmBestaetigen bestätigt einen offenen Alarm mit Kommentar.
func (c Client) AlarmBestaetigen(ctx context.Context, id, kommentar string) error {
	return c.send(ctx, http.MethodPost, "/api/v1/alarme/"+p(id)+"/bestaetigen", map[string]string{"kommentar": kommentar}, nil)
}

// --- Wartung (Seite „Wartung“ wie web/src/WartungSeite.tsx) -----------------

// WartungLaufend: Gerät oder Sensor gerade in Wartung.
type WartungLaufend struct {
	ID        string    `json:"id"`
	MandantID string    `json:"mandant_id"`
	GeraetID  *string   `json:"geraet_id"`
	CheckID   *string   `json:"check_id"`
	Geraet    string    `json:"geraet"`
	Sensor    *string   `json:"sensor"`
	Seit      time.Time `json:"seit"`
	Bis       time.Time `json:"bis"`
	Grund     string    `json:"grund"`
	Von       *string   `json:"von"`
	FensterID *string   `json:"fenster_id"`
}

// Ziel: „Gerät“ bzw. „Gerät · Sensor“.
func (l WartungLaufend) Ziel() string {
	if l.Sensor != nil && *l.Sensor != "" {
		return l.Geraet + " · " + *l.Sensor
	}
	return l.Geraet
}

// WartungFenster: geplantes Fenster. Roh hält alle Felder, damit Pausieren
// genau das zurückschickt, was die Zentrale geliefert hat.
type WartungFenster struct {
	ID        string      `json:"id"`
	MandantID string      `json:"mandant_id"`
	Name      string      `json:"name"`
	Grund     string      `json:"grund"`
	ZielArt   string      `json:"ziel_art"`
	ZielName  string      `json:"ziel_name"`
	Untergr   bool        `json:"untergruppen"`
	Zeitzone  string      `json:"zeitzone"`
	Aktiv     bool        `json:"aktiv"`
	Text      string      `json:"text"`
	LaeuftBis *time.Time  `json:"laeuft_bis"`
	Naechstes []time.Time `json:"naechstes"`
	Roh       rohFelder   `json:"-"`
}

type rohFelder map[string]any

// Wartungen: laufende Wartungen und Fenster.
type Wartungen struct {
	Laufend []WartungLaufend `json:"laufend"`
	Fenster []WartungFenster `json:"fenster"`
}

// WartungenHolen: GET /api/v1/wartung (mandant = "" für alle sichtbaren).
func (c Client) WartungenHolen(ctx context.Context, mandant string) (Wartungen, error) {
	pfad := "/api/v1/wartung"
	if mandant != "" {
		pfad += "?mandant=" + url.QueryEscape(mandant)
	}
	var roh struct {
		Laufend []WartungLaufend  `json:"laufend"`
		Fenster []json.RawMessage `json:"fenster"`
	}
	if err := c.send(ctx, http.MethodGet, pfad, nil, &roh); err != nil {
		return Wartungen{}, err
	}
	w := Wartungen{Laufend: roh.Laufend}
	for _, b := range roh.Fenster {
		var f WartungFenster
		if err := json.Unmarshal(b, &f); err != nil {
			return Wartungen{}, err
		}
		if err := json.Unmarshal(b, &f.Roh); err != nil {
			return Wartungen{}, err
		}
		w.Fenster = append(w.Fenster, f)
	}
	return w, nil
}

// Beschreibung: „Gruppe Server mit Untergruppen · dienstags 22:00“ wie im Web.
func (f WartungFenster) Beschreibung() string {
	art := map[string]string{"geraet": "Gerät", "sensor": "Sensor", "gruppe": "Gruppe"}[f.ZielArt]
	t := strings.TrimSpace(art + " " + f.ZielName)
	if f.ZielArt == "gruppe" {
		if f.Untergr {
			t += " mit Untergruppen"
		} else {
			t += " ohne Untergruppen"
		}
	}
	if f.Text != "" {
		t += " · " + f.Text
	}
	if f.Zeitzone != "" && f.Zeitzone != "Europe/Berlin" {
		t += " (" + f.Zeitzone + ")"
	}
	return t
}

// WartungZeit: „Do., 26.11., 22:00“ wie zeit() im Web, in zone (leer = Ortszeit).
func WartungZeit(t time.Time, zone string) string {
	if zone != "" {
		if l, err := time.LoadLocation(zone); err == nil {
			t = t.In(l)
		} else {
			t = t.Local()
		}
	} else {
		t = t.Local()
	}
	tag := [...]string{"So.", "Mo.", "Di.", "Mi.", "Do.", "Fr.", "Sa."}[t.Weekday()]
	return tag + ", " + t.Format("02.01., 15:04")
}

// FensterEingabe: Rumpf für PUT wie eingabe() im Web (fehlende Zahlen 0, Uhrzeit "").
func FensterEingabe(f WartungFenster, aktiv bool) map[string]any {
	r := f.Roh
	zahl := func(k string) any {
		if v, ok := r[k]; ok && v != nil {
			return v
		}
		return 0
	}
	text := func(k string) any {
		if v, ok := r[k]; ok && v != nil {
			return v
		}
		return ""
	}
	return map[string]any{
		"name": r["name"], "grund": r["grund"], "ziel_art": r["ziel_art"], "ziel_id": r["ziel_id"],
		"untergruppen": r["untergruppen"], "wiederholung": r["wiederholung"], "beginn": r["beginn"], "ende": r["ende"],
		"wochentage": r["wochentage"], "nter": zahl("nter"), "wochentag": zahl("wochentag"), "versatz": zahl("versatz"),
		"uhrzeit": text("uhrzeit"), "dauer_min": zahl("dauer_min"), "zeitzone": r["zeitzone"], "aktiv": aktiv,
	}
}

// FensterAktiv pausiert ein Fenster bzw. setzt es fort.
func (c Client) FensterAktiv(ctx context.Context, f WartungFenster, aktiv bool) error {
	return c.send(ctx, http.MethodPut, "/api/v1/wartungsfenster/"+p(f.ID), FensterEingabe(f, aktiv), nil)
}

// FensterLoeschen löscht ein Fenster; eine laufende Wartung daraus endet sofort.
func (c Client) FensterLoeschen(ctx context.Context, id string) error {
	return c.send(ctx, http.MethodDelete, "/api/v1/wartungsfenster/"+p(id), nil, nil)
}

// LaufendBeenden beendet eine laufende Wartung (Gerät oder Sensor).
func (c Client) LaufendBeenden(ctx context.Context, l WartungLaufend) error {
	if l.CheckID != nil {
		return c.WartungBeenden(ctx, "checks", *l.CheckID)
	}
	if l.GeraetID != nil {
		return c.WartungBeenden(ctx, "geraete", *l.GeraetID)
	}
	return errors.New("Wartung ohne Ziel")
}

// ImBereich: nur Einträge aus den Mandanten ids (wie bereich.ids im Web).
func (w Wartungen) ImBereich(ids map[string]bool) Wartungen {
	var r Wartungen
	for _, l := range w.Laufend {
		if ids[l.MandantID] {
			r.Laufend = append(r.Laufend, l)
		}
	}
	for _, f := range w.Fenster {
		if ids[f.MandantID] {
			r.Fenster = append(r.Fenster, f)
		}
	}
	return r
}
