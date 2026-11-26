// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
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
