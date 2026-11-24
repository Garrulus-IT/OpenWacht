// SPDX-License-Identifier: AGPL-3.0-only

package agentproto

// Sensoren auf dem Agent (Etappe 18). Der Agent holt bei jedem Meldezyklus
// die Liste seiner Sensoren (Art und Parameter als Daten, keine Skripte oder
// Befehle), misst lokal nur, was auf dem Rechner freigegeben ist
// (openwacht-agent sensoren -arten … -ordner …), und schickt die Ergebnisse.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/garrulus-it/openwacht/internal/checks"
)

const (
	PathSensorJobs    = "/agent/v1/sensoren"
	PathSensorResults = "/agent/v1/sensoren/ergebnis"

	MaxSensorJobs        = 200
	MaxSensorResults     = 100
	MaxSensorFolders     = 32
	MaxSensorListBytes   = 4 << 10
	MaxSensorResultBytes = 64 << 10
)

// SensorRelease: lokale Freigabe, die der Agent mit seinen Messwerten meldet
// (nur zur Anzeige; die Zentrale kann sie nicht ändern).
type SensorRelease struct {
	Kinds   []string `json:"arten"`
	Folders []string `json:"ordner,omitempty"`
	// Docker (Etappe 18b): Adresse eines lokalen, nur-lesenden Socket-Proxys,
	// nur http auf Loopback, z. B. http://127.0.0.1:2375
	Docker string `json:"docker,omitempty"`
	// Leistungsindikatoren (0.44.0): Objekte, aus denen der Agent lesen darf,
	// z. B. SwyxServer, SwyxWare Trunk, APP_POOL_WAS (ohne Groß/Klein)
	Counters []string `json:"indikatoren,omitempty"`
}

// MaxSensorCounterObjects: höchstens so viele Objekte lassen sich freigeben.
const MaxSensorCounterObjects = 32

// CounterReleased: Das Objekt ist am Rechner freigegeben.
func (r *SensorRelease) CounterReleased(object string) bool {
	return slices.ContainsFunc(r.Counters, func(o string) bool { return strings.EqualFold(o, object) })
}

// CheckDockerURL: nur http://127.0.0.1:<port>, http://[::1]:<port> oder
// http://localhost:<port>, ohne Pfad, Abfrage und Zugangsdaten.
func CheckDockerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("sensoren.docker: http://127.0.0.1:<Port> des nur-lesenden Socket-Proxys angeben")
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "::1" && h != "localhost" {
		return errors.New("sensoren.docker: nur ein Proxy auf diesem Rechner (127.0.0.1, ::1, localhost)")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return errors.New("sensoren.docker: Port fehlt")
	}
	return nil
}

// Validate prüft Arten (bekannt, ohne Doppel) und Ordner (absolut, sauber).
func (r *SensorRelease) Validate() error {
	if len(r.Kinds) == 0 || len(r.Kinds) > len(checks.AgentKinds) {
		return errors.New("sensoren.arten: mindestens eine, nur " + strings.Join(checks.AgentKinds, ", "))
	}
	for i, k := range r.Kinds {
		if !checks.IsAgentKind(k) || slices.Contains(r.Kinds[:i], k) {
			return fmt.Errorf("sensoren.arten: %q unbekannt oder doppelt (erlaubt: %s)", clip(k, 20), strings.Join(checks.AgentKinds, ", "))
		}
	}
	if len(r.Folders) > MaxSensorFolders {
		return fmt.Errorf("sensoren.ordner: höchstens %d", MaxSensorFolders)
	}
	for _, f := range r.Folders {
		if _, err := checks.CleanPath(f); err != nil {
			return fmt.Errorf("sensoren.ordner: %q: %v", clip(f, 60), err)
		}
	}
	if len(r.Folders) > 0 && !slices.Contains(r.Kinds, "datei") {
		return errors.New("sensoren.ordner: nur zusammen mit der Art datei")
	}
	if slices.Contains(r.Kinds, "datei") && len(r.Folders) == 0 {
		return errors.New("sensoren.ordner: für die Art datei mindestens einen Ordner angeben")
	}
	if slices.Contains(r.Kinds, "docker") != (r.Docker != "") {
		return errors.New("sensoren.docker: Art docker und Adresse des Socket-Proxys nur zusammen")
	}
	if slices.Contains(r.Kinds, "leistungsindikator") != (len(r.Counters) > 0) {
		return errors.New("sensoren.indikatoren: Art leistungsindikator und mindestens ein Objekt nur zusammen")
	}
	if len(r.Counters) > MaxSensorCounterObjects {
		return fmt.Errorf("sensoren.indikatoren: höchstens %d Objekte", MaxSensorCounterObjects)
	}
	for i, o := range r.Counters {
		if !checks.ValidPerfName(o) || slices.ContainsFunc(r.Counters[:i], func(x string) bool { return strings.EqualFold(x, o) }) {
			return fmt.Errorf("sensoren.indikatoren: %q ungültig oder doppelt (Objektname wie in der Leistungsüberwachung, ohne \\ ( ) * ?)", clip(o, 60))
		}
	}
	if r.Docker != "" {
		return CheckDockerURL(r.Docker)
	}
	return nil
}

type SensorJobsRequest struct {
	State string `json:"stand"`
}

type SensorJobsResponse struct {
	State     string      `json:"stand"`
	Unchanged bool        `json:"unveraendert"`
	Sensors   []SensorJob `json:"sensoren"` // nur wenn geändert
	Due       []string    `json:"faellig"`  // IDs, die jetzt gemessen werden sollen
}

// SensorJob: ein Sensor mit Art und Parametern (geprüft mit checks.Parse,
// auf beiden Seiten).
type SensorJob struct {
	ID              string          `json:"id"`
	Revision        int             `json:"revision"`
	Kind            string          `json:"art"`
	Target          json.RawMessage `json:"ziel"`
	IntervalSeconds int             `json:"intervall_sekunden"`
}

type SensorResultsRequest struct {
	Results []SensorResult `json:"ergebnisse"`
}

type SensorResult struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Status   string `json:"status"`
	Message  string `json:"meldung"`
	Metric   string `json:"messwert,omitempty"`
}

// Validate prüft ein Ergebnis des Agents (nicht vertrauenswürdig).
func (r *SensorResult) Validate() error {
	if len(r.ID) != 36 || r.Revision < 1 {
		return errors.New("ergebnis: id oder revision ungültig")
	}
	switch r.Status {
	case checks.OK, checks.Warn, checks.Crit, checks.Unknown:
	default:
		return errors.New("ergebnis: status ungültig")
	}
	if err := checkText("ergebnis.meldung", r.Message, 300); err != nil {
		return err
	}
	return checkText("ergebnis.messwert", r.Metric, 50)
}
