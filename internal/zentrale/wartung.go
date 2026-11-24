// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Wartungsmodus je Gerät und je Check. Die Wartung eines Geräts gilt für
// seinen Agent und alle seine Checks (Migration 0012).
//
// In der Wartung laufen Messungen und Checks weiter. Die Zentrale meldet keine
// neuen Probleme und keine Erinnerungen und eröffnet keine neuen Alarme;
// Entwarnungen gehen raus. Nach dem Ende bewertet der nächste Alarmdurchlauf
// den Sensor wie jeden anderen: Besteht das Problem noch, kommt sofort ein
// Alarm. Mandant, Startzeit und Person setzt die Datenbank (Migration 0010).

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Grenzen der Dauer: ab einer Minute (Tests, kurze Eingriffe) bis 7 Tage.
const (
	maintenanceMinMinutes = 1
	maintenanceMaxMinutes = 7 * 24 * 60
)

// maintenanceSet: laufende Wartungen für einen Alarmdurchlauf.
type maintenanceSet struct {
	checks, agents, snmp map[string]bool
}

func (m maintenanceSet) check(id string) bool  { return m.checks[id] }
func (m maintenanceSet) agent(id string) bool  { return m.agents[id] }
func (m maintenanceSet) source(id string) bool { return m.snmp[id] }

// loadMaintenance liest die laufenden Wartungen (ohne Benutzerkontext) und
// räumt abgelaufene ab.
func loadMaintenance(ctx context.Context, tx pgx.Tx) (maintenanceSet, error) {
	m := maintenanceSet{checks: map[string]bool{}, agents: map[string]bool{}, snmp: map[string]bool{}}
	rows, err := tx.Query(ctx, `SELECT check_id::text, agent_id::text, snmp_id::text FROM openwacht.maintenance_active()`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var check, agent, source *string
		if err := rows.Scan(&check, &agent, &source); err != nil {
			return m, err
		}
		if check != nil {
			m.checks[*check] = true
		}
		if agent != nil {
			m.agents[*agent] = true
		}
		if source != nil {
			m.snmp[*source] = true
		}
	}
	return m, rows.Err()
}

// wartungOut: eine laufende Wartung, wie sie Listen und Sensoren zeigen.
type wartungOut struct {
	Seit  time.Time `json:"seit"`
	Bis   time.Time `json:"bis"`
	Grund string    `json:"grund"`
	Von   *string   `json:"von"`
	// Die Wartung gehört zum Gerät, nicht zum Check bzw. Agent selbst.
	UeberGeraet bool `json:"ueber_geraet"`
}

// Spalten einer Wartung für einen LEFT JOIN mit dem Alias m.
const maintenanceJoinColumns = `m.starts_at, m.ends_at, m.reason, m.created_by_name`

// scanMaintenance macht aus den Spalten (alle NULL ohne Wartung) einen Eintrag.
func scanMaintenance(start, end *time.Time, reason, by *string) *wartungOut {
	if start == nil || end == nil {
		return nil
	}
	w := &wartungOut{Seit: *start, Bis: *end, Von: by}
	if reason != nil {
		w.Grund = *reason
	}
	return w
}

// visibleMaintenance: laufende Wartungen im sichtbaren Bereich (RLS), so wie
// sie wirken. Schlüssel: c:<Check> (eigene oder über das Gerät), a:<Agent>
// (über das Gerät) und d:<Gerät>. Hat ein Check beides, zählt die Wartung, die
// länger läuft.
func visibleMaintenance(ctx context.Context, tx pgx.Tx) (map[string]*wartungOut, error) {
	rows, err := tx.Query(ctx, `
		SELECT 'c:' || m.check_id::text, false, `+maintenanceJoinColumns+` FROM openwacht.maintenance m
		 WHERE m.check_id IS NOT NULL AND m.ends_at > now()
		UNION ALL
		SELECT 'd:' || m.device_id::text, false, `+maintenanceJoinColumns+` FROM openwacht.maintenance m
		 WHERE m.device_id IS NOT NULL AND m.ends_at > now()
		UNION ALL
		SELECT 'c:' || c.id::text, true, `+maintenanceJoinColumns+` FROM openwacht.maintenance m
		  JOIN openwacht.checks c ON c.device_id = m.device_id WHERE m.ends_at > now()
		UNION ALL
		SELECT 'a:' || a.id::text, true, `+maintenanceJoinColumns+` FROM openwacht.maintenance m
		  JOIN openwacht.agents a ON a.device_id = m.device_id WHERE m.ends_at > now()
		UNION ALL
		SELECT 's:' || q.id::text, true, `+maintenanceJoinColumns+` FROM openwacht.maintenance m
		  JOIN openwacht.snmp_sources q ON q.device_id = m.device_id WHERE m.ends_at > now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*wartungOut{}
	for rows.Next() {
		var key string
		var viaDevice bool
		var reason, by *string
		var start, end *time.Time
		if err := rows.Scan(&key, &viaDevice, &start, &end, &reason, &by); err != nil {
			return nil, err
		}
		w := scanMaintenance(start, end, reason, by)
		w.UeberGeraet = viaDevice
		if old := out[key]; old == nil || w.Bis.After(old.Bis) || (w.Bis.Equal(old.Bis) && !w.UeberGeraet) {
			out[key] = w
		}
	}
	return out, rows.Err()
}

type wartungIn struct {
	Minuten int    `json:"minuten"`
	Grund   string `json:"grund"`
}

func cleanReason(s string) (string, error) {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	if utf8.RuneCountInString(s) > 200 {
		return "", badRequest("Der Grund darf höchstens 200 Zeichen lang sein.")
	}
	return s, nil
}

// Ziel einer Wartung: Check oder Gerät.
type maintenanceTarget struct {
	column string // check_id | device_id
	lookup string // liefert tenant_id::text und Namen, nur Sichtbares (RLS)
	what   string // für Meldungen und Audit
}

var (
	targetCheck = maintenanceTarget{"check_id",
		`SELECT tenant_id::text, name FROM openwacht.checks WHERE id = $1`, "check"}
	targetDevice = maintenanceTarget{"device_id",
		`SELECT tenant_id::text, name FROM openwacht.devices WHERE id = $1`, "geraet"}
)

func (s *Server) handleCheckMaintenanceSet(w http.ResponseWriter, r *http.Request) {
	s.maintenanceSet(w, r, targetCheck)
}
func (s *Server) handleCheckMaintenanceEnd(w http.ResponseWriter, r *http.Request) {
	s.maintenanceEnd(w, r, targetCheck)
}
func (s *Server) handleDeviceMaintenanceSet(w http.ResponseWriter, r *http.Request) {
	s.maintenanceSet(w, r, targetDevice)
}
func (s *Server) handleDeviceMaintenanceEnd(w http.ResponseWriter, r *http.Request) {
	s.maintenanceEnd(w, r, targetDevice)
}

// maintenanceSet setzt eine Wartung oder ersetzt die laufende. Dürfen Admins
// und Operatoren (RLS); wer das Ziel nicht sieht, bekommt 404.
func (s *Server) maintenanceSet(w http.ResponseWriter, r *http.Request, t maintenanceTarget) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in wartungIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Minuten < maintenanceMinMinutes || in.Minuten > maintenanceMaxMinutes {
		writeError(w, http.StatusBadRequest, "Die Dauer muss zwischen 1 Minute und 7 Tagen liegen.")
		return
	}
	reason, err := cleanReason(in.Grund)
	if err != nil {
		writeDBError(w, "wartung", err)
		return
	}
	s.handle(w, r, "wartung setzen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, t.lookup, id).Scan(&tenant, &name); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		// Die laufende ersetzen; RLS lässt nur Admins und Operatoren löschen.
		if _, err := tx.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE `+t.column+` = $1`, id); err != nil {
			return 0, nil, err
		}
		var start, end *time.Time
		var gotReason, by *string
		err := tx.QueryRow(ctx, `INSERT INTO openwacht.maintenance (`+t.column+`, ends_at, reason)
			VALUES ($1, now() + make_interval(mins => $2), $3)
			RETURNING `+strings.ReplaceAll(maintenanceJoinColumns, "m.", ""), id, in.Minuten, reason).
			Scan(&start, &end, &gotReason, &by)
		if err != nil {
			return 0, nil, err // Leser: 42501 → 403
		}
		out := scanMaintenance(start, end, gotReason, by)
		if err := audit(ctx, tx, &tenant, "wartung.gesetzt", map[string]any{t.what: id, "name": name,
			"bis": out.Bis, "minuten": in.Minuten, "grund": reason}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

// maintenanceEnd beendet die laufende Wartung vorzeitig.
func (s *Server) maintenanceEnd(w http.ResponseWriter, r *http.Request, t maintenanceTarget) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "wartung beenden", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, t.lookup, id).Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.maintenance WHERE `+t.column+` = $1 AND ends_at > now())`,
			id).Scan(&exists); err != nil {
			return 0, nil, err
		}
		if !exists {
			return 0, nil, &apiError{http.StatusNotFound, "Keine laufende Wartung."}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE `+t.column+` = $1`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Wartung beenden dürfen nur Admins und Operatoren."}
		}
		if err := audit(ctx, tx, &tenant, "wartung.beendet", map[string]any{t.what: id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}
