// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Ausnahmen (0.99.2, Migration 0048): einzelne Gegenstände einer SNMP-Quelle
// (NetApp-SnapMirror, Volumes, Schnittstellen …) ausnehmen, mit Begründung
// und Audit. Sie gelten für Alarme als OK und erscheinen grau.
//
// Entfernen (Migration 0063): eine Ausnahme, die zusätzlich ausgeblendet
// wird. Löschen lässt sich ein solcher Wert nicht, die Quelle meldet ihn bei
// jeder Abfrage wieder. Die entfernten Werte einer Quelle listet
// GET /api/v1/snmp/{id}/entfernt, zurück kommen sie über „einbeziehen“.

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

type ausnahmeIn struct {
	Schluessel  string `json:"schluessel"`
	Begruendung string `json:"begruendung"`
	// Entfernen: zusätzlich aus allen Listen ausblenden
	Entfernen bool `json:"entfernen"`
}

// parseExclusionKey: nur Gegenstände von SNMP-Quellen, nie die Erreichbarkeit.
func parseExclusionKey(key string) (src, subject string, err error) {
	art, src, subject, err := parseSensorKey(key)
	if err != nil {
		return "", "", err
	}
	if art != "snmp" || subject == alarm.SubjectSilent || !alarm.SNMPSubject(subject) {
		return "", "", badRequest("Ausnehmen lassen sich nur einzelne Werte von SNMP, Proxmox, NetApp, XenServer und anderen Quellen, nicht die Erreichbarkeit.")
	}
	return src, subject, nil
}

func (s *Server) handleSensorExclude(w http.ResponseWriter, r *http.Request) {
	var in ausnahmeIn
	if !readJSON(w, r, &in) {
		return
	}
	src, subject, err := parseExclusionKey(in.Schluessel)
	if err != nil {
		writeDBError(w, "ausnahme", err)
		return
	}
	reason := strings.TrimSpace(in.Begruendung)
	if n := utf8.RuneCountInString(reason); n < 3 || n > 300 || !noControl(reason) {
		writeError(w, http.StatusBadRequest, "Bitte eine Begründung mit 3 bis 300 Zeichen angeben.")
		return
	}
	s.handle(w, r, "ausnahme", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.snmp_sources WHERE id = $1`, src).Scan(&tid); err != nil {
			return 0, nil, err // Quelle nicht sichtbar: 404
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_exclusions (tenant_id, snmp_id, subject, reason, hidden) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (snmp_id, subject) DO UPDATE SET reason = EXCLUDED.reason, hidden = EXCLUDED.hidden`, tid, src, subject, reason, in.Entfernen); err != nil {
			return 0, nil, err // Leser: 42501 → 403
		}
		action := "sensor.ausgenommen"
		if in.Entfernen {
			action = "sensor.entfernt"
		}
		if err := audit(ctx, tx, &tid, action, map[string]any{"sensor": in.Schluessel, "begruendung": reason}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleSensorInclude(w http.ResponseWriter, r *http.Request) {
	var in ausnahmeIn
	if !readJSON(w, r, &in) {
		return
	}
	src, subject, err := parseExclusionKey(in.Schluessel)
	if err != nil {
		writeDBError(w, "ausnahme", err)
		return
	}
	s.handle(w, r, "ausnahme aufheben", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid, reason string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.snmp_exclusions WHERE snmp_id = $1 AND subject = $2
			RETURNING tenant_id::text, reason`, src, subject).Scan(&tid, &reason); err != nil {
			return 0, nil, err // nicht ausgenommen, nicht sichtbar oder nur Leser: 404
		}
		if err := audit(ctx, tx, &tid, "sensor.einbezogen", map[string]any{"sensor": in.Schluessel, "begruendung_war": reason}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

type entferntOut struct {
	Schluessel  string    `json:"schluessel"`
	Gegenstand  string    `json:"gegenstand"`
	Name        string    `json:"name"`
	Begruendung string    `json:"begruendung"`
	Seit        time.Time `json:"seit"`
}

// handleSensorHiddenList: die entfernten Werte einer Quelle, mit Begründung.
// Eine Quelle, die der Aufrufer nicht sieht, gibt es für ihn nicht (404).
func (s *Server) handleSensorHiddenList(w http.ResponseWriter, r *http.Request) {
	src, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "entfernte werte", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var x string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.snmp_sources WHERE id = $1`, src).Scan(&x); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT subject, reason, created_at FROM openwacht.snmp_exclusions
			WHERE snmp_id = $1 AND hidden ORDER BY lower(subject)`, src)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (entferntOut, error) {
			var e entferntOut
			err := row.Scan(&e.Gegenstand, &e.Begruendung, &e.Seit)
			e.Schluessel, e.Name = alarmKeySNMP(src, e.Gegenstand), alarm.SensorName(e.Gegenstand)
			return e, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []entferntOut{}
		}
		return http.StatusOK, map[string]any{"entfernt": list}, nil
	})
}

// snmpHidden: entfernte Gegenstände aller Quellen, die der Kontext sehen darf.
func snmpHidden(ctx context.Context, tx pgx.Tx) (map[string]map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT snmp_id::text, subject FROM openwacht.snmp_hidden_all()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var src, sub string
		if err := rows.Scan(&src, &sub); err != nil {
			return nil, err
		}
		if out[src] == nil {
			out[src] = map[string]bool{}
		}
		out[src][sub] = true
	}
	return out, rows.Err()
}
