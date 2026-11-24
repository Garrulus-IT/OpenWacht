// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Ausnahmen (0.99.2, Migration 0048): einzelne Gegenstände einer SNMP-Quelle
// (NetApp-SnapMirror, Volumes, Schnittstellen …) ausnehmen, mit Begründung
// und Audit. Sie gelten für Alarme als OK und erscheinen grau.

import (
	"context"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

type ausnahmeIn struct {
	Schluessel  string `json:"schluessel"`
	Begruendung string `json:"begruendung"`
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
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_exclusions (tenant_id, snmp_id, subject, reason) VALUES ($1, $2, $3, $4)
			ON CONFLICT (snmp_id, subject) DO UPDATE SET reason = EXCLUDED.reason`, tid, src, subject, reason); err != nil {
			return 0, nil, err // Leser: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "sensor.ausgenommen", map[string]any{"sensor": in.Schluessel, "begruendung": reason}); err != nil {
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
