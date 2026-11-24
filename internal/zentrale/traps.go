// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Trap-Regeln, Trap-Protokoll und Trap-Zustände (Etappe 14, Migration 0017).
//
// Traps empfängt ein eigener Dienst (internal/traps); die Zentrale pflegt nur
// die Regeln, zeigt Protokoll und Zustände und setzt Zustände von Hand
// zurück. Regeln gehören einem Mandanten und gelten für seine Geräte und die
// seiner Untermandanten; pflegen dürfen nur Admins (eine Regel „ignorieren“
// kann Alarme unterdrücken). Zurücksetzen dürfen Admins und Operatoren.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/traps"
)

type trapRegelOut struct {
	ID          string    `json:"id"`
	MandantID   string    `json:"mandant_id"`
	Position    int       `json:"position"`
	Name        string    `json:"name"`
	Aktiv       bool      `json:"aktiv"`
	GruppeID    *string   `json:"gruppe_id"`
	GeraetID    *string   `json:"geraet_id"`
	TrapOID     string    `json:"trap_oid"`
	WertOID     *string   `json:"wert_oid"`
	WertVergl   *string   `json:"wert_vergleich"`
	Wert        *string   `json:"wert"`
	Wirkung     string    `json:"wirkung"`
	SchluesselO *string   `json:"schluessel_oid"`
	DauerMin    int       `json:"dauer_minuten"`
	Beendet     *string   `json:"beendet"`
	Erstellt    time.Time `json:"erstellt"`
	KennfarbeID *string   `json:"kennfarbe_id"`
}

type trapRegelIn struct {
	MandantID   string `json:"mandant_id"` // nur beim Anlegen
	Name        string `json:"name"`
	Aktiv       *bool  `json:"aktiv"`
	GruppeID    string `json:"gruppe_id"`
	GeraetID    string `json:"geraet_id"`
	TrapOID     string `json:"trap_oid"`
	WertOID     string `json:"wert_oid"`
	WertVergl   string `json:"wert_vergleich"`
	Wert        string `json:"wert"`
	Wirkung     string `json:"wirkung"`
	SchluesselO string `json:"schluessel_oid"`
	DauerMin    *int   `json:"dauer_minuten"`
	Beendet     string `json:"beendet"`
	KennfarbeID string `json:"kennfarbe_id"` // leer: keine
}

const trapRuleColumns = `r.id::text, r.tenant_id::text, r.position, r.name, r.enabled, r.group_id::text, r.device_id::text,
	r.trap_oid, r.vb_oid, r.vb_op, r.vb_value, r.action, r.key_oid, r.duration_min, r.clears::text, r.created_at,
	r.kennfarbe_id::text`

func scanTrapRule(row pgx.CollectableRow) (trapRegelOut, error) {
	var o trapRegelOut
	err := row.Scan(&o.ID, &o.MandantID, &o.Position, &o.Name, &o.Aktiv, &o.GruppeID, &o.GeraetID, &o.TrapOID, &o.WertOID,
		&o.WertVergl, &o.Wert, &o.Wirkung, &o.SchluesselO, &o.DauerMin, &o.Beendet, &o.Erstellt, &o.KennfarbeID)
	return o, err
}

// trapRule: geprüfte Regel.
type trapRule struct {
	name                 string
	enabled              bool
	group, device        *string
	trapOID              string
	vbOID, vbOp, vbValue *string
	action               string
	keyOID               *string
	duration             int
	clears               *string
	kennfarbe            *string
}

func oidValid(s string, wildcard bool) bool {
	if len(s) == 0 || len(s) > 200 {
		return false
	}
	if wildcard {
		if s == "*" {
			return true
		}
		s = strings.TrimSuffix(s, ".*")
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" || len(part) > 10 {
			return false
		}
	}
	return true
}

func cleanOID(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), ".") }

func parseTrapRule(in trapRegelIn) (trapRule, error) {
	var r trapRule
	r.name = strings.TrimSpace(in.Name)
	if r.name == "" || utf8.RuneCountInString(r.name) > 100 || strings.ContainsFunc(r.name, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return r, badRequest("Name: 1 bis 100 Zeichen ohne Steuerzeichen.")
	}
	r.enabled = in.Aktiv == nil || *in.Aktiv
	var err error
	if r.group, err = optionalID(in.GruppeID, "Gruppe"); err != nil {
		return r, err
	}
	if r.device, err = optionalID(in.GeraetID, "Gerät"); err != nil {
		return r, err
	}
	if r.group != nil && r.device != nil {
		return r, badRequest("Eingrenzen auf eine Gruppe oder ein Gerät, nicht beides.")
	}
	r.trapOID = cleanOID(in.TrapOID)
	if !oidValid(r.trapOID, true) {
		return r, badRequest("Trap-OID: Ziffern mit Punkten (z. B. 1.3.6.1.6.3.1.1.5.3), „….*“ für alles darunter oder „*“ für alle.")
	}
	if v := cleanOID(in.WertOID); v != "" {
		if !oidValid(v, false) {
			return r, badRequest("OID der Bedingung: Ziffern mit Punkten.")
		}
		switch in.WertVergl {
		case "gleich", "nicht", "enthaelt", "beginnt":
		default:
			return r, badRequest("Vergleich: gleich, nicht, enthaelt oder beginnt.")
		}
		val := strings.TrimSpace(in.Wert)
		if utf8.RuneCountInString(val) > 200 || strings.ContainsFunc(val, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			return r, badRequest("Wert der Bedingung: höchstens 200 Zeichen ohne Steuerzeichen.")
		}
		op := in.WertVergl
		r.vbOID, r.vbOp, r.vbValue = &v, &op, &val
	}
	switch in.Wirkung {
	case "warn", "crit", "ok", "ignore":
		r.action = in.Wirkung
	default:
		return r, badRequest("Wirkung: warn, crit, ok oder ignore.")
	}
	if k := cleanOID(in.SchluesselO); k != "" {
		if r.action == "ignore" {
			return r, badRequest("„Ignorieren“ unterscheidet nicht nach Werten.")
		}
		if !oidValid(k, false) {
			return r, badRequest("„Unterscheiden nach“: Ziffern mit Punkten.")
		}
		r.keyOID = &k
	}
	r.duration = 60
	if in.DauerMin != nil {
		r.duration = *in.DauerMin
	}
	if r.duration < 0 || r.duration > 43200 {
		return r, badRequest("Dauer: 0 (bis zur Entwarnung) bis 43200 Minuten (30 Tage).")
	}
	if r.clears, err = optionalID(in.Beendet, "Beendet"); err != nil {
		return r, err
	}
	if (r.action == "ok") != (r.clears != nil) {
		return r, badRequest("Eine Entwarnung nennt die Regel, deren Zustand sie beendet; andere Wirkungen nicht.")
	}
	if r.kennfarbe, err = optionalID(in.KennfarbeID, "Kennfarbe"); err != nil {
		return r, err
	}
	return r, nil
}

// trapRuleError übersetzt die Prüfungen der Datenbank.
func trapRuleError(err error) error {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err
	}
	switch {
	case pe.ConstraintName == "snmp_trap_rules_limit":
		return badRequest("Höchstens 500 Trap-Regeln je Mandant.")
	case pe.ConstraintName == "snmp_trap_rules_clears":
		return badRequest(pe.Message)
	case pe.Code == "23503" && strings.Contains(pe.ConstraintName, "kennfarbe"):
		return badRequest("Kennfarbe unbekannt.")
	case pe.Code == "23503" && strings.Contains(pe.ConstraintName, "clears"):
		return &apiError{http.StatusConflict, "Eine Entwarnung beendet diese Regel. Bitte zuerst die Entwarnung löschen oder ändern."}
	case pe.Code == "23503":
		return badRequest("Gruppe, Gerät und beendete Regel müssen zum Mandanten der Regel gehören.")
	}
	return err
}

// trapRuleRef: Löschen eines Geräts oder einer Gruppe, auf die eine Regel
// eingegrenzt ist.
func trapRuleRef(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" && (pe.TableName == "snmp_trap_rules" || strings.HasPrefix(pe.ConstraintName, "snmp_trap_rules_")) {
		return &apiError{http.StatusConflict, "Eine Trap-Regel ist darauf eingegrenzt. Bitte zuerst die Regel ändern oder löschen."}
	}
	return err
}

func (s *Server) handleTrapRuleList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "trapregeln", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT `+trapRuleColumns+` FROM openwacht.snmp_trap_rules r
			WHERE ($1 = '' OR r.tenant_id = $1::uuid) ORDER BY r.tenant_id, r.position, r.created_at, r.id`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, scanTrapRule)
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []trapRegelOut{}
		}
		var engine string
		var started *time.Time
		if err := tx.QueryRow(ctx, `SELECT engine_id, started_at FROM openwacht.snmp_engine_info()`).Scan(&engine, &started); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"regeln": list, "engine_id": engine, "dienst_gestartet": started}, nil
	})
}

func ruleDetails(id string, p trapRule) map[string]any {
	return map[string]any{"id": id, "name": p.name, "aktiv": p.enabled, "gruppe_id": p.group, "geraet_id": p.device,
		"trap_oid": p.trapOID, "wert_oid": p.vbOID, "wert_vergleich": p.vbOp, "wert": p.vbValue, "wirkung": p.action,
		"schluessel_oid": p.keyOID, "dauer_minuten": p.duration, "beendet": p.clears,
		"kennfarbe_id": p.kennfarbe}
}

func (s *Server) handleTrapRuleCreate(w http.ResponseWriter, r *http.Request) {
	var in trapRegelIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "trapregel anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if !uuidPattern.MatchString(in.MandantID) {
			return 0, nil, badRequest("Mandant fehlt.")
		}
		p, err := parseTrapRule(in)
		if err != nil {
			return 0, nil, err
		}
		var visible bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.tenants WHERE id = $1)`, in.MandantID).Scan(&visible); err != nil {
			return 0, nil, err
		}
		if !visible {
			return 0, nil, errNotFound
		}
		id, err := newUUID()
		if err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, position, name, enabled, group_id, device_id,
				trap_oid, vb_oid, vb_op, vb_value, action, key_oid, duration_min, clears, kennfarbe_id)
			VALUES ($1, $2, coalesce((SELECT max(position) + 10 FROM openwacht.snmp_trap_rules WHERE tenant_id = $2), 10),
				$3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			id, in.MandantID, p.name, p.enabled, p.group, p.device, p.trapOID, p.vbOID, p.vbOp, p.vbValue, p.action, p.keyOID,
			p.duration, p.clears, p.kennfarbe); err != nil {
			return 0, nil, trapRuleError(err) // ohne Admin-Recht: 42501 → 403
		}
		if err := audit(ctx, tx, &in.MandantID, "trapregel.angelegt", ruleDetails(id, p)); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleTrapRuleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in trapRegelIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "trapregel ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := parseTrapRule(in)
		if err != nil {
			return 0, nil, err
		}
		var tenant string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.snmp_trap_rules WHERE id = $1`, id).Scan(&tenant); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_trap_rules SET name = $2, enabled = $3, group_id = $4, device_id = $5,
				trap_oid = $6, vb_oid = $7, vb_op = $8, vb_value = $9, action = $10, key_oid = $11, duration_min = $12, clears = $13,
				kennfarbe_id = $14
			WHERE id = $1`, id, p.name, p.enabled, p.group, p.device, p.trapOID, p.vbOID, p.vbOp, p.vbValue, p.action, p.keyOID,
			p.duration, p.clears, p.kennfarbe)
		if err != nil {
			return 0, nil, trapRuleError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Trap-Regeln pflegen dürfen nur Admins."}
		}
		if err := audit(ctx, tx, &tenant, "trapregel.geaendert", ruleDetails(id, p)); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleTrapRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "trapregel löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name FROM openwacht.snmp_trap_rules WHERE id = $1`, id).Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE id = $1`, id)
		if err != nil {
			return 0, nil, trapRuleError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Trap-Regeln pflegen dürfen nur Admins."}
		}
		if err := audit(ctx, tx, &tenant, "trapregel.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleTrapRuleOrder setzt die Reihenfolge der Regeln eines Mandanten
// (vollständige Liste, wie sie angezeigt wird).
func (s *Server) handleTrapRuleOrder(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		IDs []string `json:"ids"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "trapregeln ordnen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if len(in.IDs) == 0 || len(in.IDs) > 500 {
			return 0, nil, badRequest("Bitte alle Regeln des Mandanten in der neuen Reihenfolge angeben (höchstens 500).")
		}
		seen := map[string]bool{}
		for _, id := range in.IDs {
			if !uuidPattern.MatchString(id) || seen[id] {
				return 0, nil, badRequest("Ungültige oder doppelte ID.")
			}
			seen[id] = true
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('openwacht.snmp_trap_rules:' || $1, 0))`, tid); err != nil {
			return 0, nil, err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_trap_rules WHERE tenant_id = $1`, tid).Scan(&n); err != nil {
			return 0, nil, err
		}
		if n != len(in.IDs) {
			return 0, nil, &apiError{http.StatusConflict, "Die Liste ist nicht mehr aktuell. Bitte neu laden."}
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_trap_rules r SET position = x.pos * 10
			FROM unnest($2::uuid[]) WITH ORDINALITY AS x(id, pos) WHERE r.id = x.id AND r.tenant_id = $1`, tid, in.IDs)
		if err != nil {
			return 0, nil, err
		}
		if int(tag.RowsAffected()) != len(in.IDs) {
			// fremde IDs oder ohne Admin-Recht (RLS: 0 Zeilen)
			var admin bool
			if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, tid).Scan(&admin); err == nil && !admin {
				return 0, nil, &apiError{http.StatusForbidden, "Trap-Regeln pflegen dürfen nur Admins."}
			}
			return 0, nil, &apiError{http.StatusConflict, "Die Liste ist nicht mehr aktuell. Bitte neu laden."}
		}
		if err := audit(ctx, tx, &tid, "trapregeln.geordnet", map[string]any{"ids": in.IDs}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// Standardregeln: Neustart, Schnittstelle getrennt/verbunden, Anmeldefehler.
func (s *Server) handleTrapRuleDefaults(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "trapregeln standard", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		const ifIndex = "1.3.6.1.2.1.2.2.1.1"
		ids := make([]string, 5)
		for i := range ids {
			var err error
			if ids[i], err = newUUID(); err != nil {
				return 0, nil, err
			}
		}
		type def struct {
			name, oid, action string
			key, clears       *string
			minutes           int
		}
		key := ifIndex
		defs := []def{
			{"Neustart (coldStart)", "1.3.6.1.6.3.1.1.5.1", "warn", nil, nil, 60},
			{"Neustart (warmStart)", "1.3.6.1.6.3.1.1.5.2", "warn", nil, nil, 60},
			{"Schnittstelle getrennt (linkDown)", "1.3.6.1.6.3.1.1.5.3", "warn", &key, nil, 0},
			{"Schnittstelle verbunden (linkUp)", "1.3.6.1.6.3.1.1.5.4", "ok", &key, &ids[2], 60},
			{"Anmeldefehler (authenticationFailure)", "1.3.6.1.6.3.1.1.5.5", "warn", nil, nil, 60},
		}
		for i, d := range defs {
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, position, name, trap_oid, action, key_oid,
					duration_min, clears)
				VALUES ($1, $2, coalesce((SELECT max(position) + 10 FROM openwacht.snmp_trap_rules WHERE tenant_id = $2), 10),
					$3, $4, $5, $6, $7, $8)`, ids[i], tid, d.name, d.oid, d.action, d.key, d.minutes, d.clears); err != nil {
				return 0, nil, trapRuleError(err)
			}
		}
		if err := audit(ctx, tx, &tid, "trapregeln.standard", map[string]any{"ids": ids}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"ids": ids}, nil
	})
}

type trapLogOut struct {
	ID        int64           `json:"id"`
	Empfangen time.Time       `json:"empfangen"`
	Version   string          `json:"version"`
	Inform    bool            `json:"inform"`
	Bestaetig bool            `json:"bestaetigt"`
	TrapOID   string          `json:"trap_oid"`
	TrapName  string          `json:"trap_name"`
	Werte     json.RawMessage `json:"werte"`
	RegelID   *string         `json:"regel_id"`
	RegelName *string         `json:"regel_name"`
	Ergebnis  string          `json:"ergebnis"`
	Kennfarbe *kennfarbeRef   `json:"kennfarbe,omitempty"`
}

// handleTrapLog: Trap-Protokoll und aktuelle Zustände einer Quelle.
func (s *Server) handleTrapLog(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("anzahl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "anzahl: 1 bis 500.")
			return
		}
		limit = n
	}
	s.handle(w, r, "traps", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.snmp_sources WHERE id = $1)`, id).Scan(&exists); err != nil {
			return 0, nil, err
		}
		if !exists {
			return 0, nil, errNotFound
		}
		// Regelnamen nur, wenn die Regel sichtbar ist (Regeln von Eltern-Mandanten sieht ein Kind nicht).
		rows, err := tx.Query(ctx, `SELECT l.id, l.received_at, l.version, l.inform, l.authentic, l.trap_oid, l.varbinds,
				l.rule_id::text, r.name, l.result, openwacht.kennfarbe_json(r.kennfarbe_id)
			FROM openwacht.snmp_trap_log l LEFT JOIN openwacht.snmp_trap_rules r ON r.id = l.rule_id
			WHERE l.source_id = $1 ORDER BY l.id DESC LIMIT $2`, id, limit)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (trapLogOut, error) {
			var o trapLogOut
			var raw, kenn []byte
			err := row.Scan(&o.ID, &o.Empfangen, &o.Version, &o.Inform, &o.Bestaetig, &o.TrapOID, &raw, &o.RegelID, &o.RegelName, &o.Ergebnis,
				&kenn)
			o.Werte = raw
			o.Kennfarbe = parseKennfarbeRef(kenn)
			o.TrapName = trapNameOf(o.TrapOID)
			return o, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []trapLogOut{}
		}
		var states []byte
		if err := tx.QueryRow(ctx, `SELECT openwacht.snmp_trap_states_json($1)`, id).Scan(&states); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"traps": list, "zustaende": json.RawMessage(states)}, nil
	})
}

// handleTrapReset setzt einen Trap-Zustand von Hand zurück (Admins und Operatoren).
func (s *Server) handleTrapReset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Regel   string `json:"regel"`
		Instanz string `json:"instanz"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "trap zurücksetzen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if !uuidPattern.MatchString(in.Regel) || utf8.RuneCountInString(in.Instanz) > 100 {
			return 0, nil, badRequest("Regel oder Instanz ungültig.")
		}
		var tenant string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&tenant); err != nil {
			return 0, nil, err
		}
		var res string
		if err := tx.QueryRow(ctx, `SELECT openwacht.snmp_trap_reset($1, $2, $3)`, id, in.Regel, in.Instanz).Scan(&res); err != nil {
			return 0, nil, err
		}
		switch res {
		case "verboten":
			return 0, nil, &apiError{http.StatusForbidden, "Zurücksetzen dürfen Admins und Operatoren."}
		case "fehlt":
			return 0, nil, errNotFound
		}
		if err := audit(ctx, tx, &tenant, "trap.zurueckgesetzt", map[string]any{"quelle": id, "regel": in.Regel, "instanz": in.Instanz}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// trapNameOf: Name bekannter Traps ("" = unbekannt).
func trapNameOf(oid string) string {
	if n := traps.TrapName(oid); n != oid {
		return n
	}
	return ""
}
