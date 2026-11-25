// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Alarmprotokoll, Bestätigen und Sensoren für die Übersicht.
//
// Ein Alarm ist ein Problemabschnitt eines Sensors (Check oder Gegenstand
// eines Agents). Die Zentrale gleicht die Tabelle in jedem Alarmdurchlauf mit
// dem aktuellen Zustand ab (syncAlarms), unabhängig von Alarmkanälen.
// Bestätigte Alarme bekommen keine Erinnerungen mehr; Entwarnung und
// Verschlimmerung werden weiter gemeldet.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

const subjectCheck = "check"

func alarmKeyCheck(id string) string        { return "c:" + id }
func alarmKeyHost(agent, sub string) string { return "h:" + agent + "/" + sub }
func alarmKeySNMP(src, sub string) string   { return "s:" + src + "/" + sub }

type openAlarm struct {
	name, status, message string
	acked                 bool
}

// alarmInput sammelt die Problemliste für alarm_sync.
type alarmInput struct {
	checks, agents, sources           []*string
	subjects, names, status, messages []string
}

func (in *alarmInput) add(check, agent *string, subject, name, status, message string) {
	in.addSource(check, agent, nil, subject, name, status, message)
}

func (in *alarmInput) addSource(check, agent, source *string, subject, name, status, message string) {
	in.checks = append(in.checks, check)
	in.agents = append(in.agents, agent)
	in.sources = append(in.sources, source)
	in.subjects = append(in.subjects, subject)
	in.names = append(in.names, name)
	in.status = append(in.status, status)
	in.messages = append(in.messages, message)
}

// syncAlarms gleicht das Alarmprotokoll ab und liefert die Schlüssel der
// bestätigten offenen Alarme. Läuft in der Transaktion des Alarmdurchlaufs
// (unter dessen Sperre), aber in einem eigenen Sicherungspunkt: Ein Fehler
// hier darf den Versand nicht verhindern.
func (s *Server) syncAlarms(ctx context.Context, tx pgx.Tx, now time.Time, maint maintenanceSet) map[string]bool {
	sp, err := tx.Begin(ctx)
	if err != nil {
		slog.Warn("Alarmprotokoll: Sicherungspunkt fehlgeschlagen", "fehler", err)
		return nil
	}
	acked, err := s.syncAlarmsTx(ctx, sp, now, maint)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("Alarmprotokoll: Abgleich fehlgeschlagen", "fehler", err)
		}
		_ = sp.Rollback(ctx)
		return nil
	}
	if err := sp.Commit(ctx); err != nil {
		slog.Warn("Alarmprotokoll: Abgleich nicht gespeichert", "fehler", err)
		return nil
	}
	return acked
}

// In der Wartung beginnen keine neuen Alarme; laufende werden fortgeschrieben
// und enden mit der Erholung.
func (s *Server) syncAlarmsTx(ctx context.Context, tx pgx.Tx, now time.Time, maint maintenanceSet) (map[string]bool, error) {
	open := map[string]openAlarm{}
	hostPrev := map[string]map[string]string{} // Agent → Gegenstand → Zustand
	snmpPrev := map[string]map[string]string{} // SNMP-Quelle → Gegenstand → Zustand
	acked := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT check_id::text, agent_id::text, snmp_id::text, subject, name, status, message, acknowledged
		FROM openwacht.alarm_open()`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var check, agent, source *string
		var sub string
		var a openAlarm
		if err := rows.Scan(&check, &agent, &source, &sub, &a.name, &a.status, &a.message, &a.acked); err != nil {
			rows.Close()
			return nil, err
		}
		var key string
		switch {
		case check != nil:
			key = alarmKeyCheck(*check)
		case agent != nil:
			key = alarmKeyHost(*agent, sub)
			if hostPrev[*agent] == nil {
				hostPrev[*agent] = map[string]string{}
			}
			hostPrev[*agent][sub] = a.status
		case source != nil:
			key = alarmKeySNMP(*source, sub)
			if snmpPrev[*source] == nil {
				snmpPrev[*source] = map[string]string{}
			}
			snmpPrev[*source][sub] = a.status
		default:
			continue // Quelle gelöscht; der Abgleich beendet ihn
		}
		open[key] = a
		if a.acked {
			acked[key] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var in alarmInput
	// Checks: Warnungen sofort, Fehler erst ab der Schwelle, ab der auch
	// gemeldet wird (wie alarm.Decide).
	rows, err = tx.Query(ctx, `SELECT check_id::text, name, status, message, fails FROM openwacht.alarm_check_sources()`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name, status, msg string
		var fails int
		if err := rows.Scan(&id, &name, &status, &msg, &fails); err != nil {
			rows.Close()
			return nil, err
		}
		_, isOpen := open[alarmKeyCheck(id)]
		if isOpen || (status == alarm.Warn || fails >= s.cfg.AlertThreshold) && !maint.check(id) {
			in.add(&id, nil, subjectCheck, name, status, msg)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT agent_id::text, hostname, silent_s, metrics FROM openwacht.alarm_host_sources()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var agent string
		var silent float64
		var raw []byte
		var h alarm.HostInput
		if err := rows.Scan(&agent, &h.Hostname, &silent, &raw); err != nil {
			return nil, err
		}
		lim := s.limitsFor("agent", agent)
		h.Warming = now.Sub(s.started) < lim.SilentAfter
		h.Silent = time.Duration(silent * float64(time.Second))
		h.Metrics = s.withFullDays(parseMetrics(agent, raw), agent)
		prev := hostPrev[agent]
		seen := map[string]bool{}
		for _, f := range alarm.EvaluateHost(h, prev, lim) {
			seen[f.Subject] = true
			if _, isOpen := open[alarmKeyHost(agent, f.Subject)]; f.Status != alarm.OK && (isOpen || !maint.agent(agent)) {
				in.add(nil, &agent, f.Subject, f.Name, f.Status, f.Message)
			}
		}
		// Nicht bewertet (Host stumm, Zentrale gerade gestartet): Messwerte
		// sind veraltet, offene Alarme bleiben unverändert stehen.
		for sub := range prev {
			if !seen[sub] {
				a := open[alarmKeyHost(agent, sub)]
				in.add(nil, &agent, sub, a.name, a.status, a.message)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	excluded, err := snmpExclusions(ctx, tx)
	if err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT snmp_id::text, name, silent_s, interval_s, last_error, snapshot, cpu15, rebooted_s, watched,
		version, traps, `+snmpCollectorColumns+` FROM openwacht.alarm_snmp_sources()`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var q snmpRow
		if err := rows.Scan(append([]any{&q.id, &q.name, &q.silent, &q.interval, &q.lastError, &q.raw, &q.cpu15, &q.rebootedS,
			&q.watched, &q.version, &q.traps}, q.collectorDest()...)...); err != nil {
			rows.Close()
			return nil, err
		}
		q.now = now
		q.excluded = excluded[q.id]
		lim := s.limitsFor("snmp", q.id)
		in1 := q.input(now.Sub(s.started) < alarm.SilentLimit(lim, time.Duration(q.interval)*time.Second), lim)
		in1.FullDays = s.fullDaysFor("snmp", q.id)
		prev := snmpPrev[q.id]
		seen := map[string]bool{}
		id := q.id
		for _, f := range alarm.EvaluateSNMP(in1, prev, lim) {
			seen[f.Subject] = true
			if _, isOpen := open[alarmKeySNMP(id, f.Subject)]; f.Status != alarm.OK && (isOpen || !maint.source(id)) {
				in.addSource(nil, nil, &id, f.Subject, f.Name, f.Status, f.Message)
			}
		}
		for sub := range prev {
			if !seen[sub] {
				a := open[alarmKeySNMP(id, sub)]
				in.addSource(nil, nil, &id, sub, a.name, a.status, a.message)
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, `SELECT openwacht.alarm_sync($1::uuid[], $2::uuid[], $3::uuid[], $4::text[], $5::text[], $6::text[], $7::text[])`,
		in.checks, in.agents, in.sources, in.subjects, in.names, in.status, in.messages); err != nil {
		return nil, err
	}
	return acked, nil
}

func parseMetrics(agent string, raw []byte) *alarm.HostMetrics {
	if raw == nil {
		return nil
	}
	var m alarm.HostMetrics
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Warn("Messwerte eines Agents nicht lesbar", "agent", agent, "fehler", err)
		return nil
	}
	return &m
}

// --- API: Alarmprotokoll ------------------------------------------------------------

type alarmOut struct {
	ID            string     `json:"id"`
	MandantID     string     `json:"mandant_id"`
	CheckID       *string    `json:"check_id"`
	AgentID       *string    `json:"agent_id"`
	SNMPID        *string    `json:"snmp_id"`
	Gegenstand    string     `json:"gegenstand"`
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	Schlimmster   string     `json:"schlimmster"`
	Meldung       string     `json:"meldung"`
	Beginn        time.Time  `json:"beginn"`
	Geaendert     time.Time  `json:"geaendert"`
	Ende          *time.Time `json:"ende"`
	BestaetigtAm  *time.Time `json:"bestaetigt_am"`
	BestaetigtVon *string    `json:"bestaetigt_von"`
	Kommentar     *string    `json:"kommentar"`
	// Kennfarbe des Sensors bzw. der Trap-Regel (0.99.2), sonst nicht gesetzt
	Kennfarbe *kennfarbeRef `json:"kennfarbe,omitempty"`
}

const alarmColumns = `id::text, tenant_id::text, check_id::text, agent_id::text, snmp_id::text, subject, name, status, worst, message,
	started_at, changed_at, ended_at, ack_at, ack_by_name, ack_comment,
	openwacht.kennfarbe_json(openwacht.kennfarbe_of(check_id, agent_id, snmp_id, subject))`

func scanAlarm(row pgx.CollectableRow) (alarmOut, error) {
	var a alarmOut
	var kenn []byte
	err := row.Scan(&a.ID, &a.MandantID, &a.CheckID, &a.AgentID, &a.SNMPID, &a.Gegenstand, &a.Name, &a.Status, &a.Schlimmster,
		&a.Meldung, &a.Beginn, &a.Geaendert, &a.Ende, &a.BestaetigtAm, &a.BestaetigtVon, &a.Kommentar, &kenn)
	a.Kennfarbe = parseKennfarbeRef(kenn)
	return a, err
}

// handleAlarmList: alle offenen Alarme und die zuletzt beendeten (30 Tage),
// höchstens limit (Standard 200, höchstens 1000) Einträge.
func (s *Server) handleAlarmList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "limit muss zwischen 1 und 1000 liegen.")
			return
		}
		limit = n
	}
	s.handle(w, r, "alarme", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT `+alarmColumns+` FROM openwacht.alarms
			WHERE ($1 = '' OR tenant_id = $1::uuid) AND (ended_at IS NULL OR ended_at > now() - interval '30 days')
			ORDER BY ended_at IS NULL DESC, coalesce(ended_at, started_at) DESC, id
			LIMIT $2`, filter, limit)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, scanAlarm)
		if list == nil {
			list = []alarmOut{}
		}
		return http.StatusOK, map[string]any{"alarme": list}, err
	})
}

// handleAlarmAck bestätigt einen offenen Alarm. Zeitpunkt und Person setzt
// die Datenbank; bestätigen dürfen Admins und Operatoren (RLS).
func (s *Server) handleAlarmAck(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Kommentar string `json:"kommentar"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	comment := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, in.Kommentar)), " ")
	if utf8.RuneCountInString(comment) > 300 {
		writeError(w, http.StatusBadRequest, "Der Kommentar darf höchstens 300 Zeichen lang sein.")
		return
	}
	s.handle(w, r, "alarm bestätigen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		var ended, acked bool
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name, ended_at IS NOT NULL, ack_at IS NOT NULL
			FROM openwacht.alarms WHERE id = $1`, id).Scan(&tenant, &name, &ended, &acked); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		if ended {
			return 0, nil, &apiError{http.StatusConflict, "Der Alarm ist schon beendet."}
		}
		if acked {
			return 0, nil, &apiError{http.StatusConflict, "Der Alarm ist schon bestätigt."}
		}
		rows, err := tx.Query(ctx, `UPDATE openwacht.alarms SET ack_at = now(), ack_comment = nullif($2, '')
			WHERE id = $1 RETURNING `+alarmColumns, id, comment)
		if err != nil {
			return 0, nil, err
		}
		a, err := pgx.CollectOneRow(rows, scanAlarm)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, &apiError{http.StatusForbidden, "Bestätigen dürfen nur Admins und Operatoren."}
		}
		if err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "alarm.bestaetigt", map[string]any{"id": id, "name": name, "kommentar": comment}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, a, nil
	})
}

// --- API: Sensoren -------------------------------------------------------------------

type sensorOut struct {
	// Schlüssel wie im Alarmprotokoll: c:<Check>, h:<Agent>/<Gegenstand>,
	// s:<SNMP-Quelle>/<Gegenstand>
	Schluessel string `json:"schluessel"`
	Art        string `json:"art"` // check | host | snmp
	QuelleID   string `json:"quelle_id"`
	MandantID  string `json:"mandant_id"`
	GeraetID   string `json:"geraet_id"`
	// Name des Geräts
	Host       string     `json:"host,omitempty"`
	Name       string     `json:"name"`
	Gegenstand string     `json:"gegenstand"`
	Status     string     `json:"status"` // ok | warn | crit | unknown | pause | neu
	Meldung    string     `json:"meldung"`
	Seit       *time.Time `json:"seit"`
	Alarm      *alarmOut  `json:"alarm"`
	// Wartung des Checks bzw. Hosts, falls eine läuft. Status bleibt der
	// gemessene Zustand; die Oberfläche zeigt den Sensor unter „Wartung“.
	Wartung *wartungOut `json:"wartung"`
	// Kennfarbe (0.99.2): gilt in der Oberfläche nur bei Warnung, Kritisch
	// und Bestätigt; sonst nicht gesetzt
	Kennfarbe *kennfarbeRef `json:"kennfarbe,omitempty"`
	// Ausgenommen (0.99.2): Begründung, wenn der Gegenstand ausgenommen ist
	// (Status dann „pause“); leer, wenn der Kontext sie nicht lesen darf
	Ausgenommen *string `json:"ausgenommen,omitempty"`
}

// handleSensors liefert alle Sensoren im sichtbaren Bereich mit ihrem
// aktuellen Zustand und dem offenen Alarm, falls es einen gibt. Hosts werden
// mit denselben Schwellen bewertet wie für die Alarme.
func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "sensoren", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		out, err := s.collectSensors(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		lim := s.hostLimits()
		return http.StatusOK, map[string]any{"sensoren": out, "stumm_nach_s": int(lim.SilentAfter.Seconds())}, nil
	})
}

// collectSensors liest alle Sensoren, die der Kontext der Transaktion sehen
// darf (Benutzer oder Wandanzeige), und bewertet sie.
func (s *Server) collectSensors(ctx context.Context, tx pgx.Tx) ([]sensorOut, error) {
	rows, err := tx.Query(ctx, `SELECT `+alarmColumns+` FROM openwacht.alarms WHERE ended_at IS NULL`)
	if err != nil {
		return nil, err
	}
	openList, err := pgx.CollectRows(rows, scanAlarm)
	if err != nil {
		return nil, err
	}
	open := map[string]*alarmOut{}
	hostPrev := map[string]map[string]string{}
	snmpPrev := map[string]map[string]string{}
	for i := range openList {
		a := &openList[i]
		switch {
		case a.SNMPID != nil:
			open[alarmKeySNMP(*a.SNMPID, a.Gegenstand)] = a
			if snmpPrev[*a.SNMPID] == nil {
				snmpPrev[*a.SNMPID] = map[string]string{}
			}
			snmpPrev[*a.SNMPID][a.Gegenstand] = a.Status
		case a.CheckID != nil:
			open[alarmKeyCheck(*a.CheckID)] = a
		case a.AgentID != nil:
			open[alarmKeyHost(*a.AgentID, a.Gegenstand)] = a
			if hostPrev[*a.AgentID] == nil {
				hostPrev[*a.AgentID] = map[string]string{}
			}
			hostPrev[*a.AgentID][a.Gegenstand] = a.Status
		}
	}

	maint, err := visibleMaintenance(ctx, tx)
	if err != nil {
		return nil, err
	}
	out := []sensorOut{}
	rows, err = tx.Query(ctx, `SELECT c.id::text, c.tenant_id::text, c.device_id::text, d.name, c.name, c.enabled, c.status,
				coalesce(c.message, ''), c.since, openwacht.kennfarbe_json(c.kennfarbe_id)
			FROM openwacht.checks c JOIN openwacht.devices d ON d.id = c.device_id ORDER BY lower(d.name), lower(c.name)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sn sensorOut
		var enabled bool
		var status *string
		var kenn []byte
		if err := rows.Scan(&sn.QuelleID, &sn.MandantID, &sn.GeraetID, &sn.Host, &sn.Name, &enabled, &status, &sn.Meldung,
			&sn.Seit, &kenn); err != nil {
			rows.Close()
			return nil, err
		}
		sn.Kennfarbe = parseKennfarbeRef(kenn)
		sn.Art, sn.Gegenstand = "check", subjectCheck
		sn.Schluessel = alarmKeyCheck(sn.QuelleID)
		switch {
		case !enabled:
			sn.Status, sn.Meldung, sn.Seit = "pause", "pausiert", nil
		case status == nil:
			sn.Status, sn.Meldung = "neu", "noch nicht geprüft"
		default:
			sn.Status = *status
		}
		sn.Alarm = open[sn.Schluessel]
		if enabled {
			sn.Wartung = maint[sn.Schluessel]
		}
		out = append(out, sn)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT a.id::text, a.tenant_id::text, a.device_id::text, d.name, a.hostname,
				extract(epoch FROM now() - coalesce(a.last_seen, a.created_at))::double precision,
				openwacht.agent_alarm_metrics(a.id, a.snapshot)
			FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id
			WHERE a.revoked_at IS NULL ORDER BY lower(d.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var agent, tenant, device, deviceName string
		var silent float64
		var raw []byte
		var h alarm.HostInput
		if err := rows.Scan(&agent, &tenant, &device, &deviceName, &h.Hostname, &silent, &raw); err != nil {
			return nil, err
		}
		h.Silent = time.Duration(silent * float64(time.Second))
		h.Metrics = s.withFullDays(parseMetrics(agent, raw), agent)
		prev := hostPrev[agent]
		lim := s.limitsFor("agent", agent)
		stale := h.Silent >= lim.SilentAfter
		// Die Gegenstände ergeben sich aus den letzten Messwerten; ist der
		// Host stumm, sind sie veraltet und gelten als unbekannt.
		fresh := h
		fresh.Silent = 0
		for _, f := range alarm.EvaluateHost(fresh, prev, lim) {
			sn := sensorOut{Art: "host", QuelleID: agent, MandantID: tenant, GeraetID: device, Host: deviceName, Gegenstand: f.Subject,
				Name: sensorName(f.Subject), Status: f.Status, Meldung: f.Message}
			if f.Subject == alarm.SubjectSilent {
				sn.Meldung = "meldet sich"
				if stale {
					since := time.Now().Add(-h.Silent).Truncate(time.Second)
					sn.Status, sn.Meldung, sn.Seit = alarm.Crit, "meldet sich nicht", &since
				}
			} else if stale {
				sn.Status, sn.Meldung = alarm.Unknown, "Messwerte veraltet"
			} else if f.Status == alarm.OK && strings.HasSuffix(f.Message, "wird nicht mehr gemeldet oder überwacht") {
				continue // Gegenstand ist verschwunden
			}
			sn.Schluessel = alarmKeyHost(agent, f.Subject)
			sn.Wartung = maint["a:"+agent]
			if a := open[sn.Schluessel]; a != nil {
				sn.Alarm = a
				if sn.Seit == nil {
					sn.Seit = &a.Beginn
				}
			}
			out = append(out, sn)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	snmpSensors, err := s.snmpSensors(ctx, tx, open, snmpPrev, maint)
	if err != nil {
		return nil, err
	}
	out = append(out, snmpSensors...)
	ix, err := loadKennfarbenIndex(ctx, tx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		sn := &out[i]
		switch sn.Art {
		case "host":
			sn.Kennfarbe = ix.forHost(sn.QuelleID, sn.Gegenstand)
		case "snmp":
			if sn.Kennfarbe, err = ix.forSNMP(ctx, sn.QuelleID, sn.Gegenstand); err != nil {
				return nil, err
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Art != out[j].Art {
			return out[i].Art < out[j].Art
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return sensorOrder(out[i].Gegenstand) < sensorOrder(out[j].Gegenstand)
	})
	return out, nil
}

func sensorName(sub string) string {
	switch {
	case sub == alarm.SubjectSilent:
		return "Erreichbarkeit"
	case sub == alarm.SubjectMemory:
		return "Arbeitsspeicher"
	case sub == alarm.SubjectCPU:
		return "CPU"
	case sub == alarm.SubjectCollector:
		return "Sammler"
	case strings.HasPrefix(sub, "platte:"):
		return "Platte " + strings.TrimPrefix(sub, "platte:")
	}
	return sub
}

func sensorOrder(sub string) string {
	switch sub {
	case alarm.SubjectSilent:
		return "0"
	case alarm.SubjectCPU:
		return "1"
	case alarm.SubjectMemory:
		return "2"
	}
	return "3" + sub
}

// snmpSensors: die Gegenstände der sichtbaren SNMP-Quellen (RLS), bewertet
// wie für die Alarme.
func (s *Server) snmpSensors(ctx context.Context, tx pgx.Tx, open map[string]*alarmOut,
	prevAll map[string]map[string]string, maint map[string]*wartungOut) ([]sensorOut, error) {
	excluded, err := snmpExclusions(ctx, tx)
	if err != nil {
		return nil, err
	}
	// Begründungen nur, wo der Benutzer sie lesen darf (RLS; Anzeigen nie)
	reasons, err := tx.Query(ctx, `SELECT snmp_id::text, subject, reason FROM openwacht.snmp_exclusions`)
	if err != nil {
		return nil, err
	}
	for reasons.Next() {
		var src, sub, reason string
		if err := reasons.Scan(&src, &sub, &reason); err != nil {
			reasons.Close()
			return nil, err
		}
		if excluded[src] != nil {
			if _, ok := excluded[src][sub]; ok {
				excluded[src][sub] = reason
			}
		}
	}
	reasons.Close()
	if err := reasons.Err(); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text, s.tenant_id::text, s.device_id::text, d.name, NOT s.enabled,
			extract(epoch FROM now() - greatest(coalesce(s.last_ok, s.changed_at), a.collector_since))::double precision, s.interval_s,
			coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
			extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched, s.last_ok IS NULL, s.version,
			openwacht.snmp_trap_states_json(s.id),
			(SELECT cd.name FROM openwacht.devices cd WHERE cd.id = a.device_id),
			jsonb_typeof(a.snapshot -> 'sammler' -> 'netze') = 'array', a.revoked_at IS NOT NULL,
			extract(epoch FROM now() - a.collector_seen_at)::double precision
		FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
		LEFT JOIN openwacht.agents a ON a.id = s.collector_id ORDER BY lower(d.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sensorOut
	for rows.Next() {
		var q snmpRow
		var tenant, device string
		var never bool
		if err := rows.Scan(append([]any{&q.id, &tenant, &device, &q.name, &q.disabled, &q.silent, &q.interval, &q.lastError, &q.raw,
			&q.cpu15, &q.rebootedS, &q.watched, &never, &q.version, &q.traps}, q.collectorDest()...)...); err != nil {
			return nil, err
		}
		q.now = s.now()
		q.excluded = excluded[q.id]
		kind := "SNMP"
		switch q.version {
		case versionPVE:
			kind = "Proxmox"
		case versionTR064:
			kind = "FRITZ!Box"
		case versionVCenter:
			kind = "vCenter"
		case versionONTAP:
			kind = "NetApp"
		case versionXAPI:
			kind = "XenServer"
		case versionCitrix:
			kind = "Citrix"
		}
		base := sensorOut{Art: "snmp", QuelleID: q.id, MandantID: tenant, GeraetID: device, Host: q.name}
		if q.disabled {
			sn := base
			sn.Gegenstand, sn.Name, sn.Status, sn.Meldung = alarm.SubjectSilent, kind, "pause", kind+"-Abfrage ausgeschaltet"
			sn.Schluessel = alarmKeySNMP(q.id, alarm.SubjectSilent)
			out = append(out, sn)
			continue
		}
		lim := s.limitsFor("snmp", q.id)
		in := q.input(false, lim)
		in.FullDays = s.fullDaysFor("snmp", q.id)
		stale := in.Silent >= alarm.SilentLimit(lim, in.Interval)
		// Fällt der Sammler aus, sind alle Werte unbekannt (grau); den
		// Alarm dafür hat der Sammler selbst.
		down := in.CollectorDown
		fresh := in
		fresh.Silent, fresh.CollectorDown = 0, ""
		for _, f := range alarm.EvaluateSNMP(fresh, prevAll[q.id], lim) {
			sn := base
			sn.Gegenstand, sn.Name, sn.Status, sn.Meldung = f.Subject, alarm.SensorName(f.Subject), f.Status, f.Message
			if ((q.version == versionPVE || q.version == versionVCenter || q.version == versionONTAP || q.version == versionXAPI || q.version == versionCitrix) && f.Subject != alarm.SubjectSilent) || strings.HasPrefix(f.Subject, alarm.TrapPrefix) {
				// Proxmox: Namen mit Gastnamen („Backup VM 100 (srv-dms)“)
				sn.Name = strings.TrimPrefix(f.Name, q.name+" · ")
			}
			if f.Subject == alarm.SubjectSilent {
				sn.Name, sn.Meldung = kind, "antwortet"
				switch {
				case down != "":
					sn.Status, sn.Meldung = alarm.Unknown, "unbekannt: "+down
				case stale:
					since := time.Now().Add(-in.Silent).Truncate(time.Second)
					sn.Status, sn.Meldung, sn.Seit = alarm.Crit, "antwortet nicht", &since
					if in.LastError != "" {
						sn.Meldung += ": " + in.LastError
					}
				case never:
					sn.Status, sn.Meldung = "neu", "noch nicht abgefragt"
					if in.LastError != "" {
						sn.Meldung = in.LastError
					}
				}
			} else if down != "" && !strings.HasPrefix(f.Subject, alarm.TrapPrefix) {
				sn.Status, sn.Meldung = alarm.Unknown, "Messwerte veraltet ("+down+")"
			} else if stale && !strings.HasPrefix(f.Subject, alarm.TrapPrefix) { // Trap-Zustände hängen nicht an der Abfrage
				sn.Status, sn.Meldung = alarm.Unknown, "Messwerte veraltet"
			} else if f.Status == alarm.OK && strings.HasSuffix(f.Message, "wird nicht mehr gemeldet oder überwacht") {
				continue
			}
			if reason, ok := q.excluded[f.Subject]; ok && f.Subject != alarm.SubjectSilent {
				// ausgenommen: grau wie pausiert, mit Begründung
				r := reason
				sn.Status, sn.Meldung, sn.Seit, sn.Ausgenommen = "pause", alarm.ExcludedMessage(reason), nil, &r
			}
			sn.Schluessel = alarmKeySNMP(q.id, f.Subject)
			sn.Wartung = maint["s:"+q.id]
			if a := open[sn.Schluessel]; a != nil {
				sn.Alarm = a
				if sn.Seit == nil {
					sn.Seit = &a.Beginn
				}
			}
			out = append(out, sn)
		}
	}
	return out, rows.Err()
}
