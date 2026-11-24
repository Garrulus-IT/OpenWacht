// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Agent als Sammler (Etappe 15). Ein Agent, der auf seinem Rechner als
// Sammler freigegeben ist (openwacht-agent sammler -netze …), holt bei jedem
// Meldezyklus die Liste seiner SNMP-Geräte samt Zugangsdaten ab, fragt sie
// selbst ab und schickt die Ergebnisse. Leitprinzip 1 bleibt gewahrt: Die
// Zentrale antwortet nur mit Daten, der Agent öffnet keinen Port und führt
// nichts aus.
//
// Schutzschichten:
//   - Der Agent ergibt sich aus dem Client-Zertifikat (requireAgent), nie aus
//     der Anfrage. Die Datenbank liefert nur Quellen, die diesem Agent im
//     selben Mandanten zugewiesen sind (collector_jobs, collector_source,
//     collector_record, Fremdschlüssel mit tenant_id).
//   - Zugangsdaten gibt es nur, wenn sich die Liste geändert hat, und nicht
//     für Adressen außerhalb der Netze, die der Agent selbst freigegeben hat.
//   - Messwerte des Sammlers sind nicht vertrauenswürdig: geprüft wie beim
//     Lesen eines Geräts (snmp.ValidateCollected); Raten und Neustart rechnet
//     die Zentrale aus ihren eigenen gespeicherten Werten.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// collectorGuard: die Netze, die der Agent selbst als Sammler freigegeben
// hat (aus seinen Messwerten, also ungeprüft bis auf die Form).
func collectorGuard(raw []byte) *checks.Guard {
	var nets []string
	if json.Unmarshal(raw, &nets) != nil {
		return checks.NewGuard(nil)
	}
	prefixes, err := agentproto.ParseCollectorNets(nets)
	if err != nil {
		return checks.NewGuard(nil)
	}
	return checks.NewGuard(prefixes)
}

func collectorNetsText(g *checks.Guard) string {
	var out []string
	for _, p := range g.Networks() {
		out = append(out, p.String())
	}
	if out == nil {
		return "keine"
	}
	return strings.Join(out, ", ")
}

type collectorJob struct {
	id, tenant, version, host string
	port, revision, interval  int
	secret                    []byte
	due                       bool
	lastTryS                  *float64
	nets                      []byte
}

// collectorState: Stand der Liste ohne Zugangsdaten. Neue Zugangsdaten
// erhöhen die Revision (Trigger), ändern also auch den Stand.
func collectorState(list []agentproto.CollectorDevice) string {
	h := sha256.New()
	for _, d := range list {
		fmt.Fprintf(h, "%s|%d|%s|%s|%d|%d|%s|%s\n", d.ID, d.Revision, d.Version, d.Host, d.Port, d.IntervalSeconds,
			strings.Join(d.Extra, ","), strings.Join(d.Columns, ","))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (s *Server) handleCollectorDevices(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	var in agentproto.CollectorDevicesRequest
	if !readAgentJSON(w, r, agentproto.MaxCollectorListBytes, &in) {
		return
	}
	if !s.collectorListLimit.allow(ident.ID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Abrufe der Geräteliste.")
		return
	}
	ctx := r.Context()
	rows, err := s.pool.Query(ctx, `SELECT id::text, tenant_id::text, version, host, port, secret_enc, revision, interval_s,
			due, last_try_s, nets
		FROM openwacht.collector_jobs($1, $2, $3)`, ident.ID, ident.Serial, s.hostLimits().SilentAfter.Seconds())
	if err != nil {
		internalError(w, "collector_jobs", err)
		return
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (collectorJob, error) {
		var j collectorJob
		err := row.Scan(&j.id, &j.tenant, &j.version, &j.host, &j.port, &j.secret, &j.revision, &j.interval,
			&j.due, &j.lastTryS, &j.nets)
		return j, err
	})
	if err != nil {
		internalError(w, "collector_jobs", err)
		return
	}
	out := agentproto.CollectorDevicesResponse{Devices: []agentproto.CollectorDevice{}, Due: []string{}}
	ids := make([]string, len(jobs))
	for i, j := range jobs {
		ids[i] = j.id
	}
	oids, err := s.oidChecks(ctx, ids)
	if err != nil {
		internalError(w, "snmp_oid_checks", err)
		return
	}
	var guard *checks.Guard
	for _, j := range jobs {
		if guard == nil {
			guard = collectorGuard(j.nets)
		}
		dev := agentproto.CollectorDevice{ID: j.id, Revision: j.revision, Version: j.version, Host: j.host, Port: j.port,
			IntervalSeconds: j.interval, Extra: extraOIDs(oids[j.id]), Columns: extraColumns(oids[j.id])}
		fail := ""
		switch {
		case j.secret == nil && j.version == snmp.V3:
			fail = "keine SNMPv3-Zugangsdaten gespeichert, bitte neu eingeben"
		case j.secret == nil:
			fail = "keine Community gespeichert, bitte neu eingeben"
		case !checks.ValidHost(j.host) && !isLiteral(j.host):
			fail = "Adresse ungültig"
		}
		if a, err := netip.ParseAddr(j.host); fail == "" && err == nil && !guard.Allowed(a) {
			fail = fmt.Sprintf("Adresse %s liegt nicht in den Netzen, die der Sammler freigegeben hat (%s)", a, collectorNetsText(guard))
		}
		if fail == "" {
			sec, err := s.openSNMP(j.id, j.tenant, j.host, j.port, j.version, j.secret)
			switch {
			case err != nil:
				fail = err.Error()
			case j.version == snmp.V3:
				dev.V3 = &agentproto.CollectorV3{User: sec.V3.User, Auth: sec.V3.Auth, AuthPass: sec.V3.AuthPass,
					Priv: sec.V3.Priv, PrivPass: sec.V3.PrivPass}
			default:
				dev.Community = sec.Community
			}
		}
		if fail != "" {
			// Der Sammler bekommt das Gerät nicht; der Fehler steht an der
			// Quelle, höchstens einmal je Intervall geschrieben.
			if j.lastTryS == nil || *j.lastTryS >= float64(j.interval) {
				s.collectorRecord(ctx, ident, j.id, j.revision, false, fail, nil, false, nil, nil)
			}
			continue
		}
		out.Devices = append(out.Devices, dev)
		if j.due {
			out.Due = append(out.Due, j.id)
		}
	}
	out.State = collectorState(out.Devices)
	if in.State != "" && in.State == out.State {
		out.Unchanged, out.Devices = true, nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) collectorRecord(ctx context.Context, ident agentIdentity, id string, revision int, ok bool, msg string,
	raw []byte, rebooted bool, names []string, values []float64) (bool, error) {
	if names == nil {
		names, values = []string{}, []float64{}
	}
	var stored bool
	err := s.pool.QueryRow(context.WithoutCancel(ctx), `SELECT openwacht.collector_record($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		ident.ID, ident.Serial, id, revision, ok, clipRunes(msg, 300), raw, rebooted, names, values).Scan(&stored)
	if err != nil {
		slog.Warn("Sammler: Ergebnis nicht gespeichert", "agent", ident.ID, "quelle", id, "fehler", err)
	}
	return stored, err
}

func (s *Server) handleCollectorResult(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	var in agentproto.CollectorResult
	if !readAgentJSON(w, r, agentproto.MaxCollectorResultBytes, &in) {
		return
	}
	if !uuidPattern.MatchString(in.ID) || in.Revision < 1 {
		writeError(w, http.StatusBadRequest, "Ungültige Quelle.")
		return
	}
	// Eine Quelle hat mindestens 30 s Intervall; „jetzt abfragen“ wartet 10 s.
	if !s.collectorResultLimit.allow(in.ID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Ergebnisse für dieses Gerät.")
		return
	}
	ctx := r.Context()
	var tenant string
	var revision int
	var prevRaw []byte
	err := s.pool.QueryRow(ctx, `SELECT tenant_id::text, revision, snapshot FROM openwacht.collector_source($1, $2, $3)`,
		ident.ID, ident.Serial, in.ID).Scan(&tenant, &revision, &prevRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Das Gerät ist diesem Sammler nicht zugewiesen.")
		return
	}
	if err != nil {
		internalError(w, "collector_source", err)
		return
	}
	if in.Revision != revision {
		writeError(w, http.StatusConflict, "Die Einstellungen des Geräts haben sich geändert, bitte die Geräteliste neu abholen.")
		return
	}
	var raw []byte
	var names []string
	var values []float64
	var cur, prev *snmp.Snapshot
	rebooted := false
	msg := ""
	if !in.OK {
		msg = alarm.Clean(in.Error, 300)
		if msg == "" {
			msg = "Abfrage durch den Sammler fehlgeschlagen"
		}
		if len(in.Snapshot) > 0 && string(in.Snapshot) != "null" {
			writeError(w, http.StatusBadRequest, "Messwerte nur bei Erfolg.")
			return
		}
	} else {
		var snap snmp.Snapshot
		if err := json.Unmarshal(in.Snapshot, &snap); err != nil {
			writeError(w, http.StatusBadRequest, "Messwerte abgelehnt: nicht lesbar.")
			return
		}
		if err := snap.ValidateCollected(s.now()); err != nil {
			writeError(w, http.StatusBadRequest, "Messwerte abgelehnt: "+err.Error())
			return
		}
		if prevRaw != nil {
			var p snmp.Snapshot
			if json.Unmarshal(prevRaw, &p) == nil {
				prev = &p
			}
		}
		snmp.ApplyRates(&snap, prev)
		if prev != nil && prev.Counters != nil {
			dt := snap.Counters.At.Sub(prev.Counters.At).Seconds()
			rebooted = snmp.Rebooted(prev.Counters.UptimeTicks, snap.Counters.UptimeTicks, dt)
		}
		// Gespeichert wird die geprüfte Struktur, nicht der Text des Agents.
		var err error
		if raw, err = json.Marshal(&snap); err != nil || len(raw) > 512<<10 {
			writeError(w, http.StatusRequestEntityTooLarge, ErrSnapshotTooLarge.Error())
			return
		}
		names, values = snmp.Series(&snap)
		cur = &snap
	}
	stored, err := s.collectorRecord(ctx, ident, in.ID, in.Revision, in.OK, msg, raw, rebooted, names, values)
	if err != nil {
		internalError(w, "collector_record", err)
		return
	}
	if !stored {
		writeError(w, http.StatusConflict, "Ergebnis nicht gespeichert (Gerät geändert, ausgeschaltet oder nicht mehr zugewiesen).")
		return
	}
	if cur != nil && (len(cur.Extra) > 0 || len(cur.Columns) > 0) {
		if byID, err := s.oidChecks(ctx, []string{in.ID}); err == nil {
			s.recordOIDs(ctx, byID[in.ID], cur, prev, rebooted)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Oberfläche ---------------------------------------------------------------

// collectorOut: ein Agent, der sich als Sammler gemeldet hat.
type collectorOut struct {
	ID        string   `json:"id"`
	MandantID string   `json:"mandant_id"`
	GeraetID  string   `json:"geraet_id"`
	Name      string   `json:"name"` // Name des Geräts
	Hostname  string   `json:"hostname"`
	Netze     []string `json:"netze"`
	Geraete   int      `json:"geraete"`
	// AbgeholtAm: letzter Abruf der Geräteliste
	AbgeholtAm *time.Time `json:"abgeholt_am"`
}

// visibleCollectors: Agents mit lokaler Freigabe als Sammler, die der
// Benutzer sieht (RLS), ohne gesperrte.
func visibleCollectors(ctx context.Context, tx pgx.Tx) ([]collectorOut, error) {
	rows, err := tx.Query(ctx, `SELECT a.id::text, a.tenant_id::text, a.device_id::text, d.name, a.hostname,
			coalesce(a.snapshot -> 'sammler' -> 'netze', '[]'::jsonb),
			(SELECT count(*) FROM openwacht.snmp_sources s WHERE s.collector_id = a.id)::int, a.collector_seen_at
		FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id
		WHERE a.revoked_at IS NULL AND jsonb_typeof(a.snapshot -> 'sammler' -> 'netze') = 'array'
		ORDER BY lower(d.name), a.id`)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (collectorOut, error) {
		var c collectorOut
		var nets []byte
		if err := row.Scan(&c.ID, &c.MandantID, &c.GeraetID, &c.Name, &c.Hostname, &nets, &c.Geraete, &c.AbgeholtAm); err != nil {
			return c, err
		}
		c.Netze = []string{}
		for _, p := range collectorGuard(nets).Networks() {
			c.Netze = append(c.Netze, p.String())
		}
		return c, nil
	})
	if list == nil {
		list = []collectorOut{}
	}
	return list, err
}

// collectorFor prüft den gewählten Sammler für eine Quelle: sichtbar, im
// Mandanten des Geräts, nicht gesperrt, als Sammler freigegeben. Liefert die
// Netze, die er abfragen darf.
func collectorFor(ctx context.Context, tx pgx.Tx, agentID, tenant string) (*checks.Guard, string, error) {
	if !uuidPattern.MatchString(agentID) {
		return nil, "", badRequest("Sammler: ungültige ID.")
	}
	var agentTenant, host string
	var revoked bool
	var nets []byte
	err := tx.QueryRow(ctx, `SELECT a.tenant_id::text, d.name, a.revoked_at IS NOT NULL, a.snapshot -> 'sammler' -> 'netze'
		FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id WHERE a.id = $1`, agentID).Scan(&agentTenant, &host, &revoked, &nets)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, "", badRequest("Sammler nicht gefunden.")
	case err != nil:
		return nil, "", err
	case agentTenant != tenant:
		// Entscheidung 20.11.2026: nur Geräte des eigenen Mandanten, auch nicht
		// für Untermandanten (die Zugangsdaten lägen sonst auf einem fremden Rechner).
		return nil, "", badRequest("Der Sammler muss zum selben Mandanten gehören wie das Gerät.")
	case revoked:
		return nil, "", badRequest("Der Agent " + host + " ist gesperrt.")
	case nets == nil:
		return nil, "", badRequest("Der Agent " + host + " ist nicht als Sammler freigegeben. Auf dem Rechner: openwacht-agent sammler -netze <Netz>.")
	}
	return collectorGuard(nets), host, nil
}

// collectorRefs: Anzahl der Quellen, die ein Agent sammelt (für das Löschen).
func collectorRefs(ctx context.Context, tx pgx.Tx, agentID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_sources WHERE collector_id = $1`, agentID).Scan(&n)
	return n, err
}

func devicesText(n int) string {
	if n == 1 {
		return "1 Gerät"
	}
	return fmt.Sprintf("%d Geräte", n)
}
