// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

// Etappe 24: Abhängigkeiten, Bereitschaft und Eskalation im Alarmdurchlauf.

// addDependencies: Checks, Agents und Quellen von Geräten unter einem nicht
// erreichbaren Gerät gelten wie in Wartung (keine neuen Alarme, keine
// Erinnerungen; Entwarnungen gehen raus).
func addDependencies(ctx context.Context, tx pgx.Tx, m maintenanceSet) error {
	rows, err := tx.Query(ctx, `SELECT check_id::text, agent_id::text, snmp_id::text FROM openwacht.dependency_suppressed()`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var check, agent, source *string
		if err := rows.Scan(&check, &agent, &source); err != nil {
			return err
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
	return rows.Err()
}

// activeHours: Bereitschaft eines Kanals.
type activeHours struct {
	Tage []int  `json:"tage"` // 1 = Montag … 7 = Sonntag
	Von  string `json:"von"`  // HH:MM
	Bis  string `json:"bis"`  // HH:MM, kleiner als von = über Mitternacht
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

func minutes(s string) int {
	m := hhmm.FindStringSubmatch(s)
	h, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	return h*60 + mi
}

func (a activeHours) check() error {
	if len(a.Tage) == 0 || len(a.Tage) > 7 {
		return errors.New("Bereitschaft: mindestens ein Wochentag")
	}
	for _, d := range a.Tage {
		if d < 1 || d > 7 {
			return errors.New("Bereitschaft: Wochentage 1 (Montag) bis 7 (Sonntag)")
		}
	}
	if !hhmm.MatchString(a.Von) || !hhmm.MatchString(a.Bis) || a.Von == a.Bis {
		return errors.New("Bereitschaft: Uhrzeiten als HH:MM, Beginn und Ende verschieden")
	}
	return nil
}

func isoDay(t time.Time) int {
	d := int(t.Weekday())
	if d == 0 {
		return 7
	}
	return d
}

// active: Liegt t im Zeitfenster? Über Mitternacht gilt der Tag des Beginns.
func (a activeHours) active(t time.Time) bool {
	now := t.Hour()*60 + t.Minute()
	from, to := minutes(a.Von), minutes(a.Bis)
	if from < to {
		return slices.Contains(a.Tage, isoDay(t)) && now >= from && now < to
	}
	if now >= from {
		return slices.Contains(a.Tage, isoDay(t))
	}
	if now < to {
		return slices.Contains(a.Tage, isoDay(t.AddDate(0, 0, -1)))
	}
	return false
}

// inactiveChannels: Kanäle, deren Bereitschaft gerade nicht läuft. Sie
// bekommen nichts; ihre Meldungen bleiben offen und gehen raus, sobald das
// Zeitfenster beginnt.
func (s *Server) inactiveChannels(ctx context.Context, tx pgx.Tx, ids []string, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT id::text, active_hours FROM openwacht.alert_channel_hours($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	local := now.In(s.mailZone())
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var a activeHours
		if json.Unmarshal(raw, &a) != nil || a.check() != nil {
			continue // unlesbar: lieber senden als schweigen
		}
		if !a.active(local) {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// escalate schickt unbestätigte Alarme nach Ablauf der Wartezeit an den
// Eskalationskanal (je Alarm und Kanal einmal).
func (s *Server) escalate(ctx context.Context, tx pgx.Tx, maint maintenanceSet, now time.Time) (sent, failed int) {
	rows, err := tx.Query(ctx, `SELECT alarm_id::text, channel_id::text, from_channel, tenant_name, name, status, message,
		started_at, coalesce(check_id::text, ''), coalesce(agent_id::text, ''), coalesce(snmp_id::text, ''), subject
		FROM openwacht.escalation_candidates()`)
	if err != nil {
		slog.Warn("Eskalation: Kandidaten nicht lesbar", "fehler", err)
		return 0, 1
	}
	byChannel := map[string][]pending{}
	alarmsOf := map[string][]string{}
	var order []string
	for rows.Next() {
		var alarmID, channel, from string
		var started time.Time
		var p pending
		if err := rows.Scan(&alarmID, &channel, &from, &p.item.Tenant, &p.item.Check, &p.status, &p.item.Message, &started,
			&p.checkID, &p.agentID, &p.snmpID, &p.subject); err != nil {
			rows.Close()
			slog.Warn("Eskalation: Kandidat unlesbar", "fehler", err)
			return 0, 1
		}
		if _, ok := byChannel[channel]; !ok {
			order = append(order, channel)
		}
		mins := int(now.Sub(started).Minutes())
		p.item.Check = fmt.Sprintf("Eskalation (%s, seit %d Min. unbestätigt): %s", from, mins, p.item.Check)
		p.item.Status, p.item.Event = p.status, alarm.Problem
		byChannel[channel] = append(byChannel[channel], p)
		alarmsOf[channel] = append(alarmsOf[channel], alarmID)
	}
	rows.Close()
	if len(order) == 0 {
		return 0, 0
	}
	inactive, err := s.inactiveChannels(ctx, tx, order, now)
	if err != nil {
		slog.Warn("Eskalation: Bereitschaft nicht lesbar", "fehler", err)
		return 0, 1
	}
	order = slices.DeleteFunc(order, func(id string) bool { return inactive[id] })
	if len(order) == 0 {
		return 0, 0
	}
	chs, err := s.loadChannels(ctx, order)
	if err != nil {
		slog.Warn("Eskalation: Kanäle nicht lesbar", "fehler", err)
		return 0, 1
	}
	d := s.prepareDelivery(ctx, chs, byChannel, maint, now)
	for _, ch := range chs {
		if _, err := s.deliver(ctx, ch, byChannel[ch.id], d); err != nil {
			slog.Warn("Eskalation: Versand fehlgeschlagen", "kanal", ch.id, "fehler", err)
			failed++
			continue
		}
		if _, err := s.pool.Exec(context.WithoutCancel(ctx), `SELECT openwacht.escalation_sent($1::uuid[], $2)`, alarmsOf[ch.id], ch.id); err != nil {
			slog.Warn("Eskalation: Versand nicht vermerkt", "kanal", ch.id, "fehler", err)
			failed++
			continue
		}
		sent++
	}
	return sent, failed
}

// handleChannelDelivery: Bereitschaft und Eskalation eines Kanals (Admins
// des Mandanten, RLS). null schaltet die jeweilige Funktion aus.
func (s *Server) handleChannelDelivery(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Bereitschaft  *activeHours `json:"bereitschaft"`
		Eskalation    *escalation  `json:"eskalation"`
		Monatsbericht bool         `json:"monatsbericht"` // nur Mail-Kanäle (Etappe 25)
		Sammeln       *bool        `json:"sammeln"`       // nur Mail und SMS (1.0.1); fehlt = unverändert
	}
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "alarmkanal", err) }
	var hours []byte
	if in.Bereitschaft != nil {
		if err := in.Bereitschaft.check(); err != nil {
			fail(badRequest(err.Error() + "."))
			return
		}
		slices.Sort(in.Bereitschaft.Tage)
		in.Bereitschaft.Tage = slices.Compact(in.Bereitschaft.Tage)
		hours, _ = json.Marshal(in.Bereitschaft)
	}
	var after *int
	var target *string
	if e := in.Eskalation; e != nil {
		if e.NachMinuten < 5 || e.NachMinuten > 1440 {
			fail(badRequest("Eskalation: nach 5 bis 1440 Minuten."))
			return
		}
		if !uuidPattern.MatchString(e.Kanal) || e.Kanal == id {
			fail(badRequest("Eskalation: anderen Kanal desselben Mandanten wählen."))
			return
		}
		after, target = &e.NachMinuten, &e.Kanal
	}
	s.handle(w, r, "alarmkanal", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, kind string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, kind FROM openwacht.alert_channels WHERE id = $1`, id).Scan(&tenant, &kind); err != nil {
			return 0, nil, err
		}
		if in.Monatsbericht && kind != kindMail {
			return 0, nil, badRequest("Monatsberichte gibt es nur für Mail-Kanäle.")
		}
		if in.Sammeln != nil && *in.Sammeln && kind != kindMail && kind != kindSMS {
			return 0, nil, badRequest("Sammeln gibt es nur für Mail- und SMS-Kanäle.")
		}
		if target != nil {
			var same bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.alert_channels WHERE id = $1 AND tenant_id = $2)`,
				*target, tenant).Scan(&same); err != nil {
				return 0, nil, err
			}
			if !same {
				return 0, nil, badRequest("Eskalation: anderen Kanal desselben Mandanten wählen.")
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.alert_channels SET active_hours = $2, escalate_after_min = $3, escalate_channel_id = $4,
			monthly_report = $5, collect = coalesce($6, collect) WHERE id = $1`, id, hours, after, target, in.Monatsbericht, in.Sammeln)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound // nur lesend sichtbar
		}
		return http.StatusOK, map[string]any{"bereitschaft": in.Bereitschaft, "eskalation": in.Eskalation, "monatsbericht": in.Monatsbericht,
				"sammeln": in.Sammeln},
			audit(ctx, tx, &tenant, "alarmkanal.zustellung", map[string]any{"kanal": id, "bereitschaft": in.Bereitschaft,
				"eskalation": in.Eskalation, "sammeln": in.Sammeln})
	})
}
