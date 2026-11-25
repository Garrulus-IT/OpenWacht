// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Alarmwege Mail, Webhook und Teams (Etappe 20a).
//
// Der Alarmdurchlauf entscheidet wie bisher je Kanal, was zu melden ist
// (alarm.Decide, alert_state*). Für Mail, Webhook und Teams liest die Zentrale
// danach die Details nach: Gerät, seit wann, letzte OK-Messung, weitere offene
// Probleme am Gerät, Platten-Prognose, Wartung und (nur Mail) den Verlauf der
// letzten 24 Stunden für den Graphen. Das läuft über SECURITY-DEFINER-
// Funktionen (Migration 0024), weil der Durchlauf keinen Benutzerkontext hat.
//
// Mail: eine Nachricht je Ereignis, ab alarm.SummaryLimit Ereignissen in
// einem Durchlauf eine Sammelmail. Scheitert eine Mail, gelten die vorher
// verschickten als gemeldet, der Rest kommt im nächsten Durchlauf.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // Zeitzonen auch ohne tzdata im System (statisches Binary)

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
)

// mailZone: Zeitangaben in Mails und Teams, Zeitzone der Installation
// (Standard Europe/Berlin).
func (s *Server) mailZone() *time.Location {
	l, _ := s.zone()
	return l
}

// --- SMTP-Einstellung ----------------------------------------------------------

func (s *Server) smtpKey() []byte { return deriveKey(s.boxKey, "openwacht smtp v1") }

// smtpAAD bindet das Passwort an Server und Benutzer: Wechselt einer davon,
// muss das Passwort neu eingegeben werden (es geht nie an einen anderen Server).
func smtpAAD(host, user string) []byte {
	return []byte("openwacht smtp v1\x00" + strings.ToLower(host) + "\x00" + user)
}

// mailRow: SMTP-Spalten aus settings bzw. runtime_mail().
type mailRow struct {
	host, tls, from, user, ca *string
	port                      *int32
	passEnc                   []byte
}

func (m *mailRow) dest() []any {
	return []any{&m.host, &m.port, &m.tls, &m.from, &m.user, &m.passEnc, &m.ca}
}

func (s *Server) mailFromRow(m mailRow) (*alarm.SMTPConfig, error) {
	if m.host == nil {
		return nil, nil
	}
	c := &alarm.SMTPConfig{Host: *m.host, Port: int(*m.port), TLS: *m.tls, From: *m.from}
	if m.user != nil {
		c.User = *m.user
	}
	if m.ca != nil {
		c.CA = *m.ca
	}
	if m.passEnc != nil {
		pt, err := auth.Open(s.smtpKey(), m.passEnc, smtpAAD(c.Host, c.User))
		if err != nil {
			return nil, errors.New("SMTP-Passwort nicht lesbar")
		}
		c.Pass = string(pt)
	}
	return c, nil
}

// loadMail liest die SMTP-Einstellung (für ReloadSettings).
func (s *Server) loadMail(ctx context.Context) (*alarm.SMTPConfig, error) {
	var m mailRow
	if err := s.pool.QueryRow(ctx, `SELECT host, port, tls, sender, username, pass_enc, ca FROM openwacht.runtime_mail()`).
		Scan(m.dest()...); err != nil {
		return nil, err
	}
	return s.mailFromRow(m)
}

// mailConfig: die wirksame SMTP-Einstellung (nil = Mail nicht eingerichtet).
func (s *Server) mailConfig() *alarm.SMTPConfig {
	s.live.mu.RLock()
	defer s.live.mu.RUnlock()
	return s.live.mail
}

func (s *Server) handleMailSettingsGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen mail", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		var m mailRow
		if err := tx.QueryRow(ctx, `SELECT smtp_host, smtp_port, smtp_tls, smtp_from, smtp_user, smtp_pass_enc, smtp_ca
			FROM openwacht.settings`).Scan(m.dest()...); err != nil {
			return 0, nil, err
		}
		out := map[string]any{"eingerichtet": m.host != nil}
		if m.host != nil {
			out["server"], out["port"], out["tls"], out["absender"] = *m.host, *m.port, *m.tls, *m.from
			out["benutzer"] = m.user
			out["passwort_gesetzt"] = m.passEnc != nil
			out["ca"] = m.ca
		}
		return http.StatusOK, out, nil
	})
}

type mailSettingsIn struct {
	Aus      bool    `json:"aus"`
	Server   string  `json:"server"`
	Port     int     `json:"port"`
	TLS      string  `json:"tls"`
	Absender string  `json:"absender"`
	Benutzer string  `json:"benutzer"`
	Passwort *string `json:"passwort"` // fehlt = unverändert, "" = entfernen
	CA       string  `json:"ca"`
	Code     string  `json:"code"`
}

// handleMailSettingsPut: nur Betreiber, mit frischem 2FA-Code (das Relay
// bekommt alle Alarm-Mails, das Passwort ist ein Zugang).
func (s *Server) handleMailSettingsPut(w http.ResponseWriter, r *http.Request) {
	var in mailSettingsIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "einstellungen mail", err) }
	c := alarm.SMTPConfig{Host: strings.TrimSpace(in.Server), Port: in.Port, TLS: in.TLS,
		From: strings.TrimSpace(in.Absender), User: strings.TrimSpace(in.Benutzer), CA: strings.TrimSpace(in.CA)}
	if in.Passwort != nil {
		c.Pass = *in.Passwort
	}
	if !in.Aus {
		check := c
		if in.Passwort == nil && c.User != "" {
			check.Pass = "x" // unverändert, nur die Form prüfen
		}
		if err := alarm.ValidateSMTP(check); err != nil {
			fail(badRequest(err.Error() + "."))
			return
		}
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	s.handle(w, r, "einstellungen mail", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		if in.Aus {
			_, err := tx.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL,
				smtp_from = NULL, smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
			return http.StatusOK, map[string]any{"eingerichtet": false}, err
		}
		var oldHost, oldUser *string
		var hadPass bool
		if err := tx.QueryRow(ctx, `SELECT smtp_host, smtp_user, smtp_pass_enc IS NOT NULL FROM openwacht.settings`).
			Scan(&oldHost, &oldUser, &hadPass); err != nil {
			return 0, nil, err
		}
		q := `UPDATE openwacht.settings SET smtp_host = $1, smtp_port = $2, smtp_tls = $3, smtp_from = $4,
			smtp_user = nullif($5, ''), smtp_ca = nullif($6, '')`
		args := []any{c.Host, c.Port, c.TLS, c.From, c.User, c.CA}
		switch {
		case c.User == "":
			q += `, smtp_pass_enc = NULL`
		case in.Passwort != nil && *in.Passwort == "":
			q += `, smtp_pass_enc = NULL`
		case in.Passwort != nil:
			enc, err := auth.Seal(s.smtpKey(), []byte(*in.Passwort), smtpAAD(c.Host, c.User))
			if err != nil {
				return 0, nil, err
			}
			q += `, smtp_pass_enc = $7`
			args = append(args, enc)
		case hadPass && (oldHost == nil || !strings.EqualFold(*oldHost, c.Host) || oldUser == nil || *oldUser != c.User):
			return 0, nil, badRequest("Bei neuem Server oder Benutzer bitte das Passwort neu eingeben.")
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"eingerichtet": true}, nil
	})
	if err := s.ReloadSettings(context.WithoutCancel(r.Context())); err != nil {
		slog.Warn("Einstellungen: nach dem Speichern nicht neu geladen", "fehler", err)
	}
}

// handleMailSettingsTest: Testmail an den Betreiber selbst.
func (s *Server) handleMailSettingsTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var email string
	if err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		if err := requireOperator(ctx, tx); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT email FROM openwacht.users WHERE id = $1`, sess.UserID).Scan(&email)
	}); err != nil {
		writeDBError(w, "mail test", err)
		return
	}
	if !s.alertTestLimit.allow("mail:"+sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Gerade erst getestet. Bitte einen Moment warten.")
		return
	}
	c, err := s.loadMail(ctx)
	if err != nil {
		writeDBError(w, "mail test", err)
		return
	}
	if c == nil {
		writeError(w, http.StatusConflict, "Der Mailversand ist noch nicht eingerichtet.")
		return
	}
	_, err = s.mailer.Send(ctx, *c, []string{email}, alarm.TestMail("OpenWacht", "Einstellungen → Mail"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Versand fehlgeschlagen: "+err.Error()+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gesendet": true, "an": email})
}

// handleMyAlertMail: Alarm-Mails für sich selbst an- oder abbestellen.
func (s *Server) handleMyAlertMail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		An *bool `json:"an"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.An == nil {
		writeError(w, http.StatusBadRequest, "Feld „an“ fehlt.")
		return
	}
	s.handle(w, r, "alarm-mails", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		_, err := tx.Exec(ctx, `SELECT openwacht.set_alert_mail($1)`, *in.An)
		return http.StatusOK, map[string]any{"alarm_mails": *in.An}, err
	})
}

// --- Details für ausführliche Meldungen ----------------------------------------

// reportKey: Schlüssel eines Ereignisses (Check, Agent+Gegenstand, Quelle+Gegenstand).
func reportKey(p pending) string {
	switch {
	case p.snmpID != "":
		return "snmp\x00" + p.snmpID + "\x00" + p.subject
	case p.agentID != "":
		return "agent\x00" + p.agentID + "\x00" + p.subject
	}
	return "check\x00" + p.checkID
}

// delivery: was die Kanäle eines Durchlaufs brauchen.
type delivery struct {
	now     time.Time
	reports map[string]*alarm.Report
	rcpts   map[string][]string // Mail-Kanal → Adressen
	mail    *alarm.SMTPConfig
}

type sourceInfo struct {
	deviceID, device string
	since, lastOK    *time.Time
}

// prepareDelivery liest Details nur, wenn ein Kanal sie braucht. Fehler
// kosten nur Details, nie den Versand.
func (s *Server) prepareDelivery(ctx context.Context, chs []sendChannel, by map[string][]pending, maint maintenanceSet,
	now time.Time) *delivery {
	d := &delivery{now: now, reports: map[string]*alarm.Report{}, rcpts: map[string][]string{}, mail: s.mailConfig()}
	need := map[string]pending{}
	charts := map[string]bool{}
	var mailCh []string
	for _, ch := range chs {
		if ch.kind == kindNtfy {
			continue
		}
		if ch.kind == kindMail {
			mailCh = append(mailCh, ch.id)
		}
		for _, p := range by[ch.id] {
			k := reportKey(p)
			need[k] = p
			if ch.kind == kindMail && len(by[ch.id]) < alarm.SummaryLimit {
				charts[k] = true
			}
		}
	}
	if len(need) == 0 {
		return d
	}
	if len(mailCh) > 0 {
		if rows, err := s.pool.Query(ctx, `SELECT channel_id::text, email FROM openwacht.alert_mail_recipients($1::uuid[])`, mailCh); err == nil {
			for rows.Next() {
				var ch, email string
				if rows.Scan(&ch, &email) == nil {
					d.rcpts[ch] = append(d.rcpts[ch], email)
				}
			}
			rows.Close()
		} else {
			slog.Warn("Alarme: Empfänger nicht lesbar", "fehler", err)
		}
	}
	list := make([]pending, 0, len(need))
	for _, p := range need {
		list = append(list, p)
	}
	for k, r := range s.buildReports(ctx, list, maint, now, charts) {
		d.reports[k] = r
	}
	return d
}

// buildReports: ausführliche Meldungen zu den Ereignissen; charts nennt die
// Schlüssel, für die ein Graph gezeichnet wird.
func (s *Server) buildReports(ctx context.Context, list []pending, maint maintenanceSet, now time.Time,
	charts map[string]bool) map[string]*alarm.Report {
	out := map[string]*alarm.Report{}
	var checkIDs, agentIDs, snmpIDs []string
	for _, p := range list {
		r := &alarm.Report{Item: p.item, Sensor: alarm.SplitLabel(p.item.Check, "")}
		out[reportKey(p)] = r
		switch {
		case p.snmpID != "":
			snmpIDs = append(snmpIDs, p.snmpID)
			r.Maintenance = maint.source(p.snmpID)
		case p.agentID != "":
			agentIDs = append(agentIDs, p.agentID)
			r.Maintenance = maint.agent(p.agentID)
		default:
			checkIDs = append(checkIDs, p.checkID)
			r.Maintenance = maint.check(p.checkID)
		}
	}
	src := map[string]sourceInfo{}
	rows, err := s.pool.Query(ctx, `SELECT kind, source_id::text, device_id::text, device_name, since, last_ok
		FROM openwacht.alert_sources($1::uuid[], $2::uuid[], $3::uuid[])`, checkIDs, agentIDs, snmpIDs)
	if err != nil {
		slog.Warn("Alarme: Details nicht lesbar", "fehler", err)
		return out
	}
	devSet := map[string]bool{}
	for rows.Next() {
		var kind, id string
		var si sourceInfo
		if rows.Scan(&kind, &id, &si.deviceID, &si.device, &si.since, &si.lastOK) == nil {
			src[kind+"\x00"+id] = si
			devSet[si.deviceID] = true
		}
	}
	rows.Close()
	var devices []string
	for id := range devSet {
		devices = append(devices, id)
	}
	type openAlarm struct {
		check, agent, snmp, subject string
		o                           alarm.Other
	}
	open := map[string][]openAlarm{}
	if rows, err := s.pool.Query(ctx, `SELECT device_id::text, coalesce(check_id::text, ''), coalesce(agent_id::text, ''),
			coalesce(snmp_id::text, ''), subject, name, status, message, started_at, acked
		FROM openwacht.alert_open_alarms($1::uuid[])`, devices); err == nil {
		for rows.Next() {
			var dev string
			var a openAlarm
			if rows.Scan(&dev, &a.check, &a.agent, &a.snmp, &a.subject, &a.o.Name, &a.o.Status, &a.o.Message,
				&a.o.Since, &a.o.Acked) == nil {
				open[dev] = append(open[dev], a)
			}
		}
		rows.Close()
	}
	fc := s.forecastsFor(ctx, devices)

	base := s.cfg.BaseURL
	for _, p := range list {
		r := out[reportKey(p)]
		kind, id := "check", p.checkID
		if p.snmpID != "" {
			kind, id = "snmp", p.snmpID
		} else if p.agentID != "" {
			kind, id = "agent", p.agentID
		}
		si, ok := src[kind+"\x00"+id]
		if !ok {
			continue
		}
		r.Device = si.device
		r.Sensor = alarm.SplitLabel(p.item.Check, si.device)
		r.Since, r.LastOK = si.since, si.lastOK
		if base != nil {
			u := *base
			u.Path = strings.TrimRight(u.Path, "/") + "/hosts"
			u.RawQuery = url.Values{"geraet": {si.deviceID}}.Encode()
			r.Link = u.String()
		}
		for _, a := range open[si.deviceID] {
			self := kind == "check" && a.check == id || kind == "agent" && a.agent == id && a.subject == p.subject ||
				kind == "snmp" && a.snmp == id && a.subject == p.subject
			if self {
				if r.Since == nil || kind != "check" {
					t := a.o.Since
					r.Since = &t
				}
				continue
			}
			r.Others = append(r.Others, a.o)
		}
		if mount, isDisk := strings.CutPrefix(p.subject, "platte:"); isDisk && kind != "check" {
			art := map[string]string{"agent": "host", "snmp": "snmp"}[kind]
			if f, ok := fc[art+"\x00"+id+"\x00"+mount]; ok {
				r.Forecast = f
			}
		}
		if charts[reportKey(p)] {
			r.Chart = s.chartFor(ctx, kind, id, p.subject, r.Sensor, now)
			if r.Chart != nil && kind != "check" && r.LastOK == nil && r.Chart.Warn > 0 {
				// Letzter Wert unter der Warnschwelle im gezeigten Zeitraum.
				for i := len(r.Chart.Points) - 1; i >= 0; i-- {
					if r.Chart.Points[i].V < r.Chart.Warn {
						t := r.Chart.Points[i].T
						r.LastOK = &t
						break
					}
				}
			}
		}
	}
	return out
}

// forecastsFor: Prognose-Text je „art, Quelle, Einhängepunkt“.
func (s *Server) forecastsFor(ctx context.Context, devices []string) map[string]string {
	out := map[string]string{}
	if len(devices) == 0 {
		return out
	}
	rows, err := s.pool.Query(ctx, `SELECT art, quelle::text, platte, slope_day, points, span_days, current
		FROM openwacht.disk_forecasts_sys($1::uuid[], $2::interval, $3)`, devices, interval(forecastWindow), forecastDrop)
	if err != nil {
		slog.Warn("Alarme: Prognose nicht lesbar", "fehler", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var art, id, mount string
		var slope, span, cur float64
		var points int
		if rows.Scan(&art, &id, &mount, &slope, &points, &span, &cur) != nil {
			continue
		}
		out[art+"\x00"+id+"\x00"+mount] = forecastText(slope, points, span, cur)
	}
	return out
}

// forecastText: „voll in etwa 12 Tagen (+0,8 Prozentpunkte je Tag, Basis 30 Tage)“.
func forecastText(slope float64, points int, span, current float64) string {
	stand, days := forecastResult(slope, points, span, current)
	switch stand {
	case forecastTooLittle:
		return "noch zu wenig Verlauf für eine Prognose"
	case forecastStable:
		return "stabil, kein Anstieg"
	}
	return fmt.Sprintf("%s (+%s Prozentpunkte je Tag, Basis %.0f Tage)", alarm.FullText(*days),
		strings.Replace(fmt.Sprintf("%.1f", slope), ".", ",", 1), span)
}

// chartSeries: welche Reihe zu einem Gegenstand gehört.
func chartSeries(kind, subject string) (series string, percent bool, ok bool) {
	if kind == "check" {
		return "", false, true
	}
	switch {
	case subject == "cpu", subject == "speicher":
		return subject, true, true
	case strings.HasPrefix(subject, "platte:"):
		return subject, true, true
	}
	return "", false, false
}

// chartFor: Verlauf der letzten 24 Std. mit den wirksamen Schwellen.
func (s *Server) chartFor(ctx context.Context, kind, id, subject, title string, now time.Time) *alarm.Chart {
	series, percent, ok := chartSeries(kind, subject)
	if !ok {
		return nil
	}
	rows, err := s.pool.Query(ctx, `SELECT t, v FROM openwacht.alert_series($1, $2, $3, 24)`, kind, id, series)
	if err != nil {
		return nil
	}
	defer rows.Close()
	c := &alarm.Chart{Title: title, Percent: percent, From: now.Add(-24 * time.Hour), To: now}
	if percent {
		c.Unit = "%"
	} else {
		c.Unit, c.Title = "ms", title+" (Antwortzeit)"
	}
	for rows.Next() {
		var p alarm.ChartPoint
		if rows.Scan(&p.T, &p.V) == nil {
			c.Points = append(c.Points, p)
		}
	}
	if len(c.Points) < 2 {
		return nil
	}
	if kind != "check" {
		lim := s.limitsFor(map[string]string{"agent": "agent", "snmp": "snmp"}[kind], id)
		switch {
		case subject == "cpu":
			c.Warn, c.Crit = lim.CPUWarn, lim.CPUCrit
		case subject == "speicher":
			c.Warn, c.Crit = lim.MemWarn, lim.MemCrit
		default:
			c.Warn, c.Crit = lim.DiskWarn, lim.DiskCrit
		}
	}
	return c
}

// --- Versand -------------------------------------------------------------------

// reportsOf: die Meldungen zu list (ohne Details, falls sie fehlen).
func (d *delivery) reportsOf(list []pending) []alarm.Report {
	out := make([]alarm.Report, 0, len(list))
	for _, p := range list {
		if r, ok := d.reports[reportKey(p)]; ok {
			out = append(out, *r)
		} else {
			out = append(out, alarm.Report{Item: p.item, Sensor: alarm.SplitLabel(p.item.Check, "")})
		}
	}
	return out
}

func (s *Server) alarmsLink() string {
	if s.cfg.BaseURL == nil {
		return ""
	}
	u := *s.cfg.BaseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/alarme"
	return u.String()
}

// deliver verschickt die Ereignisse eines Kanals. done: was als gemeldet gilt.
func (s *Server) deliver(ctx context.Context, ch sendChannel, list []pending, d *delivery) (done []pending, err error) {
	items := make([]alarm.Item, len(list))
	for i, p := range list {
		items[i] = p.item
	}
	switch ch.kind {
	case kindNtfy:
		if err := s.sendTo(ctx, ch, alarm.Build(ch.tenantName, items)); err != nil {
			return nil, err
		}
		return list, nil
	case kindWebhook, kindTeams:
		var body []byte
		if ch.kind == kindTeams {
			body = alarm.BuildTeams(ch.tenantName, d.reportsOf(list), d.now, s.mailZone(), s.alarmsLink())
		} else {
			body = alarm.BuildHook(ch.tenantName, ch.name, d.reportsOf(list), d.now)
		}
		if err := s.postHook(ctx, ch, body); err != nil {
			return nil, err
		}
		return list, nil
	case kindMail:
		return s.deliverMail(ctx, ch, list, d)
	case kindSMS:
		return s.deliverSMS(ctx, ch, list, d)
	}
	return nil, fmt.Errorf("unbekannte Kanalart %q", ch.kind)
}

// postHook entschlüsselt URL und Schlüssel und schickt body.
func (s *Server) postHook(ctx context.Context, ch sendChannel, body []byte) error {
	raw, err := auth.Open(s.boxKey, ch.tokenEnc, channelAAD(ch.id, ch.tenantID, ch.server))
	if err != nil {
		return errors.New("URL nicht entschlüsselbar, bitte neu eingeben")
	}
	var secret string
	if ch.kind == kindWebhook {
		sec, err := auth.Open(s.boxKey, ch.secretEnc, hookSecretAAD(ch.id, ch.tenantID))
		if err != nil {
			return errors.New("Signaturschlüssel nicht entschlüsselbar, Kanal bitte neu anlegen")
		}
		secret = string(sec)
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return s.alertSender.PostHook(sctx, string(raw), secret, body, s.now())
}

var errNoMail = errors.New("Der Mailversand ist nicht eingerichtet (Einstellungen → Mail)")

func (s *Server) deliverMail(ctx context.Context, ch sendChannel, list []pending, d *delivery) ([]pending, error) {
	if d.mail == nil {
		return nil, errNoMail
	}
	rcpts := d.rcpts[ch.id]
	if len(rcpts) == 0 {
		// Niemand will (noch) Mails: nichts nachzuholen.
		return list, nil
	}
	send := func(m alarm.Mail) error {
		rej, err := s.mailer.Send(ctx, *d.mail, rcpts, m)
		if len(rej) > 0 {
			slog.Warn("Alarme: Relay hat Empfänger abgelehnt", "kanal", ch.id, "abgelehnt", len(rej))
		}
		return err
	}
	reports := d.reportsOf(list)
	// Sammelnde Kanäle (1.0.1) schicken ab zwei Ereignissen eine Sammelmail.
	if len(list) >= alarm.SummaryLimit || ch.collect && len(list) > 1 {
		if err := send(alarm.BuildSummary(ch.tenantName, ch.name, reports, s.alarmsLink())); err != nil {
			return nil, err
		}
		return list, nil
	}
	var done []pending
	for i, p := range list {
		if err := send(alarm.BuildMail(ch.tenantName, ch.name, reports[i], d.now, s.mailZone())); err != nil {
			return done, err
		}
		done = append(done, p)
	}
	return done, nil
}

// sendTest: „Test senden“ je Art.
func (s *Server) sendTest(ctx context.Context, ch sendChannel) error {
	switch ch.kind {
	case kindNtfy:
		return s.sendTo(ctx, ch, alarm.TestMessage(ch.tenantName, ch.name))
	case kindWebhook:
		return s.postHook(ctx, ch, alarm.HookTest(ch.tenantName, ch.name, s.now()))
	case kindTeams:
		return s.postHook(ctx, ch, alarm.TeamsTest(ch.tenantName, ch.name))
	case kindSMS:
		return s.sendSMSText(ctx, ch, alarm.TestSMS(ch.tenantName, ch.name))
	case kindMail:
		c := s.mailConfig()
		if c == nil {
			return errNoMail
		}
		var rcpts []string
		rows, err := s.pool.Query(ctx, `SELECT email FROM openwacht.alert_mail_recipients(ARRAY[$1::uuid])`, ch.id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e string
			if rows.Scan(&e) == nil {
				rcpts = append(rcpts, e)
			}
		}
		rows.Close()
		if len(rcpts) == 0 {
			return errors.New("Der Kanal hat keine Empfänger (oder alle haben Alarm-Mails abbestellt)")
		}
		_, err = s.mailer.Send(ctx, *c, rcpts, alarm.TestMail(ch.tenantName, ch.name))
		return err
	}
	return fmt.Errorf("unbekannte Kanalart %q", ch.kind)
}
