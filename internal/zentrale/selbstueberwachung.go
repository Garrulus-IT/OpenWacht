// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Selbstüberwachung (Etappe 31): Die Zentrale prüft alle fünf Minuten sich
// selbst und meldet Probleme als Hinweis an den Betreiber (Alarmkanäle des
// Hauptmandanten): fehlgeschlagene oder überfällige Sicherung, Ablauf der
// Zertifikate, volle Platte, gebrochene Audit-Kette, Fehler beim
// Audit-Export, abgefangene Programmfehler (M3), stummer Trap-Dienst.
// Dazu Hinweise an Mandanten, deren Alarme seit 7 Tagen wegen eines
// ausgefallenen Elterngeräts ruhen (Befund N2).
//
// Hinweise sind bewusst einfacher als Alarme: kein Bestätigen, keine
// Wartung, keine Eskalation; eine Meldung beim Auftreten, bei einem Wechsel
// zwischen Warnung und Fehler und eine Entwarnung.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/safe"
)

// beats: letzter Durchlauf der Hintergrundläufe (Unix-Nanosekunden, 0 = nie).
type beats struct {
	checks, alerts, selfWatch atomic.Int64
}

func beat(a *atomic.Int64, t time.Time) { a.Store(t.UnixNano()) }

func since(a *atomic.Int64, now time.Time) (time.Duration, bool) {
	n := a.Load()
	if n == 0 {
		return 0, false
	}
	return now.Sub(time.Unix(0, n)), true
}

// Notice: ein Hinweis, wie notice_put ihn erwartet.
type Notice struct {
	Key    string     `json:"key"`
	Tenant *string    `json:"mandant"`
	Status string     `json:"status"` // warn, crit
	Title  string     `json:"titel"`
	Text   string     `json:"text"`
	Since  *time.Time `json:"seit,omitempty"`
}

// Grenzen der Selbstüberwachung.
const (
	selfWatchEvery     = 5 * time.Minute
	backupOverdue      = 26 * time.Hour // täglich plus Spielraum
	certWarnDays       = 21             // eigene CA erneuert 30 Tage vorher
	certCritDays       = 7
	caWarnDays         = 365
	caCritDays         = 90
	diskWarnPct        = 90.0
	diskCritPct        = 95.0
	trapSilentAfter    = 5 * time.Minute
	auditCheckOverdue  = 48 * time.Hour
	auditExportWarn    = time.Hour
	suppressedNoticeAt = 7 * 24 * time.Hour
)

var defaultSelfWatchDisks = []string{"/", "/var/lib/postgresql", "/var/backups/openwacht", "/var/log/openwacht"}

// selfNotices bewertet die Zentrale. Fehler beim Lesen einzelner Teile
// werden zu Hinweisen, nicht zum Abbruch.
func (s *Server) selfNotices(ctx context.Context, now time.Time) []Notice {
	var out []Notice
	add := func(key, status, title, text string) {
		out = append(out, Notice{Key: "zentrale:" + key, Status: status, Title: title, Text: text})
	}

	// Sicherung (nur, wenn es schon einmal eine gab: ohne Unit kein Alarm)
	var (
		started, lastOK *time.Time
		ok              *bool
		msg             *string
		runs            int64
	)
	if err := s.pool.QueryRow(ctx, `SELECT started_at, ok, message, last_ok_at, runs FROM openwacht.backup_last()`).
		Scan(&started, &ok, &msg, &lastOK, &runs); err != nil {
		add("sicherung", alarm.Warn, "Sicherung nicht prüfbar", "Die Liste der Sicherungen ist nicht lesbar.")
	} else if runs > 0 {
		switch {
		case ok != nil && !*ok:
			t := "Die letzte Sicherung ist fehlgeschlagen"
			if msg != nil && *msg != "" {
				t += ": " + clipRunes(*msg, 300)
			}
			add("sicherung", alarm.Crit, "Sicherung fehlgeschlagen", t+". Siehe Einstellungen → Sicherungen und das Journal von openwacht-sicherung.")
		case lastOK == nil || now.Sub(*lastOK) > backupOverdue:
			last := "noch nie"
			if lastOK != nil {
				last = "zuletzt " + lastOK.In(s.mailZone()).Format("02.01.2006 15:04")
			}
			add("sicherung", alarm.Crit, "Sicherung überfällig", "Erfolgreiche Sicherung "+last+". Läuft der Timer openwacht-sicherung?")
		}
	}

	// Zertifikate
	if s.https != nil {
		info := s.https.info()
		if na, ok := info["gueltig_bis"].(time.Time); ok {
			if st := expiryStatus(na, now, certWarnDays, certCritDays); st != "" {
				add("zertifikat", st, "HTTPS-Zertifikat läuft ab", "Das Zertifikat der Oberfläche ist gültig bis "+
					na.In(s.mailZone()).Format("02.01.2006")+". Bei eigener CA erneuert die Zentrale es selbst; sonst unter Einstellungen → HTTPS ein neues hochladen.")
			}
		}
		if na, ok := info["ca_gueltig_bis"].(time.Time); ok {
			if st := expiryStatus(na, now, caWarnDays, caCritDays); st != "" {
				add("https-wurzel", st, "HTTPS-Wurzel läuft ab", "Die eigene Wurzel der Oberfläche ist gültig bis "+
					na.In(s.mailZone()).Format("02.01.2006")+". Neue Wurzel unter Einstellungen → HTTPS erzeugen und auf den Geräten installieren.")
			}
		}
	}
	s.agent.mu.Lock()
	ca := s.agent.ca
	s.agent.mu.Unlock()
	if ca != nil {
		if st := expiryStatus(ca.Cert.NotAfter, now, caWarnDays, caCritDays); st != "" {
			add("agent-ca", st, "Agent-CA läuft ab", "Die CA für die Agents ist gültig bis "+
				ca.Cert.NotAfter.In(s.mailZone()).Format("02.01.2006")+". Danach können sich Agents nicht mehr melden.")
		}
	}

	// Platten
	for _, d := range diskUsage(s.selfWatchDisks()) {
		st := ""
		switch {
		case d.pct >= diskCritPct:
			st = alarm.Crit
		case d.pct >= diskWarnPct:
			st = alarm.Warn
		}
		if st != "" {
			add("platte."+diskKey(d.path), st, "Platte der Zentrale fast voll",
				fmt.Sprintf("%s ist zu %.1f %% belegt (frei: %s).", d.path, d.pct, humanBytes(d.free)))
		}
	}

	// Audit-Kette
	if c, err := s.lastAuditCheck(ctx); err != nil {
		add("audit", alarm.Warn, "Audit-Prüfung nicht lesbar", "Das Ergebnis der letzten Prüfung ist nicht lesbar.")
	} else if c != nil && !c.OK {
		add("audit", alarm.Crit, "Audit-Log manipuliert oder beschädigt", fmt.Sprintf(
			"Die Hash-Kette ist ab Eintrag %d gebrochen (Prüfung %s). Mit `openwacht-zentrale audit-pruefen` und dem Export vergleichen.",
			*c.BrokenSeq, c.At.In(s.mailZone()).Format("02.01.2006 15:04")))
	} else if c != nil && now.Sub(c.At) > auditCheckOverdue && now.Sub(s.started) > auditCheckOverdue {
		add("audit", alarm.Warn, "Audit-Prüfung überfällig", "Die tägliche Prüfung des Audit-Logs lief seit "+
			c.At.In(s.mailZone()).Format("02.01.2006 15:04")+" nicht mehr.")
	}
	if since, msg := s.auditExportFailure(); !since.IsZero() && now.Sub(since) >= auditExportWarn {
		add("audit-export", alarm.Warn, "Audit-Export fehlgeschlagen", "Seit "+since.In(s.mailZone()).Format("02.01.2006 15:04")+
			" schlägt der Export fehl: "+clipRunes(msg, 300)+". Die Einträge bleiben in der Datenbank und werden nachgeholt.")
	}

	// Abgefangene Programmfehler (M3)
	if n := safe.Total(); n > 0 {
		add("programmfehler", alarm.Warn, "Programmfehler abgefangen", fmt.Sprintf(
			"Seit dem Start %d abgefangene Fehler in: %s. Die Überwachung läuft weiter; Details im Journal („Programmfehler abgefangen“). Bitte melden.",
			n, strings.Join(safe.Areas(), ", ")))
	}

	// Trap-Dienst (nur, wenn er schon einmal lief)
	var seen *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.trap_service_seen()`).Scan(&seen); err == nil && seen != nil &&
		now.Sub(*seen) > trapSilentAfter {
		add("traps", alarm.Warn, "Trap-Dienst meldet sich nicht", "Der Trap-Dienst hat sich zuletzt "+
			seen.In(s.mailZone()).Format("02.01.2006 15:04")+" gemeldet. systemctl status openwacht-traps prüfen.")
	}
	return out
}

func expiryStatus(notAfter, now time.Time, warnDays, critDays int) string {
	left := notAfter.Sub(now)
	switch {
	case left < time.Duration(critDays)*24*time.Hour:
		return alarm.Crit
	case left < time.Duration(warnDays)*24*time.Hour:
		return alarm.Warn
	}
	return ""
}

func (s *Server) selfWatchDisks() []string {
	if s.cfg.SelfWatchDisks != nil {
		return s.cfg.SelfWatchDisks
	}
	return defaultSelfWatchDisks
}

type diskInfo struct {
	path      string
	pct       float64
	free      uint64
	fsid, dev uint64
}

func diskKey(p string) string {
	k := strings.Trim(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, p), "_")
	if k == "" {
		k = "wurzel"
	}
	return clipRunes(k, 80)
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TiB", float64(b)/(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	default:
		return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
	}
}

// suppressionNotices: N2, Alarme seit 7 Tagen wegen einer Abhängigkeit
// unterdrückt (Hinweis an den Mandanten der Geräte).
func (s *Server) suppressionNotices(ctx context.Context, now time.Time) ([]Notice, error) {
	list, err := s.suppressions(ctx, s.pool, false)
	if err != nil {
		return nil, err
	}
	var out []Notice
	for _, u := range list {
		if u.Since == nil || now.Sub(*u.Since) < suppressedNoticeAt {
			continue
		}
		t := u.Tenant
		out = append(out, Notice{Key: "unterdrueckt:" + u.BlockerID, Tenant: &t, Status: alarm.Warn,
			Title: "Alarme seit " + fmt.Sprint(int(now.Sub(*u.Since).Hours()/24)) + " Tagen unterdrückt",
			Text: fmt.Sprintf("%d Gerät(e) hängen von „%s“ ab, das seit %s nicht erreichbar ist: %s. Ihre Alarme ruhen seitdem. Abhängigkeit prüfen oder „%s“ reparieren.",
				u.Devices, u.BlockerName, u.Since.In(s.mailZone()).Format("02.01.2006 15:04"), strings.Join(u.Names, ", "), u.BlockerName),
			Since: u.Since})
	}
	return out, nil
}

// suppression: Geräte, deren Alarme ruhen, je auslösendem Gerät.
type suppression struct {
	Tenant      string     `json:"mandant_id"`
	BlockerID   string     `json:"geraet_id"`
	BlockerName string     `json:"geraet"`
	Since       *time.Time `json:"seit"`
	Devices     int64      `json:"anzahl"`
	Names       []string   `json:"geraete"`
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// suppressions: visible = nur sichtbare Mandanten (in einer Transaktion mit
// Benutzerkontext), sonst alle (Hintergrundlauf).
func (s *Server) suppressions(ctx context.Context, q querier, visible bool) ([]suppression, error) {
	sql := `SELECT tenant_id::text, blocker_id::text, blocker_name, since, devices, names FROM openwacht.dependency_suppression()`
	if visible {
		sql += ` WHERE tenant_id IN (SELECT openwacht.visible_tenants())`
	}
	rows, err := q.Query(ctx, sql+` ORDER BY since NULLS LAST, blocker_name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (suppression, error) {
		var u suppression
		err := row.Scan(&u.Tenant, &u.BlockerID, &u.BlockerName, &u.Since, &u.Devices, &u.Names)
		return u, err
	})
}

// SelfWatchRound: ein Durchlauf (bewerten, speichern, versenden).
func (s *Server) SelfWatchRound(ctx context.Context) error {
	now := s.now()
	beat(&s.beats.selfWatch, now)
	var errs []error
	if b, err := json.Marshal(nonNil(s.selfNotices(ctx, now))); err == nil {
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.notice_put('zentrale', $1::jsonb)`, b); err != nil {
			errs = append(errs, err)
		}
	}
	if list, err := s.suppressionNotices(ctx, now); err != nil {
		errs = append(errs, err)
	} else if b, err := json.Marshal(nonNil(list)); err == nil {
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.notice_put('unterdrueckt', $1::jsonb)`, b); err != nil {
			errs = append(errs, err)
		}
	}
	// Überwachte SMS-Gateways (0.43.0)
	if list, err := s.smsWatchNotices(ctx, now); err != nil {
		errs = append(errs, err)
	} else if b, err := json.Marshal(nonNil(list)); err == nil {
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.notice_put('smsgateway', $1::jsonb)`, b); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.sendNotices(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func nonNil(n []Notice) []Notice {
	if n == nil {
		return []Notice{}
	}
	return n
}

// RunSelfWatch: alle fünf Minuten, der erste Lauf nach einer Minute.
func (s *Server) RunSelfWatch(ctx context.Context) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.SelfWatchRound(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Selbstüberwachung: Durchlauf mit Fehlern", "fehler", err)
		}
		t.Reset(selfWatchEvery)
	}
}

// sendNotices verschickt fällige Hinweise an die Alarmkanäle.
func (s *Server) sendNotices(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT key, tenant_id::text, status, title, message, since, channels::text[] FROM openwacht.notice_due()`)
	if err != nil {
		return err
	}
	type due struct {
		key, status, title, text string
		tenant                   *string
		since                    time.Time
		channels                 []string
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (due, error) {
		var d due
		err := row.Scan(&d.key, &d.tenant, &d.status, &d.title, &d.text, &d.since, &d.channels)
		return d, err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range list {
		if len(d.channels) == 0 {
			// niemand zu benachrichtigen: als verschickt vermerken (sichtbar in der Oberfläche)
			if d.tenant == nil {
				slog.Warn("Hinweis an den Betreiber ohne Alarmkanal im Hauptmandanten", "hinweis", d.key, "zustand", d.status, "titel", d.title)
			}
			_, err := s.pool.Exec(ctx, `SELECT openwacht.notice_sent($1, $2)`, d.key, d.status)
			errs = append(errs, err)
			continue
		}
		chs, err := s.loadChannels(ctx, d.channels)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		n := alarm.Notice{Status: d.status, Title: d.title, Text: d.text, Since: d.since, Link: s.alarmsLink(),
			Operator: d.tenant == nil}
		sent := 0
		for _, ch := range chs {
			if err := s.sendNotice(ctx, ch, n); err != nil {
				slog.Warn("Hinweis nicht zugestellt", "hinweis", d.key, "kanal", ch.id, "art", ch.kind, "fehler", err)
				continue
			}
			sent++
		}
		if sent > 0 {
			_, err := s.pool.Exec(ctx, `SELECT openwacht.notice_sent($1, $2)`, d.key, d.status)
			errs = append(errs, err)
		} else {
			errs = append(errs, fmt.Errorf("Hinweis %s an keinen Kanal zugestellt", d.key))
		}
	}
	return errors.Join(errs...)
}

// sendNotice: ein Hinweis an einen Kanal, je Art.
func (s *Server) sendNotice(ctx context.Context, ch sendChannel, n alarm.Notice) error {
	n.Channel, n.Tenant = ch.name, ch.tenantName
	switch ch.kind {
	case kindNtfy:
		return s.sendTo(ctx, ch, n.Ntfy())
	case kindWebhook:
		return s.postHook(ctx, ch, n.Hook(s.now()))
	case kindTeams:
		return s.postHook(ctx, ch, n.Teams())
	case kindSMS:
		return s.sendSMSText(ctx, ch, n.SMS())
	case kindMail:
		c := s.mailConfig()
		if c == nil {
			return errNoMail
		}
		rows, err := s.pool.Query(ctx, `SELECT email FROM openwacht.alert_mail_recipients(ARRAY[$1::uuid])`, ch.id)
		if err != nil {
			return err
		}
		rcpts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(rcpts) == 0 {
			return errors.New("keine Empfänger")
		}
		_, err = s.mailer.Send(ctx, *c, rcpts, n.Mail())
		return err
	}
	return fmt.Errorf("unbekannte Kanalart %q", ch.kind)
}

// --- API ---------------------------------------------------------------------------

type noticeOut struct {
	Key    string    `json:"schluessel"`
	Tenant *string   `json:"mandant_id"`
	Status string    `json:"zustand"`
	Title  string    `json:"titel"`
	Text   string    `json:"text"`
	Since  time.Time `json:"seit"`
}

// handleNotices: GET /api/v1/hinweise – offene Hinweise (eigene Mandanten;
// die der Zentrale nur für den Betreiber) und die Geräte, deren Alarme
// gerade wegen einer Abhängigkeit ruhen (N2).
func (s *Server) handleNotices(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "hinweise", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT key, tenant_id::text, status, title, message, since FROM openwacht.notice_list()`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (noticeOut, error) {
			var n noticeOut
			err := row.Scan(&n.Key, &n.Tenant, &n.Status, &n.Title, &n.Text, &n.Since)
			return n, err
		})
		if err != nil {
			return 0, nil, err
		}
		sup, err := s.suppressions(ctx, tx, true)
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []noticeOut{}
		}
		if sup == nil {
			sup = []suppression{}
		}
		return http.StatusOK, map[string]any{"hinweise": list, "unterdrueckt": sup}, nil
	})
}

// handleHealth: GET /api/v1/gesund – ohne Anmeldung, ohne Interna: nur
// Zustände je Teil. 503, wenn Datenbank oder Planer gestört sind.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	out := map[string]string{"status": "ok", "datenbank": "ok", "planer": "ok", "traps": "aus"}
	broken := false
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var seen *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.trap_service_seen()`).Scan(&seen); err != nil {
		out["datenbank"] = "gestoert"
		out["traps"] = "unbekannt"
		broken = true
	} else if seen != nil {
		out["traps"] = "ok"
		if now.Sub(*seen) > trapSilentAfter {
			out["traps"] = "stumm"
		}
	}
	limit := max(3*s.cfg.CheckPoll, 2*time.Minute)
	for _, b := range []struct {
		a     *atomic.Int64
		limit time.Duration
	}{{&s.beats.checks, limit}, {&s.beats.alerts, max(3*s.cfg.AlertPoll, 2*time.Minute)}} {
		if d, ok := since(b.a, now); ok && d > b.limit {
			out["planer"] = "verzoegert"
			broken = true
		}
	}
	if _, ok := since(&s.beats.checks, now); !ok {
		out["planer"] = "aus"
	}
	code := http.StatusOK
	if broken {
		out["status"] = "gestoert"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, code, out)
}
