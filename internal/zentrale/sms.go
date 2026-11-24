// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Alarmkanal „SMS (brevis.one)“ (0.43.0, Migration 0044).
//
// Gateway-Adresse nur aus den Alarmzielen, Passwort verschlüsselt und an
// Kanal, Mandant, Gateway, Benutzer und Fingerabdruck gebunden, immer POST.
// Empfänger sind Benutzerkonten mit freiwilliger Mobilnummer (nur über
// Definer-Funktionen lesbar) oder eine Gruppe auf dem Gateway.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
)

const kindSMS = "sms"

// Empfänger eines SMS-Kanals.
const (
	smsToUsers = "benutzer"
	smsToGroup = "gruppe"
)

// smsAAD: Das Passwort hängt an Kanal, Mandant, Gateway, Benutzer und
// Fingerabdruck; mit einem anderen davon lässt es sich nicht öffnen.
func smsAAD(id, tenant, server, user, pin string) []byte {
	return channelAAD(id, tenant, server+"\x00sms\x00"+user+"\x00"+pin)
}

// channelTokenAAD: Zusatzdaten von token_enc je Art (für den Schlüsselwechsel).
func channelTokenAAD(f []string) []byte {
	id, tenant, server, kind, user, pin := f[0], f[1], f[2], f[3], f[4], f[5]
	if kind == kindSMS {
		return smsAAD(id, tenant, server, user, pin)
	}
	return channelAAD(id, tenant, server)
}

// parsedSMS: geprüfte SMS-Angaben eines Kanals.
type parsedSMS struct {
	user, pin, target, group string
	ring, watch              bool
}

func (s *Server) parseSMS(in channelIn, p *parsedChannel) error {
	gw, err := alarm.NormalizeGateway(in.Server)
	if err != nil {
		return badRequest("Gateway: " + err.Error() + ".")
	}
	if !s.alertTargets.AllowedURL(alarm.SMSEndpoint(gw)) {
		return badRequest(fmt.Sprintf("Das Gateway %s ist nicht als Alarmziel freigegeben. Freigegeben: %s.", gw, s.targetsHint()))
	}
	p.server = gw
	in.SMSUser = strings.TrimSpace(in.SMSUser)
	if err := alarm.ValidSMSUser(in.SMSUser); err != nil {
		return badRequest(err.Error() + ".")
	}
	pin, ok := alarm.NormalizePin(in.Fingerprint)
	if !ok {
		return badRequest("Fingerabdruck des Zertifikats fehlt oder ist ungültig (64 Hexziffern, „Fingerabdruck holen“).")
	}
	if in.Password != nil && !alarm.ValidSMSPassword(*in.Password) {
		return badRequest("Passwort: 1 bis 128 Zeichen ohne Steuerzeichen.")
	}
	sp := parsedSMS{user: in.SMSUser, pin: pin, target: in.SMSTarget, ring: in.Ring, watch: in.Watch}
	switch in.SMSTarget {
	case smsToUsers:
		if in.Empfaenger != nil {
			if len(*in.Empfaenger) > alarm.MaxSMSReceivers {
				return badRequest(fmt.Sprintf("Höchstens %d Empfänger je SMS-Kanal.", alarm.MaxSMSReceivers))
			}
			for _, id := range *in.Empfaenger {
				if !uuidPattern.MatchString(id) {
					return badRequest("Ungültige Benutzer-ID.")
				}
			}
		}
	case smsToGroup:
		sp.group = strings.TrimSpace(in.SMSGroup)
		if !alarm.ValidSMSGroup(sp.group) {
			return badRequest("Gruppe: ID oder Name der Gruppe auf dem Gateway (Buchstaben, Ziffern, Leerzeichen, . _ -, höchstens 64).")
		}
	default:
		return badRequest("Empfänger: „benutzer“ oder „gruppe“.")
	}
	p.sms = &sp
	return nil
}

// smsCreate: Passwort verschlüsseln und SMS-Spalten anlegen (in der
// Transaktion von handleChannelCreate).
func (s *Server) smsCreate(ctx context.Context, tx pgx.Tx, id, tid string, p parsedChannel, in channelIn,
	details map[string]any) error {
	if in.Password == nil || *in.Password == "" {
		return badRequest("Passwort des API-Benutzers fehlt.")
	}
	enc, err := auth.Seal(s.boxKey, []byte(*in.Password), smsAAD(id, tid, p.server, p.sms.user, p.sms.pin))
	if err != nil {
		return err
	}
	enabled := in.Aktiv == nil || *in.Aktiv
	if _, err := tx.Exec(ctx, `INSERT INTO openwacht.alert_channels
			(id, tenant_id, name, kind, server, token_enc, include_children, enabled,
			 sms_user, sms_pin, sms_target, sms_group, sms_ring, sms_watch)
		VALUES ($1, $2, $3, 'sms', $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12, $13)`,
		id, tid, p.name, p.server, enc, in.Untermandanten, enabled,
		p.sms.user, p.sms.pin, p.sms.target, p.sms.group, p.sms.ring, p.sms.watch); err != nil {
		return err
	}
	smsDetails(details, p)
	if p.sms.target == smsToUsers && in.Empfaenger != nil {
		if err := setRecipients(ctx, tx, id, tid, *in.Empfaenger); err != nil {
			return err
		}
		details["empfaenger"] = len(uniq(*in.Empfaenger))
	}
	return nil
}

// smsDetails: Audit ohne Passwort und ohne Nummern.
func smsDetails(details map[string]any, p parsedChannel) {
	details["gateway"], details["benutzer"], details["fingerabdruck"] = p.server, p.sms.user, p.sms.pin
	details["empfaenger_art"], details["anrufen"], details["ueberwachen"] = p.sms.target, p.sms.ring, p.sms.watch
	if p.sms.group != "" {
		details["gruppe"] = p.sms.group
	}
}

// smsUpdate: Ändern; neues Gateway, neuer Benutzer oder neuer Fingerabdruck
// nur mit neuem Passwort.
func (s *Server) smsUpdate(ctx context.Context, tx pgx.Tx, id, tenant string, p parsedChannel, in channelIn,
	details map[string]any) error {
	var oldServer, oldUser, oldPin string
	if err := tx.QueryRow(ctx, `SELECT server, sms_user, sms_pin FROM openwacht.alert_channels WHERE id = $1`, id).
		Scan(&oldServer, &oldUser, &oldPin); err != nil {
		return err
	}
	newPass := in.Password != nil && *in.Password != ""
	if !newPass && (oldServer != p.server || oldUser != p.sms.user || oldPin != p.sms.pin) {
		return badRequest("Bei neuem Gateway, Benutzer oder Fingerabdruck bitte das Passwort neu eingeben.")
	}
	enabled := in.Aktiv == nil || *in.Aktiv
	q := `UPDATE openwacht.alert_channels SET name = $2, include_children = $3, enabled = $4, server = $5,
		sms_user = $6, sms_pin = $7, sms_target = $8, sms_group = nullif($9, ''), sms_ring = $10, sms_watch = $11`
	args := []any{id, p.name, in.Untermandanten, enabled, p.server, p.sms.user, p.sms.pin, p.sms.target, p.sms.group,
		p.sms.ring, p.sms.watch}
	if newPass {
		enc, err := auth.Seal(s.boxKey, []byte(*in.Password), smsAAD(id, tenant, p.server, p.sms.user, p.sms.pin))
		if err != nil {
			return err
		}
		q += `, token_enc = $12`
		args = append(args, enc)
		details["passwort_geaendert"] = true
	}
	if _, err := tx.Exec(ctx, q+` WHERE id = $1`, args...); err != nil {
		return err
	}
	smsDetails(details, p)
	if p.sms.target == smsToUsers && in.Empfaenger != nil {
		if err := setRecipients(ctx, tx, id, tenant, *in.Empfaenger); err != nil {
			return err
		}
		details["empfaenger"] = len(uniq(*in.Empfaenger))
	}
	return nil
}

// --- Fingerabdruck holen ---------------------------------------------------------

// handleSMSFingerprint: TLS-Handshake mit dem Gateway, ohne Anfrage und ohne
// Zugangsdaten. Nur Admins des Mandanten, nur freigegebene Ziele, höchstens
// alle 10 Sekunden je Person.
func (s *Server) handleSMSFingerprint(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Server string `json:"server"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var admin bool
	if err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, tid).Scan(&admin)
	}); err != nil {
		writeDBError(w, "sms fingerabdruck", err)
		return
	}
	if !admin {
		writeError(w, http.StatusNotFound, "Nicht gefunden.")
		return
	}
	gw, err := alarm.NormalizeGateway(in.Server)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Gateway: "+err.Error()+".")
		return
	}
	if !s.alertTargets.AllowedURL(alarm.SMSEndpoint(gw)) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Das Gateway %s ist nicht als Alarmziel freigegeben. Freigegeben: %s.", gw, s.targetsHint()))
		return
	}
	if !s.alertTestLimit.allow("smspin:"+sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Gerade erst abgefragt. Bitte einen Moment warten.")
		return
	}
	pin, err := s.alertSender.SMSFingerprint(ctx, gw)
	bg := context.WithoutCancel(ctx)
	if e := s.withUser(bg, sess.UserID, func(tx pgx.Tx) error {
		return audit(bg, tx, &tid, "alarmkanal.sms_fingerabdruck", map[string]any{"gateway": gw, "erfolg": err == nil})
	}); e != nil {
		slog.Warn("Alarme: Audit für Fingerabdruck fehlgeschlagen", "fehler", e)
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error()+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gateway": gw, "fingerabdruck": pin, "anzeige": formatPin(pin)})
}

// formatPin: AB:CD:… zum Vergleich mit der Anzeige des Gateways.
func formatPin(pin string) string {
	h := strings.ToUpper(pin)
	var sb strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// --- Mobilnummer am eigenen Konto ------------------------------------------------

// handleMyAlertMobile: GET liefert die eigene Nummer, PUT setzt oder
// entfernt sie ({"nummer": ""}). Im Audit steht nur, ob eine Nummer gesetzt ist.
func (s *Server) handleMyAlertMobileGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "mobilnummer", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var n *string
		if err := tx.QueryRow(ctx, `SELECT openwacht.my_alert_mobile()`).Scan(&n); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"nummer": n}, nil
	})
}

func (s *Server) handleMyAlertMobilePut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Nummer *string `json:"nummer"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Nummer == nil {
		writeError(w, http.StatusBadRequest, "Feld „nummer“ fehlt.")
		return
	}
	var num *string
	if strings.TrimSpace(*in.Nummer) != "" {
		n, ok := alarm.NormalizeMobile(*in.Nummer)
		if !ok {
			writeError(w, http.StatusBadRequest, "Mobilnummer bitte international (z. B. +49 170 1234567) oder als 0170 1234567.")
			return
		}
		num = &n
	}
	if sessionFrom(r.Context()).APIToken {
		writeError(w, http.StatusForbidden, "Mit einem API-Token nicht möglich.")
		return
	}
	s.handle(w, r, "mobilnummer", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `SELECT openwacht.set_alert_mobile($1)`, num); err != nil {
			return 0, nil, err
		}
		// Audit beim Heimatmandanten, ohne die Nummer.
		var home string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.users WHERE id = openwacht.current_user_id()`).Scan(&home); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &home, "konto.mobilnummer", map[string]any{"gesetzt": num != nil}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"nummer": num}, nil
	})
}

// --- Versand ---------------------------------------------------------------------

type smsChannel struct {
	cfg    alarm.SMSConfig
	target string
	group  string
	ring   bool
	to     []alarm.SMSTarget
}

// loadSMS: Zugang und Empfänger eines SMS-Kanals.
func (s *Server) loadSMS(ctx context.Context, ch sendChannel) (*smsChannel, error) {
	c := &smsChannel{}
	var group *string
	if err := s.pool.QueryRow(ctx, `SELECT sms_user, sms_pin, sms_target, sms_group, sms_ring
		FROM openwacht.alert_sms_channels(ARRAY[$1::uuid])`, ch.id).
		Scan(&c.cfg.User, &c.cfg.Pin, &c.target, &group, &c.ring); err != nil {
		return nil, err
	}
	pass, err := auth.Open(s.boxKey, ch.tokenEnc, smsAAD(ch.id, ch.tenantID, ch.server, c.cfg.User, c.cfg.Pin))
	if err != nil {
		return nil, errors.New("Passwort des Gateways nicht entschlüsselbar, bitte neu eingeben")
	}
	c.cfg.Gateway, c.cfg.Password = ch.server, string(pass)
	if c.target == smsToGroup && group != nil {
		c.group = *group
		c.to = []alarm.SMSTarget{{Mode: alarm.SMSModeGroup, To: *group}}
		return c, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT mobile FROM openwacht.alert_sms_recipients(ARRAY[$1::uuid])`, ch.id)
	if err != nil {
		return nil, err
	}
	nums, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, n := range nums {
		c.to = append(c.to, alarm.SMSTarget{Mode: alarm.SMSModeNumber, To: n})
	}
	return c, nil
}

var errNoSMSReceivers = errors.New("Kein Empfänger des Kanals hat eine Mobilnummer für Alarme hinterlegt")

// sendSMSAll schickt text an alle Empfänger. Ergebnis: wie viele gingen,
// und ein Fehler, falls mindestens einer scheiterte (ohne Nummern).
func (s *Server) sendSMSAll(ctx context.Context, c *smsChannel, text string, ring bool) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	ok := 0
	var first error
	for _, t := range c.to {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			err := s.alertSender.SendSMS(ctx, c.cfg, t, text, ring)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else if first == nil {
				first = err
			}
		}()
	}
	wg.Wait()
	if first != nil {
		if len(c.to) > 1 {
			return ok, fmt.Errorf("%d von %d Empfängern nicht erreicht: %w", len(c.to)-ok, len(c.to), first)
		}
		return ok, first
	}
	return ok, nil
}

// deliverSMS: eine SMS je Empfänger für alle Ereignisse des Durchlaufs.
// Scheitert sie bei einem Teil der Empfänger, gilt sie als gemeldet (sonst
// bekämen die anderen sie im nächsten Durchlauf noch einmal) und der Fehler
// steht am Kanal.
func (s *Server) deliverSMS(ctx context.Context, ch sendChannel, list []pending, d *delivery) ([]pending, error) {
	c, err := s.loadSMS(ctx, ch)
	if err != nil {
		return nil, err
	}
	if len(c.to) == 0 {
		// Niemand mit Nummer: nichts nachzuholen (wie Mail ohne Empfänger).
		return list, nil
	}
	ring := false
	if c.ring {
		for _, p := range list {
			if p.item.Status == alarm.Crit && p.item.Event == alarm.Problem {
				ring = true
			}
		}
	}
	sent, err := s.sendSMSAll(ctx, c, alarm.BuildSMS(ch.tenantName, d.reportsOf(list)), ring)
	if sent == 0 {
		return nil, err
	}
	return list, err
}

// sendSMSText: Test-SMS und Hinweise (ohne Anruf).
func (s *Server) sendSMSText(ctx context.Context, ch sendChannel, text string) error {
	c, err := s.loadSMS(ctx, ch)
	if err != nil {
		return err
	}
	if len(c.to) == 0 {
		return errNoSMSReceivers
	}
	_, err = s.sendSMSAll(ctx, c, text, false)
	return err
}

// --- Gateway überwachen ----------------------------------------------------------

// smsWatch: Fehlschläge in Folge je Kanal (erst ab zwei ein Hinweis, damit
// ein kurzer Aussetzer nicht meldet).
type smsWatch struct {
	mu    sync.Mutex
	fails map[string]int
	errs  map[string]string
	since map[string]time.Time
}

const smsWatchFailsNeeded = 2

// smsWatchNotices: TLS-Handshake mit jedem überwachten Gateway (ohne
// Anfrage und Zugangsdaten). Hinweis an den Mandanten des Kanals.
func (s *Server) smsWatchNotices(ctx context.Context, now time.Time) ([]Notice, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, tenant_id::text, name, server, sms_pin FROM openwacht.alert_sms_watch()`)
	if err != nil {
		return nil, err
	}
	type gw struct{ id, tenant, name, server, pin string }
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gw, error) {
		var g gw
		err := row.Scan(&g.id, &g.tenant, &g.name, &g.server, &g.pin)
		return g, err
	})
	if err != nil {
		return nil, err
	}
	w := &s.smsWatch
	w.mu.Lock()
	if w.fails == nil {
		w.fails, w.errs, w.since = map[string]int{}, map[string]string{}, map[string]time.Time{}
	}
	w.mu.Unlock()
	var out []Notice
	seen := map[string]bool{}
	for _, g := range list {
		seen[g.id] = true
		err := s.alertSender.SMSReachable(ctx, g.server, g.pin)
		w.mu.Lock()
		if err == nil {
			delete(w.fails, g.id)
			delete(w.errs, g.id)
			delete(w.since, g.id)
			w.mu.Unlock()
			continue
		}
		if w.fails[g.id] == 0 {
			w.since[g.id] = now
		}
		w.fails[g.id]++
		w.errs[g.id] = err.Error()
		n, since, msg := w.fails[g.id], w.since[g.id], w.errs[g.id]
		w.mu.Unlock()
		if n < smsWatchFailsNeeded {
			continue
		}
		t := g.tenant
		out = append(out, Notice{Key: "smsgateway:" + g.id, Tenant: &t, Status: alarm.Crit,
			Title: "SMS-Gateway nicht erreichbar",
			Text: fmt.Sprintf("Das Gateway des Alarmkanals „%s“ (%s) ist seit %s nicht erreichbar: %s. Alarme per SMS kommen so nicht an.",
				alarm.Clean(g.name, 100), strings.TrimPrefix(g.server, "https://"), since.In(s.mailZone()).Format("02.01.2006 15:04"),
				alarm.Clean(msg, 200)),
			Since: &since})
	}
	w.mu.Lock()
	for id := range w.fails {
		if !seen[id] {
			delete(w.fails, id)
			delete(w.errs, id)
			delete(w.since, id)
		}
	}
	w.mu.Unlock()
	return out, nil
}
