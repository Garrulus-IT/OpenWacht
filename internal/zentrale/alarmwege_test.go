// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/alarm/smtptest"
	"github.com/garrulus-it/openwacht/internal/auth"
)

// Mail-, Webhook- und Teams-Kanäle über die API: Mandantentrennung,
// Empfänger nur mit Rolle im Mandanten, URL und Schlüssel nur verschlüsselt.
func TestAlarmwegeKanaele(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()

	// Mail mit Auswahl: nur Benutzer mit Rolle in genau diesem Mandanten.
	r := newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "mail", "name": "FW Mail", "empfaenger": []string{ids["v_fw"]}})
	expectStatus(t, "Mail anlegen", r, 201)
	mailID := r.body["id"].(string)
	for _, u := range []string{"v_lz", "v_it", "v_oa"} {
		r := newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "mail", "name": "Mail " + u, "empfaenger": []string{ids[u]}})
		expectStatus(t, "Empfänger "+u+" ohne Rolle in Fertigung", r, 400)
	}
	expectStatus(t, "Leser legt Mail an", newChannel(t, "v_lz", "Lager Nord", map[string]any{"art": "mail", "name": "x"}), 403)
	expectStatus(t, "Organisation bei Fertigung", newChannel(t, "v_oa", "Fertigung", map[string]any{"art": "mail", "name": "y"}), 403)
	expectStatus(t, "unbekannte Art", newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "fax", "name": "z"}), 400)

	ch := channels(t, "v_fw")["FW Mail"]
	if ch["typ"] != "mail" || len(ch["empfaenger"].([]any)) != 1 {
		t.Fatalf("Mail-Kanal: %v", ch)
	}
	// Mögliche Empfänger: nur Admins des Mandanten.
	r = as(t, "v_fw").do("GET", "/api/v1/mandanten/"+ids["Fertigung"]+"/alarm-empfaenger", nil)
	expectStatus(t, "Empfänger Fertigung", r, 200)
	seen := map[string]bool{}
	for _, x := range r.body["benutzer"].([]any) {
		seen[x.(map[string]any)["id"].(string)] = true
	}
	if !seen[ids["v_fw"]] || seen[ids["v_lz"]] || seen[ids["v_it"]] || seen[ids["v_oa"]] {
		t.Errorf("Empfänger: %v", r.body["benutzer"])
	}
	for _, u := range []string{"v_oa", "v_lz"} {
		expectStatus(t, u+" liest Empfänger Fertigung", as(t, u).do("GET", "/api/v1/mandanten/"+ids["Fertigung"]+"/alarm-empfaenger", nil), 404)
	}
	// RLS: Organisation sieht die Empfänger der Fertigung nicht.
	if _, ok := channels(t, "v_oa")["FW Mail"]; ok {
		t.Error("Geschwister sieht Mail-Kanal")
	}
	// Art lässt sich nicht ändern.
	expectStatus(t, "Art ändern", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+mailID,
		map[string]any{"art": "webhook", "name": "FW Mail"}), 400)
	// An alle: Auswahl wird geleert.
	expectStatus(t, "an alle", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+mailID,
		map[string]any{"name": "FW Mail", "alle_benutzer": true, "empfaenger": []string{}}), 200)
	if c := channels(t, "v_fw")["FW Mail"]; c["alle_benutzer"] != true || len(c["empfaenger"].([]any)) != 0 {
		t.Errorf("an alle: %v", c)
	}

	// Webhook: Host muss freigegeben sein; Schlüssel kommt einmal zurück.
	expectStatus(t, "Webhook fremder Host", newChannel(t, "v_fw", "Fertigung",
		map[string]any{"art": "webhook", "name": "evil", "url": "https://evil.example/hook"}), 400)
	expectStatus(t, "Webhook ohne URL", newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "webhook", "name": "leer"}), 400)
	r = newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "webhook", "name": "FW Hook", "url": "http://127.0.0.1:9/hook?sig=GEHEIM1"})
	expectStatus(t, "Webhook anlegen", r, 201)
	hookID := r.body["id"].(string)
	secret, _ := r.body["geheimnis"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("Schlüssel: %v", r.body)
	}
	r = newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "teams", "name": "FW Teams",
		"url": "https://ntfy.test.invalid:443/workflows/1/triggers/manual/paths/invoke?sig=GEHEIM2"})
	expectStatus(t, "Teams anlegen", r, 201)
	if _, ok := r.body["geheimnis"]; ok {
		t.Error("Teams bekommt einen Schlüssel")
	}
	list := as(t, "v_fw").do("GET", "/api/v1/alarm-kanaele", nil)
	for _, s := range []string{"GEHEIM1", "GEHEIM2", secret} {
		if strings.Contains(string(list.raw), s) {
			t.Errorf("%s in der Liste", s)
		}
	}
	if c := channels(t, "v_fw"); c["FW Hook"]["server"] != "http://127.0.0.1:9" || c["FW Teams"]["server"] != "https://ntfy.test.invalid" {
		t.Errorf("Ursprung: %v / %v", c["FW Hook"]["server"], c["FW Teams"]["server"])
	}
	var audits string
	owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM openwacht.audit_log WHERE details->>'id' = $1`, hookID).Scan(&audits)
	if strings.Contains(audits, "GEHEIM") || strings.Contains(audits, secret) || !strings.Contains(audits, "127.0.0.1:9") {
		t.Errorf("Audit: %s", audits)
	}
	var tok, sec []byte
	owner.QueryRow(ctx, `SELECT token_enc, secret_enc FROM openwacht.alert_channels WHERE id = $1`, hookID).Scan(&tok, &sec)
	if len(tok) == 0 || len(sec) == 0 || strings.Contains(string(tok), "GEHEIM") || strings.Contains(string(sec), "whsec") {
		t.Error("URL oder Schlüssel nicht verschlüsselt")
	}
	// Die Anwendungsrolle kann URL und Schlüssel nicht lesen.
	if _, err := pool.Exec(ctx, `SELECT secret_enc FROM openwacht.alert_channels LIMIT 1`); err == nil {
		t.Error("secret_enc für die Anwendung lesbar")
	}
	// Ändern ohne URL behält sie, eine neue URL braucht wieder die Freigabe.
	expectStatus(t, "Name ändern", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+hookID, map[string]any{"name": "FW Hook 2"}), 200)
	var tok2 []byte
	owner.QueryRow(ctx, `SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, hookID).Scan(&tok2)
	if string(tok2) != string(tok) {
		t.Error("URL ohne Angabe geändert")
	}
	expectStatus(t, "neue URL fremd", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+hookID,
		map[string]any{"name": "FW Hook 2", "url": "https://evil.example/x"}), 400)
	expectStatus(t, "Leser ändert Webhook", as(t, "v_lz").do("PUT", "/api/v1/alarm-kanaele/"+hookID, map[string]any{"name": "x"}), 404)

	// Datenbank: Art und Felder passen zusammen, auch am Code vorbei.
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, server, topic)
		VALUES ($1, 'kaputt', 'mail', 'https://x.de', 't')`, ids["Fertigung"]); err == nil {
		t.Error("Mail-Kanal mit Server angenommen")
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, server)
		VALUES ($1, 'kaputt2', 'webhook', 'https://x.de')`, ids["Fertigung"]); err == nil {
		t.Error("Webhook ohne URL angenommen")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET kind = 'ntfy' WHERE id = $1`, mailID); err == nil {
		t.Error("Art in der DB geändert")
	}
	// Teams → Webhook mit Schlüssel erfüllt den CHECK; nur der Trigger verhindert es.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET kind = 'webhook', secret_enc = token_enc
		WHERE tenant_id = $1 AND name = 'FW Teams'`, ids["Fertigung"]); err == nil || !strings.Contains(err.Error(), "unveränderlich") {
		t.Errorf("Teams zu Webhook: %v", err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channel_users (channel_id, user_id) VALUES ($1, $2)`, hookID, ids["v_fw"]); err == nil {
		t.Error("Empfänger an Webhook")
	}
}

// Rolle entziehen entfernt den Empfänger; abbestellen gilt sofort.
func TestAlarmwegeEmpfaengerUndAbbestellen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	var uid string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, 'empf@test.invalid', 'Empf')
		RETURNING id::text`, ids["Fertigung"]).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, uid) })
	owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'leser')`, uid, ids["Fertigung"])
	r := newChannel(t, "v_fw", "Fertigung", map[string]any{"art": "mail", "name": "Empf Mail", "empfaenger": []string{uid, ids["v_fw"]}})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	rcpts := func() []string {
		rows, _ := pool.Query(ctx, `SELECT email FROM openwacht.alert_mail_recipients(ARRAY[$1::uuid])`, id)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var e string
			rows.Scan(&e)
			out = append(out, e)
		}
		return out
	}
	if got := rcpts(); len(got) != 2 {
		t.Fatalf("Empfänger: %v", got)
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, uid)
	if got := rcpts(); len(got) != 1 {
		t.Errorf("gesperrter Benutzer bekommt Mails: %v", got)
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = false WHERE id = $1`, uid)
	owner.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1`, uid)
	if got := rcpts(); len(got) != 1 || got[0] != "v_fw@test.invalid" {
		t.Errorf("nach Rollenentzug: %v", got)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alert_channel_users WHERE user_id = $1`, uid).Scan(&n)
	if n != 0 {
		t.Error("Eintrag bleibt nach Rollenentzug")
	}
	// Abbestellen über die API (eigener Benutzer, auch als Leser).
	expectStatus(t, "abbestellen", as(t, "v_fw").do("PUT", "/api/v1/ich/alarm-mails", map[string]any{"an": false}), 200)
	t.Cleanup(func() { owner.Exec(ctx, `UPDATE openwacht.users SET alert_mail = true`) })
	if r := as(t, "v_fw").do("GET", "/api/v1/ich", nil); r.body["alarm_mails"] != false {
		t.Errorf("ich: %v", r.body["alarm_mails"])
	}
	if got := rcpts(); len(got) != 0 {
		t.Errorf("abbestellt, trotzdem Empfänger: %v", got)
	}
	if c := channels(t, "v_fw")["Empf Mail"]; c["empfaenger"].([]any)[0].(map[string]any)["abbestellt"] != true {
		t.Errorf("Anzeige abbestellt: %v", c["empfaenger"])
	}
	expectStatus(t, "Leser bestellt ab", as(t, "v_lz").do("PUT", "/api/v1/ich/alarm-mails", map[string]any{"an": false}), 200)
	// Nur für sich selbst: Die Funktion kennt keinen anderen Benutzer.
	var lzMail bool
	owner.QueryRow(ctx, `SELECT alert_mail FROM openwacht.users WHERE id = $1`, ids["v_lz2"]).Scan(&lzMail)
	if !lzMail {
		t.Error("anderer Benutzer abbestellt")
	}
}

// hookRecorder nimmt Webhooks an und merkt sich Kopf und Rumpf je Pfad.
type hookRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	got  map[string][]hookReq
	fail bool
}

type hookReq struct {
	header http.Header
	body   []byte
}

func newHookRecorder() *hookRecorder {
	h := &hookRecorder{got: map[string][]hookReq{}}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got[r.URL.Path] = append(h.got[r.URL.Path], hookReq{r.Header.Clone(), b})
		fail := h.fail
		h.mu.Unlock()
		if fail {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(202)
	}))
	return h
}

func (h *hookRecorder) take() map[string][]hookReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.got
	h.got = map[string][]hookReq{}
	return out
}

// Ende zu Ende: ein Check fällt aus, Mail (mit Graph), Webhook (signiert)
// und Teams melden ihn, dann die Entwarnung. Dazu Abbestellen, gestörtes
// Relay und Sammelmail.
func TestAlarmwegeVersand(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	hooks := newHookRecorder()
	defer hooks.Close()
	smtp := smtptest.Start(t, false, "relay", "relay-pass")
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(hooks.URL)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MaintainMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	setSMTP := func(port int) {
		t.Helper()
		enc, _ := auth.Seal(s.smtpKey(), []byte("relay-pass"), smtpAAD("127.0.0.1", "relay"))
		if _, err := owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = '127.0.0.1', smtp_port = $1, smtp_tls = 'starttls',
			smtp_from = 'openwacht@test.invalid', smtp_user = 'relay', smtp_pass_enc = $2, smtp_ca = $3`, port, enc, smtp.CAPEM); err != nil {
			t.Fatal(err)
		}
		if err := s.ReloadSettings(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL, smtp_from = NULL,
			smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
	})

	var tid, uid, dev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Wege A') RETURNING id::text`, ids["IT"]).Scan(&tid)
	owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, 'wege@test.invalid', 'Wege')
		RETURNING id::text`, tid).Scan(&uid)
	owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'leser')`, uid, tid)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'wege-router') RETURNING id::text`, tid).Scan(&dev)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, uid)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tid)
	})
	check := func(name string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, $2, 'ping', '{"host":"x.lan"}', 60) RETURNING id::text`, dev, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	c1 := check("Ping")
	// Verlauf für den Graphen: Antwortzeiten der letzten Stunden.
	for i := 1; i <= 12; i++ {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.metrics_check_raw (tenant_id, check_id, ts, status, ms)
			VALUES ($1, $2, now() - make_interval(mins => $3), 'ok', $4)`, tid, c1, i*20, float64(10+i)); err != nil {
			t.Fatal(err)
		}
	}
	record := func(id, status, msg string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, $3, '', NULL)`, id, status, msg).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	mk := func(body map[string]any) (string, map[string]any) {
		t.Helper()
		id, _ := newUUID()
		var tokenEnc, secEnc []byte
		server := ""
		kind := body["art"].(string)
		var sec string
		if u, ok := body["url"].(string); ok {
			full, origin, _ := alarm.NormalizeHookURL(u)
			server = origin
			tokenEnc, _ = auth.Seal(s.boxKey, []byte(full), channelAAD(id, tid, server))
		}
		if kind == kindWebhook {
			sec, _ = alarm.NewHookSecret()
			secEnc, _ = auth.Seal(s.boxKey, []byte(sec), hookSecretAAD(id, tid))
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, kind, server, token_enc, secret_enc, all_users)
			VALUES ($1, $2, $3, $4, nullif($5, ''), $6, $7, $8)`, id, tid, body["name"], kind, server, tokenEnc, secEnc, kind == kindMail); err != nil {
			t.Fatal(err)
		}
		return id, map[string]any{"secret": sec}
	}
	mailCh, _ := mk(map[string]any{"art": kindMail, "name": "Wege Mail"})
	_, hk := mk(map[string]any{"art": kindWebhook, "name": "Wege Hook", "url": hooks.URL + "/hook"})
	mk(map[string]any{"art": kindTeams, "name": "Wege Teams", "url": hooks.URL + "/teams?sig=s3cr3t"})

	round := func(what string) (int, int) {
		t.Helper()
		sent, failed, err := s.alertRoundR(ctx)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return sent, failed
	}

	// Ohne SMTP-Einstellung: Mail-Kanal gestört, die anderen melden.
	record(c1, "crit", "keine Antwort")
	record(c1, "crit", "keine Antwort")
	if _, failed := round("ohne SMTP"); failed != 1 {
		t.Errorf("ohne SMTP: %d gescheitert, erwartet 1", failed)
	}
	var lastErr *string
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.alert_channels WHERE id = $1`, mailCh).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "nicht eingerichtet") {
		t.Errorf("Fehler am Kanal: %v", lastErr)
	}
	got := hooks.take()
	if len(got["/hook"]) != 1 || len(got["/teams"]) != 1 {
		t.Fatalf("Webhooks: %v", got)
	}
	h := got["/hook"][0]
	if !alarm.VerifyHookSignature(hk["secret"].(string), h.header.Get("webhook-id"), h.header.Get("webhook-timestamp"),
		h.header.Get("webhook-signature"), h.body, time.Now(), time.Minute) {
		t.Error("Signatur ungültig")
	}
	var p alarm.HookPayload
	if err := json.Unmarshal(h.body, &p); err != nil || len(p.Events) != 1 {
		t.Fatalf("Rumpf: %s", h.body)
	}
	if e := p.Events[0]; e.Event != "problem" || e.Status != "crit" || e.Device != "wege-router" || e.Sensor != "Ping" ||
		e.Since == nil || !strings.Contains(e.Link, "/hosts?geraet="+dev) {
		t.Errorf("Ereignis: %+v", e)
	}
	if tb := string(got["/teams"][0].body); !strings.Contains(tb, "KRIT · wege\\\\-router · Ping") || got["/teams"][0].header.Get("webhook-signature") != "" {
		t.Errorf("Teams: %s", tb)
	}

	// Mit SMTP: Die Mail kommt nach, mit Graph; Webhooks melden nicht doppelt.
	setSMTP(smtp.Port)
	if _, failed := round("mit SMTP"); failed != 0 {
		t.Errorf("mit SMTP gescheitert: %d", failed)
	}
	msgs := smtp.Messages()
	if len(msgs) != 1 || len(msgs[0].To) != 1 || msgs[0].To[0] != "wege@test.invalid" {
		t.Fatalf("Mails: %+v", msgs)
	}
	if d := msgs[0].Data; !strings.Contains(d, "image/png") || !strings.Contains(d, "Subject: =?utf-8?q?KRIT_=C2=B7_wege-router_=C2=B7_Ping") {
		t.Errorf("Mail:\n%.600s", d)
	}
	if len(hooks.take()) != 0 {
		t.Error("Webhook doppelt")
	}

	// Entwarnung an alle; danach abbestellt: keine Mail mehr.
	record(c1, "ok", "")
	round("Entwarnung")
	if msgs := smtp.Messages(); len(msgs) != 2 || !strings.Contains(msgs[1].Data, "=?utf-8?q?OK_=C2=B7") {
		t.Errorf("Entwarnung per Mail fehlt: %d", len(msgs))
	}
	if got := hooks.take(); len(got["/hook"]) != 1 || len(got["/teams"]) != 1 {
		t.Errorf("Entwarnung Webhooks: %v", got)
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET alert_mail = false WHERE id = $1`, uid)
	record(c1, "crit", "x")
	record(c1, "crit", "x")
	round("abbestellt")
	if len(smtp.Messages()) != 2 {
		t.Error("Mail trotz Abbestellen")
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET alert_mail = true WHERE id = $1`, uid)
	record(c1, "ok", "")
	round("wieder an")
	hooks.take()

	// Relay gestört: Kanal meldet den Fehler, nach der Reparatur kommt die Mail.
	setSMTP(1)
	record(c1, "crit", "y")
	record(c1, "crit", "y")
	if _, failed := round("Relay weg"); failed != 1 {
		t.Errorf("Relay weg: %d gescheitert", failed)
	}
	n := len(smtp.Messages())
	setSMTP(smtp.Port)
	round("Relay zurück")
	if len(smtp.Messages()) != n+1 {
		t.Error("Mail nicht nachgeholt")
	}

	// Viele Ereignisse: eine Sammelmail statt einzelner.
	var many []string
	for i := 0; i < alarm.SummaryLimit; i++ {
		many = append(many, check("Port "+string(rune('a'+i))))
	}
	for _, id := range many {
		record(id, "crit", "zu")
		record(id, "crit", "zu")
	}
	n = len(smtp.Messages())
	hooks.take()
	round("Sammelmail")
	msgs = smtp.Messages()
	if len(msgs) != n+1 || !strings.Contains(msgs[n].Data, "Probleme") || strings.Contains(msgs[n].Data, "image/png") {
		t.Errorf("Sammelmail: %d neue", len(msgs)-n)
	}
	var p2 alarm.HookPayload
	if got := hooks.take(); len(got["/hook"]) != 1 || json.Unmarshal(got["/hook"][0].body, &p2) != nil || len(p2.Events) != alarm.SummaryLimit {
		t.Errorf("Webhook bei vielen Ereignissen: %d", len(p2.Events))
	}
}

// SMTP-Einstellung: nur Betreiber, mit Code, Passwort nie lesbar und an
// Server und Benutzer gebunden.
func TestAlarmwegeMailEinstellung(t *testing.T) {
	s, srv := settingsServer(t, Config{})
	resetSettings(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL, smtp_from = NULL,
			smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
		resetSettings(t)
	})
	smtp := smtptest.Start(t, false, "relay", "Relay-Pw-123")
	in := map[string]any{"server": "127.0.0.1", "port": smtp.Port, "tls": "starttls", "absender": "openwacht@test.invalid",
		"benutzer": "relay", "passwort": "Relay-Pw-123", "ca": smtp.CAPEM}
	it := loginOn(t, srv, "v_it")
	expectStatus(t, "Nicht-Betreiber", it.do("PUT", "/api/v1/einstellungen/mail", in), 403)
	setOperator(t, "v_it", true)
	expectStatus(t, "ohne Code", it.do("PUT", "/api/v1/einstellungen/mail", in), 403)
	in["code"] = freshCode(t, "v_it")
	expectStatus(t, "speichern", it.do("PUT", "/api/v1/einstellungen/mail", in), 200)
	if s.mailConfig() == nil || s.mailConfig().Pass != "Relay-Pw-123" {
		t.Fatal("nicht übernommen")
	}
	r := it.do("GET", "/api/v1/einstellungen/mail", nil)
	if strings.Contains(string(r.raw), "Relay-Pw") || r.body["passwort_gesetzt"] != true {
		t.Errorf("GET: %s", r.raw)
	}
	var audits string
	owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM openwacht.audit_log WHERE action = 'einstellungen.geaendert'`).Scan(&audits)
	if strings.Contains(audits, "Relay-Pw") || !strings.Contains(audits, `"passwort": "geändert"`) {
		t.Errorf("Audit: %s", audits)
	}
	// Testmail an den Betreiber selbst.
	expectStatus(t, "Testmail", it.do("POST", "/api/v1/einstellungen/mail/test", nil), 200)
	if m := smtp.Messages(); len(m) != 1 || m[0].To[0] != "v_it@test.invalid" {
		t.Errorf("Testmail: %+v", m)
	}
	// Neuer Server ohne Passwort: abgelehnt (Passwort geht nie an einen anderen).
	delete(in, "passwort")
	in["server"], in["code"] = "localhost", freshCode(t, "v_it")
	expectStatus(t, "neuer Server ohne Passwort", it.do("PUT", "/api/v1/einstellungen/mail", in), 400)
	// Ungültig: Klartext zu fremdem Server, Absender mit Umbruch.
	for _, bad := range []map[string]any{
		{"server": "mail.example.de", "port": 25, "tls": "keine", "absender": "a@b.de"},
		{"server": "127.0.0.1", "port": 25, "tls": "starttls", "absender": "a@b.de\r\nBcc: x@y"},
	} {
		bad["code"] = "000000"
		expectStatus(t, "ungültig", it.do("PUT", "/api/v1/einstellungen/mail", bad), 400)
	}
	// Ausschalten.
	expectStatus(t, "aus", it.do("PUT", "/api/v1/einstellungen/mail", map[string]any{"aus": true, "code": freshCode(t, "v_it")}), 200)
	if s.mailConfig() != nil {
		t.Error("nach „aus“ noch eingerichtet")
	}
	// Andere Admins kommen nicht heran.
	fw := loginOn(t, srv, "v_fw")
	expectStatus(t, "Fertigung liest", fw.do("GET", "/api/v1/einstellungen/mail", nil), 403)
	expectStatus(t, "Fertigung testet", fw.do("POST", "/api/v1/einstellungen/mail/test", nil), 403)
}

// 1.0.1: Mail-Kanäle mit „Sammeln“ warten ab dem ersten Ereignis ein Fenster
// lang und schicken dann eine Sammelmail; ein kurzer Aussetzer im Fenster
// meldet nichts; ohne Schalter geht die Mail sofort.
func TestAlarmwegeSammeln(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	smtp := smtptest.Start(t, false, "relay", "relay-pass")
	cfg := vServer.cfg
	cfg.AlertCollect = time.Minute
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	s.now = func() time.Time { return clock }
	enc, _ := auth.Seal(s.smtpKey(), []byte("relay-pass"), smtpAAD("127.0.0.1", "relay"))
	if _, err := owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = '127.0.0.1', smtp_port = $1, smtp_tls = 'starttls',
		smtp_from = 'openwacht@test.invalid', smtp_user = 'relay', smtp_pass_enc = $2, smtp_ca = $3`, smtp.Port, enc, smtp.CAPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	var tid, uid, dev, ch string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Sammeln S') RETURNING id::text`, ids["IT"]).Scan(&tid)
	owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, 'sammeln@test.invalid', 'Sammeln')
		RETURNING id::text`, tid).Scan(&uid)
	owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'leser')`, uid, tid)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'sammel-srv') RETURNING id::text`, tid).Scan(&dev)
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, all_users)
		VALUES ($1, 'Sammel-Mail', 'mail', true) RETURNING id::text`, tid).Scan(&ch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL, smtp_from = NULL,
			smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, uid)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tid)
	})
	var collect bool
	owner.QueryRow(ctx, `SELECT collect FROM openwacht.alert_channels WHERE id = $1`, ch).Scan(&collect)
	if !collect {
		t.Fatal("Sammeln ist für neue Kanäle nicht an")
	}
	check := func(name string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, $2, 'ping', '{"host":"x.lan"}', 60) RETURNING id::text`, dev, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	c1, c2, c3 := check("Ping A"), check("Ping B"), check("Ping C")
	record := func(id, status string) {
		t.Helper()
		for range 2 { // zwei Fehlschläge bis zum Alarm
			var ok bool
			if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, 'keine Antwort', '', NULL)`, id, status).Scan(&ok); err != nil || !ok {
				t.Fatalf("check_record: %v %v", ok, err)
			}
		}
	}
	round := func(after time.Duration) int {
		t.Helper()
		clock = clock.Add(after)
		if _, failed, err := s.alertRoundR(ctx); err != nil || failed != 0 {
			t.Fatalf("Durchlauf: %v, %d gescheitert", err, failed)
		}
		n := len(smtp.Messages())
		return n
	}

	// Zwei Probleme: erst nach einer Minute, dann eine Sammelmail.
	record(c1, "crit")
	record(c2, "warn")
	if n := round(0); n != 0 {
		t.Fatalf("sofort %d Mails, erwartet 0 (Fenster)", n)
	}
	if n := round(30 * time.Second); n != 0 {
		t.Fatalf("nach 30 s %d Mails, erwartet 0", n)
	}
	if n := round(31 * time.Second); n != 1 {
		t.Fatalf("nach 61 s %d Mails, erwartet 1", n)
	}
	// Betreff (1.0.3): schlimmster Zustand vorn; mit „·“ ist er MIME-kodiert.
	betreff := func(d string) string {
		for _, z := range strings.Split(d, "\r\n") {
			if v, ok := strings.CutPrefix(z, "Subject: "); ok {
				out, err := new(mime.WordDecoder).DecodeHeader(v)
				if err != nil {
					return v
				}
				return out
			}
		}
		return ""
	}
	if d := smtp.Messages()[0].Data; betreff(d) != "KRIT · OpenWacht: 2 Probleme" || !strings.Contains(d, "Ping A") || !strings.Contains(d, "Ping B") {
		t.Errorf("Sammelmail:\n%.800s", d)
	}
	if n := round(15 * time.Second); n != 1 {
		t.Fatalf("doppelt gemeldet: %d Mails", n)
	}

	// Entwarnungen gesammelt.
	record(c1, "ok")
	record(c2, "ok")
	round(0)
	if n := round(61 * time.Second); n != 2 {
		t.Fatalf("Entwarnung: %d Mails, erwartet 2", n)
	}
	if d := smtp.Messages()[1].Data; betreff(d) != "OK · OpenWacht: 2 wieder OK" {
		t.Errorf("Entwarnungsmail:\n%.800s", d)
	}

	// Aussetzer innerhalb des Fensters: keine Mail.
	record(c3, "crit")
	round(0)
	record(c3, "ok")
	if n := round(61 * time.Second); n != 2 {
		t.Fatalf("Aussetzer gemeldet: %d Mails, erwartet 2", n)
	}

	// Schalter aus: sofort einzeln.
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET collect = false WHERE id = $1`, ch)
	record(c3, "crit")
	if n := round(0); n != 3 {
		t.Fatalf("ohne Sammeln: %d Mails, erwartet 3", n)
	}

	// Schalter über die API (Admin des Mandanten; an einem Kanal der Fertigung,
	// weil der Audit-Eintrag den Mandanten festhält).
	var fwCh, hookCh string
	owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, all_users)
		VALUES ($1, 'Sammel-API', 'mail', true) RETURNING id::text`, ids["Fertigung"]).Scan(&fwCh)
	if hookErr := owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, server, token_enc)
		VALUES ($1, 'Sammel-Teams', 'teams', 'https://hook.test.invalid', decode(repeat('00', 32), 'hex')) RETURNING id::text`,
		ids["Fertigung"]).Scan(&hookCh); hookErr != nil {
		t.Fatalf("Teams-Kanal: %v", hookErr)
	}
	if fwCh == "" || hookCh == "" {
		t.Fatal("Kanäle der Fertigung nicht angelegt")
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = ANY($1::uuid[])`, []string{fwCh, hookCh})
	})
	put := func(user, id string, on bool) response {
		return as(t, user).do("PUT", "/api/v1/alarm-kanaele/"+id+"/zustellung", map[string]any{"sammeln": on})
	}
	expectStatus(t, "Leser schaltet", put("v_lz", fwCh, false), 404)
	expectStatus(t, "Geschwister schaltet", put("v_oa", fwCh, false), 404)
	if r := put("v_fw", hookCh, true); r.status != 400 || !strings.Contains(r.raw, "nur für Mail- und SMS") {
		t.Errorf("Teams sammelt: %d %s", r.status, r.raw)
	}
	expectStatus(t, "Admin schaltet aus", put("v_fw", fwCh, false), 200)
	if r := as(t, "v_fw").do("GET", "/api/v1/alarm-kanaele?mandant="+ids["Fertigung"], nil); !strings.Contains(r.raw, `"sammeln":false`) {
		t.Errorf("Liste zeigt den Schalter nicht: %s", r.raw)
	}
	// ohne Feld „sammeln“ bleibt der Schalter, wie er ist
	expectStatus(t, "ohne Feld", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+fwCh+"/zustellung", map[string]any{}), 200)
	var on bool
	owner.QueryRow(ctx, `SELECT collect FROM openwacht.alert_channels WHERE id = $1`, fwCh).Scan(&on)
	if on {
		t.Error("PUT ohne Feld hat den Schalter verändert")
	}
}
