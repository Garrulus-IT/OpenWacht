// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/alarm/brevistest"
	"github.com/garrulus-it/openwacht/internal/auth"
)

// smsGateway startet eine Attrappe und gibt sie am gemeinsamen Testserver
// als Alarmziel frei (danach wieder zurück).
func smsGateway(t *testing.T) (*brevistest.Fake, *brevistest.Server) {
	t.Helper()
	verwaltungSetup(t)
	f := brevistest.NewFake()
	srv := brevistest.Start(t, f)
	old := vServer.alertTargets.List()
	vServer.alertTargets.Set(alarm.NewTargets(append(append([]string(nil), old...), srv.Gateway)...))
	t.Cleanup(func() {
		vServer.alertTargets.Set(alarm.NewTargets(old...))
		resetAlertTestLimit(vServer)
	})
	resetAlertTestLimit(vServer)
	return f, srv
}

func resetAlertTestLimit(s *Server) {
	s.alertTestLimit.mu.Lock()
	s.alertTestLimit.last = nil
	s.alertTestLimit.mu.Unlock()
}

func smsBody(srv *brevistest.Server, extra map[string]any) map[string]any {
	b := map[string]any{"art": "sms", "name": "SMS", "server": srv.Gateway, "sms_benutzer": brevistest.User,
		"passwort": brevistest.Password, "fingerabdruck": srv.Pin, "empfaenger_art": "gruppe", "gruppe": "Bereitschaft"}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func setMobile(t *testing.T, user, number string) {
	t.Helper()
	expectStatus(t, "Mobilnummer "+user, as(t, user).do("PUT", "/api/v1/ich/alarm-mobilnummer", map[string]any{"nummer": number}), 200)
}

// Anlegen, Sehen, Ändern: Mandantentrennung, Prüfungen, Geheimnisse.
func TestSMSKanal(t *testing.T) {
	f, srv := smsGateway(t)
	ctx := context.Background()
	t.Cleanup(func() { owner.Exec(ctx, `UPDATE openwacht.users SET alert_mobile = NULL`) })

	// Fingerabdruck holen: nur Admins des Mandanten, nur freigegebene Ziele.
	path := "/api/v1/mandanten/" + ids["Fertigung"] + "/alarm-kanaele/sms-fingerabdruck"
	r := as(t, "v_fw").do("POST", path, map[string]any{"server": strings.TrimPrefix(srv.Gateway, "https://")})
	expectStatus(t, "Fingerabdruck", r, 200)
	if r.body["fingerabdruck"] != srv.Pin || r.body["gateway"] != srv.Gateway || !strings.Contains(r.body["anzeige"].(string), ":") {
		t.Errorf("Fingerabdruck: %v", r.body)
	}
	expectStatus(t, "gleich nochmal", as(t, "v_fw").do("POST", path, map[string]any{"server": srv.Gateway}), 429)
	resetAlertTestLimit(vServer)
	expectStatus(t, "fremdes Gateway", as(t, "v_fw").do("POST", path, map[string]any{"server": "https://sms.example"}), 400)
	expectStatus(t, "http", as(t, "v_fw").do("POST", path, map[string]any{"server": "http://127.0.0.1:1"}), 400)
	for _, u := range []string{"v_oa", "v_lz"} {
		expectStatus(t, u+" holt Fingerabdruck für Fertigung", as(t, u).do("POST", path, map[string]any{"server": srv.Gateway}), 404)
	}
	expectStatus(t, "Leser im eigenen Mandanten", as(t, "v_lz").do("POST",
		"/api/v1/mandanten/"+ids["Lager Nord"]+"/alarm-kanaele/sms-fingerabdruck", map[string]any{"server": srv.Gateway}), 404)
	if len(f.Requests()) != 0 {
		t.Fatal("Fingerabdruck hat eine Anfrage gesendet")
	}

	// Ungültige Eingaben.
	bad := map[string]map[string]any{
		"ohne Passwort":   {"passwort": nil},
		"admin":           {"sms_benutzer": "admin"},
		"fremdes Gateway": {"server": "https://sms.example"},
		"http":            {"server": strings.Replace(srv.Gateway, "https", "http", 1)},
		"Pfad":            {"server": srv.Gateway + "/x"},
		"Fingerabdruck":   {"fingerabdruck": "abc"},
		"Gruppe":          {"gruppe": "a&to=0170"},
		"Empfängerart":    {"empfaenger_art": "nummern"},
		"zu viele": {"empfaenger_art": "benutzer", "empfaenger": func() []string {
			var l []string
			for i := 0; i < 21; i++ {
				l = append(l, ids["v_fw"])
			}
			return l
		}()},
		"ohne Rolle": {"empfaenger_art": "benutzer", "empfaenger": []string{ids["v_lz"]}},
	}
	for name, extra := range bad {
		b := smsBody(srv, extra)
		if v, ok := extra["passwort"]; ok && v == nil {
			delete(b, "passwort")
		}
		expectStatus(t, "anlegen: "+name, newChannel(t, "v_fw", "Fertigung", b), 400)
	}
	expectStatus(t, "Leser legt an", newChannel(t, "v_lz", "Lager Nord", smsBody(srv, nil)), 403)
	expectStatus(t, "Geschwister legt an", newChannel(t, "v_oa", "Fertigung", smsBody(srv, nil)), 403)

	r = newChannel(t, "v_fw", "Fertigung", smsBody(srv, map[string]any{"name": "FW SMS", "anrufen": true, "ueberwachen": true}))
	expectStatus(t, "Gruppe anlegen", r, 201)
	groupID := r.body["id"].(string)
	r = newChannel(t, "v_fw", "Fertigung", smsBody(srv, map[string]any{"name": "FW SMS Personen", "empfaenger_art": "benutzer",
		"empfaenger": []string{ids["v_fw"]}}))
	expectStatus(t, "Benutzer anlegen", r, 201)
	usersID := r.body["id"].(string)
	expectStatus(t, "Eltern legen an", newChannel(t, "v_it", "Fertigung", smsBody(srv, map[string]any{"name": "IT für FW"})), 201)

	// Sehen: eigener Mandant und Eltern, nicht Geschwister oder Kinder.
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := channels(t, user)["FW SMS"]; got != want {
			t.Errorf("%s sieht SMS-Kanal: %v, erwartet %v", user, got, want)
		}
	}
	c := channels(t, "v_fw")["FW SMS"]
	if c["typ"] != "sms" || c["server"] != srv.Gateway || c["sms_benutzer"] != brevistest.User || c["fingerabdruck"] != srv.Pin ||
		c["gruppe"] != "Bereitschaft" || c["anrufen"] != true || c["ueberwachen"] != true || c["empfaenger_art"] != "gruppe" {
		t.Errorf("Kanal: %v", c)
	}
	list := as(t, "v_it").do("GET", "/api/v1/alarm-kanaele", nil)
	var audits string
	owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM openwacht.audit_log WHERE action LIKE 'alarmkanal.%'`).Scan(&audits)
	for _, where := range []string{string(list.raw), audits} {
		if strings.Contains(where, brevistest.Password) {
			t.Error("Passwort in Liste oder Audit")
		}
	}
	if !strings.Contains(audits, "alarmkanal.sms_fingerabdruck") && !strings.Contains(audits, srv.Gateway) {
		t.Error("Abruf des Fingerabdrucks nicht im Audit")
	}
	// Die Anwendungsrolle liest weder Passwort noch Mobilnummern.
	for _, q := range []string{`SELECT token_enc FROM openwacht.alert_channels LIMIT 1`, `SELECT alert_mobile FROM openwacht.users LIMIT 1`} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("für die Anwendung lesbar: %s", q)
		}
	}
	var enc []byte
	owner.QueryRow(ctx, `SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, groupID).Scan(&enc)
	if pt, err := auth.Open(vServer.boxKey, enc, smsAAD(groupID, ids["Fertigung"], srv.Gateway, brevistest.User, srv.Pin)); err != nil ||
		string(pt) != brevistest.Password {
		t.Fatalf("Passwort nicht an Gateway, Benutzer und Fingerabdruck gebunden: %v", err)
	}
	if _, err := auth.Open(vServer.boxKey, enc, smsAAD(groupID, ids["Fertigung"], srv.Gateway, brevistest.User, strings.Repeat("0", 64))); err == nil {
		t.Error("Passwort mit anderem Fingerabdruck lesbar")
	}

	// Ändern: neues Gateway, neuer Benutzer oder Fingerabdruck nur mit Passwort.
	upd := func(extra map[string]any) map[string]any {
		b := smsBody(srv, extra)
		delete(b, "passwort")
		if p, ok := extra["passwort"]; ok {
			b["passwort"] = p
		}
		b["name"] = "FW SMS"
		return b
	}
	other := brevistest.Start(t, brevistest.NewFake())
	r = as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+groupID, upd(map[string]any{"fingerabdruck": other.Pin}))
	if r.status != 400 || !strings.Contains(r.raw, "Passwort neu eingeben") {
		t.Errorf("neuer Fingerabdruck ohne Passwort: %d %s", r.status, r.raw)
	}
	expectStatus(t, "neuer Benutzer ohne Passwort", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+groupID,
		upd(map[string]any{"sms_benutzer": "anderer"})), 400)
	expectStatus(t, "Name und Anruf ändern", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+groupID,
		upd(map[string]any{"anrufen": false})), 200)
	var enc2 []byte
	owner.QueryRow(ctx, `SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, groupID).Scan(&enc2)
	if string(enc2) != string(enc) {
		t.Error("Passwort ohne Angabe geändert")
	}
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/alarm-kanaele/"+groupID, upd(nil)), 404)
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+groupID, upd(nil)), 404)
	expectStatus(t, "Art ändern", as(t, "v_fw").do("PUT", "/api/v1/alarm-kanaele/"+groupID,
		map[string]any{"art": "mail", "name": "FW SMS"}), 400)

	// Datenbank am Code vorbei: kein admin, kein Fingerabdruck ohne Passwort.
	// Mit neuem Passwort, damit nur die Prüfung auf admin greift.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_user = 'Admin', token_enc = $2 WHERE id = $1`, groupID,
		mustSeal(t, vServer.boxKey, "x", smsAAD(groupID, ids["Fertigung"], srv.Gateway, "Admin", srv.Pin))); err == nil {
		t.Error("admin in der DB angenommen")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_pin = $2 WHERE id = $1`, groupID, other.Pin); err == nil {
		t.Error("neuer Fingerabdruck behält das Passwort")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET server = 'https://sms.example' WHERE id = $1`, groupID); err == nil {
		t.Error("neues Gateway behält das Passwort")
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, server, token_enc, sms_user, sms_pin, sms_target)
		VALUES ($1, 'kaputt', 'sms', 'https://sms.example', $2, 'x', $3, 'gruppe')`, ids["Fertigung"], enc, srv.Pin); err == nil {
		t.Error("Gruppe ohne Namen angenommen")
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, sms_ring) VALUES ($1, 'Mail mit Anruf', 'mail', true)`,
		ids["Fertigung"]); err == nil {
		t.Error("SMS-Felder an einem Mail-Kanal")
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channel_users (channel_id, user_id) VALUES ($1, $2)`, groupID, ids["v_fw"]); err == nil {
		t.Error("Benutzer an einem Gruppen-Kanal")
	}

	// Mobilnummer: nur die eigene, im Audit ohne Nummer.
	expectStatus(t, "ungültige Nummer", as(t, "v_fw").do("PUT", "/api/v1/ich/alarm-mobilnummer", map[string]any{"nummer": "123"}), 400)
	expectStatus(t, "Nummer fehlt", as(t, "v_fw").do("PUT", "/api/v1/ich/alarm-mobilnummer", map[string]any{}), 400)
	setMobile(t, "v_fw", "0170 1234567")
	if r := as(t, "v_fw").do("GET", "/api/v1/ich/alarm-mobilnummer", nil); r.body["nummer"] != "+491701234567" {
		t.Errorf("eigene Nummer: %v", r.body)
	}
	if r := as(t, "v_it").do("GET", "/api/v1/ich/alarm-mobilnummer", nil); r.body["nummer"] != nil {
		t.Errorf("Nummer eines anderen sichtbar: %v", r.body)
	}
	owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM openwacht.audit_log WHERE action = 'konto.mobilnummer'`).Scan(&audits)
	if audits == "" || strings.Contains(audits, "1234567") {
		t.Errorf("Audit Mobilnummer: %q", audits)
	}
	// Admins sehen nur, ob eine Nummer da ist.
	r = as(t, "v_fw").do("GET", "/api/v1/mandanten/"+ids["Fertigung"]+"/alarm-empfaenger", nil)
	if strings.Contains(string(r.raw), "1234567") || !strings.Contains(string(r.raw), `"mobilnummer":true`) {
		t.Errorf("Kandidaten: %s", r.raw)
	}
	if strings.Contains(string(as(t, "v_it").do("GET", "/api/v1/alarm-kanaele", nil).raw), "1234567") {
		t.Error("Nummer in der Kanalliste")
	}
	if c := channels(t, "v_fw")["FW SMS Personen"]; c["empfaenger"].([]any)[0].(map[string]any)["mobilnummer"] != true {
		t.Errorf("Empfänger ohne Kennzeichen: %v", c["empfaenger"])
	}

	// Test senden: an die Nummer bzw. die Gruppe, immer POST.
	f.Reset()
	expectStatus(t, "Test an Benutzer", as(t, "v_fw").do("POST", "/api/v1/alarm-kanaele/"+usersID+"/test", nil), 200)
	expectStatus(t, "Test an Gruppe", as(t, "v_fw").do("POST", "/api/v1/alarm-kanaele/"+groupID+"/test", nil), 200)
	sent := f.Sent()
	if len(sent) != 2 || sent[0].To != "00491701234567" || sent[0].Mode != "number" || sent[1].Mode != "group" ||
		sent[1].To != "Bereitschaft" || !strings.Contains(sent[0].Text, "Test des Alarmkanals") {
		t.Fatalf("Test-SMS: %+v", sent)
	}
	for _, s := range sent {
		if s.RawQuery != "" || s.Ring {
			t.Errorf("Anfrage: %+v", s)
		}
	}
	expectStatus(t, "Test Leser", as(t, "v_lz").do("POST", "/api/v1/alarm-kanaele/"+groupID+"/test", nil), 404)
	// Ohne Nummer: Fehler am Kanal.
	setMobile(t, "v_fw", "")
	resetAlertTestLimit(vServer)
	r = as(t, "v_fw").do("POST", "/api/v1/alarm-kanaele/"+usersID+"/test", nil)
	expectStatus(t, "Test ohne Nummer", r, 502)
	if !strings.Contains(r.raw, "Mobilnummer") {
		t.Errorf("Meldung: %s", r.raw)
	}
	// Falsches Passwort am Gateway: 401 als verständlicher Fehler.
	f.NoRight(true)
	resetAlertTestLimit(vServer)
	r = as(t, "v_fw").do("POST", "/api/v1/alarm-kanaele/"+groupID+"/test", nil)
	if r.status != 502 || !strings.Contains(r.raw, "HTTP API") || strings.Contains(r.raw, brevistest.Password) {
		t.Errorf("403 vom Gateway: %d %s", r.status, r.raw)
	}
	f.NoRight(false)
	// Freigabe entzogen: kein Versand mehr.
	old := vServer.alertTargets.List()
	vServer.alertTargets.Set(alarm.NewTargets(vNtfy.URL))
	resetAlertTestLimit(vServer)
	f.Reset()
	r = as(t, "v_fw").do("POST", "/api/v1/alarm-kanaele/"+groupID+"/test", nil)
	if r.status != 502 || !strings.Contains(r.raw, "Alarmziel") || len(f.Requests()) != 0 {
		t.Errorf("ohne Freigabe: %d %s", r.status, r.raw)
	}
	vServer.alertTargets.Set(alarm.NewTargets(old...))
}

// Ende zu Ende: Check fällt aus → SMS (bei kritisch mit Anruf), Entwarnung,
// Gateway-Fehler am Kanal, Teilausfall ohne doppelte SMS.
func TestSMSVersand(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := brevistest.NewFake()
	gw := brevistest.Start(t, f)
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(gw.Gateway)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	var tid, dev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'SMS A') RETURNING id::text`, ids["IT"]).Scan(&tid)
	users := make([]string, 3)
	for i := range users {
		owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, alert_mobile) VALUES ($1, $2, 'S', $3)
			RETURNING id::text`, tid, "sms"+string(rune('a'+i))+"@test.invalid", "+4917000000"+string(rune('1'+i))).Scan(&users[i])
		owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'leser')`, users[i], tid)
	}
	// Der dritte ist gesperrt, bekommt also nichts.
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, users[2])
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'sms-router') RETURNING id::text`, tid).Scan(&dev)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.users WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tid)
	})
	var check string
	owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
		VALUES ($1, 'Ping', 'ping', '{"host":"x.lan"}', 60) RETURNING id::text`, dev).Scan(&check)
	record := func(status, msg string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, $3, '', NULL)`, check, status, msg).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	id, _ := newUUID()
	enc, _ := auth.Seal(s.boxKey, []byte(brevistest.Password), smsAAD(id, tid, gw.Gateway, brevistest.User, gw.Pin))
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, kind, server, token_enc, sms_user, sms_pin,
			sms_target, sms_ring) VALUES ($1, $2, 'SMS Bereitschaft', 'sms', $3, $4, $5, $6, 'benutzer', true)`,
		id, tid, gw.Gateway, enc, brevistest.User, gw.Pin); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		owner.Exec(ctx, `INSERT INTO openwacht.alert_channel_users (channel_id, user_id) VALUES ($1, $2)`, id, u)
	}
	round := func(what string) (int, int) {
		t.Helper()
		sent, failed, err := s.alertRoundR(ctx)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return sent, failed
	}
	lastError := func() string {
		var e *string
		owner.QueryRow(ctx, `SELECT last_error FROM openwacht.alert_channels WHERE id = $1`, id).Scan(&e)
		if e == nil {
			return ""
		}
		return *e
	}

	record("crit", "keine Antwort")
	record("crit", "keine Antwort")
	if sent, failed := round("Problem"); sent != 1 || failed != 0 {
		t.Fatalf("Problem: %d/%d", sent, failed)
	}
	reqs := f.Requests()
	// zwei aktive Empfänger, je SMS und Anruf
	if len(reqs) != 4 {
		t.Fatalf("Anfragen: %+v", reqs)
	}
	sms, calls := 0, 0
	for _, r := range reqs {
		if r.Ring {
			calls++
			continue
		}
		sms++
		if r.Text != "OpenWacht: KRIT sms-router - Ping: keine Antwort" || r.To == "00491700000003" {
			t.Errorf("SMS: %+v", r)
		}
	}
	if sms != 2 || calls != 2 {
		t.Errorf("SMS %d, Anrufe %d", sms, calls)
	}
	f.Reset()
	round("nichts Neues")
	if len(f.Requests()) != 0 {
		t.Error("doppelte SMS")
	}

	// Entwarnung ohne Anruf.
	record("ok", "")
	round("Entwarnung")
	reqs = f.Requests()
	if len(reqs) != 2 || reqs[0].Ring || !strings.HasPrefix(reqs[0].Text, "OpenWacht: OK sms-router - Ping") {
		t.Fatalf("Entwarnung: %+v", reqs)
	}

	// Gateway lehnt ab (401): Fehler am Kanal, nichts gilt als gemeldet.
	f.Reset()
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_ring = false WHERE id = $1`, id)
	f.NoRight(true)
	record("crit", "x")
	record("crit", "x")
	if _, failed := round("403"); failed != 1 {
		t.Errorf("403: %d gescheitert", failed)
	}
	if e := lastError(); !strings.Contains(e, "HTTP API") || strings.Contains(e, "0170") {
		t.Errorf("Fehler am Kanal: %q", e)
	}
	f.NoRight(false)
	f.Reset()
	round("nach Reparatur")
	if len(f.Sent()) != 2 {
		t.Fatalf("nach Reparatur: %+v", f.Requests())
	}

	// Teilausfall: einer erreicht, einer nicht → gemeldet, Fehler am Kanal, keine Wiederholung.
	record("ok", "")
	round("ok")
	f.Reset()
	f.FailNext(1)
	record("crit", "y")
	record("crit", "y")
	if _, failed := round("Teilausfall"); failed != 1 {
		t.Errorf("Teilausfall: %d gescheitert", failed)
	}
	if e := lastError(); !strings.Contains(e, "1 von 2 Empfängern") {
		t.Errorf("Teilausfall am Kanal: %q", e)
	}
	n := len(f.Sent())
	round("nach Teilausfall")
	if n != 1 || len(f.Sent()) != 1 {
		t.Errorf("Teilausfall wiederholt: %d → %d", n, len(f.Sent()))
	}

	// Falsches Zertifikat: kein Passwort hinaus.
	f.Reset()
	other := brevistest.Start(t, brevistest.NewFake())
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_pin = $2, token_enc = $3 WHERE id = $1`, id, other.Pin,
		mustSeal(t, s.boxKey, brevistest.Password, smsAAD(id, tid, gw.Gateway, brevistest.User, other.Pin)))
	record("crit", "z")
	record("crit", "z")
	if _, failed := round("falsches Zertifikat"); failed != 1 || len(f.Requests()) != 0 {
		t.Errorf("falsches Zertifikat: %d gescheitert, %d Anfragen", failed, len(f.Requests()))
	}
	if e := lastError(); !strings.Contains(e, "Fingerabdruck") {
		t.Errorf("Fehler: %q", e)
	}

	// Sammeln (1.0.1): Die SMS kommt erst nach dem Fenster.
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_pin = $2, token_enc = $3 WHERE id = $1`, id, gw.Pin,
		mustSeal(t, s.boxKey, brevistest.Password, smsAAD(id, tid, gw.Gateway, brevistest.User, gw.Pin)))
	record("ok", "")
	round("vor dem Sammeln")
	f.Reset()
	s.cfg.AlertCollect = time.Minute
	clock := time.Now()
	s.now = func() time.Time { return clock }
	record("crit", "w")
	record("crit", "w")
	round("Sammeln: Fenster beginnt")
	if len(f.Requests()) != 0 {
		t.Fatalf("Sammeln: SMS vor Ablauf des Fensters: %+v", f.Requests())
	}
	clock = clock.Add(61 * time.Second)
	round("Sammeln: Fenster abgelaufen")
	if len(f.Sent()) != 2 {
		t.Fatalf("Sammeln: nach dem Fenster %+v", f.Requests())
	}
}

func mustSeal(t *testing.T, key []byte, pt string, aad []byte) []byte {
	t.Helper()
	b, err := auth.Seal(key, []byte(pt), aad)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Gateway überwachen: erst nach zwei Fehlschlägen ein Hinweis an den
// Mandanten, Entwarnung, wenn es wieder antwortet.
func TestSMSGatewayUeberwachen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := brevistest.NewFake()
	gw := brevistest.Start(t, f)
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(gw.Gateway)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	tid := ids["Organisation"]
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, kind, server, token_enc, sms_user, sms_pin,
			sms_target, sms_group, sms_watch) VALUES ($1, $2, 'SMS Wache', 'sms', $3, $4, $5, $6, 'gruppe', '1', true)`,
		id, tid, gw.Gateway, mustSeal(t, s.boxKey, "x", smsAAD(id, tid, gw.Gateway, brevistest.User, gw.Pin)), brevistest.User, gw.Pin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, id) })
	now := time.Now()
	if l, err := s.smsWatchNotices(ctx, now); err != nil || len(l) != 0 {
		t.Fatalf("erreichbar: %v %v", l, err)
	}
	gw.Close()
	if l, _ := s.smsWatchNotices(ctx, now); len(l) != 0 {
		t.Fatal("Hinweis schon nach einem Fehlschlag")
	}
	l, _ := s.smsWatchNotices(ctx, now.Add(5*time.Minute))
	if len(l) != 1 || l[0].Key != "smsgateway:"+id || *l[0].Tenant != tid || l[0].Status != alarm.Crit ||
		!strings.Contains(l[0].Text, "SMS Wache") || !l[0].Since.Equal(now) {
		t.Fatalf("Hinweis: %+v", l)
	}
	if len(f.Requests()) != 0 {
		t.Error("Überwachung sendet Anfragen")
	}
	// Überwachung aus: kein Hinweis mehr, Zähler weg.
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET sms_watch = false WHERE id = $1`, id)
	if l, _ := s.smsWatchNotices(ctx, now); len(l) != 0 || len(s.smsWatch.fails) != 0 {
		t.Errorf("nach Abschalten: %v %v", l, s.smsWatch.fails)
	}
}
