// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
)

// fakeNtfy nimmt Nachrichten an wie ntfy und merkt sie sich je Topic.
// Topics in fail antworten mit 503.
type fakeNtfy struct {
	*httptest.Server
	mu   sync.Mutex
	got  []ntfyMsg
	fail map[string]bool
}

type ntfyMsg struct {
	Topic, Title, Message, Auth string
	Priority                    int
}

func newFakeNtfy() *fakeNtfy {
	f := &fakeNtfy{fail: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m ntfyMsg
		if r.Method != http.MethodPost || r.URL.Path != "/" || json.NewDecoder(r.Body).Decode(&m) != nil {
			http.Error(w, `{"error":"falsche Anfrage"}`, 400)
			return
		}
		m.Auth = r.Header.Get("Authorization")
		f.mu.Lock()
		f.got = append(f.got, m)
		fail := f.fail[m.Topic]
		f.mu.Unlock()
		if fail {
			http.Error(w, `{"error":"vorübergehend gestört"}`, 503)
			return
		}
		w.Write([]byte(`{"id":"1"}`))
	}))
	return f
}

// take liefert die seit dem letzten Aufruf eingegangenen Nachrichten je Topic.
func (f *fakeNtfy) take() map[string][]ntfyMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]ntfyMsg{}
	for _, m := range f.got {
		out[m.Topic] = append(out[m.Topic], m)
	}
	f.got = nil
	return out
}

func (f *fakeNtfy) setFail(topic string, v bool) {
	f.mu.Lock()
	f.fail[topic] = v
	f.mu.Unlock()
}

func newChannel(t *testing.T, user, tenant string, body map[string]any) response {
	t.Helper()
	full := map[string]any{"name": "Kanal", "server": vNtfy.URL, "topic": "betrieb"}
	for k, v := range body {
		full[k] = v
	}
	r := as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/alarm-kanaele", full)
	if r.status == 201 {
		id := r.body["id"].(string)
		t.Cleanup(func() { owner.Exec(context.Background(), `DELETE FROM openwacht.alert_channels WHERE id = $1`, id) })
	}
	return r
}

func channels(t *testing.T, user string) map[string]map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/alarm-kanaele", nil)
	expectStatus(t, "Kanäle "+user, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.body["kanaele"].([]any) {
		c := x.(map[string]any)
		out[c["name"].(string)] = c
	}
	return out
}

func TestAlarmkanaeleMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newChannel(t, "v_fw", "Fertigung", map[string]any{"name": "FW Handy"})
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	// Sehen: eigener Mandant und Eltern ja, Geschwister und Kinder nein.
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := channels(t, user)["FW Handy"]; got != want {
			t.Errorf("%s sieht Kanal: %v, erwartet %v", user, got, want)
		}
	}
	// Anlegen: nur Admins, nur im eigenen Teilbaum.
	expectStatus(t, "Leser legt an", newChannel(t, "v_lz", "Lager Nord", map[string]any{"name": "LZ"}), 403)
	expectStatus(t, "Organisation bei Fertigung", newChannel(t, "v_oa", "Fertigung", map[string]any{"name": "fremd"}), 403)
	expectStatus(t, "Fertigung bei IT", newChannel(t, "v_fw", "IT", map[string]any{"name": "nach oben"}), 403)
	expectStatus(t, "IT bei Fertigung", newChannel(t, "v_it", "Fertigung", map[string]any{"name": "IT für FW"}), 201)
	r = newChannel(t, "v_fw", "Lager Nord", map[string]any{"name": "LZ Handy"})
	expectStatus(t, "Fertigung beim Lager", r, 201)
	lz := r.body["id"].(string)

	// Ein Leser sieht den Kanal seines Mandanten, darf ihn aber weder ändern,
	// löschen noch testen.
	if _, ok := channels(t, "v_lz")["LZ Handy"]; !ok {
		t.Error("Leser sieht Kanal im eigenen Mandanten nicht")
	}
	upd := map[string]any{"name": "geändert", "server": vNtfy.URL, "topic": "x"}
	for _, u := range []string{"v_lz", "v_oa"} {
		expectStatus(t, u+" ändert", as(t, u).do("PUT", "/api/v1/alarm-kanaele/"+lz, upd), 404)
		expectStatus(t, u+" löscht", as(t, u).do("DELETE", "/api/v1/alarm-kanaele/"+lz, nil), 404)
		expectStatus(t, u+" testet", as(t, u).do("POST", "/api/v1/alarm-kanaele/"+lz+"/test", nil), 404)
		expectStatus(t, u+" ändert FW", as(t, u).do("PUT", "/api/v1/alarm-kanaele/"+id, upd), 404)
	}
	expectStatus(t, "IT ändert", as(t, "v_it").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{
		"name": "FW Handy neu", "server": vNtfy.URL, "topic": "fw"}), 200)
	if _, ok := channels(t, "v_fw")["FW Handy neu"]; !ok {
		t.Error("Änderung nicht sichtbar")
	}
	expectStatus(t, "Fertigung löscht", as(t, "v_fw").do("DELETE", "/api/v1/alarm-kanaele/"+id, nil), 204)
	expectStatus(t, "doppelt löschen", as(t, "v_fw").do("DELETE", "/api/v1/alarm-kanaele/"+id, nil), 404)

	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id = $1
		AND action LIKE 'alarmkanal.%' AND details->>'id' = $2`, ids["Fertigung"], id).Scan(&n)
	if n != 3 {
		t.Errorf("Audit: %d Einträge, erwartet 3", n)
	}
}

func TestAlarmkanaeleEingabe(t *testing.T) {
	verwaltungSetup(t)
	for name, body := range map[string]map[string]any{
		"Server nicht freigegeben": {"server": "https://ntfy.sh"},
		"http im Netz":             {"server": "http://192.168.1.5"},
		"Zugangsdaten im Server":   {"server": "https://u:p@ntfy.test.invalid"},
		"Topic mit Schrägstrich":   {"topic": "a/b"},
		"Topic leer":               {"topic": ""},
		"Token mit Zeilenumbruch":  {"token": "tk_a\r\nX-Evil: 1"},
		"Token mit Leerzeichen":    {"token": "tk a"},
		"leerer Name":              {"name": " "},
		"unbekanntes Feld":         {"kind": "mail"},
	} {
		r := newChannel(t, "v_oa", "Organisation", body)
		if r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	r := newChannel(t, "v_oa", "Organisation", map[string]any{"server": "https://ntfy.sh"})
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "nicht als Alarmziel freigegeben") ||
		!strings.Contains(msg, "https://ntfy.test.invalid") {
		t.Errorf("Meldung zur Freigabe: %s", r.raw)
	}
	// Normalisiert gespeichert: Großschreibung und Schrägstrich am Ende sind egal.
	expectStatus(t, "gültig", newChannel(t, "v_oa", "Organisation", map[string]any{"name": "Doppelt",
		"server": "HTTPS://ntfy.test.invalid/"}), 201)
	if c := channels(t, "v_oa")["Doppelt"]; c == nil || c["server"] != "https://ntfy.test.invalid" {
		t.Errorf("Server gespeichert als %v", c["server"])
	}
	expectStatus(t, "doppelter Name", newChannel(t, "v_oa", "Organisation", map[string]any{"name": "doppelt"}), 409)
	r = as(t, "v_oa").do("GET", "/api/v1/alarm-kanaele", nil)
	if z, _ := r.body["ziele"].([]any); len(z) != 3 {
		t.Errorf("Ziele: %v", r.body["ziele"])
	}
}

// Das Token kommt nie zurück, ist für die Anwendungsrolle nicht lesbar und
// geht nach einem Serverwechsel nicht an den neuen Server.
func TestAlarmkanalToken(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	const secret = "tk_geheimes1234567890abcdefghi"
	r := newChannel(t, "v_oa", "Organisation", map[string]any{"name": "Mit Token", "token": secret})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	list := as(t, "v_oa").do("GET", "/api/v1/alarm-kanaele", nil)
	if strings.Contains(string(list.raw), secret) || strings.Contains(string(list.raw), "token_enc") {
		t.Fatal("Token in der Liste")
	}
	if channels(t, "v_oa")["Mit Token"]["token_gesetzt"] != true {
		t.Error("token_gesetzt fehlt")
	}
	var audits string
	owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM openwacht.audit_log WHERE details->>'id' = $1`, id).Scan(&audits)
	if strings.Contains(audits, secret) {
		t.Error("Token im Audit-Log")
	}
	// In der Datenbank nur verschlüsselt.
	var enc []byte
	owner.QueryRow(ctx, `SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, id).Scan(&enc)
	if len(enc) == 0 || strings.Contains(string(enc), secret) {
		t.Error("Token nicht verschlüsselt")
	}
	// Test senden: Token kommt beim Server an.
	vNtfy.take()
	expectStatus(t, "Test senden", as(t, "v_oa").do("POST", "/api/v1/alarm-kanaele/"+id+"/test", nil), 200)
	got := vNtfy.take()["betrieb"]
	if len(got) != 1 || got[0].Auth != "Bearer "+secret || !strings.Contains(got[0].Title, "Organisation: Testnachricht") {
		t.Errorf("Testnachricht: %+v", got)
	}
	expectStatus(t, "Test zu früh", as(t, "v_oa").do("POST", "/api/v1/alarm-kanaele/"+id+"/test", nil), 429)

	// Unverändert lassen (Feld fehlt), dann Serverwechsel ohne neues Token.
	r = as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{"name": "Mit Token", "server": vNtfy.URL, "topic": "betrieb2"})
	if r.status != 200 || r.body["token_gesetzt"] != true {
		t.Errorf("Topic ändern: %d %s", r.status, r.raw)
	}
	r = as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{"name": "Mit Token",
		"server": "https://ntfy.test.invalid", "topic": "betrieb2"})
	if r.status != 200 || r.body["token_gesetzt"] != false || r.body["token_entfernt"] != true {
		t.Errorf("Serverwechsel: %d %s", r.status, r.raw)
	}
	// Auch an der API vorbei: Der Trigger entfernt das Token beim Serverwechsel.
	r = as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{"name": "Mit Token",
		"server": vNtfy.URL, "topic": "betrieb2", "token": secret})
	if r.body["token_gesetzt"] != true {
		t.Fatalf("Token neu setzen: %s", r.raw)
	}
	err := vServer.withUser(ctx, ids["v_oa"], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.alert_channels SET server = 'https://ntfy.test.invalid' WHERE id = $1`, id)
		return err
	})
	var has bool
	owner.QueryRow(ctx, `SELECT has_token FROM openwacht.alert_channels WHERE id = $1`, id).Scan(&has)
	if err != nil || has {
		t.Errorf("Serverwechsel über SQL: Token noch da (%v)", err)
	}
	// Token entfernen mit "".
	as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{"name": "Mit Token",
		"server": vNtfy.URL, "topic": "betrieb2", "token": secret})
	r = as(t, "v_oa").do("PUT", "/api/v1/alarm-kanaele/"+id, map[string]any{"name": "Mit Token",
		"server": vNtfy.URL, "topic": "betrieb2", "token": ""})
	if r.body["token_gesetzt"] != false {
		t.Errorf("Token entfernen: %s", r.raw)
	}

	// Ein in einen anderen Kanal kopierter Geheimtext lässt sich dort nicht
	// entschlüsseln (AAD), der Versand schlägt mit klarer Meldung fehl.
	r = newChannel(t, "v_oa", "Organisation", map[string]any{"name": "Kopie", "topic": "kopie"})
	other := r.body["id"].(string)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET token_enc = $2 WHERE id = $1`, other, enc); err != nil {
		t.Fatal(err)
	}
	vNtfy.take()
	r = as(t, "v_oa").do("POST", "/api/v1/alarm-kanaele/"+other+"/test", nil)
	if r.status != 502 || !strings.Contains(r.body["fehler"].(string), "nicht entschlüsselbar") {
		t.Errorf("kopiertes Token: %d %s", r.status, r.raw)
	}
	if len(vNtfy.take()) != 0 {
		t.Error("mit kopiertem Token gesendet")
	}
	if c := channels(t, "v_oa")["Kopie"]; c["letzter_fehler"] == nil {
		t.Error("Fehler nicht am Kanal vermerkt")
	}
}

func TestAlarmkanalTestNichtErreichbar(t *testing.T) {
	verwaltungSetup(t)
	r := newChannel(t, "v_oa", "Organisation", map[string]any{"name": "Tot", "server": "http://127.0.0.1:9"})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	r = as(t, "v_oa").do("POST", "/api/v1/alarm-kanaele/"+id+"/test", nil)
	if r.status != 502 || !strings.Contains(r.body["fehler"].(string), "nicht erreichbar") {
		t.Errorf("Test: %d %s", r.status, r.raw)
	}
	c := channels(t, "v_oa")["Tot"]
	if c["letzter_fehler"] == nil || c["zuletzt_ok"] != nil {
		t.Errorf("Zustand: %v", c)
	}
}

// Schichten einzeln: Die Datenbank allein schützt Kanäle und Token.
func TestAlarmkanaelePruefungJeSchicht(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newChannel(t, "v_fw", "Fertigung", map[string]any{"name": "Schicht", "token": "tk_x"})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	tryAs := func(user string, sql string, args ...any) int64 {
		var n int64
		err := vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return -1
		}
		return n
	}
	if n := tryAs("v_oa", `UPDATE openwacht.alert_channels SET topic = 'umgeleitet' WHERE id = $1`, id); n != 0 {
		t.Errorf("Organisation ändert über SQL: %d", n)
	}
	// Ein Leser sieht den Kanal seines Mandanten, darf ihn aber weder ändern
	// noch löschen.
	r = newChannel(t, "v_fw", "Lager Nord", map[string]any{"name": "Schicht LZ"})
	expectStatus(t, "anlegen beim Lager", r, 201)
	lz := r.body["id"].(string)
	if n := tryAs("v_lz", `UPDATE openwacht.alert_channels SET topic = 'umgeleitet' WHERE id = $1`, lz); n != 0 {
		t.Errorf("Leser ändert über SQL: %d", n)
	}
	if n := tryAs("v_lz", `DELETE FROM openwacht.alert_channels WHERE id = $1`, lz); n != 0 {
		t.Errorf("Leser löscht über SQL: %d", n)
	}
	if n := tryAs("v_lz", `INSERT INTO openwacht.alert_channels (tenant_id, name, server, topic)
		VALUES ($1, 'x', 'https://ntfy.test.invalid', 'x')`, ids["Lager Nord"]); n != -1 {
		t.Errorf("Leser legt über SQL an: %d", n)
	}
	if n := tryAs("v_oa", `INSERT INTO openwacht.alert_channels (tenant_id, name, server, topic)
		VALUES ($1, 'x', 'https://ntfy.test.invalid', 'x')`, ids["Fertigung"]); n != -1 {
		t.Errorf("Organisation legt über SQL bei Fertigung an: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.alert_channels SET tenant_id = $2 WHERE id = $1`, id, ids["Lager Nord"]); n != -1 {
		t.Errorf("Mandant eines Kanals geändert: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.alert_channels SET last_ok = now() WHERE id = $1`, id); n != -1 {
		t.Errorf("Versandzustand von außen gesetzt: %d", n)
	}
	// Das Token ist auch für den eigenen Admin nicht lesbar.
	if n := tryAs("v_fw", `SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, id); n != -1 {
		t.Error("token_enc lesbar")
	}
	if n := tryAs("v_fw", `SELECT * FROM openwacht.alert_state`); n != -1 {
		t.Error("alert_state lesbar")
	}
	if n := tryAs("v_fw", `DELETE FROM openwacht.alert_state`); n != -1 {
		t.Error("alert_state änderbar")
	}
}

// Versand Ende-zu-Ende: Zustände über check_record, Durchläufe über
// alertRoundN, Empfang beim nachgebauten ntfy.
//
//	IT ── Alarm A (Kanal a: mit Untermandanten, Token; Kanal a2: ohne)
//	        └── Alarm B (Kanal b)
func TestAlarmVersand(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := alarm.NormalizeServer(f.URL)

	tenant := func(name, parent string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2) RETURNING id::text`,
			parent, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ta := tenant("Alarm A", ids["IT"])
	tb := tenant("Alarm B", ta)
	channel := func(tid, name, topic string, children bool, token string) string {
		id, _ := newUUID()
		var enc []byte
		if token != "" {
			enc, _ = auth.Seal(s.boxKey, []byte(token), channelAAD(id, tid, server))
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic, token_enc, include_children)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tid, name, server, topic, enc, children); err != nil {
			t.Fatal(err)
		}
		return id
	}
	channel(ta, "A mit Kindern", "a", true, "tk_alarm_a")
	channel(ta, "A allein", "a2", false, "")
	chB := channel(tb, "B", "b", false, "")
	check := func(tid, name string) string {
		var id string
		if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
			INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, $2, 'ping', '{"host":"x.lan"}', 60 FROM d RETURNING id::text`, tid, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	cA := check(ta, "A-Router")
	cB := check(tb, "B-NAS")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id IN ($1, $2)`, ta, tb)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id IN ($1, $2)`, ta, tb)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tb)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, ta)
	})
	record := func(id, status, msg string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, $3, '', NULL)`, id, status, msg).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	round := func(what string) map[string][]ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return f.take()
	}
	expect := func(what string, got map[string][]ntfyMsg, want map[string]string) {
		t.Helper()
		for topic, title := range want {
			if len(got[topic]) != 1 || got[topic][0].Title != title {
				t.Errorf("%s: an %s %+v, erwartet „%s“", what, topic, got[topic], title)
			}
		}
		for topic, msgs := range got {
			if _, ok := want[topic]; !ok {
				t.Errorf("%s: unerwartet an %s: %+v", what, topic, msgs)
			}
		}
	}

	expect("noch nie gelaufen", round("leer"), nil)
	record(cB, "crit", "keine Antwort")
	expect("erster Fehlschlag", round("1"), nil)
	record(cB, "crit", "keine Antwort")
	got := round("2")
	expect("zweiter Fehlschlag", got, map[string]string{"a": "Alarm B: 1 Problem", "b": "Alarm B: 1 Problem"})
	if m := got["a"]; len(m) == 1 && (m[0].Message != "❌ Alarm B / Testgerät · B-NAS: keine Antwort" || m[0].Priority != 4 || m[0].Auth != "Bearer tk_alarm_a") {
		t.Errorf("Nachricht an a: %+v", m[0])
	}
	if m := got["b"]; len(m) == 1 && (m[0].Message != "❌ Testgerät · B-NAS: keine Antwort" || m[0].Auth != "") {
		t.Errorf("Nachricht an b: %+v", m[0])
	}
	expect("keine Wiederholung", round("3"), nil)

	// Kanal b gestört: a bekommt die Warnung und die Entwarnung, b wird
	// wiederholt, bis es klappt, und bekommt dann nur, was ihm fehlt.
	f.setFail("b", true)
	record(cA, "warn", "Zertifikat läuft in 10 Tagen ab")
	expect("Warnung sofort", round("4"), map[string]string{"a": "Alarm A: 1 Problem", "a2": "Alarm A: 1 Problem"})
	record(cB, "ok", "erreichbar")
	expect("Entwarnung", round("5"), map[string]string{"a": "Alarm B: 1 wieder OK", "b": "Alarm B: 1 wieder OK"})
	var lastErr *string
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.alert_channels WHERE id = $1`, chB).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "HTTP 503") {
		t.Errorf("Fehler an Kanal b: %v", lastErr)
	}
	expect("erneuter Versuch", round("6"), map[string]string{"b": "Alarm B: 1 wieder OK"})
	f.setFail("b", false)
	expect("Versuch klappt", round("7"), map[string]string{"b": "Alarm B: 1 wieder OK"})
	expect("danach still", round("8"), nil)
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.alert_channels WHERE id = $1`, chB).Scan(&lastErr)
	if lastErr != nil {
		t.Errorf("Fehler nach Erfolg: %v", *lastErr)
	}

	// Erinnerung nach 12 h, Warnungen nie.
	record(cB, "crit", "keine Antwort")
	record(cB, "crit", "keine Antwort")
	expect("neuer Fehler", round("9"), map[string]string{"a": "Alarm B: 1 Problem", "b": "Alarm B: 1 Problem"})
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	got = round("10")
	expect("Erinnerung", got, map[string]string{"a": "Alarm B: 1 Problem", "b": "Alarm B: 1 Problem"})
	if m := got["b"]; len(m) == 1 && !strings.HasSuffix(m[0].Message, "(Erinnerung)") {
		t.Errorf("Erinnerung: %q", m[0].Message)
	}
	s.now = time.Now

	// Neuer Kanal erfährt den aktuellen Stand; neues Topic ebenso.
	channel(tb, "B neu", "b3", false, "")
	expect("neuer Kanal", round("11"), map[string]string{"b3": "Alarm B: 1 Problem"})
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET topic = 'b4' WHERE id = $1`, chB); err != nil {
		t.Fatal(err)
	}
	expect("neues Topic", round("12"), map[string]string{"b4": "Alarm B: 1 Problem"})

	// Abgeschaltete Checks und Kanäle melden nichts.
	owner.Exec(ctx, `UPDATE openwacht.checks SET enabled = false WHERE id = $1`, cA)
	record(cB, "ok", "erreichbar")
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET enabled = false WHERE tenant_id = $1`, tb)
	expect("abgeschaltet", round("13"), map[string]string{"a": "Alarm B: 1 wieder OK"})

	// Server aus der Freigabe genommen: nichts senden, Fehler am Kanal.
	owner.Exec(ctx, `UPDATE openwacht.alert_channels SET enabled = true WHERE id = $1`, chB)
	s2, _ := New(vServer.cfg, pool, testKey) // ohne dieses Ziel
	if _, err := s2.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.take(); len(got) != 0 {
		t.Errorf("an nicht freigegebenen Server gesendet: %v", got)
	}
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.alert_channels WHERE id = $1`, chB).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "nicht (mehr) als Alarmziel freigegeben") {
		t.Errorf("Fehler bei entzogener Freigabe: %v", lastErr)
	}

	// Mehrere Zentralen: Hält eine andere die Sperre, sendet diese nichts.
	if _, err := owner.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(alertLockKey)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.alertRoundN(ctx); err != nil || n != 0 {
		t.Errorf("trotz Sperre: %d %v", n, err)
	}
	owner.Exec(ctx, `SELECT pg_advisory_unlock($1)`, int64(alertLockKey))
	if len(f.take()) != 0 {
		t.Error("trotz Sperre gesendet")
	}
	expect("nach der Sperre", round("14"), map[string]string{"b4": "Alarm B: 1 wieder OK"})

	// Gelöschter Check: Zustand verschwindet mit (ON DELETE CASCADE, auch als
	// Anwendungsrolle ohne Rechte auf alert_state).
	expectStatus(t, "Check löschen", as(t, "v_it").do("DELETE", "/api/v1/checks/"+cB, nil), 204)
	var left int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alert_state WHERE check_id = $1`, cB).Scan(&left)
	if left != 0 {
		t.Errorf("Zustand nach Löschen: %d", left)
	}
}
