// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

// alarmeVon: Name → Alarm (offen oder beendet), wie ihn user über die API sieht.
func alarmeVon(t *testing.T, user string) map[string]map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/alarme", nil)
	expectStatus(t, "Alarme "+user, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.body["alarme"].([]any) {
		a := x.(map[string]any)
		if _, seen := out[a["name"].(string)]; !seen { // neueste zuerst
			out[a["name"].(string)] = a
		}
	}
	return out
}

func sensorenVon(t *testing.T, user string) map[string]map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/sensoren", nil)
	expectStatus(t, "Sensoren "+user, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.body["sensoren"].([]any) {
		s := x.(map[string]any)
		out[s["schluessel"].(string)] = s
	}
	return out
}

// Alarmprotokoll Ende-zu-Ende im Testbaum:
//
//	IT (v_it, Admin)
//	├── Fertigung (v_fw, Admin) ── Kanal „fw“ mit Untermandanten
//	│     └── Lager Nord (v_lz, Leser)
//	└── Organisation (v_oa, Admin)
func TestAlarmprotokoll(t *testing.T) {
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
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(f.URL)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic, include_children)
		VALUES ($1, $2, 'Protokoll', $3, 'fw', true)`, chID, ids["Fertigung"], server); err != nil {
		t.Fatal(err)
	}
	check := func(tenant, name string) string {
		var id string
		if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
			INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, $2, 'ping', '{"host":"x.lan"}', 60 FROM d RETURNING id::text`, ids[tenant], name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	cLZ := check("Lager Nord", "P-Pumpe")
	cFW := check("Fertigung", "P-Funk")
	cW := check("Fertigung", "P-Zertifikat")
	agID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, last_seen, snapshot)
		VALUES ($1, $2, 'p-host', 'sp', now() + interval '30 days', now(), $3)`,
		agID, ids["Lager Nord"], hostSnapshot(t, 50, map[string]int{"/": 50})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name LIKE 'P-%' OR name LIKE 'p-host%'`)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, chID)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE id IN ($1, $2, $3)`, cLZ, cFW, cW)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, agID)
	})
	record := func(id, status, msg string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, $3, '', NULL)`, id, status, msg).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	round := func(what string) []ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return f.take()["fw"]
	}

	// Erster Fehlschlag: noch kein Alarm (Schwelle 2), zweiter: Alarm.
	record(cLZ, "crit", "keine Antwort")
	round("1")
	if _, ok := alarmeVon(t, "v_it")["Testgerät · P-Pumpe"]; ok {
		t.Error("Alarm schon nach dem ersten Fehlschlag")
	}
	record(cLZ, "crit", "keine Antwort")
	if m := round("2"); len(m) != 1 {
		t.Errorf("Meldung beim Alarm: %+v", m)
	}
	a := alarmeVon(t, "v_it")["Testgerät · P-Pumpe"]
	if a == nil || a["status"] != "crit" || a["ende"] != nil || a["mandant_id"] != ids["Lager Nord"] || a["meldung"] != "keine Antwort" {
		t.Fatalf("offener Alarm: %+v", a)
	}
	id := a["id"].(string)

	// Sehen: eigener Mandant und Eltern ja, Geschwister nein.
	for user, want := range map[string]bool{"v_lz": true, "v_fw": true, "v_it": true, "v_oa": false} {
		if _, got := alarmeVon(t, user)["Testgerät · P-Pumpe"]; got != want {
			t.Errorf("%s sieht den Alarm: %v, erwartet %v", user, got, want)
		}
		sn, got := sensorenVon(t, user)[alarmKeyCheck(cLZ)]
		if got != want {
			t.Errorf("%s sieht den Sensor: %v, erwartet %v", user, got, want)
		}
		if got && (sn["status"] != "crit" || sn["alarm"] == nil) {
			t.Errorf("Sensor für %s: %+v", user, sn)
		}
	}

	// Bestätigen: Leser nein, Geschwister sieht ihn nicht, Admin darüber ja.
	ack := func(user, alarmID, comment string) response {
		return as(t, user).do("POST", "/api/v1/alarme/"+alarmID+"/bestaetigen", map[string]any{"kommentar": comment})
	}
	expectStatus(t, "Leser bestätigt", ack("v_lz", id, ""), 403)
	expectStatus(t, "Organisation bestätigt", ack("v_oa", id, ""), 404)
	expectStatus(t, "zu langer Kommentar", ack("v_fw", id, strings.Repeat("x", 301)), 400)
	r := ack("v_fw", id, "Pumpe\nwird getauscht")
	expectStatus(t, "Fertigung bestätigt", r, 200)
	if r.body["bestaetigt_von"] != "v_fw" || r.body["kommentar"] != "Pumpe wird getauscht" || r.body["bestaetigt_am"] == nil {
		t.Errorf("Bestätigung: %+v", r.body)
	}
	expectStatus(t, "doppelt bestätigen", ack("v_it", id, ""), 409)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id = $1 AND action = 'alarm.bestaetigt'
		AND details->>'id' = $2`, ids["Lager Nord"], id).Scan(&n)
	if n != 1 {
		t.Errorf("Audit: %d Einträge, erwartet 1", n)
	}

	// Erinnerung: Der unbestätigte Alarm erinnert, der bestätigte nicht.
	record(cFW, "crit", "Funk weg")
	record(cFW, "crit", "Funk weg")
	if m := round("3"); len(m) != 1 || !strings.Contains(m[0].Message, "P-Funk") {
		t.Errorf("zweiter Alarm: %+v", m)
	}
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	m := round("4")
	s.now = time.Now
	if len(m) != 1 || !strings.Contains(m[0].Message, "P-Funk: Funk weg (Erinnerung)") || strings.Contains(m[0].Message, "P-Pumpe") {
		t.Errorf("Erinnerung nur für den unbestätigten Alarm: %+v", m)
	}

	// Verschlimmerung hebt die Bestätigung auf und wird gemeldet.
	record(cW, "warn", "läuft in 10 Tagen ab")
	round("5")
	w := alarmeVon(t, "v_fw")["Testgerät · P-Zertifikat"]
	expectStatus(t, "Warnung bestätigen", ack("v_fw", w["id"].(string), ""), 200)
	record(cW, "crit", "abgelaufen")
	record(cW, "crit", "abgelaufen")
	if m := round("6"); len(m) != 1 || !strings.Contains(m[0].Message, "P-Zertifikat: abgelaufen") {
		t.Errorf("Verschlimmerung gemeldet: %+v", m)
	}
	w = alarmeVon(t, "v_fw")["Testgerät · P-Zertifikat"]
	if w["status"] != "crit" || w["schlimmster"] != "crit" || w["bestaetigt_am"] != nil || w["ende"] != nil {
		t.Errorf("nach Verschlimmerung: %+v", w)
	}

	// Erholung beendet den Alarm; beendete lassen sich nicht bestätigen.
	record(cLZ, "ok", "erreichbar")
	if m := round("7"); len(m) != 1 || !strings.Contains(m[0].Title, "wieder OK") {
		t.Errorf("Entwarnung trotz Bestätigung: %+v", m)
	}
	a = alarmeVon(t, "v_lz")["Testgerät · P-Pumpe"]
	if a["ende"] == nil || a["bestaetigt_von"] != "v_fw" {
		t.Errorf("beendeter Alarm: %+v", a)
	}
	expectStatus(t, "beendeten bestätigen", ack("v_fw", id, ""), 409)
	if sn := sensorenVon(t, "v_lz")[alarmKeyCheck(cLZ)]; sn["status"] != "ok" || sn["alarm"] != nil {
		t.Errorf("Sensor nach Erholung: %+v", sn)
	}

	// Host: Platte voll, dann stumm. Solange er stumm ist, bleibt der
	// Plattenalarm stehen (Messwerte veraltet), statt still zu enden.
	setAgent := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE openwacht.agents SET `+sql+` WHERE id = $1`, append([]any{agID}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	setAgent(`snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 92}))
	round("8")
	if p := alarmeVon(t, "v_lz")["p-host · Platte /"]; p == nil || p["status"] != "warn" || p["gegenstand"] != "platte:/" {
		t.Errorf("Plattenalarm: %+v", p)
	}
	sn := sensorenVon(t, "v_lz")
	if p := sn[alarmKeyHost(agID, "platte:/")]; p == nil || p["status"] != "warn" || p["name"] != "Platte /" || p["host"] != "p-host" {
		t.Errorf("Plattensensor: %+v", p)
	}
	if e := sn[alarmKeyHost(agID, alarm.SubjectSilent)]; e == nil || e["status"] != "ok" {
		t.Errorf("Erreichbarkeit: %+v", e)
	}
	setAgent(`last_seen = now() - interval '1 hour'`)
	round("9")
	al := alarmeVon(t, "v_lz")
	if p := al["p-host"]; p == nil || p["status"] != "crit" || p["ende"] != nil {
		t.Errorf("stumm: %+v", p)
	}
	if p := al["p-host · Platte /"]; p["ende"] != nil {
		t.Errorf("Plattenalarm endet, obwohl der Host stumm ist: %+v", p)
	}
	if p := sensorenVon(t, "v_lz")[alarmKeyHost(agID, "platte:/")]; p["status"] != "unknown" {
		t.Errorf("Plattensensor bei stummem Host: %+v", p)
	}
	if e := sensorenVon(t, "v_lz")[alarmKeyHost(agID, alarm.SubjectSilent)]; e["status"] != "crit" || e["alarm"] == nil {
		t.Errorf("Erreichbarkeit bei stummem Host: %+v", e)
	}
	// Bestätigt: keine Erinnerung für den Host.
	expectStatus(t, "Host bestätigen", ack("v_fw", al["p-host"]["id"].(string), ""), 200)
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	m = round("9b")
	s.now = time.Now
	for _, x := range m {
		if strings.Contains(x.Message, "p-host") {
			t.Errorf("Erinnerung trotz Bestätigung: %q", x.Message)
		}
	}
	setAgent(`last_seen = now(), snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 50}))
	round("10")
	al = alarmeVon(t, "v_lz")
	if al["p-host"]["ende"] == nil || al["p-host · Platte /"]["ende"] == nil {
		t.Errorf("Host-Alarme nach Erholung: %+v / %+v", al["p-host"], al["p-host · Platte /"])
	}

	// Gelöschte Quelle: Der offene Alarm endet, der Eintrag bleibt.
	owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE id = $1`, cFW)
	round("11")
	if p := alarmeVon(t, "v_fw")["Testgerät · P-Funk"]; p == nil || p["ende"] == nil || p["check_id"] != nil {
		t.Errorf("Alarm eines gelöschten Checks: %+v", p)
	}
}

// Schutz in der Datenbank, unabhängig von der API.
func TestAlarmprotokollPruefungJeSchicht(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	var cid, aid string
	if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
		INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, 'S-Check', 'ping', '{"host":"x.lan"}', 60 FROM d RETURNING id::text`, ids["Lager Nord"]).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at)
		VALUES ($1, $2, 'check', 'S-Check', 'crit', 'crit', now(), now()) RETURNING id::text`, ids["Lager Nord"], cid).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE id = $1`, aid)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE id = $1`, cid)
	})
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
	if n := tryAs("v_lz", `UPDATE openwacht.alarms SET ack_at = now() WHERE id = $1`, aid); n != 0 {
		t.Errorf("Leser bestätigt über SQL: %d", n)
	}
	if n := tryAs("v_oa", `UPDATE openwacht.alarms SET ack_at = now() WHERE id = $1`, aid); n != 0 {
		t.Errorf("Geschwister bestätigt über SQL: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.alarms SET ack_by = $2 WHERE id = $1`, aid, ids["v_it"]); n != -1 {
		t.Errorf("Person der Bestätigung gefälscht: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.alarms SET ended_at = now() WHERE id = $1`, aid); n != -1 {
		t.Errorf("Alarm von außen beendet: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.alarms (tenant_id, subject, name, status, worst, started_at, changed_at)
		VALUES ($1, 'check', 'falsch', 'crit', 'crit', now(), now())`, ids["Fertigung"]); n != -1 {
		t.Errorf("Alarm von außen angelegt: %d", n)
	}
	if n := tryAs("v_fw", `DELETE FROM openwacht.alarms WHERE id = $1`, aid); n != -1 {
		t.Errorf("Alarm gelöscht: %d", n)
	}
	// Mit Recht: Die Datenbank setzt Zeit und Person selbst.
	if n := tryAs("v_fw", `UPDATE openwacht.alarms SET ack_at = '2000-01-01' WHERE id = $1`, aid); n != 1 {
		t.Errorf("Fertigung bestätigt über SQL: %d", n)
	}
	var by, name string
	var recent bool
	owner.QueryRow(ctx, `SELECT ack_by::text, ack_by_name, ack_at > now() - interval '1 minute' FROM openwacht.alarms WHERE id = $1`,
		aid).Scan(&by, &name, &recent)
	if by != ids["v_fw"] || name != "v_fw" || !recent {
		t.Errorf("Bestätigung: %s %s %v", by, name, recent)
	}
	if n := tryAs("v_it", `UPDATE openwacht.alarms SET ack_at = now(), ack_comment = 'anders' WHERE id = $1`, aid); n != -1 {
		t.Errorf("Bestätigung überschrieben: %d", n)
	}
	// Abgleich mit Unsinn: Mandant kommt aus dem Check, nicht aus den Eingaben;
	// unvollständige Einträge fallen weg.
	if _, err := pool.Exec(ctx, `SELECT openwacht.alarm_sync(ARRAY[$1::uuid, NULL], ARRAY[NULL, NULL]::uuid[],
		ARRAY[NULL, NULL]::uuid[], ARRAY['check', 'stumm'], ARRAY['S-Check', 'x'], ARRAY['crit', 'crit'], ARRAY[E'a\nb', ''])`, cid); err != nil {
		t.Fatal(err)
	}
	var msg string
	var cnt int
	owner.QueryRow(ctx, `SELECT message FROM openwacht.alarms WHERE id = $1`, aid).Scan(&msg)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE name = 'x'`).Scan(&cnt)
	if msg != "a b" || cnt != 0 {
		t.Errorf("Abgleich: Meldung %q, unvollständige Einträge %d", msg, cnt)
	}
	if _, err := pool.Exec(ctx, `SELECT openwacht.alarm_sync(ARRAY[$1::uuid], ARRAY[NULL]::uuid[], ARRAY[]::uuid[],
		ARRAY['check'], ARRAY['x'], ARRAY['crit'], ARRAY[''])`, cid); err == nil {
		t.Error("Listen unterschiedlicher Länge angenommen")
	}
}
