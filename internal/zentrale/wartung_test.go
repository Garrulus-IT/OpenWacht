// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
)

// wartungZiele legt im Testbaum einen Check und einen Agent im Lager Nord
// an und einen Operator dort (ohne 2FA, wie Leser).
func wartungZiele(t *testing.T, prefix string) (check, agent, operator string) {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
		INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, $2, 'ping', '{"host":"x.lan"}', 60 FROM d RETURNING id::text`, ids["Lager Nord"], prefix+"-Pumpe").Scan(&check); err != nil {
		t.Fatal(err)
	}
	agent, _ = newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, last_seen, snapshot)
		VALUES ($1, $2, $3, 'sw', now() + interval '30 days', now(), $4)`,
		agent, ids["Lager Nord"], strings.ToLower(prefix)+"-host", hostSnapshot(t, 50, map[string]int{"/": 50})); err != nil {
		t.Fatal(err)
	}
	operator = strings.ToLower(prefix) + "_op"
	hash, _ := auth.HashPassword(testPassword, testParams)
	var uid string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
		VALUES ($1, $2, $3, $4) RETURNING id::text`, ids["Lager Nord"], operator+"@test.invalid", operator, hash).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	ids[operator] = uid
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'operator')`,
		uid, ids["Lager Nord"]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE check_id = $1 OR agent_id = $2`, check, agent)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE id = $1`, check)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, agent)
		owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, uid)
	})
	return
}

// agentDevice liefert das Gerät eines Agents.
func agentDevice(t *testing.T, agent string) string {
	t.Helper()
	var d string
	if err := owner.QueryRow(context.Background(), `SELECT device_id::text FROM openwacht.agents WHERE id = $1`, agent).Scan(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func listEntry(t *testing.T, user, path, key, id string) (map[string]any, bool) {
	t.Helper()
	r := as(t, user).do("GET", path, nil)
	expectStatus(t, path+" "+user, r, 200)
	for _, x := range r.body[key].([]any) {
		e := x.(map[string]any)
		if e["id"] == id {
			return e, true
		}
	}
	return nil, false
}

// Mandantenbaum wie in TestAlarmprotokoll; Ziele im Lager Nord.
func TestWartungMandantentrennung(t *testing.T) {
	cid, aid, op := wartungZiele(t, "WM")
	set := func(user, path string, body any) response {
		return as(t, user).do("PUT", path, body)
	}
	end := func(user, path string) response { return as(t, user).do("DELETE", path, nil) }
	dev := agentDevice(t, aid)
	cPath, aPath := "/api/v1/checks/"+cid+"/wartung", "/api/v1/geraete/"+dev+"/wartung"

	// Eingaben
	for name, body := range map[string]any{
		"0 Minuten":      map[string]any{"minuten": 0},
		"über 7 Tage":    map[string]any{"minuten": 7*24*60 + 1},
		"Grund zu lang":  map[string]any{"minuten": 60, "grund": strings.Repeat("x", 201)},
		"fremdes Feld":   map[string]any{"minuten": 60, "mandant_id": ids["IT"]},
		"falscher Typ":   map[string]any{"minuten": "60"},
		"negative Dauer": map[string]any{"minuten": -5},
	} {
		expectStatus(t, name, set("v_fw", cPath, body), 400)
	}
	expectStatus(t, "ungültige ID", set("v_fw", "/api/v1/checks/kein-uuid/wartung", map[string]any{"minuten": 60}), 400)

	// Rechte: Leser nein, Geschwister sieht das Ziel nicht, Eltern-Admin ja.
	expectStatus(t, "Leser setzt", set("v_lz", cPath, map[string]any{"minuten": 60}), 403)
	expectStatus(t, "Geschwister setzt", set("v_oa", cPath, map[string]any{"minuten": 60}), 404)
	expectStatus(t, "Geschwister setzt Host", set("v_oa", aPath, map[string]any{"minuten": 60}), 404)
	r := set("v_fw", cPath, map[string]any{"minuten": 120, "grund": "Firmware\nUpdate"})
	expectStatus(t, "Eltern-Admin setzt", r, 200)
	bis, _ := time.Parse(time.RFC3339Nano, r.body["bis"].(string))
	if d := time.Until(bis); d < 119*time.Minute || d > 121*time.Minute || r.body["grund"] != "Firmware Update" || r.body["von"] != "v_fw" {
		t.Errorf("Wartung: %+v (in %s)", r.body, d)
	}

	// Sehen: eigener Mandant und Eltern ja, Geschwister nein.
	for user, want := range map[string]bool{"v_lz": true, "v_fw": true, "v_it": true} {
		c, ok := listEntry(t, user, "/api/v1/checks", "checks", cid)
		if !ok || (c["wartung"] != nil) != want {
			t.Errorf("%s: Check %v, Wartung %v", user, ok, c["wartung"])
		}
		if sn := sensorenVon(t, user)[alarmKeyCheck(cid)]; sn == nil || sn["wartung"] == nil {
			t.Errorf("%s: Sensor ohne Wartung: %+v", user, sn)
		}
	}
	if _, ok := listEntry(t, "v_oa", "/api/v1/checks", "checks", cid); ok {
		t.Error("Geschwister sieht den Check")
	}

	// Beenden: Leser nein, Geschwister 404, Operator im eigenen Mandanten ja.
	expectStatus(t, "Leser beendet", end("v_lz", cPath), 403)
	expectStatus(t, "Geschwister beendet", end("v_oa", cPath), 404)
	expectStatus(t, "Operator beendet", end(op, cPath), 204)
	expectStatus(t, "nochmal beenden", end(op, cPath), 404)
	if c, _ := listEntry(t, "v_lz", "/api/v1/checks", "checks", cid); c["wartung"] != nil {
		t.Errorf("Wartung nach Beenden: %+v", c["wartung"])
	}

	// Host: Operator setzt, Admin darüber ersetzt.
	expectStatus(t, "Operator setzt Host", set(op, aPath, map[string]any{"minuten": 30}), 200)
	r = set("v_it", aPath, map[string]any{"minuten": 480, "grund": "Umzug"})
	expectStatus(t, "IT ersetzt", r, 200)
	a, ok := listEntry(t, "v_lz", "/api/v1/agents", "agents", aid)
	w, _ := a["wartung"].(map[string]any)
	if !ok || w == nil || w["grund"] != "Umzug" || w["von"] != "v_it" || w["ueber_geraet"] != true {
		t.Errorf("Host-Wartung: %+v", a["wartung"])
	}
	d, ok := listEntry(t, "v_lz", "/api/v1/geraete", "geraete", dev)
	if w, _ := d["wartung"].(map[string]any); !ok || w == nil || w["grund"] != "Umzug" || w["ueber_geraet"] != false {
		t.Errorf("Gerätewartung: %+v", d)
	}
	if _, ok := listEntry(t, "v_oa", "/api/v1/geraete", "geraete", dev); ok {
		t.Error("Geschwister sieht das Gerät")
	}
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.maintenance WHERE device_id = $1`, dev).Scan(&n)
	if n != 1 {
		t.Errorf("%d Wartungen für den Host, erwartet 1", n)
	}
	sn := sensorenVon(t, "v_lz")
	for k, v := range sn {
		if strings.HasPrefix(k, "h:"+aid+"/") && v["wartung"] == nil {
			t.Errorf("Host-Sensor %s ohne Wartung", k)
		}
	}
	// Gesperrter Agent: zeigt keine Wartung mehr (das Gerät behält sie).
	owner.Exec(context.Background(), `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, aid)
	if a, _ := listEntry(t, "v_lz", "/api/v1/agents", "agents", aid); a["wartung"] != nil {
		t.Errorf("gesperrter Agent mit Wartung: %+v", a["wartung"])
	}

	// Audit
	var actions string
	owner.QueryRow(context.Background(), `SELECT string_agg(action, ',' ORDER BY id) FROM openwacht.audit_log
		WHERE details ->> 'check' = $1 OR details ->> 'geraet' = $2`, cid, dev).Scan(&actions)
	if actions != "wartung.gesetzt,wartung.beendet,wartung.gesetzt,wartung.gesetzt" {
		t.Errorf("Audit: %s", actions)
	}
}

func TestWartungPruefungJeSchicht(t *testing.T) {
	cid, _, _ := wartungZiele(t, "WS")
	ctx := context.Background()
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
	ins := `INSERT INTO openwacht.maintenance (check_id, ends_at) VALUES ($1, now() + interval '1 hour')`
	if n := tryAs("v_lz", ins, cid); n != -1 {
		t.Errorf("Leser setzt über SQL: %d", n)
	}
	if n := tryAs("v_oa", ins, cid); n != -1 {
		t.Errorf("Geschwister setzt über SQL: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (tenant_id, check_id, ends_at) VALUES ($2, $1, now() + interval '1 hour')`,
		cid, ids["Organisation"]); n != -1 {
		t.Errorf("Mandant vorgegeben: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (check_id, ends_at, starts_at) VALUES ($1, now() + interval '1 hour', now() - interval '1 day')`,
		cid); n != -1 {
		t.Errorf("Start vorgegeben: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (check_id, ends_at, created_by) VALUES ($1, now() + interval '1 hour', $2)`,
		cid, ids["v_it"]); n != -1 {
		t.Errorf("Person vorgegeben: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (check_id, ends_at) VALUES ($1, now() + interval '7 days 1 minute')`, cid); n != -1 {
		t.Errorf("länger als 7 Tage: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (check_id, ends_at) VALUES ($1, now() - interval '1 minute')`, cid); n != -1 {
		t.Errorf("Ende in der Vergangenheit: %d", n)
	}
	if n := tryAs("v_fw", `INSERT INTO openwacht.maintenance (check_id, device_id, ends_at) VALUES ($1, NULL, now() + interval '1 hour'),
		(NULL, NULL, now() + interval '1 hour')`, cid); n != -1 {
		t.Errorf("ohne Ziel: %d", n)
	}
	if n := tryAs("v_fw", ins, cid); n != 1 {
		t.Fatalf("Fertigung setzt über SQL: %d", n)
	}
	var tenant, by, name string
	var recent bool
	owner.QueryRow(ctx, `SELECT tenant_id::text, created_by::text, created_by_name, starts_at > now() - interval '1 minute'
		FROM openwacht.maintenance WHERE check_id = $1`, cid).Scan(&tenant, &by, &name, &recent)
	if tenant != ids["Lager Nord"] || by != ids["v_fw"] || name != "v_fw" || !recent {
		t.Errorf("Wartung: %s %s %s %v", tenant, by, name, recent)
	}
	if n := tryAs("v_fw", ins, cid); n != -1 {
		t.Errorf("zweite Wartung für denselben Check: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.maintenance SET ends_at = now() + interval '30 days' WHERE check_id = $1`, cid); n != -1 {
		t.Errorf("Wartung geändert: %d", n)
	}
	if n := tryAs("v_oa", `DELETE FROM openwacht.maintenance WHERE check_id = $1`, cid); n != 0 {
		t.Errorf("Geschwister löscht: %d", n)
	}
	if n := tryAs("v_lz", `DELETE FROM openwacht.maintenance WHERE check_id = $1`, cid); n != 0 {
		t.Errorf("Leser löscht: %d", n)
	}
	// Abgelaufene räumt maintenance_active ab; nur laufende kommen zurück.
	owner.Exec(ctx, `UPDATE openwacht.maintenance SET starts_at = now() - interval '2 hours', ends_at = now() - interval '1 second'
		WHERE check_id = $1`, cid)
	var cnt, left int
	pool.QueryRow(ctx, `SELECT count(*) FROM openwacht.maintenance_active() WHERE check_id = $1`, cid).Scan(&cnt)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.maintenance WHERE check_id = $1`, cid).Scan(&left)
	if cnt != 0 || left != 0 {
		t.Errorf("abgelaufene Wartung: aktiv %d, übrig %d", cnt, left)
	}
}

// Alarme in der Wartung: keine Probleme, keine Erinnerungen, keine neuen
// Alarme im Protokoll; Entwarnungen ja; nach dem Ende sofort Alarm.
func TestWartungAlarme(t *testing.T) {
	cid, aid, _ := wartungZiele(t, "WA")
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
		VALUES ($1, $2, 'Wartung', $3, 'wa', false)`, chID, ids["Lager Nord"], server); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, chID) })
	record := func(status string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, 'x', '', NULL)`, cid, status).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	round := func(what string) []ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return f.take()["wa"]
	}
	maint := func(col, id string) {
		t.Helper()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.maintenance (`+col+`, ends_at) VALUES ($1, now() + interval '1 hour')`, id); err != nil {
			t.Fatal(err)
		}
	}
	dev := agentDevice(t, aid)
	unmaint := func() {
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE check_id = $1 OR device_id = $2`, cid, dev)
	}
	openAlarms := func() int {
		var n int
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE (check_id = $1 OR agent_id = $2) AND ended_at IS NULL`, cid, aid).Scan(&n)
		return n
	}
	expect := func(what string, got []ntfyMsg, title string) {
		t.Helper()
		if title == "" && len(got) != 0 || title != "" && (len(got) != 1 || got[0].Title != title) {
			t.Errorf("%s: %+v, erwartet „%s“", what, got, title)
		}
	}

	// Check fällt in der Wartung aus: still, kein Alarm im Protokoll.
	maint("check_id", cid)
	record("crit")
	record("crit")
	expect("Check in Wartung", round("1"), "")
	if n := openAlarms(); n != 0 {
		t.Errorf("Alarm in der Wartung eröffnet: %d", n)
	}
	// Wartung endet, Problem besteht: sofort Alarm.
	unmaint()
	expect("Wartung vorbei", round("2"), "Lager Nord: 1 Problem")
	if n := openAlarms(); n != 1 {
		t.Errorf("offene Alarme nach Wartung: %d", n)
	}
	// Bestehender Alarm, dann Wartung: keine Erinnerung, Entwarnung schon.
	maint("check_id", cid)
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	expect("Erinnerung in Wartung", round("3"), "")
	s.now = time.Now
	if n := openAlarms(); n != 1 {
		t.Errorf("laufender Alarm in Wartung beendet: %d", n)
	}
	record("ok")
	expect("Entwarnung in Wartung", round("4"), "Lager Nord: 1 wieder OK")
	if n := openAlarms(); n != 0 {
		t.Errorf("Alarm nach Entwarnung offen: %d", n)
	}
	unmaint()

	// Host: stumm in der Wartung des Geräts still, danach sofort.
	maint("device_id", dev)
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_seen = now() - interval '5 minutes' WHERE id = $1`, aid)
	expect("Host stumm in Wartung", round("5"), "")
	if n := openAlarms(); n != 0 {
		t.Errorf("Host-Alarm in der Wartung eröffnet: %d", n)
	}
	// Die Wartung eines Geräts gilt nicht für Checks anderer Geräte.
	record("crit")
	record("crit")
	expect("Check neben Host-Wartung", round("6"), "Lager Nord: 1 Problem")
	unmaint()
	got := round("7")
	if len(got) != 1 || !strings.Contains(got[0].Message, "meldet sich nicht") {
		t.Errorf("Host nach Wartung: %+v", got)
	}

	// Check am selben Gerät: Die Gerätewartung gilt auch für ihn.
	record("ok")
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_seen = now() WHERE id = $1`, aid)
	round("8")
	owner.Exec(ctx, `UPDATE openwacht.checks SET device_id = $2 WHERE id = $1`, cid, dev)
	maint("device_id", dev)
	record("crit")
	record("crit")
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_seen = now() - interval '5 minutes' WHERE id = $1`, aid)
	expect("Check und Host in Gerätewartung", round("9"), "")
	if sn := sensorenVon(t, "v_lz")[alarmKeyCheck(cid)]; sn == nil || sn["wartung"] == nil {
		t.Errorf("Check-Sensor ohne Gerätewartung: %+v", sn)
	}
	unmaint()
	got = round("10")
	if len(got) != 1 || !strings.Contains(got[0].Title, "2 Probleme") {
		t.Errorf("nach Gerätewartung: %+v", got)
	}
}

// CPU: Mittel über 15 Minuten aus den Rohwerten; erst mit 10 Minuten Werten.
func TestCPUAlarm(t *testing.T) {
	_, aid, _ := wartungZiele(t, "WC")
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
		VALUES ($1, $2, 'CPU', $3, 'wc', false)`, chID, ids["Lager Nord"], server); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, chID) })
	values := func(minutes []int, v float64) {
		t.Helper()
		owner.Exec(ctx, `DELETE FROM openwacht.metrics_host_raw WHERE agent_id = $1`, aid)
		for _, m := range minutes {
			if _, err := owner.Exec(ctx, `INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
				VALUES ($1, $2, now() - make_interval(mins => $3), 'cpu', $4)`, ids["Lager Nord"], aid, m, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	round := func() []ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatal(err)
		}
		return f.take()["wc"]
	}
	// Erst 5 Minuten Werte: noch nicht bewertet.
	values([]int{0, 1, 2, 3, 4, 5}, 99)
	if m := round(); len(m) != 0 {
		t.Errorf("zu kurze Reihe alarmiert: %+v", m)
	}
	// 12 Minuten bei 99 %: kritisch. Ältere Werte (20 min) zählen nicht.
	values([]int{0, 3, 6, 9, 12}, 99)
	owner.Exec(ctx, `INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
		VALUES ($1, $2, now() - interval '20 minutes', 'cpu', 0)`, ids["Lager Nord"], aid)
	m := round()
	if len(m) != 1 || !strings.Contains(m[0].Message, "wc-host · CPU: 99 % ausgelastet, Mittel 15 Min. (kritisch ab 98 %)") {
		t.Errorf("CPU kritisch: %+v", m)
	}
	sn := sensorenVon(t, "v_lz")["h:"+aid+"/cpu"]
	if sn == nil || sn["status"] != "crit" || sn["name"] != "CPU" || sn["alarm"] == nil {
		t.Errorf("CPU-Sensor: %+v", sn)
	}
	// 97 %: Hysterese hält kritisch (≥ 96), 95 %: Warnung, 50 %: wieder OK.
	values([]int{0, 6, 12}, 97)
	if m := round(); len(m) != 0 {
		t.Errorf("Hysterese: %+v", m)
	}
	values([]int{0, 6, 12}, 95)
	if m := round(); len(m) != 1 || !strings.Contains(m[0].Message, "(Warnung ab 90 %)") {
		t.Errorf("CPU Warnung: %+v", m)
	}
	values([]int{0, 6, 12}, 50)
	if m := round(); len(m) != 1 || !strings.Contains(m[0].Title, "wieder OK") {
		t.Errorf("CPU Entwarnung: %+v", m)
	}
	// Abgeschaltet (-cpu-warn 0 -cpu-krit 0): kein CPU-Sensor.
	cfg.CPUWarn, cfg.CPUCrit = -1, -1
	off, _ := New(cfg, pool, testKey)
	if l := off.cfg.hostLimits(); l.CPUWarn != 0 || l.CPUCrit != 0 {
		t.Errorf("CPU aus: %+v", l)
	}
	if r := off.alertRules(); r["cpu_warn"] != 0.0 || r["cpu_krit"] != 0.0 {
		t.Errorf("Regeln: %+v", r)
	}
}
