// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
	"time"
)

func windowBody(name, art, id string, extra map[string]any) map[string]any {
	b := map[string]any{"name": name, "ziel_art": art, "ziel_id": id, "wiederholung": "woechentlich",
		"wochentage": []int{2, 4}, "uhrzeit": "22:00", "dauer_min": 240, "zeitzone": "Europe/Berlin"}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func maintenanceOf(t *testing.T, column, id string) (until *time.Time, window *string) {
	t.Helper()
	owner.QueryRow(context.Background(), `SELECT ends_at, window_id::text FROM openwacht.maintenance WHERE `+column+` = $1`, id).
		Scan(&until, &window)
	return
}

// Fenster über die API: Rechte, Mandantentrennung, Prüfung der Eingaben.
func TestWartungsfensterAPI(t *testing.T) {
	check, _, op := wartungZiele(t, "WF")
	ctx := context.Background()
	var dev string
	owner.QueryRow(ctx, `SELECT device_id::text FROM openwacht.checks WHERE id = $1`, check).Scan(&dev)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance_windows WHERE device_id = $1 OR check_id = $2`, dev, check)
	})

	r := as(t, op).do("POST", "/api/v1/wartungsfenster", windowBody("Patchday", "geraet", dev,
		map[string]any{"wiederholung": "monatlich", "nter": 2, "wochentag": 2, "versatz": 1, "uhrzeit": "20:00", "dauer_min": 180}))
	expectStatus(t, "Operator legt an", r, 201)
	id := r.body["id"].(string)
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("POST", "/api/v1/wartungsfenster", windowBody("x", "geraet", dev, nil)), 403)
	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("POST", "/api/v1/wartungsfenster", windowBody("x", "geraet", dev, nil)), 404)
	expectStatus(t, "Eltern legt an (Sensor)", as(t, "v_fw").do("POST", "/api/v1/wartungsfenster", windowBody("Nachts", "sensor", check, nil)), 201)

	for name, bad := range map[string]map[string]any{
		"Zeitzone":      {"zeitzone": "Mars/Olympus"},
		"Dauer":         {"dauer_min": 8 * 24 * 60},
		"Uhrzeit":       {"uhrzeit": "25:00"},
		"Wochentag":     {"wochentage": []int{8}},
		"keine Tage":    {"wochentage": []int{}},
		"Vergangenheit": {"wiederholung": "einmalig", "beginn": "2020-01-01T00:00:00Z", "ende": "2020-01-01T02:00:00Z"},
		"zu lang":       {"wiederholung": "einmalig", "beginn": time.Now().Format(time.RFC3339), "ende": time.Now().Add(8 * 24 * time.Hour).Format(time.RFC3339)},
		"Ziel":          {"ziel_art": "mandant"},
	} {
		expectStatus(t, name, as(t, op).do("POST", "/api/v1/wartungsfenster", windowBody("x", "geraet", dev, bad)), 400)
	}

	// Übersicht: Leser im Mandanten sieht das Fenster, Geschwister nicht.
	for user, want := range map[string]bool{"v_lz": true, "v_fw": true, "v_it": true, "v_oa": false} {
		r := as(t, user).do("GET", "/api/v1/wartung", nil)
		expectStatus(t, "Übersicht "+user, r, 200)
		found := false
		for _, x := range r.body["fenster"].([]any) {
			w := x.(map[string]any)
			if w["id"] == id {
				found = true
				if w["text"] != "monatlich am 2. Dienstag + 1 Tag um 20:00 für 3 Std." || w["naechstes"] == nil || w["ziel_name"] != "Testgerät" {
					t.Errorf("Fenster: %v", w)
				}
			}
		}
		if found != want {
			t.Errorf("%s sieht Fenster: %v, erwartet %v", user, found, want)
		}
	}
	// Ändern und löschen: Leser und Geschwister nicht.
	upd := windowBody("Patchday neu", "geraet", dev, nil)
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/wartungsfenster/"+id, upd), 404)
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/wartungsfenster/"+id, upd), 404)
	expectStatus(t, "Operator ändert", as(t, op).do("PUT", "/api/v1/wartungsfenster/"+id, upd), 204)
	expectStatus(t, "Geschwister löscht", as(t, "v_oa").do("DELETE", "/api/v1/wartungsfenster/"+id, nil), 404)
	expectStatus(t, "Operator löscht", as(t, op).do("DELETE", "/api/v1/wartungsfenster/"+id, nil), 204)

	// Die Anwendung kann window_id nicht setzen.
	if _, err := pool.Exec(ctx, `INSERT INTO openwacht.maintenance (device_id, ends_at, window_id) VALUES ($1, now() + interval '1 hour', NULL)`, dev); err == nil {
		t.Error("Wartung ohne Benutzer angelegt")
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'wartungsfenster.%' AND details->>'id' = $1`, id).Scan(&audits)
	if audits != 3 {
		t.Errorf("Audit: %d Einträge, erwartet 3", audits)
	}
}

// Ein laufendes Fenster wird zur Wartung: Gruppe mit Untergruppen,
// dynamisch, vorzeitig beendet bleibt beendet, geändert beginnt neu.
func TestWartungsfensterAbgleich(t *testing.T) {
	_, _, op := wartungZiele(t, "WG")
	ctx := context.Background()
	tenant := ids["Lager Nord"]
	var g1, g2, d1, d2, d3 string
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'WG Server') RETURNING id::text`, tenant).Scan(&g1)
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, parent_id, name) VALUES ($1, $2, 'WG Windows') RETURNING id::text`, tenant, g1).Scan(&g2)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, 'wg-a', $2) RETURNING id::text`, tenant, g1).Scan(&d1)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, 'wg-b', $2) RETURNING id::text`, tenant, g2).Scan(&d2)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance_windows WHERE group_id IN ($1, $2)`, g1, g2)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'wg-%'`)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id = $1`, g2)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id = $1`, g1)
	})
	start := time.Now().Add(-time.Minute).UTC()
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Minute)
	r := as(t, op).do("POST", "/api/v1/wartungsfenster", windowBody("Jetzt", "gruppe", g1, map[string]any{
		"wiederholung": "einmalig", "beginn": start.Format(time.RFC3339), "ende": end.Format(time.RFC3339), "grund": "Umbau"}))
	expectStatus(t, "Gruppenfenster", r, 201)
	wid := r.body["id"].(string)
	if _, err := vServer.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{d1, d2} {
		until, w := maintenanceOf(t, "device_id", d)
		if until == nil || !until.Equal(end) || w == nil || *w != wid {
			t.Errorf("Gerät %s: Wartung bis %v aus %v", d, until, w)
		}
	}
	var by, reason string
	owner.QueryRow(ctx, `SELECT created_by_name, reason FROM openwacht.maintenance WHERE device_id = $1`, d1).Scan(&by, &reason)
	if by != "Wartungsfenster „Jetzt“" || reason != "Umbau" {
		t.Errorf("Wartung: %q %q", by, reason)
	}
	// Ohne Untergruppen: nur die Gruppe selbst (nach Änderung neu angelegt).
	r = as(t, op).do("PUT", "/api/v1/wartungsfenster/"+wid, windowBody("Jetzt", "gruppe", g1, map[string]any{
		"wiederholung": "einmalig", "beginn": start.Format(time.RFC3339), "ende": end.Format(time.RFC3339), "untergruppen": false}))
	expectStatus(t, "ohne Untergruppen", r, 204)
	if u, _ := maintenanceOf(t, "device_id", d1); u != nil {
		t.Error("Änderung hat die laufende Wartung nicht beendet")
	}
	vServer.alertRoundN(ctx)
	if u, _ := maintenanceOf(t, "device_id", d1); u == nil {
		t.Error("Gruppe selbst nicht in Wartung")
	}
	if u, _ := maintenanceOf(t, "device_id", d2); u != nil {
		t.Error("Untergruppe trotz „ohne Untergruppen“")
	}
	// Dynamisch: neues Gerät in der Gruppe kommt im nächsten Durchlauf dazu.
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, 'wg-c', $2) RETURNING id::text`, tenant, g1).Scan(&d3)
	vServer.alertRoundN(ctx)
	if u, _ := maintenanceOf(t, "device_id", d3); u == nil {
		t.Error("neues Gerät nicht in Wartung")
	}
	// Vorzeitig beendet: bleibt beendet, bis das Vorkommen vorbei ist.
	expectStatus(t, "beenden", as(t, op).do("DELETE", "/api/v1/geraete/"+d1+"/wartung", nil), 204)
	vServer.alertRoundN(ctx)
	if u, _ := maintenanceOf(t, "device_id", d1); u != nil {
		t.Error("beendete Wartung wieder angelegt")
	}
	// Eine Wartung von Hand hat Vorrang und wird nicht überschrieben.
	expectStatus(t, "Wartung von Hand", as(t, op).do("PUT", "/api/v1/geraete/"+d3+"/wartung", map[string]any{"minuten": 30, "grund": "Hand"}), 200)
	vServer.alertRoundN(ctx)
	if _, w := maintenanceOf(t, "device_id", d3); w != nil {
		t.Error("Wartung von Hand durch Fenster ersetzt")
	}
	// Pausiert: Wartungen aus dem Fenster enden sofort.
	r = as(t, op).do("PUT", "/api/v1/wartungsfenster/"+wid, windowBody("Jetzt", "gruppe", g1, map[string]any{
		"wiederholung": "einmalig", "beginn": start.Format(time.RFC3339), "ende": end.Format(time.RFC3339), "aktiv": false}))
	expectStatus(t, "pausieren", r, 204)
	vServer.alertRoundN(ctx)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.maintenance WHERE window_id = $1`, wid).Scan(&n)
	if n != 0 {
		t.Errorf("%d Wartungen trotz Pause", n)
	}
	// Übersicht zeigt die laufende Wartung von Hand.
	r = as(t, "v_lz").do("GET", "/api/v1/wartung", nil)
	found := false
	for _, x := range r.body["laufend"].([]any) {
		if m := x.(map[string]any); m["geraet_id"] == d3 && m["grund"] == "Hand" {
			found = true
		}
	}
	if !found {
		t.Error("laufende Wartung fehlt in der Übersicht")
	}
	// Löschen des Fensters entfernt seine Wartungen (Kaskade) ohne Fehler.
	expectStatus(t, "löschen", as(t, op).do("DELETE", "/api/v1/wartungsfenster/"+wid, nil), 204)
}

// „Platte voll in < N Tagen“ im Alarmprotokoll, mit Schwelle je Mandant.
func TestPlatteVollAlarm(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	// 240 Stunden von 40 % auf 76 %: +3,6 Punkte je Tag → voll in etwa 6 Tagen.
	agent := forecastAgent(t, "v_oa", "Organisation", "pv-host", 240, map[string]func(int) float64{
		"/daten": func(h int) float64 { return 40 + float64(h)*0.15 },
	})
	if _, err := owner.Exec(ctx, `UPDATE openwacht.agents SET snapshot = $2, last_seen = now() WHERE id = $1`,
		agent, hostSnapshot(t, 40, map[string]int{"/daten": 76})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE agent_id = $1`, agent)
		owner.Exec(ctx, `DELETE FROM openwacht.tenant_settings WHERE tenant_id = $1`, ids["Organisation"])
	})
	open := func() (string, string) {
		t.Helper()
		var st, msg string
		owner.QueryRow(ctx, `SELECT status, message FROM openwacht.alarms WHERE agent_id = $1 AND subject = 'platte:/daten' AND ended_at IS NULL`,
			agent).Scan(&st, &msg)
		return st, msg
	}
	s, err := New(vServer.cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	if st, msg := open(); st != "warn" || !strings.Contains(msg, "voll in etwa") || !strings.Contains(msg, "Warnung unter 14 Tagen") {
		t.Fatalf("Alarm: %q %q", st, msg)
	}
	// Mandant schaltet aus (0): Alarm endet.
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.tenant_settings (tenant_id, disk_days) VALUES ($1, 0)`, ids["Organisation"]); err != nil {
		t.Fatal(err)
	}
	s2, _ := New(vServer.cfg, pool, testKey)
	if err := s2.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if l := s2.limitsFor("agent", agent); l.DiskDays != 0 {
		t.Fatalf("Schwelle je Mandant: %v", l.DiskDays)
	}
	s2.alertRoundN(ctx)
	if st, _ := open(); st != "" {
		t.Errorf("trotz 0 noch offen: %q", st)
	}
	// Ungültige Schwellen (dieselbe Prüfung für global, Mandant, Gerät).
	for _, v := range []float64{-1, 366, 2.5} {
		if _, err := s.parseLimits(map[string]*float64{"platte_tage": &v}); err == nil {
			t.Errorf("platte_tage %v angenommen", v)
		}
	}
	ok := 30.0
	if l, err := s.parseLimits(map[string]*float64{"platte_tage": &ok}); err != nil || *l[7] != 30 {
		t.Errorf("platte_tage 30: %v", err)
	}
}
