// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

func TestBereitschaftZeitfenster(t *testing.T) {
	loc := time.UTC
	at := func(day, hh, mm int) time.Time { return time.Date(2026, 11, 16+day-1, hh, mm, 0, 0, loc) } // 16.11.2026 = Montag
	buero := activeHours{Tage: []int{1, 2, 3, 4, 5}, Von: "07:00", Bis: "17:00"}
	nacht := activeHours{Tage: []int{5}, Von: "22:00", Bis: "06:00"} // Freitagnacht
	for _, c := range []struct {
		a    activeHours
		t    time.Time
		want bool
	}{
		{buero, at(1, 7, 0), true}, {buero, at(1, 16, 59), true}, {buero, at(1, 17, 0), false}, {buero, at(1, 6, 59), false},
		{buero, at(6, 10, 0), false}, {nacht, at(5, 23, 0), true}, {nacht, at(6, 5, 59), true}, {nacht, at(6, 6, 0), false},
		{nacht, at(5, 5, 0), false}, {nacht, at(4, 23, 0), false},
	} {
		if got := c.a.active(c.t); got != c.want {
			t.Errorf("%+v um %s: %v", c.a, c.t.Format("Mon 15:04"), got)
		}
	}
	for _, bad := range []activeHours{{Tage: nil, Von: "07:00", Bis: "08:00"}, {Tage: []int{8}, Von: "07:00", Bis: "08:00"},
		{Tage: []int{1}, Von: "7:00", Bis: "08:00"}, {Tage: []int{1}, Von: "08:00", Bis: "08:00"}, {Tage: []int{1}, Von: "24:00", Bis: "08:00"}} {
		if bad.check() == nil {
			t.Errorf("%+v angenommen", bad)
		}
	}
}

func TestAbhaengigkeitenUndEskalation(t *testing.T) {
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
	var ta string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Abh A') RETURNING id::text`, ids["IT"]).Scan(&ta); err != nil {
		t.Fatal(err)
	}
	channel := func(name, topic string) string {
		id, _ := newUUID()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, $3, $4, $5)`,
			id, ta, name, server, topic); err != nil {
			t.Fatal(err)
		}
		return id
	}
	chHaupt := channel("Haupt", "haupt")
	chChef := channel("Chef", "chef")
	device := func(name string) (dev, check string) {
		if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, 'Ping', 'ping', '{"host":"x.lan"}', 60 FROM d
			RETURNING device_id::text, id::text`, ta, name).Scan(&dev, &check); err != nil {
			t.Fatal(err)
		}
		return
	}
	router, cRouter := device("Router")
	srv, cSrv := device("Server")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, ta)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, ta)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, ta)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, ta)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, ta)
	})
	record := func(id, status string) {
		t.Helper()
		for range 2 {
			if _, err := pool.Exec(ctx, `SELECT openwacht.check_record($1, 1, $2, 'test', '', NULL)`, id, status); err != nil {
				t.Fatal(err)
			}
		}
	}
	round := func() map[string][]ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatal(err)
		}
		return f.take()
	}
	it := as(t, "v_it")
	setParent := func(dev, name, parent string) response {
		return it.do("PUT", "/api/v1/geraete/"+dev, map[string]any{"name": name, "adresse": "", "abhaengig_von": parent})
	}

	// Abhängigkeit: Prüfungen
	expectStatus(t, "Server hängt am Router", setParent(srv, "Server", router), 204)
	if r := setParent(router, "Router", srv); r.status != 400 || !strings.Contains(r.raw, "Kreis") {
		t.Errorf("Kreis: %d %s", r.status, r.raw)
	}
	var fremd string
	owner.QueryRow(ctx, `SELECT id::text FROM openwacht.devices WHERE tenant_id = $1 LIMIT 1`, ids["Fertigung"]).Scan(&fremd)
	if fremd == "" {
		owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'abh-fremd') RETURNING id::text`, ids["Fertigung"]).Scan(&fremd)
		t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, fremd) })
	}
	expectStatus(t, "Elterngerät anderer Mandant", setParent(srv, "Server", fremd), 400)
	expectStatus(t, "Leser setzt Abhängigkeit", as(t, "v_lz").do("PUT", "/api/v1/geraete/"+srv,
		map[string]any{"name": "Server", "abhaengig_von": ""}), 404)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.devices SET parent_id = $1 WHERE id = $2`, fremd, router); err == nil {
		t.Error("DB: Elterngerät aus anderem Mandanten")
	}

	// Router fällt aus: Alarm. Danach fällt der Server aus: kein eigener Alarm.
	record(cRouter, "crit")
	if got := round(); len(got["haupt"]) != 1 || !strings.Contains(got["haupt"][0].Message, "Router") {
		t.Fatalf("Router-Alarm: %+v", got)
	}
	record(cSrv, "crit")
	if got := round(); len(got) != 0 {
		t.Errorf("Server trotz Abhängigkeit gemeldet: %+v", got)
	}
	var open int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE check_id = $1 AND ended_at IS NULL`, cSrv).Scan(&open)
	if open != 0 {
		t.Error("Alarmprotokoll: Server-Alarm trotz Abhängigkeit")
	}
	l := it.do("GET", "/api/v1/geraete?mandant="+ta, nil)
	if !strings.Contains(l.raw, `"nicht_erreichbar_wegen":"Router"`) {
		t.Errorf("Hinweis fehlt: %s", l.raw)
	}

	// Eskalation: Prüfungen, dann unbestätigt nach 5 Min. an Chef
	esk := func(user, ch string, body map[string]any) response {
		return as(t, user).do("PUT", "/api/v1/alarm-kanaele/"+ch+"/zustellung", body)
	}
	var fwChannel string
	owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, server, topic) VALUES ($1, 'abh-fw', $2, 'fw') RETURNING id::text`,
		ids["Fertigung"], server).Scan(&fwChannel)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, fwChannel) })
	for name, b := range map[string]map[string]any{
		"zu früh":         {"eskalation": map[string]any{"nach_minuten": 1, "kanal": chChef}},
		"anderer Mandant": {"eskalation": map[string]any{"nach_minuten": 10, "kanal": fwChannel}},
		"sich selbst":     {"eskalation": map[string]any{"nach_minuten": 10, "kanal": chHaupt}},
		"Uhrzeit":         {"bereitschaft": map[string]any{"tage": []int{1}, "von": "25:00", "bis": "08:00"}},
	} {
		expectStatus(t, name, esk("v_it", chHaupt, b), 400)
	}
	expectStatus(t, "Geschwister", esk("v_oa", chHaupt, map[string]any{}), 404)
	expectStatus(t, "Eskalation an", esk("v_it", chHaupt, map[string]any{"eskalation": map[string]any{"nach_minuten": 5, "kanal": chChef}}), 200)
	if got := round(); len(got) != 0 {
		t.Errorf("Eskalation vor Ablauf: %+v", got)
	}
	owner.Exec(ctx, `UPDATE openwacht.alarms SET started_at = now() - interval '6 minutes' WHERE check_id = $1 AND ended_at IS NULL`, cRouter)
	// Chef hat gerade keine Bereitschaft: wartet
	loc := s.mailZone()
	h := time.Now().In(loc).Add(2 * time.Hour)
	off := map[string]any{"tage": []int{1, 2, 3, 4, 5, 6, 7}, "von": h.Format("15:04"), "bis": h.Add(time.Hour).Format("15:04")}
	expectStatus(t, "Bereitschaft Chef", esk("v_it", chChef, map[string]any{"bereitschaft": off}), 200)
	if got := round(); len(got) != 0 {
		t.Errorf("Eskalation außerhalb der Bereitschaft: %+v", got)
	}
	expectStatus(t, "Bereitschaft aus", esk("v_it", chChef, map[string]any{}), 200)
	got := round()
	if len(got["chef"]) != 1 || !strings.Contains(got["chef"][0].Message, "Eskalation (Haupt") || len(got) != 1 {
		t.Fatalf("Eskalation: %+v", got)
	}
	if got := round(); len(got) != 0 {
		t.Errorf("Eskalation doppelt: %+v", got)
	}
	// Liste zeigt die Einstellungen
	lc := it.do("GET", "/api/v1/alarm-kanaele?mandant="+ta, nil)
	if !strings.Contains(lc.raw, fmt.Sprintf(`"eskalation":{"nach_minuten":5,"kanal":"%s"}`, chChef)) {
		t.Errorf("Liste: %s", lc.raw)
	}
	// Bestätigt: keine Eskalation; Router wieder da: Server meldet sich
	record(cRouter, "ok")
	got = round()
	if len(got["haupt"]) != 1 || !strings.Contains(got["haupt"][0].Title, "wieder OK") {
		t.Errorf("Entwarnung Router: %+v", got)
	}
	record(cSrv, "crit")
	got = round()
	if len(got["haupt"]) != 1 || !strings.Contains(got["haupt"][0].Message, "Server") {
		t.Errorf("Server nach Entwarnung des Routers: %+v", got)
	}
	owner.Exec(ctx, `UPDATE openwacht.alarms SET started_at = now() - interval '6 minutes', ack_at = now(), ack_by_name = 'Test'
		WHERE check_id = $1 AND ended_at IS NULL`, cSrv)
	if got := round(); len(got) != 0 {
		t.Errorf("bestätigt eskaliert: %+v", got)
	}
	// Bereitschaft des Hauptkanals: außerhalb bleibt die Meldung liegen und kommt später
	expectStatus(t, "Haupt außerhalb", esk("v_it", chHaupt, map[string]any{"bereitschaft": off}), 200)
	record(cSrv, "ok")
	if got := round(); len(got["haupt"]) != 0 || len(got["chef"]) != 1 {
		t.Errorf("außerhalb gesendet: %+v", got)
	}
	expectStatus(t, "Haupt immer", esk("v_it", chHaupt, map[string]any{}), 200)
	if got := round(); len(got["haupt"]) != 1 {
		t.Errorf("nachgeholt: %+v", got)
	}
}
