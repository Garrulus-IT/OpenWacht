// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

// TestFehlversuche (1.0.6): Standard 3 Fehlschläge bis zum Alarm, je Sensor
// 1 bis 10 einstellbar, über Vorlagen übernommen; Warnungen sofort.
func TestFehlversuche(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertThreshold = 0 // Standard der Zentrale
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.AlertThreshold != 3 {
		t.Fatalf("Standard: %d", s.cfg.AlertThreshold)
	}
	server, _ := alarm.NormalizeServer(f.URL)

	var tid, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Fehlversuche') RETURNING id::text`,
		ids["IT"]).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, tid)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tid)
	})
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'fv-gerät') RETURNING id::text`, tid).
		Scan(&dev); err != nil {
		t.Fatal(err)
	}
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'fv', $3, 'fv')`,
		chID, tid, server); err != nil {
		t.Fatal(err)
	}

	admin := as(t, "v_it")
	create := func(name string, body map[string]any) string {
		t.Helper()
		body["name"], body["typ"] = name, "ping"
		body["ziel"] = map[string]any{"host": "fv.lan"}
		r := admin.do("POST", "/api/v1/geraete/"+dev+"/checks", body)
		if r.status != 201 {
			t.Fatalf("%s anlegen: %d %s", name, r.status, r.raw)
		}
		return r.body["id"].(string)
	}
	standard := create("Standard", map[string]any{})
	einer := create("Einer", map[string]any{"fehlversuche": 1})
	for _, bad := range []int{-1, 11} {
		r := admin.do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{"name": "x", "typ": "ping",
			"ziel": map[string]any{"host": "fv.lan"}, "fehlversuche": bad})
		expectStatus(t, "fehlversuche ungültig", r, 400)
	}

	gilt := func() map[string]float64 {
		t.Helper()
		r := admin.do("GET", "/api/v1/checks?mandant="+tid, nil)
		out := map[string]float64{}
		for _, x := range r.body["checks"].([]any) {
			c := x.(map[string]any)
			out[c["name"].(string)] = c["fehlversuche_gilt"].(float64)
		}
		return out
	}
	// Die API läuft über den gemeinsamen Testserver; „gilt“ zeigt dessen Standard.
	std := float64(vServer.cfg.AlertThreshold)
	if g := gilt(); g["Standard"] != std || g["Einer"] != 1 {
		t.Errorf("geltende Fehlversuche: %v", g)
	}

	record := func(id, status string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, 'keine Antwort', '', NULL)`, id, status).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	round := func() []ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatal(err)
		}
		return f.take()["fv"]
	}

	record(einer, "crit")
	record(standard, "crit")
	if m := round(); len(m) != 1 || m[0].Title != "Fehlversuche: 1 Problem" {
		t.Fatalf("nach 1 Fehlschlag (nur „Einer“): %+v", m)
	}
	record(standard, "crit")
	if m := round(); len(m) != 0 {
		t.Fatalf("nach 2 Fehlschlägen schon gemeldet: %+v", m)
	}
	record(standard, "crit")
	if m := round(); len(m) != 1 {
		t.Fatalf("nach 3 Fehlschlägen nicht gemeldet: %+v", m)
	}

	// Ändern: ohne Feld bleibt der Wert, 0 setzt auf Standard, 5 gilt.
	update := func(id, name string, body map[string]any) {
		t.Helper()
		body["name"], body["typ"] = name, "ping"
		body["ziel"] = map[string]any{"host": "fv.lan"}
		if r := admin.do("PUT", "/api/v1/checks/"+id, body); r.status != 204 {
			t.Fatalf("%s ändern: %d %s", name, r.status, r.raw)
		}
	}
	update(einer, "Einer", map[string]any{})
	update(standard, "Standard", map[string]any{"fehlversuche": 5})
	if g := gilt(); g["Einer"] != 1 || g["Standard"] != 5 {
		t.Errorf("nach Ändern: %v", g)
	}
	update(einer, "Einer", map[string]any{"fehlversuche": 0})
	if g := gilt(); g["Einer"] != std {
		t.Errorf("zurück auf Standard: %v", g)
	}

	// Vorlage trägt den Wert, Anwenden übernimmt ihn.
	r := admin.do("POST", "/api/v1/mandanten/"+tid+"/sensor-vorlagen", map[string]any{"name": "Ping geduldig", "typ": "ping",
		"ziel": map[string]any{"host": "{adresse}"}, "fehlversuche": 7})
	if r.status != 201 {
		t.Fatalf("Vorlage: %d %s", r.status, r.raw)
	}
	vid := r.body["id"].(string)
	owner.Exec(ctx, `UPDATE openwacht.devices SET address = 'fv2.lan' WHERE id = $1`, dev)
	if r := admin.do("POST", "/api/v1/sensor-vorlagen/anwenden", map[string]any{"vorlage_id": vid, "geraete": []string{dev}}); r.status != 200 {
		t.Fatalf("Anwenden: %d %s", r.status, r.raw)
	}
	var n *int
	if err := owner.QueryRow(ctx, `SELECT fail_threshold FROM openwacht.checks WHERE device_id = $1 AND origin = 'Ping geduldig'`, dev).
		Scan(&n); err != nil || n == nil || *n != 7 {
		t.Errorf("Fehlversuche aus der Vorlage: %v %v", n, err)
	}
}
