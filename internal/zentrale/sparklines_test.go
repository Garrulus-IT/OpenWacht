// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
)

func TestSparklinesJeGeraet(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	agent := forecastAgent(t, "v_fw", "Lager Nord", "sp-lz", 30, map[string]func(int) float64{
		"/": func(h int) float64 { return 40 + float64(h)/10 },
	})
	var dev string
	owner.QueryRow(ctx, `SELECT device_id::text FROM openwacht.agents WHERE id = $1`, agent).Scan(&dev)
	// 5-Minuten-Werte der letzten Stunden (die Sparklines lesen die 5-Minuten-Stufe)
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.metrics_host_5m (tenant_id, agent_id, bucket, series, avg, min, max, n)
		SELECT $1, $2, date_bin('5 minutes', now(), timestamptz 'epoch') - make_interval(mins => 5 * k), s.series, 20 + k, 20 + k, 20 + k, 1
		  FROM generate_series(2, 60) k, (VALUES ('cpu'), ('platte:/')) s(series)`, ids["Lager Nord"], agent); err != nil {
		t.Fatal(err)
	}
	r := as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{
		"name": "SP Dienst", "typ": "tcp", "ziel": map[string]any{"host": "nas.lan", "port": 5001}, "intervall_sekunden": 60})
	expectStatus(t, "Check", r, 201)
	check := r.body["id"].(string)
	// Ein Check an einem anderen Gerät desselben Mandanten gehört nicht dazu.
	expectStatus(t, "anderer Check", newCheck(t, "v_fw", "Lager Nord", "SP anderes Gerät"), 201)
	for _, st := range []string{"ok", "crit", "ok"} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, 'Meldung', '', 12)`, check, st).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	// SNMP-Quelle am selben Gerät mit Verkehr einer Schnittstelle
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("sp-lz.lan", nil))
	expectStatus(t, "SNMP", r, 201)
	snmpID := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, snmpID) })
	var rev int
	owner.QueryRow(ctx, `SELECT revision FROM openwacht.snmp_sources WHERE id = $1`, snmpID).Scan(&rev)
	var stored bool
	if err := pool.QueryRow(ctx, `SELECT openwacht.snmp_record($1, $2, true, '', '{"system":{}}', false,
		ARRAY['if_ein:Port 1', 'if_aus:Port 1'], ARRAY[1e6, 2e6])`, snmpID, rev).Scan(&stored); err != nil || !stored {
		t.Fatalf("SNMP speichern: %v %v", stored, err)
	}

	path := "/api/v1/geraete/" + dev + "/sparklines"
	for user, want := range map[string]int{"v_lz": 200, "v_fw": 200, "v_it": 200, "v_oa": 404, "v_oa_user": 404} {
		r := as(t, user).do("GET", path, nil)
		expectStatus(t, user, r, want)
		if want != 200 {
			for _, leak := range []string{"reihen", "punkte", agent, snmpID, check} {
				if strings.Contains(r.raw, leak) {
					t.Errorf("%s bekommt %q eines fremden Geräts", user, leak)
				}
			}
			continue
		}
		if r.body["spanne_s"] != 86400.0 || r.body["schritt_s"] != 1800.0 {
			t.Errorf("%s: Spanne/Schritt %v/%v", user, r.body["spanne_s"], r.body["schritt_s"])
		}
		a, _ := r.body["agent"].(map[string]any)
		if a == nil || a["id"] != agent {
			t.Fatalf("%s: Agent fehlt: %s", user, r.raw)
		}
		series := historySeries(t, response{body: map[string]any{"reihen": a["reihen"]}})
		if len(series["cpu"]) == 0 || len(series["platte:/"]) == 0 {
			t.Errorf("%s: Reihen cpu/platte:/ fehlen: %v", user, a["reihen"])
		}
		// 30-Minuten-Schritte: höchstens 49 Punkte in 24 Stunden
		if n := len(series["cpu"]); n > 49 {
			t.Errorf("%s: %d CPU-Punkte", user, n)
		}
		q, _ := r.body["snmp"].(map[string]any)
		if q == nil || q["id"] != snmpID || !strings.Contains(r.raw, `"if_aus:Port 1"`) {
			t.Errorf("%s: SNMP fehlt: %v", user, q)
		}
		cs := r.body["checks"].([]any)
		if len(cs) != 1 || cs[0].(map[string]any)["id"] != check {
			t.Fatalf("%s: Checks %v", user, cs)
		}
		var n, okN float64
		for _, p := range cs[0].(map[string]any)["punkte"].([]any) {
			n += p.(map[string]any)["n"].(float64)
			okN += p.(map[string]any)["ok"].(float64)
		}
		if n != 3 || okN != 2 {
			t.Errorf("%s: Check-Punkte n=%v ok=%v", user, n, okN)
		}
	}
	expectStatus(t, "ungültige ID", as(t, "v_fw").do("GET", "/api/v1/geraete/xyz/sparklines", nil), 400)
	expectStatus(t, "unbekanntes Gerät", as(t, "v_it").do("GET", "/api/v1/geraete/00000000-0000-4000-8000-000000000000/sparklines", nil), 404)

	// Gesperrter Agent: keine Sparklines mehr für ihn.
	owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, agent)
	r = as(t, "v_fw").do("GET", path, nil)
	expectStatus(t, "nach Sperre", r, 200)
	if r.body["agent"] != nil {
		t.Errorf("gesperrter Agent liefert noch Sparklines: %v", r.body["agent"])
	}
}
