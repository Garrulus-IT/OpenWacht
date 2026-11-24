// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

func trapRuleBody(tenant, name, oid, action string, extra map[string]any) map[string]any {
	b := map[string]any{"mandant_id": tenant, "name": name, "trap_oid": oid, "wirkung": action}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func ruleVisible(t *testing.T, user, id string) bool {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/trapregeln", nil)
	expectStatus(t, "Regeln lesen", r, 200)
	for _, x := range r.body["regeln"].([]any) {
		if x.(map[string]any)["id"] == id {
			return true
		}
	}
	return false
}

func TestTrapRegelnMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	fw, lz := ids["Fertigung"], ids["Lager Nord"]
	// Anlegen: Admins im eigenen Teilbaum, Eltern beim Kind; Geschwister sehen den Mandanten nicht.
	r := as(t, "v_fw").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "TR Port getrennt", "1.3.6.1.6.3.1.1.5.3", "crit",
		map[string]any{"schluessel_oid": ".1.3.6.1.2.1.2.2.1.1", "dauer_minuten": 0}))
	expectStatus(t, "Fertigung legt an", r, 201)
	down := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE tenant_id IN ($1, $2)`, fw, lz) })
	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "x", "*", "warn", nil)), 404)
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("POST", "/api/v1/trapregeln", trapRuleBody(lz, "x", "*", "warn", nil)), 403)
	_, _, op := wartungZiele(t, "TR")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("POST", "/api/v1/trapregeln", trapRuleBody(lz, "x", "*", "warn", nil)), 403)
	r = as(t, "v_it").do("POST", "/api/v1/trapregeln", trapRuleBody(lz, "TR LZ alle", "*", "warn", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzRule := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if got := ruleVisible(t, user, down); got != want {
			t.Errorf("%s sieht Fertigung-Regel: %v", user, got)
		}
	}
	if !ruleVisible(t, "v_lz", lzRule) {
		t.Error("Lager sieht die eigene Regel nicht")
	}
	// Ändern und Löschen
	upd := trapRuleBody("", "TR LZ alle", "*", "crit", nil)
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/trapregeln/"+lzRule, upd), 404)
	expectStatus(t, "Operator ändert", opc.do("PUT", "/api/v1/trapregeln/"+lzRule, upd), 403)
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/trapregeln/"+lzRule, upd), 403)
	expectStatus(t, "Eltern ändern", as(t, "v_fw").do("PUT", "/api/v1/trapregeln/"+lzRule, upd), 200)
	expectStatus(t, "Kind ändert Eltern-Regel", as(t, "v_lz").do("PUT", "/api/v1/trapregeln/"+down, upd), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", "/api/v1/trapregeln/"+lzRule, nil), 403)

	// Eingabeprüfung
	for name, body := range map[string]map[string]any{
		"OID":              trapRuleBody(fw, "x", "1.3.x", "warn", nil),
		"Wirkung":          trapRuleBody(fw, "x", "*", "boom", nil),
		"Entwarnung ohne":  trapRuleBody(fw, "x", "*", "ok", nil),
		"beendet bei warn": trapRuleBody(fw, "x", "*", "warn", map[string]any{"beendet": down}),
		"Vergleich":        trapRuleBody(fw, "x", "*", "warn", map[string]any{"wert_oid": "1.2", "wert_vergleich": "regex", "wert": "x"}),
		"Dauer":            trapRuleBody(fw, "x", "*", "warn", map[string]any{"dauer_minuten": 50000}),
		"beides":           trapRuleBody(fw, "x", "*", "warn", map[string]any{"gruppe_id": down, "geraet_id": down}),
		"ignore mit key":   trapRuleBody(fw, "x", "*", "ignore", map[string]any{"schluessel_oid": "1.2"}),
		"Name":             trapRuleBody(fw, "", "*", "warn", nil),
	} {
		expectStatus(t, name, as(t, "v_fw").do("POST", "/api/v1/trapregeln", body), 400)
	}
	// Entwarnung muss eine Regel desselben Mandanten beenden.
	expectStatus(t, "Entwarnung fremder Mandant", as(t, "v_it").do("POST", "/api/v1/trapregeln",
		trapRuleBody(lz, "x", "1.3.6.1.6.3.1.1.5.4", "ok", map[string]any{"beendet": down})), 400)
	r = as(t, "v_fw").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "TR Port verbunden", "1.3.6.1.6.3.1.1.5.4", "ok",
		map[string]any{"beendet": down, "schluessel_oid": "1.3.6.1.2.1.2.2.1.1"}))
	expectStatus(t, "Entwarnung", r, 201)
	up := r.body["id"].(string)
	expectStatus(t, "Ziel einer Entwarnung löschen", as(t, "v_fw").do("DELETE", "/api/v1/trapregeln/"+down, nil), 409)
	expectStatus(t, "Ziel einer Entwarnung auf ignore", as(t, "v_fw").do("PUT", "/api/v1/trapregeln/"+down,
		trapRuleBody("", "TR Port getrennt", "1.3.6.1.6.3.1.1.5.3", "ignore", nil)), 400)

	// Eingrenzung: Gruppe/Gerät eines anderen Mandanten wird abgelehnt.
	var grpOA, grpFW, devFW string
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'TR Gruppe') RETURNING id::text`, ids["Organisation"]).Scan(&grpOA)
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'TR Gruppe') RETURNING id::text`, fw).Scan(&grpFW)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'TR Gerät') RETURNING id::text`, fw).Scan(&devFW)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE tenant_id = $1`, fw)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, devFW)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id IN ($1, $2)`, grpOA, grpFW)
	})
	expectStatus(t, "fremde Gruppe", as(t, "v_it").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "x", "*", "warn",
		map[string]any{"gruppe_id": grpOA})), 400)
	r = as(t, "v_fw").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "TR Gruppe", "*", "warn", map[string]any{"gruppe_id": grpFW}))
	expectStatus(t, "eigene Gruppe", r, 201)
	r = as(t, "v_fw").do("POST", "/api/v1/trapregeln", trapRuleBody(fw, "TR Gerät", "*", "warn", map[string]any{"geraet_id": devFW}))
	expectStatus(t, "eigenes Gerät", r, 201)
	// Gruppe oder Gerät mit Regel löschen: Konflikt mit Hinweis.
	res := as(t, "v_fw").do("DELETE", "/api/v1/gruppen/"+grpFW, nil)
	expectStatus(t, "Gruppe mit Regel löschen", res, 409)
	if !strings.Contains(res.raw, "Trap-Regel") {
		t.Errorf("Meldung: %s", res.raw)
	}
	expectStatus(t, "Gerät mit Regel löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+devFW, nil), 409)

	// Reihenfolge: vollständige Liste, nur Admins.
	list := as(t, "v_fw").do("GET", "/api/v1/trapregeln?mandant="+fw, nil)
	var order []string
	for _, x := range list.body["regeln"].([]any) {
		order = append(order, x.(map[string]any)["id"].(string))
	}
	if len(order) != 4 || order[0] != down || order[1] != up {
		t.Fatalf("Reihenfolge: %v", order)
	}
	rev := []string{order[3], order[2], order[1], order[0]}
	expectStatus(t, "unvollständig", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+fw+"/trapregeln/reihenfolge",
		map[string]any{"ids": rev[:3]}), 409)
	expectStatus(t, "Geschwister ordnet", as(t, "v_oa").do("POST", "/api/v1/mandanten/"+fw+"/trapregeln/reihenfolge",
		map[string]any{"ids": rev}), 409)
	expectStatus(t, "ordnen", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+fw+"/trapregeln/reihenfolge",
		map[string]any{"ids": rev}), 204)
	list = as(t, "v_fw").do("GET", "/api/v1/trapregeln?mandant="+fw, nil)
	if first := list.body["regeln"].([]any)[0].(map[string]any)["id"]; first != rev[0] {
		t.Errorf("erste Regel nach Ordnen: %v", first)
	}
	if list.body["engine_id"] == "" || !strings.HasPrefix(list.body["engine_id"].(string), "8000000005") {
		t.Errorf("Engine-ID: %v", list.body["engine_id"])
	}
	// Standardregeln
	r = as(t, "v_it").do("POST", "/api/v1/mandanten/"+ids["Organisation"]+"/trapregeln/standard", nil)
	expectStatus(t, "Standardregeln", r, 201)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE tenant_id = $1`, ids["Organisation"])
	})
	expectStatus(t, "Standardregeln Leser", as(t, "v_lz").do("POST", "/api/v1/mandanten/"+lz+"/trapregeln/standard", nil), 403)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_trap_rules WHERE tenant_id = $1 AND clears IS NOT NULL`, ids["Organisation"]).Scan(&n)
	if n != 1 {
		t.Errorf("Entwarnung in den Standardregeln: %d", n)
	}
}

// TestTrapsAlarmeUndProtokoll: Ein Trap-Zustand wird Sensor und Alarm;
// Zurücksetzen von Hand entwarnt. Protokoll nur im eigenen Teilbaum.
func TestTrapsAlarmeUndProtokoll(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(f.URL)
	lz := ids["Lager Nord"]
	_, _, op := wartungZiele(t, "TA")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)

	var dev, src, rule, ch string
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'ta-switch') RETURNING id::text`, lz).Scan(&dev)
	ch, _ = newUUID()
	owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'TA', $3, 'ta')`, ch, lz, server)
	owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, secret_enc, traps, trap_secret_enc, snapshot, last_ok)
		VALUES (gen_random_uuid(), $1, '2c', 'ta.lan', '\x0102030405060708091011121314151617181920212223242526272829', true,
		        '\x0102030405060708091011121314151617181920212223242526272829', '{}', now()) RETURNING id::text`, dev).Scan(&src)
	owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, name, trap_oid, action, key_oid, duration_min)
		VALUES (gen_random_uuid(), $1, 'Port getrennt', '1.3.6.1.6.3.1.1.5.3', 'crit', '1.3.6.1.2.1.2.2.1.1', 0) RETURNING id::text`,
		ids["Fertigung"]).Scan(&rule)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE snmp_id = $1`, src)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, src)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE id = $1`, rule)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, ch)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev)
	})
	// Wie der Trap-Dienst: Regel der Eltern (Fertigung) wirkt beim Kind.
	var res string
	if err := owner.QueryRow(ctx, `SELECT openwacht.traps_record($1, '2c', false, false, '1.3.6.1.6.3.1.1.5.3',
		'[{"oid":"1.3.6.1.2.1.2.2.1.1.4","typ":"Zahl","wert":"4"}]', $2, '4', 'linkDown: ifIndex.4 = 4')`, src, rule).Scan(&res); err != nil || res != "crit" {
		t.Fatalf("traps_record: %q %v", res, err)
	}
	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := f.take()["ta"]
	if len(msgs) != 1 || !strings.Contains(msgs[0].Message, "Port getrennt (4)") || !strings.Contains(msgs[0].Message, "linkDown") {
		t.Fatalf("Alarm: %+v", msgs)
	}
	// Sensor
	sub := "trap:" + rule + ":4"
	found := false
	for _, x := range as(t, "v_lz").do("GET", "/api/v1/sensoren", nil).body["sensoren"].([]any) {
		sn := x.(map[string]any)
		if sn["quelle_id"] == src && sn["gegenstand"] == sub {
			found = true
			if sn["status"] != "crit" || sn["name"] != "Port getrennt (4)" {
				t.Errorf("Sensor: %+v", sn)
			}
		}
	}
	if !found {
		t.Fatal("Trap-Sensor fehlt")
	}
	// Antwortet das Gerät nicht mehr auf Abfragen, bleibt der Trap-Zustand (er hängt nicht an der Abfrage).
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET last_ok = now() - interval '2 hours' WHERE id = $1`, src)
	for _, x := range as(t, "v_lz").do("GET", "/api/v1/sensoren", nil).body["sensoren"].([]any) {
		if sn := x.(map[string]any); sn["quelle_id"] == src && sn["gegenstand"] == sub && sn["status"] != "crit" {
			t.Errorf("Trap-Sensor bei stummem Gerät: %+v", sn)
		}
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET last_ok = now() WHERE id = $1`, src)
	// Protokoll: eigener Teilbaum ja, Geschwister nein. Der Regelname der
	// Eltern-Regel ist für das Kind nicht sichtbar.
	r := as(t, "v_lz").do("GET", "/api/v1/snmp/"+src+"/traps", nil)
	expectStatus(t, "Protokoll Kind", r, 200)
	tl := r.body["traps"].([]any)
	if len(tl) != 1 || tl[0].(map[string]any)["trap_name"] != "linkDown" || tl[0].(map[string]any)["regel_name"] != nil ||
		len(r.body["zustaende"].([]any)) != 1 {
		t.Fatalf("Protokoll: %s", r.raw)
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/snmp/"+src+"/traps", nil); r.body["traps"].([]any)[0].(map[string]any)["regel_name"] != "Port getrennt" {
		t.Errorf("Eltern sehen den Regelnamen nicht: %s", r.raw)
	}
	expectStatus(t, "Protokoll Geschwister", as(t, "v_oa").do("GET", "/api/v1/snmp/"+src+"/traps", nil), 404)

	// Zurücksetzen: Leser nein, Geschwister nein, Operator ja.
	body := map[string]any{"regel": rule, "instanz": "4"}
	path := "/api/v1/snmp/" + src + "/traps/zuruecksetzen"
	expectStatus(t, "Leser setzt zurück", as(t, "v_lz").do("POST", path, body), 403)
	expectStatus(t, "Geschwister setzt zurück", as(t, "v_oa").do("POST", path, body), 404)
	expectStatus(t, "falsche Instanz", opc.do("POST", path, map[string]any{"regel": rule, "instanz": "5"}), 404)
	expectStatus(t, "Operator setzt zurück", opc.do("POST", path, body), 204)
	s.alertRoundN(ctx)
	if m := f.take()["ta"]; len(m) != 1 || !strings.Contains(strings.ToLower(m[0].Title+m[0].Message), "entwarnung") &&
		!strings.Contains(m[0].Message, "nicht mehr") {
		t.Errorf("Entwarnung: %+v", m)
	}
	// Abgelaufene Zustände zählen nicht.
	owner.QueryRow(ctx, `SELECT openwacht.traps_record($1, '2c', false, false, '1.3.6.1.6.3.1.1.5.3', '[]', $2, '7', 'x')`, src, rule).Scan(&res)
	owner.Exec(ctx, `UPDATE openwacht.snmp_trap_state SET expires_at = now() - interval '1 second' WHERE source_id = $1`, src)
	var states string
	owner.QueryRow(ctx, `SELECT openwacht.snmp_trap_states_json($1)::text`, src).Scan(&states)
	if states != "[]" {
		t.Errorf("abgelaufener Zustand: %s", states)
	}
}
