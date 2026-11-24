// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
)

// fullDevice legt im Mandanten ein Gerät mit Sensor, Agent, SNMP-Quelle,
// Trap-Regel und Alarm an (als Eigentümer).
func fullDevice(t *testing.T, tenant, name string) (dev, agent, src string) {
	t.Helper()
	ctx := context.Background()
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
		ids[tenant], name).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	var check string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
		VALUES ($1, 'Ping', 'ping', '{"host":"x.lan"}', 60) RETURNING id::text`, dev).Scan(&check); err != nil {
		t.Fatal(err)
	}
	agent, _ = newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, device_id, hostname, cert_serial, cert_not_after, last_seen)
		VALUES ($1, $2, $3, $4, 'gl', now() + interval '30 days', now())`, agent, ids[tenant], dev, strings.ToLower(name)); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, secret_enc)
		VALUES (gen_random_uuid(), $1, '2c', 'gl.lan', '\x0102030405060708091011121314151617181920212223242526272829')
		RETURNING id::text`, dev).Scan(&src); err != nil {
		t.Fatal(err)
	}
	var rule string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, device_id, name, trap_oid, action, duration_min)
		VALUES (gen_random_uuid(), $1, $2, 'Lüfter', '1.3.6.1.4.1.9.9.1', 'crit', 0) RETURNING id::text`, ids[tenant], dev).Scan(&rule); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, device_id, name, trap_oid, action, clears)
		VALUES (gen_random_uuid(), $1, $2, 'Lüfter ok', '1.3.6.1.4.1.9.9.2', 'ok', $3)`, ids[tenant], dev, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at, ended_at)
		VALUES ($1, $2, 'check', $3, 'crit', 'crit', now() - interval '1 hour', now(), now())`, ids[tenant], check, name+" · Ping"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE device_id = $1 AND clears IS NOT NULL`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE device_id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE device_id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE device_id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = $1`, name+" · Ping")
	})
	return dev, agent, src
}

func TestGeraetMitInhaltLoeschen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	dev, agent, _ := fullDevice(t, "Fertigung", "GL Server")
	path := "/api/v1/geraete/" + dev

	// Vorschau: alle, die das Gerät sehen; darf nur Admin/Operator.
	expectStatus(t, "Geschwister Vorschau", as(t, "v_oa").do("GET", path+"/loeschen", nil), 404)
	expectStatus(t, "Kind Vorschau", as(t, "v_lz").do("GET", path+"/loeschen", nil), 404)
	r := as(t, "v_it").do("GET", path+"/loeschen", nil)
	expectStatus(t, "Eltern Vorschau", r, 200)
	if r.body["sensoren"] != 1.0 || len(r.body["agents"].([]any)) != 1 || len(r.body["quellen"].([]any)) != 1 ||
		len(r.body["trap_regeln"].([]any)) != 2 || r.body["darf"] != true || r.body["sammler_fuer"] != 0.0 {
		t.Errorf("Vorschau: %s", r.raw)
	}

	// Ohne Bestätigung wie bisher: 409.
	expectStatus(t, "ohne Bestätigung", as(t, "v_fw").do("DELETE", path, nil), 409)
	expectStatus(t, "Geschwister", as(t, "v_oa").do("DELETE", path, map[string]any{"bestaetigung": "GL Server"}), 404)
	expectStatus(t, "falscher Name", as(t, "v_fw").do("DELETE", path, map[string]any{"bestaetigung": "GL"}), 400)
	expectStatus(t, "unbekanntes Feld", as(t, "v_fw").do("DELETE", path, map[string]any{"name": "GL Server"}), 400)
	expectStatus(t, "Löschen", as(t, "v_fw").do("DELETE", path, map[string]any{"bestaetigung": " gl server "}), 204)

	var n int
	owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM openwacht.devices WHERE id = $1) + (SELECT count(*) FROM openwacht.agents WHERE id = $2)
		+ (SELECT count(*) FROM openwacht.checks WHERE device_id = $1) + (SELECT count(*) FROM openwacht.snmp_sources WHERE device_id = $1)
		+ (SELECT count(*) FROM openwacht.snmp_trap_rules WHERE device_id = $1)`, dev, agent).Scan(&n)
	if n != 0 {
		t.Errorf("Reste: %d", n)
	}
	var alarms int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE name = 'GL Server · Ping'`).Scan(&alarms)
	if alarms != 1 {
		t.Errorf("Alarmprotokoll: %d Einträge", alarms)
	}
	var actions string
	owner.QueryRow(ctx, `SELECT string_agg(action, ',' ORDER BY chain_seq) FROM openwacht.audit_log
		WHERE details->>'agent' = $1 OR details->>'id' = $2`, agent, dev).Scan(&actions)
	if actions != "agent.gesperrt,agent.geloescht,geraet.geloescht" {
		t.Errorf("Audit: %s", actions)
	}
	expectStatus(t, "weg", as(t, "v_fw").do("GET", path+"/loeschen", nil), 404)
}

func TestGeraetLoeschenRechteUndSperren(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	dev, agent, _ := fullDevice(t, "Lager Nord", "GL Pumpe")
	path := "/api/v1/geraete/" + dev

	// Leser sieht die Vorschau, darf aber nicht.
	r := as(t, "v_lz").do("GET", path+"/loeschen", nil)
	if r.status != 200 || r.body["darf"] != false {
		t.Errorf("Leser Vorschau: %d %s", r.status, r.raw)
	}
	expectStatus(t, "Leser löscht", as(t, "v_lz").do("DELETE", path, map[string]any{"bestaetigung": "GL Pumpe"}), 403)

	// Agent ist Sammler eines anderen Geräts: gesperrt.
	other, _, otherSrc := fullDevice(t, "Lager Nord", "GL Switch")
	_ = other
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = $1 WHERE id = $2`, agent, otherSrc); err != nil {
		t.Fatal(err)
	}
	r = as(t, "v_fw").do("DELETE", path, map[string]any{"bestaetigung": "GL Pumpe"})
	if r.status != 409 || !strings.Contains(r.raw, "Sammler") {
		t.Errorf("Sammler: %d %s", r.status, r.raw)
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = NULL WHERE id = $1`, otherSrc)

	// Entwarn-Regel außerhalb des Geräts beendet eine Regel des Geräts: gesperrt.
	var rule string
	owner.QueryRow(ctx, `SELECT id::text FROM openwacht.snmp_trap_rules WHERE device_id = $1 AND action = 'crit'`, dev).Scan(&rule)
	var outside string
	owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, name, trap_oid, action, clears)
		VALUES (gen_random_uuid(), $1, 'Alle ok', '1.3.6.1.4.1.9.9.3', 'ok', $2) RETURNING id::text`, ids["Lager Nord"], rule).Scan(&outside)
	r = as(t, "v_fw").do("DELETE", path, map[string]any{"bestaetigung": "GL Pumpe"})
	if r.status != 409 || !strings.Contains(r.raw, "Trap-Regel") {
		t.Errorf("Entwarn-Regel: %d %s", r.status, r.raw)
	}
	owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE id = $1`, outside)

	// Nichts ist halb gelöscht.
	var revoked bool
	owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM openwacht.agents WHERE id = $1`, agent).Scan(&revoked)
	if revoked {
		t.Error("Agent nach abgelehntem Löschen gesperrt")
	}
	// Eltern (Admin der Fertigung) löscht im Kind.
	expectStatus(t, "Eltern löscht", as(t, "v_fw").do("DELETE", path, map[string]any{"bestaetigung": "GL Pumpe"}), 204)

	// Direkt in der DB: ohne Rolle nichts.
	dev2, _, _ := fullDevice(t, "Fertigung", "GL Direkt")
	tx, _ := pool.Begin(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_oa"])
	_, err := tx.Exec(ctx, `SELECT openwacht.device_delete_all($1, 'GL Direkt', true)`, dev2)
	tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "P0002") {
		t.Errorf("Geschwister direkt: %v", err)
	}
	tx, _ = pool.Begin(ctx)
	_, err = tx.Exec(ctx, `SELECT openwacht.device_delete_all($1, 'GL Direkt', true)`, dev2)
	tx.Rollback(ctx)
	if err == nil {
		t.Error("ohne Benutzerkontext gelöscht")
	}

	// Leeres Gerät: wie bisher ohne Bestätigung.
	r = newDevice(t, "v_fw", "Fertigung", "GL Leer", "")
	expectStatus(t, "leer anlegen", r, 201)
	expectStatus(t, "leer löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+r.body["id"].(string), nil), 204)
}
