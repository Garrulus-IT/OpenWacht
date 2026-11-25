// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6: Gerät in einen anderen Mandanten verschieben.

import (
	"context"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/traps"
)

type moveFixture struct {
	dev, child, agent, check, src, rule, ruleOK, group, color string
}

// moveDevice legt in Lager Nord ein Gerät mit allem an, was mitziehen oder
// wegfallen soll.
func moveDevice(t *testing.T, name string) moveFixture {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	var f moveFixture
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant := ids["Lager Nord"]
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
		tenant, name+" Gruppe").Scan(&f.group))
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, $2, $3) RETURNING id::text`,
		tenant, name, f.group).Scan(&f.dev))
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, parent_id) VALUES ($1, $2, $3) RETURNING id::text`,
		tenant, name+"-kind", f.dev).Scan(&f.child))
	// Kennfarbe der Fertigung: gilt in Lager Nord, nicht in der Organisation.
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.kennfarben (tenant_id, name, color) VALUES ($1, $2, '#00838a') RETURNING id::text`,
		ids["Fertigung"], name+" Farbe").Scan(&f.color))
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s, kennfarbe_id)
		VALUES ($1, 'Ping', 'ping', '{"host":"x.lan"}', 60, $2) RETURNING id::text`, f.dev, f.color).Scan(&f.check))
	f.agent, _ = newUUID()
	_, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, device_id, hostname, cert_serial, cert_not_after, last_seen)
		VALUES ($1, $2, $3, $4, 'mv', now() + interval '30 days', now())`, f.agent, tenant, f.dev, strings.ToLower(name))
	must(err)
	_, err = owner.Exec(ctx, `INSERT INTO openwacht.sensor_kennfarben (tenant_id, agent_id, subject, kennfarbe_id) VALUES ($1, $2, 'speicher', $3)`,
		tenant, f.agent, f.color)
	must(err)
	f.src, _ = newUUID()
	sec := snmpSecret{Community: "geheim-" + name}
	enc, err := vServer.sealSNMP(f.src, tenant, "mv.lan", 161, sec)
	must(err)
	trap, err := traps.Seal(vServer.trapKey, sec, f.src, tenant, "mv.lan", 161, "2c")
	must(err)
	_, err = owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc, traps, trap_secret_enc)
		VALUES ($1, $2, '2c', 'mv.lan', 161, $3, true, $4)`, f.src, f.dev, enc, trap)
	must(err)
	_, err = owner.Exec(ctx, `INSERT INTO openwacht.snmp_trap_log (source_id, tenant_id, version, inform, authentic, trap_oid, varbinds, result)
		VALUES ($1, $2, '2c', false, true, '1.3.6.1.4.1.9.9.1', '[]', 'crit')`, f.src, tenant)
	must(err)
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, device_id, name, trap_oid, action, duration_min)
		VALUES (gen_random_uuid(), $1, $2, 'Lüfter', '1.3.6.1.4.1.9.9.1', 'crit', 0) RETURNING id::text`, tenant, f.dev).Scan(&f.rule))
	must(owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, device_id, name, trap_oid, action, clears)
		VALUES (gen_random_uuid(), $1, $2, 'Lüfter ok', '1.3.6.1.4.1.9.9.2', 'ok', $3) RETURNING id::text`, tenant, f.dev, f.rule).Scan(&f.ruleOK))
	_, err = owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at)
		VALUES ($1, $2, 'check', $3, 'crit', 'crit', now() - interval '1 hour', now())`, tenant, f.check, name+" · Ping")
	must(err)
	_, err = owner.Exec(ctx, `INSERT INTO openwacht.maintenance (tenant_id, device_id, starts_at, ends_at, reason)
		VALUES ($1, $2, now(), now() + interval '1 hour', 'Umbau')`, tenant, f.dev)
	must(err)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = $1`, name+" · Ping")
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE device_id = $1`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE device_id = $1 AND clears IS NOT NULL`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE device_id = $1`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id = $1`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_log WHERE source_id = $1`, f.src)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE device_id = $1`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE device_id = $1`, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id IN ($1, $2)`, f.child, f.dev)
		owner.Exec(ctx, `DELETE FROM openwacht.kennfarben WHERE id = $1`, f.color)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id = $1`, f.group)
	})
	return f
}

func tenantOf(t *testing.T, table, id string) string {
	t.Helper()
	var tid string
	if err := owner.QueryRow(context.Background(), `SELECT tenant_id::text FROM openwacht.`+table+` WHERE id = $1`, id).Scan(&tid); err != nil {
		t.Fatalf("%s %s: %v", table, id, err)
	}
	return tid
}

func TestGeraetVerschieben(t *testing.T) {
	f := moveDevice(t, "Verschiebe1")
	ctx := context.Background()
	move := func(user, target string) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+f.dev+"/verschieben", map[string]string{"mandant_id": ids[target]})
	}
	// Rechte: Admin nur des alten Mandanten, Leser, Admin nur des Ziels.
	expectStatus(t, "v_fw (nur Fertigung) nach Organisation", move("v_fw", "Organisation"), 403)
	if r := move("v_lz", "Fertigung"); r.status != 403 && r.status != 404 {
		t.Errorf("Leser verschiebt: %d", r.status)
	}
	expectStatus(t, "v_oa sieht das Gerät nicht", move("v_oa", "Organisation"), 404)
	expectStatus(t, "gleicher Mandant", move("v_it", "Lager Nord"), 400)
	expectStatus(t, "ungültiges Ziel", as(t, "v_it").do("POST", "/api/v1/geraete/"+f.dev+"/verschieben", map[string]string{"mandant_id": "x"}), 400)
	if got := tenantOf(t, "devices", f.dev); got != ids["Lager Nord"] {
		t.Fatal("abgelehnter Versuch hat verschoben")
	}

	r := move("v_it", "Organisation")
	expectStatus(t, "v_it verschiebt", r, 200)
	if r.body["sensoren"] != float64(1) || r.body["abfragen"] != float64(1) || r.body["alarme"] != float64(1) ||
		r.body["wartungen_entfernt"] != float64(1) || r.body["abhaengigkeiten_geloest"] != float64(1) ||
		r.body["trap_regeln"] != float64(2) {
		t.Errorf("Antwort: %s", r.raw)
	}
	org := ids["Organisation"]
	for table, id := range map[string]string{"devices": f.dev, "checks": f.check, "agents": f.agent, "snmp_sources": f.src,
		"snmp_trap_rules": f.rule} {
		if got := tenantOf(t, table, id); got != org {
			t.Errorf("%s nicht umgezogen: %s", table, got)
		}
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE check_id = $1 AND tenant_id = $2`, f.check, org).Scan(&n)
	if n != 1 {
		t.Error("Alarm nicht umgezogen")
	}
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_trap_log WHERE source_id = $1 AND tenant_id <> $2`, f.src, org).Scan(&n)
	if n != 0 {
		t.Error("Trap-Protokoll nicht umgezogen")
	}
	var clears *string
	owner.QueryRow(ctx, `SELECT clears::text FROM openwacht.snmp_trap_rules WHERE id = $1`, f.ruleOK).Scan(&clears)
	if clears == nil || *clears != f.rule {
		t.Error("Entwarnung der Trap-Regel verloren")
	}
	// Bezüge weg
	var group, parent, color *string
	owner.QueryRow(ctx, `SELECT group_id::text FROM openwacht.devices WHERE id = $1`, f.dev).Scan(&group)
	owner.QueryRow(ctx, `SELECT parent_id::text FROM openwacht.devices WHERE id = $1`, f.child).Scan(&parent)
	owner.QueryRow(ctx, `SELECT kennfarbe_id::text FROM openwacht.checks WHERE id = $1`, f.check).Scan(&color)
	if group != nil || parent != nil || color != nil {
		t.Errorf("Bezüge geblieben: Gruppe %v, Abhängigkeit %v, Kennfarbe %v", group, parent, color)
	}
	owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM openwacht.maintenance WHERE device_id = $1)
		+ (SELECT count(*) FROM openwacht.sensor_kennfarben WHERE agent_id = $2)`, f.dev, f.agent).Scan(&n)
	if n != 0 {
		t.Errorf("Wartung oder Kennfarbe am Agent geblieben: %d", n)
	}
	// Zugangsdaten mit dem neuen Mandanten lesbar, mit dem alten nicht mehr.
	var enc, trap []byte
	owner.QueryRow(ctx, `SELECT secret_enc, trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.src).Scan(&enc, &trap)
	if sec, err := vServer.openSNMP(f.src, org, "mv.lan", 161, "2c", enc); err != nil || sec.Community != "geheim-Verschiebe1" {
		t.Errorf("Community nach dem Umzug: %v", err)
	}
	if _, err := vServer.openSNMP(f.src, ids["Lager Nord"], "mv.lan", 161, "2c", enc); err == nil {
		t.Error("Community mit altem Mandanten lesbar")
	}
	if sec, err := traps.Open(vServer.trapKey, trap, f.src, org, "mv.lan", 161, "2c"); err != nil || sec.Community != "geheim-Verschiebe1" {
		t.Errorf("Trap-Zugangsdaten nach dem Umzug: %v", err)
	}
	// Audit in beiden Mandanten
	owner.QueryRow(ctx, `SELECT count(DISTINCT tenant_id) FROM openwacht.audit_log WHERE action = 'geraet.verschoben' AND details->>'geraet' = $1`, f.dev).Scan(&n)
	if n != 2 {
		t.Errorf("Audit in %d Mandanten", n)
	}
	// Sichtbarkeit: Fertigung sieht das Gerät nicht mehr, Organisation schon.
	if strings.Contains(as(t, "v_fw").do("GET", "/api/v1/geraete", nil).raw, f.dev) {
		t.Error("alter Mandant sieht das Gerät noch")
	}
	if !strings.Contains(as(t, "v_oa").do("GET", "/api/v1/geraete", nil).raw, f.dev) {
		t.Error("neuer Mandant sieht das Gerät nicht")
	}
}

// Sammler auf einem anderen Gerät: abgelehnt, nichts ändert sich.
func TestGeraetVerschiebenSammler(t *testing.T) {
	f := moveDevice(t, "Verschiebe2")
	g := moveDevice(t, "Verschiebe3")
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = false, collector_id = $1 WHERE id = $2`, g.agent, f.src); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = NULL WHERE id = $1`, f.src) })
	r := as(t, "v_it").do("POST", "/api/v1/geraete/"+f.dev+"/verschieben", map[string]string{"mandant_id": ids["Organisation"]})
	expectStatus(t, "Abfrage über fremden Sammler", r, 400)
	if !strings.Contains(r.raw, "Sammler") {
		t.Errorf("Meldung: %s", r.raw)
	}
	r = as(t, "v_it").do("POST", "/api/v1/geraete/"+g.dev+"/verschieben", map[string]string{"mandant_id": ids["Organisation"]})
	expectStatus(t, "Gerät sammelt für andere", r, 400)
	if tenantOf(t, "devices", f.dev) != ids["Lager Nord"] || tenantOf(t, "devices", g.dev) != ids["Lager Nord"] {
		t.Error("trotz Ablehnung verschoben")
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.maintenance WHERE device_id IN ($1, $2)`, f.dev, g.dev).Scan(&n)
	if n != 2 {
		t.Error("Ablehnung hat Wartungen gelöscht")
	}
}

// Außerhalb von device_move bleibt der Mandant unveränderlich, auch wenn die
// App-Rolle den Schalter setzt.
func TestGeraetMandantBleibtUnveraenderlich(t *testing.T) {
	f := moveDevice(t, "Verschiebe4")
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true), set_config('openwacht.verschieben', 'an', true)`, ids["v_it"]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE openwacht.devices SET tenant_id = $1 WHERE id = $2`, ids["Organisation"], f.dev); err == nil {
		t.Fatal("App-Rolle ändert den Mandanten eines Geräts")
	}
	tx.Rollback(ctx)
	// Auch der Eigentümer ohne Schalter nicht.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET tenant_id = $1 WHERE id = $2`, ids["Organisation"], f.check); err == nil ||
		!strings.Contains(err.Error(), "unveränderlich") {
		t.Fatalf("Eigentümer ohne Schalter: %v", err)
	}
}

// Alle Arten von Abfragen: neu verschlüsselt mit dem Ziel-Mandanten.
func TestResealAlleArten(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{boxKey: deriveKey(master, "openwacht secretbox v1"), trapKey: traps.DeriveKey(master)}
	for _, v := range []string{"2c", "3", "pve", "vcenter", "tr064", "ontap", "xapi"} {
		old := []string{"11111111-1111-1111-1111-111111111111", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", v, "q.lan", "443", "CA"}
		box, err := auth.Seal(s.boxKey, []byte("geheim-"+v), snmpSourceAAD(old))
		if err != nil {
			t.Fatal(err)
		}
		src := moveSource{id: old[0], tenant: old[1], version: v, host: "q.lan", port: 443, ca: "CA", secret: box}
		target := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		sec, trap, err := s.resealSource(src, target)
		if err != nil || trap != nil {
			t.Fatalf("%s: %v", v, err)
		}
		pt, err := auth.Open(s.boxKey, sec, snmpSourceAAD([]string{old[0], target, v, "q.lan", "443", "CA"}))
		if err != nil || string(pt) != "geheim-"+v {
			t.Errorf("%s: %v", v, err)
		}
		// Verfälschter Kasten: Abbruch statt stiller Verlust.
		src.secret = append([]byte(nil), box...)
		src.secret[len(src.secret)-1] ^= 1
		if _, _, err := s.resealSource(src, target); err == nil {
			t.Errorf("%s: verfälschter Kasten angenommen", v)
		}
	}
}
