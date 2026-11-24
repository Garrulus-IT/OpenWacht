// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"
)

// „Satz von diesem Gerät entfernen“: nur Sensoren dieser Herkunft an diesem
// Gerät, nur mit Recht zum Löschen, sonst 404.
func TestChecksHerkunftLoeschen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	dev := func(tenant, name string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
			ids[tenant], name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	fw, lz := dev("Fertigung", "HK Server"), dev("Lager Nord", "HK Pumpe")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id IN ($1, $2)`, fw, lz)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id IN ($1, $2)`, fw, lz)
	})
	check := func(device, name, origin string) {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s, origin)
			VALUES ($1, $2, 'ping', '{"host":"x.lan"}', 60, $3)`, device, name, origin); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"HK A", "HK B", "HK C"} {
		check(fw, n, "Ferrari OfficeMaster")
	}
	check(fw, "HK eigen", "Ping")
	check(lz, "HK Lager", "Ferrari OfficeMaster")
	count := func(device string) int {
		var n int
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE device_id = $1`, device).Scan(&n)
		return n
	}
	del := func(user, device, origin string) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+device+"/checks/herkunft-loeschen", map[string]any{"herkunft": origin})
	}
	expectStatus(t, "ohne Herkunft", del("v_fw", fw, " "), 400)
	expectStatus(t, "Geschwister", del("v_oa", fw, "Ferrari OfficeMaster"), 404)
	expectStatus(t, "Kind-Leser", del("v_lz", fw, "Ferrari OfficeMaster"), 404)
	expectStatus(t, "Leser im eigenen Mandanten", del("v_lz", lz, "Ferrari OfficeMaster"), 404)
	expectStatus(t, "unbekannte Herkunft", del("v_fw", fw, "Gibt es nicht"), 404)
	if n := count(fw); n != 4 {
		t.Fatalf("vorher gelöscht: %d übrig", n)
	}
	r := del("v_fw", fw, "Ferrari OfficeMaster")
	expectStatus(t, "Admin", r, 200)
	if r.body["geloescht"] != float64(3) || count(fw) != 1 || count(lz) != 1 {
		t.Errorf("gelöscht %v, übrig %d/%d", r.body["geloescht"], count(fw), count(lz))
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'check.herkunft_geloescht' AND details->>'geraet' = $1`, fw).Scan(&audits)
	if audits != 1 {
		t.Errorf("Audit: %d", audits)
	}
}
