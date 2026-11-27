// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"
)

// Die Sensorliste nennt neben der Meldung den zuletzt gelesenen Wert eines
// Checks; pausierte und noch nicht geprüfte Checks haben keinen.
func TestSensorenMesswert(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	var dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'MW Switch') RETURNING id::text`,
		ids["Fertigung"]).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	check := func(name string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, $2, 'tcp', '{"host": "10.20.0.40", "port": 443}', 60) RETURNING id::text`, dev, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mit, pause, neu := check("MW Lüfter"), check("MW Pause"), check("MW Neu")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id = $1`, dev)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev)
	})
	for _, id := range []string{mit, pause} {
		if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET status = 'ok', message = 'Wert im Rahmen', metric = '1500 RPM',
			next_run = now() + interval '1 day' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET enabled = false WHERE id = $1`, pause); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, x := range as(t, "v_fw").do("GET", "/api/v1/sensoren", nil).body["sensoren"].([]any) {
		sn := x.(map[string]any)
		got[sn["quelle_id"].(string)] = sn
	}
	if sn := got[mit]; sn == nil || sn["messwert"] != "1500 RPM" || sn["meldung"] != "Wert im Rahmen" {
		t.Errorf("Check mit Wert: %v", sn)
	}
	if sn := got[pause]; sn == nil || sn["messwert"] != nil || sn["status"] != "pause" {
		t.Errorf("pausierter Check: %v", sn)
	}
	if sn := got[neu]; sn == nil || sn["messwert"] != nil || sn["status"] != "neu" {
		t.Errorf("neuer Check: %v", sn)
	}
	for _, x := range as(t, "v_oa").do("GET", "/api/v1/sensoren", nil).body["sensoren"].([]any) {
		if x.(map[string]any)["quelle_id"] == mit {
			t.Error("Geschwister sehen den Sensor")
		}
	}
}
