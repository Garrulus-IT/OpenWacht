// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"
)

// Anlegen mit Elterngerät (1.0.12): nur ein sichtbares Gerät im selben
// Mandanten; das Audit nennt es.
func TestGeraetAnlegenMitEltern(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	dev := func(tenant, name string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`, ids[tenant], name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	sw := dev("Fertigung", "EL Switch")
	fremd := dev("Organisation", "EL fremd")
	unten := dev("Lager Nord", "EL Lager")
	var neu []string
	t.Cleanup(func() {
		for _, id := range append(neu, sw, fremd, unten) {
			owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, id)
		}
	})
	create := func(user, name, parent string) response {
		body := map[string]any{"name": name, "adresse": "10.20.0.80"}
		if parent != "-" {
			body["abhaengig_von"] = parent
		}
		r := as(t, user).do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/geraete", body)
		if r.status == 201 {
			neu = append(neu, r.body["id"].(string))
		}
		return r
	}
	expectStatus(t, "Eltern aus anderem Mandanten", create("v_fw", "EL AP 1", fremd), 400)
	expectStatus(t, "Eltern aus Kind-Mandant", create("v_fw", "EL AP 2", unten), 400)
	expectStatus(t, "ungültige ID", create("v_fw", "EL AP 3", "kein-uuid"), 400)
	// Ohne Recht auf den Mandanten scheitert es an beidem: Das Elterngerät ist
	// nicht sichtbar (400), ohne Elterngerät verweigert die Datenbank (RLS).
	for _, parent := range []string{sw, "-"} {
		if r := create("v_lz", "EL AP 4", parent); r.status == 201 || r.status/100 != 4 {
			t.Errorf("Leser legt an (%s): %d", parent, r.status)
		}
	}
	r := create("v_fw", "EL AP 5", sw)
	expectStatus(t, "mit Elterngerät", r, 201)
	var parent *string
	owner.QueryRow(ctx, `SELECT parent_id::text FROM openwacht.devices WHERE id = $1`, r.body["id"]).Scan(&parent)
	if parent == nil || *parent != sw {
		t.Errorf("parent_id: %v", parent)
	}
	var audited string
	owner.QueryRow(ctx, `SELECT coalesce(details->>'abhaengig_von', '') FROM openwacht.audit_log WHERE action = 'geraet.angelegt'
		AND details->>'id' = $1`, r.body["id"]).Scan(&audited)
	if audited != sw {
		t.Errorf("Audit: %q", audited)
	}
	expectStatus(t, "leer = keins", create("v_fw", "EL AP 6", ""), 201)
	expectStatus(t, "ohne Feld", create("v_fw", "EL AP 7", "-"), 201)
}
