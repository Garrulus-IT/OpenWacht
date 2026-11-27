// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"
)

func TestSNMPAusnahmen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	var dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'AN NetApp') RETURNING id::text`,
		ids["Fertigung"]).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	src, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, secret_enc)
		VALUES ($1, $2, '2c', '10.20.0.30', '\x0102030405060708091011121314151617181920212223242526272829')`, src, dev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, src)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev)
	})
	key := "s:" + src + "/snapmirror:svm-sicherung:vol_daten_02_vault"
	ex := func(user, key, reason string) response {
		return as(t, user).do("POST", "/api/v1/sensoren/ausnehmen", map[string]any{"schluessel": key, "begruendung": reason})
	}
	in := func(user, key string) response {
		return as(t, user).do("POST", "/api/v1/sensoren/einbeziehen", map[string]any{"schluessel": key})
	}
	expectStatus(t, "Erreichbarkeit", ex("v_fw", "s:"+src+"/stumm", "geht nicht"), 400)
	expectStatus(t, "Agent", ex("v_fw", "h:"+src+"/speicher", "geht nicht"), 400)
	expectStatus(t, "unbekannter Gegenstand", ex("v_fw", "s:"+src+"/quatsch", "geht nicht"), 400)
	expectStatus(t, "ohne Begründung", ex("v_fw", key, " x "), 400)
	expectStatus(t, "Geschwister", ex("v_oa", key, "alte Beziehung"), 404)
	expectStatus(t, "Kind-Leser", ex("v_lz", key, "alte Beziehung"), 404)
	expectStatus(t, "Admin", ex("v_fw", key, "alte Vault-Beziehung, wird nicht mehr gepflegt"), 204)
	expectStatus(t, "Eltern ändern Begründung", ex("v_it", key, "Altlast, Aufräumen geplant"), 204)

	var reason string
	var n int
	owner.QueryRow(ctx, `SELECT reason FROM openwacht.snmp_exclusions WHERE snmp_id = $1`, src).Scan(&reason)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_exclusions WHERE snmp_id = $1`, src).Scan(&n)
	if n != 1 || reason != "Altlast, Aufräumen geplant" {
		t.Errorf("Ausnahmen: %d, %q", n, reason)
	}
	// ohne Kontext (Alarme) sichtbar, für Geschwister nicht
	sees := func(user string) bool {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if user != "" {
			tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[user])
		}
		var c int
		tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_exclusions_all() WHERE snmp_id = $1`, src).Scan(&c)
		return c == 1
	}
	if !sees("") || !sees("v_fw") || !sees("v_it") || sees("v_oa") {
		t.Errorf("snmp_exclusions_all: ohne %v fw %v it %v oa %v", sees(""), sees("v_fw"), sees("v_it"), sees("v_oa"))
	}

	// Entfernen (0063): dieselbe Ausnahme, zusätzlich ausgeblendet
	rm := func(user, key, reason string) response {
		return as(t, user).do("POST", "/api/v1/sensoren/ausnehmen", map[string]any{"schluessel": key, "begruendung": reason, "entfernen": true})
	}
	list := func(user string) response { return as(t, user).do("GET", "/api/v1/snmp/"+src+"/entfernt", nil) }
	hides := func(user string) bool {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if user != "" {
			tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[user])
		}
		var c int
		tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_hidden_all() WHERE snmp_id = $1`, src).Scan(&c)
		return c == 1
	}
	if hides("") || hides("v_fw") {
		t.Error("ausgenommen gilt schon als entfernt")
	}
	if r := list("v_fw"); r.status != 200 || len(r.body["entfernt"].([]any)) != 0 {
		t.Errorf("Liste vor dem Entfernen: %d %s", r.status, r.raw)
	}
	expectStatus(t, "Geschwister entfernt", rm("v_oa", key, "alte Beziehung"), 404)
	expectStatus(t, "Kind-Leser entfernt", rm("v_lz", key, "alte Beziehung"), 404)
	expectStatus(t, "entfernen", rm("v_fw", key, "Altlast, bleibt auf der NetApp"), 204)
	if !hides("") || !hides("v_fw") || !hides("v_it") || hides("v_oa") {
		t.Errorf("snmp_hidden_all: ohne %v fw %v it %v oa %v", hides(""), hides("v_fw"), hides("v_it"), hides("v_oa"))
	}
	if n := 0; owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_exclusions WHERE snmp_id = $1 AND hidden`, src).Scan(&n) != nil || n != 1 {
		t.Errorf("entfernt in der Tabelle: %d", n)
	}
	r := list("v_fw")
	if r.status != 200 || len(r.body["entfernt"].([]any)) != 1 {
		t.Fatalf("Liste: %d %s", r.status, r.raw)
	}
	e := r.body["entfernt"].([]any)[0].(map[string]any)
	if e["schluessel"] != key || e["name"] != "SnapMirror svm-sicherung:vol_daten_02_vault" || e["begruendung"] != "Altlast, bleibt auf der NetApp" {
		t.Errorf("Eintrag: %v", e)
	}
	expectStatus(t, "Liste für Geschwister", list("v_oa"), 404)
	expectStatus(t, "Liste für Eltern", list("v_it"), 200)
	// erneutes Ausnehmen ohne „entfernen“ blendet wieder ein
	expectStatus(t, "nur ausnehmen", ex("v_fw", key, "Altlast, bleibt auf der NetApp"), 204)
	if hides("v_fw") {
		t.Error("nach „nur ausnehmen“ noch entfernt")
	}
	expectStatus(t, "wieder entfernen", rm("v_fw", key, "Altlast, bleibt auf der NetApp"), 204)

	expectStatus(t, "Geschwister hebt auf", in("v_oa", key), 404)
	expectStatus(t, "aufheben", in("v_fw", key), 204)
	expectStatus(t, "doppelt aufheben", in("v_fw", key), 404)
	if hides("") {
		t.Error("nach dem Aufheben noch entfernt")
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('sensor.ausgenommen', 'sensor.einbezogen', 'sensor.entfernt')
		AND details->>'sensor' = $1`, key).Scan(&audits)
	if audits != 6 {
		t.Errorf("Audit: %d", audits)
	}
}
