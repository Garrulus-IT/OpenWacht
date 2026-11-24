// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAufbewahrungRechte(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	// Ohne Betreiber-Kennzeichen: nichts, auch nicht für Admins des Hauptmandanten.
	for _, u := range []string{"v_it", "v_fw", "v_lz"} {
		expectStatus(t, u+" lesen", as(t, u).do("GET", "/api/v1/einstellungen/aufbewahrung", nil), 403)
		expectStatus(t, u+" global", as(t, u).do("PUT", "/api/v1/einstellungen/aufbewahrung", map[string]any{"fuenf_min_tage": 60}), 403)
		expectStatus(t, u+" Mandant", as(t, u).do("PUT", "/api/v1/einstellungen/mandanten/"+ids["Fertigung"]+"/aufbewahrung",
			map[string]any{"fuenf_min_tage": 60}), 403)
	}
	// Auch die Datenbank lässt nur den Betreiber die Aufbewahrung je Mandant und den Platz lesen.
	for _, q := range []string{`SELECT count(*) FROM openwacht.settings_retention()`, `SELECT count(*) FROM openwacht.metrics_sizes()`} {
		err := asDB(t, "v_it", func(tx pgx.Tx) error {
			var n int
			return tx.QueryRow(context.Background(), q).Scan(&n)
		})
		if !isDenied(err) {
			t.Errorf("%s ohne Betreiber: %v", q, err)
		}
	}
	setOperator(t, "v_it", true)
	r := as(t, "v_it").do("GET", "/api/v1/einstellungen/aufbewahrung", nil)
	expectStatus(t, "Betreiber liest", r, 200)
	if list, _ := r.body["mandanten"].([]any); len(list) < 4 {
		t.Fatalf("Mandanten: %v", r.body["mandanten"])
	}
}

func TestAufbewahrungGlobalUndJeMandant(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	setOperator(t, "v_it", true)
	it := as(t, "v_it")
	put := func(body map[string]any) response { return it.do("PUT", "/api/v1/einstellungen/aufbewahrung", body) }
	tenant := func(name string, body map[string]any) response {
		return it.do("PUT", "/api/v1/einstellungen/mandanten/"+ids[name]+"/aufbewahrung", body)
	}
	wirksam := func(name string) [2]int {
		var d5, d1 int
		owner.QueryRow(context.Background(), `SELECT days_5m, days_1h FROM openwacht.metrics_retention() WHERE tenant_id = $1`, ids[name]).Scan(&d5, &d1)
		return [2]int{d5, d1}
	}

	for name, b := range map[string]map[string]any{
		"Roh zu kurz": {"roh_tage": 1}, "Roh zu lang": {"roh_tage": 8}, "5m zu kurz": {"fuenf_min_tage": 29},
		"1h zu lang": {"stunden_tage": 1831}, "1h zu kurz": {"stunden_tage": 89},
	} {
		expectStatus(t, name, put(b), 400)
	}
	// Länger geht ohne Code, kürzer nur mit.
	expectStatus(t, "länger", put(map[string]any{"roh_tage": 3, "fuenf_min_tage": 90, "stunden_tage": 730}), 204)
	if w := wirksam("Lager Nord"); w != [2]int{90, 730} {
		t.Fatalf("geerbt: %v", w)
	}
	expectStatus(t, "kürzer ohne Code", put(map[string]any{"roh_tage": 3, "fuenf_min_tage": 60, "stunden_tage": 730}), 403)
	expectStatus(t, "Standard ohne Code (kürzer)", put(map[string]any{}), 403)
	expectStatus(t, "kürzer mit Code", put(map[string]any{"roh_tage": 3, "fuenf_min_tage": 60, "stunden_tage": 730,
		"code": freshCode(t, "v_it")}), 204)

	// Je Mandant: Fertigung länger, Lager Nord erbt, Geschwister nicht.
	expectStatus(t, "Rohwerte je Mandant", tenant("Fertigung", map[string]any{"roh_tage": 5}), 400)
	expectStatus(t, "Fertigung länger", tenant("Fertigung", map[string]any{"fuenf_min_tage": 120}), 200)
	if w := wirksam("Lager Nord"); w != [2]int{120, 730} {
		t.Errorf("Kind erbt nicht: %v", w)
	}
	if w := wirksam("Organisation"); w != [2]int{60, 730} {
		t.Errorf("Geschwister betroffen: %v", w)
	}
	if w := wirksam("IT"); w != [2]int{60, 730} {
		t.Errorf("Eltern betroffen: %v", w)
	}
	// Eigener Wert im Kind gewinnt; Zurücksetzen der Fertigung verkürzt das Kind nicht mehr.
	expectStatus(t, "Lager eigener Wert", tenant("Lager Nord", map[string]any{"fuenf_min_tage": 200, "stunden_tage": 1000}), 200)
	if w := wirksam("Lager Nord"); w != [2]int{200, 1000} {
		t.Errorf("eigener Wert verliert gegen den der Fertigung: %v", w)
	}
	expectStatus(t, "Fertigung zurück ohne Code", tenant("Fertigung", map[string]any{}), 403)
	expectStatus(t, "Fertigung zurück mit Code", tenant("Fertigung", map[string]any{"code": freshCode(t, "v_it")}), 200)
	if w := wirksam("Lager Nord"); w != [2]int{200, 1000} {
		t.Errorf("eigener Wert des Kinds: %v", w)
	}
	// Zurücksetzen der Schwellen behält die Aufbewahrung.
	expectStatus(t, "Schwellen zurück", it.do("PUT", "/api/v1/einstellungen/mandanten/"+ids["Lager Nord"], map[string]any{}), 204)
	if w := wirksam("Lager Nord"); w != [2]int{200, 1000} {
		t.Errorf("Aufbewahrung beim Zurücksetzen der Schwellen verloren: %v", w)
	}
	expectStatus(t, "unbekannter Mandant", it.do("PUT", "/api/v1/einstellungen/mandanten/00000000-0000-4000-8000-000000000000/aufbewahrung",
		map[string]any{"fuenf_min_tage": 60}), 404)

	// Audit
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'einstellungen.aufbewahrung'`).Scan(&n)
	if n < 5 {
		t.Errorf("Audit-Einträge: %d", n)
	}
}

// TestAufbewahrungWartung: metrics_maintain löscht je Mandant nach dessen Frist.
func TestAufbewahrungWartung(t *testing.T) {
	agentServer(t)
	resetSettings(t)
	ctx := context.Background()
	tokFW, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	fw, _, _ := register(t, tokFW, "keep-fw")
	tokOA, _ := newAgentToken(t, "v_oa", "Organisation", 1)
	oa, _, _ := register(t, tokOA, "keep-oa")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'keep-%'`)
		owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE hostname LIKE 'keep-%' AND revoked_at IS NULL`)
		resetSettings(t)
	})
	if _, err := owner.Exec(ctx, `UPDATE openwacht.tenant_settings SET keep_5m_days = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.tenant_settings (tenant_id, keep_5m_days, keep_1h_days) VALUES ($1, 60, 400)
		ON CONFLICT (tenant_id) DO UPDATE SET keep_5m_days = 60, keep_1h_days = 400`, ids["Fertigung"]); err != nil {
		t.Fatal(err)
	}
	insert := func(table, agent, tenant string, days int) {
		t.Helper()
		_, err := owner.Exec(ctx, `INSERT INTO openwacht.`+table+` (tenant_id, agent_id, bucket, series, avg, min, max, n)
			VALUES ($1, $2, date_bin('5 minutes', now() - make_interval(days => $3), timestamptz 'epoch'), 'cpu', 1, 1, 1, 1)`, tenant, agent, days)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("metrics_host_5m", fw.id, ids["Fertigung"], 45)     // bleibt (60 Tage)
	insert("metrics_host_5m", oa.id, ids["Organisation"], 45)  // weg (30 Tage)
	insert("metrics_host_5m", oa.id, ids["Organisation"], 20)  // bleibt
	insert("metrics_host_1h", fw.id, ids["Fertigung"], 380)    // bleibt (400 Tage)
	insert("metrics_host_1h", oa.id, ids["Organisation"], 380) // weg (365 Tage)
	if _, err := owner.Exec(ctx, `SELECT openwacht.metrics_maintain()`); err != nil {
		t.Fatal(err)
	}
	count := func(table, agent string) int {
		var n int
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.`+table+` WHERE agent_id = $1 AND series = 'cpu' AND bucket < now() - interval '10 days'`, agent).Scan(&n)
		return n
	}
	if count("metrics_host_5m", fw.id) != 1 || count("metrics_host_5m", oa.id) != 1 {
		t.Errorf("5 Minuten: Fertigung %d (erwartet 1), Organisation %d (erwartet 1)", count("metrics_host_5m", fw.id), count("metrics_host_5m", oa.id))
	}
	if count("metrics_host_1h", fw.id) != 1 || count("metrics_host_1h", oa.id) != 0 {
		t.Errorf("Stunden: Fertigung %d (erwartet 1), Organisation %d (erwartet 0)", count("metrics_host_1h", fw.id), count("metrics_host_1h", oa.id))
	}
}
