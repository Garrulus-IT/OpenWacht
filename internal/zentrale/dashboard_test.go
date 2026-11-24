// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"math"
	"testing"

	"github.com/jackc/pgx/v5"
)

// write5m schreibt 5-Minuten-Werte (k = Blöcke vor jetzt, ab 2) für eine Quelle.
func write5m(t *testing.T, table, idCol, id, tenant, series string, value float64, blocks []int) {
	t.Helper()
	// Tabellen- und Spaltennamen sind feste Werte der Tests.
	if _, err := owner.Exec(context.Background(), `INSERT INTO openwacht.`+table+` (tenant_id, `+idCol+`, bucket, series, avg, min, max, n)
		SELECT $1, $2, date_bin('5 minutes', now(), timestamptz 'epoch') - make_interval(mins => 5 * k), $3, $4, $4, $4, 1
		  FROM unnest($5::int[]) AS k`, ids[tenant], id, series, value, blocks); err != nil {
		t.Fatal(err)
	}
}

func blocks(from, to, every int) []int {
	var out []int
	for k := from; k <= to; k += every {
		out = append(out, k)
	}
	return out
}

func fleetLines(t *testing.T, r response, key string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, x := range r.body[key].(map[string]any)["linien"].([]any) {
		m := x.(map[string]any)
		out[m["quelle_id"].(string)] = m
	}
	return out
}

func TestDashboardVerlauf(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	lz := forecastAgent(t, "v_fw", "Lager Nord", "db-lz", 0, nil)
	oa := forecastAgent(t, "v_oa", "Organisation", "db-oa", 0, nil)
	r := newDevice(t, "v_fw", "Fertigung", "DB Switch", "")
	expectStatus(t, "Gerät", r, 201)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+r.body["id"].(string)+"/snmp", snmpBody("db-switch.lan", nil))
	expectStatus(t, "SNMP", r, 201)
	sw := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, sw) })
	recent := blocks(2, 100, 1)
	write5m(t, "metrics_host_5m", "agent_id", lz, "Lager Nord", "cpu", 97, recent)
	write5m(t, "metrics_host_5m", "agent_id", oa, "Organisation", "cpu", 96, recent)
	write5m(t, "metrics_snmp_5m", "snmp_id", sw, "Fertigung", "cpu", 95, recent)
	write5m(t, "metrics_host_5m", "agent_id", lz, "Lager Nord", "speicher", 40, recent)
	write5m(t, "metrics_snmp_5m", "snmp_id", sw, "Fertigung", "speicher", 60, recent)

	for user, want := range map[string][]string{
		"v_lz": {lz}, "v_fw": {lz, sw}, "v_it": {lz, oa, sw}, "v_oa": {oa}, "v_oa_user": {oa},
	} {
		r := as(t, user).do("GET", "/api/v1/dashboard/verlauf?zeitraum=7t", nil)
		expectStatus(t, user, r, 200)
		cpu := fleetLines(t, r, "cpu")
		for _, q := range []string{lz, oa, sw} {
			if _, ok := cpu[q]; ok != contains(want, q) {
				t.Errorf("%s sieht CPU von %s: %v, erwartet %v", user, q, ok, contains(want, q))
			}
		}
		if l := cpu[lz]; l != nil {
			pts := l["punkte"].([]any)
			if l["art"] != "host" || l["geraet"] != "db-lz" || l["mandant_id"] != ids["Lager Nord"] || len(pts) == 0 ||
				pts[0].([]any)[1].(float64) != 97 {
				t.Errorf("%s: Linie %v", user, l)
			}
		}
		if l := cpu[sw]; l != nil && (l["art"] != "snmp" || l["geraet"] != "DB Switch") {
			t.Errorf("%s: SNMP-Linie %v", user, l)
		}
		mem := fleetLines(t, r, "speicher")
		if _, ok := mem[oa]; ok {
			t.Errorf("%s: Speicher ohne Werte liefert eine Linie", user)
		}
		if user == "v_fw" && (mem[sw] == nil || mem[lz] == nil) {
			t.Errorf("v_fw: Speicherlinien %v", mem)
		}
	}

	// Filter grenzt nur ein.
	r = as(t, "v_it").do("GET", "/api/v1/dashboard/verlauf?zeitraum=7t&mandanten="+ids["Organisation"], nil)
	expectStatus(t, "Filter", r, 200)
	if cpu := fleetLines(t, r, "cpu"); len(cpu) != 1 || cpu[oa] == nil {
		t.Errorf("Filter Organisation: %v", cpu)
	}
	r = as(t, "v_oa").do("GET", "/api/v1/dashboard/verlauf?zeitraum=7t&mandanten="+ids["Fertigung"]+","+ids["Lager Nord"], nil)
	expectStatus(t, "fremder Filter", r, 200)
	if cpu := fleetLines(t, r, "cpu"); len(cpu) != 0 {
		t.Errorf("Geschwister erweitert mit dem Filter: %v", cpu)
	}
	expectStatus(t, "Zeitraum", as(t, "v_it").do("GET", "/api/v1/dashboard/verlauf?zeitraum=2j", nil), 400)
	expectStatus(t, "Filter ungültig", as(t, "v_it").do("GET", "/api/v1/dashboard/verlauf?mandanten=1,2", nil), 400)

	// Höchstens N Linien, die mit dem höchsten Mittel; gesamt zählt alle.
	err := vServer.withUser(ctx, ids["v_it"], func(tx pgx.Tx) error {
		out, err := fleetSeries(ctx, tx, nil, periods["7t"], "cpu", 2)
		if err != nil {
			return err
		}
		if len(out.Linien) != 2 || out.Linien[0].QuelleID != lz || out.Linien[1].QuelleID != oa || out.Gesamt < 3 {
			t.Errorf("Top 2: %d Linien, gesamt %d: %+v", len(out.Linien), out.Gesamt, out.Linien)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Gesperrte Agents fallen heraus.
	owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, oa)
	r = as(t, "v_it").do("GET", "/api/v1/dashboard/verlauf?zeitraum=7t", nil)
	if fleetLines(t, r, "cpu")[oa] != nil {
		t.Error("gesperrter Agent im Dashboard")
	}
}

func TestDashboardKennzahlen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	lz := forecastAgent(t, "v_fw", "Lager Nord", "kz-lz", 0, nil)
	oa := forecastAgent(t, "v_oa", "Organisation", "kz-oa", 0, nil)
	// Seit 30 Tagen angelegt; Werte nur in jedem zweiten Block der letzten 7 Tage.
	owner.Exec(ctx, `UPDATE openwacht.agents SET created_at = now() - interval '30 days', last_seen = now() WHERE id = ANY ($1)`, []string{lz, oa})
	write5m(t, "metrics_host_5m", "agent_id", lz, "Lager Nord", "cpu", 10, blocks(2, 7*288, 2))
	write5m(t, "metrics_host_5m", "agent_id", oa, "Organisation", "cpu", 10, blocks(2, 30*288-12, 1))
	// Erst seit einem Tag da und seitdem lückenlos: 100 %, nicht 1/7.
	neu := forecastAgent(t, "v_fw", "Lager Nord", "kz-neu", 0, nil)
	owner.Exec(ctx, `UPDATE openwacht.agents SET created_at = now() - interval '1 day', last_seen = now() WHERE id = $1`, neu)
	write5m(t, "metrics_host_5m", "agent_id", neu, "Lager Nord", "cpu", 10, blocks(2, 288, 1))

	// Check im Lager: vor 5 Tagen halb, vor 20 Tagen ganz verfügbar
	r := newCheck(t, "v_fw", "Lager Nord", "KZ Dienst")
	expectStatus(t, "Check", r, 201)
	check := r.body["id"].(string)
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.metrics_check_1h (tenant_id, check_id, bucket, n, n_ok, worst, ms_n)
		VALUES ($1, $2, date_bin('1 hour', now() - interval '5 days', timestamptz 'epoch'), 60, 30, 'crit', 0),
		       ($1, $2, date_bin('1 hour', now() - interval '20 days', timestamptz 'epoch'), 60, 60, 'ok', 0)`,
		ids["Lager Nord"], check); err != nil {
		t.Fatal(err)
	}
	// Alarme vor zehn Tagen: Lager kritisch, Organisation Warnung
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, agent_id, subject, name, status, worst, started_at, changed_at, ended_at)
		VALUES ($1, $2, 'stumm', 'kz', 'crit', 'crit', date_bin('1 hour', now() - interval '10 days', timestamptz 'epoch') + interval '7 minutes',
		        now() - interval '10 days', now() - interval '9 days'),
		       ($3, $4, 'stumm', 'kz', 'warn', 'warn', date_bin('1 hour', now() - interval '10 days', timestamptz 'epoch') + interval '9 minutes',
		        now() - interval '10 days', now() - interval '9 days')`, ids["Lager Nord"], lz, ids["Organisation"], oa); err != nil {
		t.Fatal(err)
	}
	var hour float64
	owner.QueryRow(ctx, `SELECT extract(epoch FROM date_bin('1 hour', now() - interval '10 days', timestamptz 'epoch'))::double precision`).Scan(&hour)

	type exp struct {
		check, lz, oa bool
		warn, crit    float64
	}
	for user, e := range map[string]exp{
		"v_lz": {true, true, false, 0, 1}, "v_fw": {true, true, false, 0, 1}, "v_it": {true, true, true, 1, 1},
		"v_oa": {false, false, true, 1, 0}, "v_oa_user": {false, false, true, 1, 0},
	} {
		r := as(t, user).do("GET", "/api/v1/dashboard/kennzahlen", nil)
		expectStatus(t, user, r, 200)
		var warn, crit float64
		for _, x := range r.body["alarme_je_stunde"].([]any) {
			m := x.(map[string]any)
			if m["t"].(float64) == hour {
				warn, crit = m["warn"].(float64), m["crit"].(float64)
			}
		}
		if warn != e.warn || crit != e.crit {
			t.Errorf("%s: Alarme in der Stunde warn=%v crit=%v, erwartet %v/%v", user, warn, crit, e.warn, e.crit)
		}
		var gotCheck map[string]any
		for _, x := range r.body["checks"].([]any) {
			if m := x.(map[string]any); m["id"] == check {
				gotCheck = m
			}
		}
		if (gotCheck != nil) != e.check {
			t.Errorf("%s sieht Check: %v, erwartet %v", user, gotCheck != nil, e.check)
		}
		if gotCheck != nil && (gotCheck["tage7"] != 50.0 || gotCheck["tage30"] != 75.0 || gotCheck["pruefungen30"] != 120.0) {
			t.Errorf("%s: Verfügbarkeit Check %v", user, gotCheck)
		}
		reach := map[string]map[string]any{}
		for _, x := range r.body["erreichbarkeit"].([]any) {
			m := x.(map[string]any)
			reach[m["quelle_id"].(string)] = m
		}
		if (reach[lz] != nil) != e.lz || (reach[oa] != nil) != e.oa {
			t.Errorf("%s: Erreichbarkeit sichtbar lz=%v oa=%v", user, reach[lz] != nil, reach[oa] != nil)
		}
		if m := reach[lz]; m != nil {
			// jeder zweite Block der letzten 7 Tage: ~50 %, über 30 Tage ~11,7 %
			if v := m["tage7"].(float64); math.Abs(v-50) > 1 {
				t.Errorf("%s: Erreichbarkeit 7 Tage %v", user, v)
			}
			if v := m["tage30"].(float64); math.Abs(v-100.0*7/30/2) > 1 {
				t.Errorf("%s: Erreichbarkeit 30 Tage %v", user, v)
			}
		}
		if m := reach[neu]; e.lz && (m == nil || m["tage7"].(float64) < 99 || m["tage30"].(float64) < 99) {
			t.Errorf("%s: Erreichbarkeit seit einem Tag %v", user, m)
		}
		if m := reach[oa]; m != nil && (m["tage7"].(float64) < 99 || m["tage30"].(float64) < 99) {
			t.Errorf("%s: Erreichbarkeit lückenlos %v", user, m)
		}
	}
	// Filter grenzt nur ein.
	r = as(t, "v_oa").do("GET", "/api/v1/dashboard/kennzahlen?mandanten="+ids["Lager Nord"], nil)
	expectStatus(t, "fremder Filter", r, 200)
	if len(r.body["checks"].([]any)) != 0 || len(r.body["erreichbarkeit"].([]any)) != 0 || len(r.body["alarme_je_stunde"].([]any)) != 0 {
		t.Errorf("Geschwister erweitert mit dem Filter: %s", r.raw)
	}
	r = as(t, "v_it").do("GET", "/api/v1/dashboard/kennzahlen?mandanten="+ids["Organisation"], nil)
	for _, x := range r.body["checks"].([]any) {
		if x.(map[string]any)["mandant_id"] != ids["Organisation"] {
			t.Errorf("Filter Organisation liefert %v", x)
		}
	}
	expectStatus(t, "Filter ungültig", as(t, "v_it").do("GET", "/api/v1/dashboard/kennzahlen?mandanten=x", nil), 400)
}

func TestDashboardAbdeckung(t *testing.T) {
	for _, c := range []struct {
		seen  int64
		span  float64
		width int
		want  float64
	}{
		{0, 3600, 300, 0},
		{13, 3600, 300, 100},
		{20, 3600, 300, 100}, // nie über 100
		{1, 0.5, 300, 100},   // eben angelegt
		{6, 3600, 300, 6.0 / 13 * 100},
	} {
		got := coverage(c.seen, c.span, c.width)
		if got == nil || math.Abs(*got-round2(c.want)) > 1e-9 {
			t.Errorf("coverage(%d, %v, %d) = %v, erwartet %v", c.seen, c.span, c.width, got, c.want)
		}
	}
	if coverage(1, 0, 300) != nil || coverage(1, 10, 0) != nil || percent(1, 0) != nil {
		t.Error("ohne Zeitspanne bzw. Prüfungen muss es nil sein")
	}
}
