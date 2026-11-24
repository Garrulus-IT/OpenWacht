// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/agentproto"
)

func TestHostReihen(t *testing.T) {
	s := validSnapshot("h")
	s.Memory.SwapTotalBytes, s.Memory.SwapFreeBytes = 1000, 750
	s.Disks = append(s.Disks,
		agentproto.Disk{Mount: "/mnt/nas", FSType: "NFS4", TotalBytes: 100, FreeBytes: 1}, // Netzwerkfreigabe
		agentproto.Disk{Mount: "/", FSType: "ext4", TotalBytes: 100, FreeBytes: 1},        // doppelt
		agentproto.Disk{Mount: "/leer", FSType: "ext4", TotalBytes: 0, FreeBytes: 0},      // ohne Größe
		agentproto.Disk{Mount: "/daten", FSType: "xfs", TotalBytes: 200, FreeBytes: 50})
	names, values := hostSeries(&s)
	got := map[string]float64{}
	for i, n := range names {
		got[n] = values[i]
	}
	want := map[string]float64{"cpu": 7.5, "last1": 0.1, "speicher": 50, "swap": 25, "platte:/": 50, "platte:/daten": 75}
	if len(got) != len(want) || len(names) != len(want) {
		t.Fatalf("Reihen %v, erwartet %v", got, want)
	}
	for k, v := range want {
		if math.Abs(got[k]-v) > 1e-9 {
			t.Errorf("%s = %v, erwartet %v", k, got[k], v)
		}
	}
	// Windows: keine Last, und ohne Swap keine Swap-Reihe.
	s = validSnapshot("w")
	s.CPU.NoLoad, s.CPU.Load1 = true, 0
	names, _ = hostSeries(&s)
	if strings.Contains(strings.Join(names, ","), "last1") || strings.Contains(strings.Join(names, ","), "swap") {
		t.Errorf("Reihen ohne Last/Swap: %v", names)
	}
}

func historySeries(t *testing.T, r response) map[string][]any {
	t.Helper()
	out := map[string][]any{}
	for _, x := range r.body["reihen"].([]any) {
		m := x.(map[string]any)
		out[m["name"].(string)] = m["punkte"].([]any)
	}
	return out
}

func TestVerlaufHostMandantentrennung(t *testing.T) {
	agentServer(t)
	tok, r := newAgentToken(t, "v_fw", "Lager Nord", 1)
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, tok, "lz-verlauf")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	for i := 0; i < 2; i++ {
		if s, b := a.report("lz-verlauf"); s != 200 {
			t.Fatalf("Messwerte: %d %s", s, b)
		}
	}
	path := "/api/v1/agents/" + a.id + "/verlauf"
	// Sehen: eigener Mandant (auch als Leser) und Eltern ja, Geschwister nein.
	for user, want := range map[string]int{"v_lz": 200, "v_fw": 200, "v_it": 200, "v_oa": 404, "v_oa_user": 404} {
		for _, zr := range []string{"1h", "24h", "7t", "30t"} {
			r := as(t, user).do("GET", path+"?zeitraum="+zr, nil)
			expectStatus(t, user+" "+zr, r, want)
			if want != 200 {
				if _, leaked := r.body["reihen"]; leaked {
					t.Errorf("%s bekommt Reihen eines fremden Agents", user)
				}
				continue
			}
			// Frische Werte sind noch nicht verdichtet und kommen aus den Rohdaten.
			series := historySeries(t, r)
			for _, name := range []string{"cpu", "speicher", "platte:/", "last1"} {
				if len(series[name]) == 0 {
					t.Errorf("%s %s: Reihe %s fehlt (%v)", user, zr, name, r.body)
				}
			}
			if pts := series["cpu"]; len(pts) > 0 {
				p := pts[len(pts)-1].([]any)
				if p[1].(float64) != 7.5 || p[2].(float64) != 7.5 || p[3].(float64) != 7.5 {
					t.Errorf("%s %s: CPU-Punkt %v", user, zr, p)
				}
			}
		}
	}
	expectStatus(t, "unbekannter Zeitraum", as(t, "v_fw").do("GET", path+"?zeitraum=1j", nil), 400)
	expectStatus(t, "ungültige ID", as(t, "v_fw").do("GET", "/api/v1/agents/xyz/verlauf", nil), 400)
	expectStatus(t, "unbekannter Agent", as(t, "v_it").do("GET", "/api/v1/agents/00000000-0000-4000-8000-000000000000/verlauf", nil), 404)

	// Der Mandant der Rohwerte kommt aus dem Agent, nicht aus der Anfrage.
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.metrics_host_raw
		WHERE agent_id = $1 AND tenant_id = $2 AND series = 'cpu'`, a.id, ids["Lager Nord"]).Scan(&n)
	if n != 2 {
		t.Errorf("Rohwerte cpu: %d, erwartet 2", n)
	}
	// Zweite Schicht: RLS auf den Verlaufstabellen selbst, ohne die Prüfung im Handler.
	for user, want := range map[string]bool{"v_lz": true, "v_fw": true, "v_oa": false, "v_oa_user": false} {
		var rows int
		err := vServer.withUser(context.Background(), ids[user], func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.metrics_host_raw WHERE agent_id = $1`, a.id).Scan(&rows)
		})
		if err != nil {
			t.Fatal(err)
		}
		if (rows > 0) != want {
			t.Errorf("RLS: %s sieht %d Rohwerte, erwartet sichtbar=%v", user, rows, want)
		}
	}
}

func TestVerlaufCheck(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newCheck(t, "v_fw", "Fertigung", "Verlauf NAS")
	expectStatus(t, "Check", r, 201)
	id := r.body["id"].(string)
	for _, x := range []struct {
		status string
		ms     any
	}{{"ok", 10.0}, {"ok", 30.0}, {"crit", nil}, {"ok", 20.0}} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, $2, 'Meldung', '', $3)`, id, x.status, x.ms).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	// Ungültige Antwortzeiten werden nicht gespeichert, das Ergebnis schon.
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, 'ok', 'Meldung', '', 'NaN'::float8)`, id).Scan(&ok); err != nil || !ok {
		t.Fatalf("check_record NaN: %v %v", ok, err)
	}
	path := "/api/v1/checks/" + id + "/verlauf?zeitraum=1h"
	for user, want := range map[string]int{"v_fw": 200, "v_it": 200, "v_lz": 404, "v_oa": 404} {
		r := as(t, user).do("GET", path, nil)
		expectStatus(t, user, r, want)
		if want != 200 {
			continue
		}
		pts := r.body["punkte"].([]any)
		if len(pts) == 0 {
			t.Fatalf("%s: keine Punkte", user)
		}
		var n, okN, msMin, msMax float64
		worst := ""
		for _, p := range pts {
			m := p.(map[string]any)
			n += m["n"].(float64)
			okN += m["ok"].(float64)
			if m["schlechtester"] == "crit" {
				worst = "crit"
			}
			if v, ok := m["ms_min"].(float64); ok && (msMin == 0 || v < msMin) {
				msMin = v
			}
			if v, ok := m["ms_max"].(float64); ok && v > msMax {
				msMax = v
			}
		}
		if n != 5 || okN != 4 || worst != "crit" || msMin != 10 || msMax != 30 {
			t.Errorf("%s: n=%v ok=%v schlechtester=%q ms %v–%v", user, n, okN, worst, msMin, msMax)
		}
		// Wechsel: erstes Ergebnis (von nichts), nach crit, zurück nach ok.
		var seq []string
		for _, c := range r.body["wechsel"].([]any) {
			seq = append(seq, c.(map[string]any)["nach"].(string))
		}
		if strings.Join(seq, ",") != "ok,crit,ok" {
			t.Errorf("%s: Wechsel %v", user, seq)
		}
	}
	// Der Mandant kommt aus dem Check.
	var mine int
	owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM openwacht.metrics_check_raw WHERE check_id = $1 AND tenant_id = $2)
		+ (SELECT count(*) FROM openwacht.check_transitions WHERE check_id = $1 AND tenant_id = $2)`, id, ids["Fertigung"]).Scan(&mine)
	if mine != 5+3 {
		t.Errorf("Verlaufszeilen mit Mandant Fertigung: %d, erwartet 8", mine)
	}
	// Löschen nimmt den Verlauf mit (Fremdschlüssel, obwohl die Anwendung
	// in den Verlaufstabellen nichts löschen darf).
	expectStatus(t, "löschen", as(t, "v_fw").do("DELETE", "/api/v1/checks/"+id, nil), 204)
	var left int
	owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM openwacht.metrics_check_raw WHERE check_id = $1)
		+ (SELECT count(*) FROM openwacht.check_transitions WHERE check_id = $1)`, id).Scan(&left)
	if left != 0 {
		t.Errorf("Nach dem Löschen bleiben %d Verlaufszeilen", left)
	}
}

func TestVerlaufNurLesen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	// Die Anwendungsrolle darf in die Verlaufstabellen nichts schreiben und
	// die Wartungsstände nicht lesen.
	for _, q := range []string{
		`INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
		 SELECT tenant_id, id, now(), 'cpu', 1 FROM openwacht.agents LIMIT 1`,
		`INSERT INTO openwacht.check_transitions (tenant_id, check_id, ts, new_status)
		 SELECT tenant_id, id, now(), 'ok' FROM openwacht.checks LIMIT 1`,
		`DELETE FROM openwacht.metrics_host_1h`,
		`UPDATE openwacht.metrics_check_5m SET n = 1`,
		`SELECT * FROM openwacht.metrics_rollup_state`,
		`SELECT * FROM openwacht.metrics_host_raw_` + time.Now().UTC().Format("20060102"),
	} {
		_, err := pool.Exec(ctx, q)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s: %v, erwartet Rechtefehler", strings.Fields(q)[0], err)
		}
	}
}

func TestVerlaufVerdichtung(t *testing.T) {
	agentServer(t)
	ctx := context.Background()
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a, status, body := register(t, tok, "fw-verdichtung")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := vServer.MaintainMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	// Zwei volle Stunden Rohwerte, mindestens drei Stunden alt und an zwei
	// Stunden ausgerichtet (Schritt der 30-Tage-Ansicht): je Minute ein Wert,
	// cpu steigt von 0 bis 119. Die Partition von gestern gibt es immer.
	var base time.Time
	if err := owner.QueryRow(ctx, `SELECT date_bin('2 hours', now() - interval '5 hours', timestamptz 'epoch')`).Scan(&base); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
		SELECT $2, $1, $3::timestamptz + make_interval(mins => i), 'cpu', i FROM generate_series(0, 119) i`,
		a.id, ids["Fertigung"], base)
	// Ein Ausreißer im ersten Block: Er hat 6 statt 5 Werte, damit falsch
	// gewichtete Mittel auffallen.
	exec(`INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
		VALUES ($2, $1, $3::timestamptz + interval '30 seconds', 'cpu', 1000)`, a.id, ids["Fertigung"], base)
	exec(`UPDATE openwacht.metrics_rollup_state SET done_until = $1`, base)
	if err := vServer.MaintainMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	var n5 int
	var avg, mn, mx float64
	var cnt int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.metrics_host_5m WHERE agent_id = $1`, a.id).Scan(&n5)
	if n5 != 24 {
		t.Errorf("5-Minuten-Blöcke: %d, erwartet 24", n5)
	}
	owner.QueryRow(ctx, `SELECT avg, min, max, n FROM openwacht.metrics_host_5m WHERE agent_id = $1 AND bucket = $2`,
		a.id, base.Add(5*time.Minute)).Scan(&avg, &mn, &mx, &cnt)
	if avg != 7 || mn != 5 || mx != 9 || cnt != 5 {
		t.Errorf("Block 2: avg=%v min=%v max=%v n=%v", avg, mn, mx, cnt)
	}
	owner.QueryRow(ctx, `SELECT avg, min, max, n FROM openwacht.metrics_host_1h WHERE agent_id = $1 AND bucket = $2`,
		a.id, base.Add(time.Hour)).Scan(&avg, &mn, &mx, &cnt)
	if avg != 89.5 || mn != 60 || mx != 119 || cnt != 60 {
		t.Errorf("Stunde 2: avg=%v min=%v max=%v n=%v", avg, mn, mx, cnt)
	}
	owner.QueryRow(ctx, `SELECT avg, max, n FROM openwacht.metrics_host_1h WHERE agent_id = $1 AND bucket = $2`,
		a.id, base).Scan(&avg, &mx, &cnt)
	if math.Abs(avg-2770.0/61) > 1e-9 || mx != 1000 || cnt != 61 {
		t.Errorf("Stunde 1 (gewichtet): avg=%v max=%v n=%v", avg, mx, cnt)
	}
	// Ab jetzt gelten für diesen Zeitraum nur die verdichteten Werte: Ein
	// veränderter Rohwert darf in den Ansichten ab 7 Tagen nicht auftauchen.
	exec(`UPDATE openwacht.metrics_host_raw SET value = 5000 WHERE agent_id = $1 AND ts = $2`, a.id, base.Add(10*time.Minute))

	// Abfrage über 7 Tage: verdichtete Blöcke plus Rohwerte danach, ohne Doppelzählung.
	r := as(t, "v_fw").do("GET", "/api/v1/agents/"+a.id+"/verlauf?zeitraum=7t", nil)
	expectStatus(t, "7t", r, 200)
	pts := historySeries(t, r)["cpu"]
	for _, p := range pts {
		if pt := p.([]any); pt[3].(float64) > 1000 || pt[2].(float64) < 0 {
			t.Errorf("Punkt außerhalb der Werte (doppelt gezählt?): %v", pt)
		}
	}
	// 2 Stunden in 30-Minuten-Schritten; der erste Schritt gewichtet nach Anzahl.
	if len(pts) != 4 || pts[0].([]any)[1].(float64) != round2(1435.0/31) {
		t.Errorf("7t: %v", pts)
	}
	r = as(t, "v_fw").do("GET", "/api/v1/agents/"+a.id+"/verlauf?zeitraum=30t", nil)
	expectStatus(t, "30t", r, 200)
	if pts := historySeries(t, r)["cpu"]; len(pts) != 1 || pts[0].([]any)[1].(float64) != round2(8140.0/121) {
		t.Errorf("30t: %v", pts)
	}

	// Aufräumen: alte Blöcke und alte Tagespartitionen verschwinden.
	exec(`INSERT INTO openwacht.metrics_host_5m (tenant_id, agent_id, bucket, series, avg, min, max, n)
		VALUES ($2, $1, now() - interval '31 days', 'cpu', 1, 1, 1, 1), ($2, $1, now() - interval '29 days', 'cpu', 1, 1, 1, 1)`,
		a.id, ids["Fertigung"])
	exec(`INSERT INTO openwacht.metrics_host_1h (tenant_id, agent_id, bucket, series, avg, min, max, n)
		VALUES ($2, $1, now() - interval '366 days', 'cpu', 1, 1, 1, 1), ($2, $1, now() - interval '364 days', 'cpu', 1, 1, 1, 1)`,
		a.id, ids["Fertigung"])
	old := time.Now().UTC().AddDate(0, 0, -4)
	day := time.Date(old.Year(), old.Month(), old.Day(), 0, 0, 0, 0, time.UTC)
	partition := "metrics_host_raw_" + day.Format("20060102")
	exec(`CREATE TABLE openwacht.` + partition + ` PARTITION OF openwacht.metrics_host_raw
		FOR VALUES FROM ('` + day.Format(time.RFC3339) + `') TO ('` + day.AddDate(0, 0, 1).Format(time.RFC3339) + `')`)
	if err := vServer.MaintainMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	var old5, old1 int
	var exists bool
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.metrics_host_5m WHERE agent_id = $1 AND bucket < now() - interval '28 days'`, a.id).Scan(&old5)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.metrics_host_1h WHERE agent_id = $1 AND bucket < now() - interval '300 days'`, a.id).Scan(&old1)
	owner.QueryRow(ctx, `SELECT to_regclass('openwacht.`+partition+`') IS NOT NULL`).Scan(&exists)
	if old5 != 1 || old1 != 1 || exists {
		t.Errorf("Aufräumen: 5m=%d (1), 1h=%d (1), alte Partition noch da: %v", old5, old1, exists)
	}
	var today bool
	owner.QueryRow(ctx, `SELECT to_regclass('openwacht.metrics_check_raw_`+time.Now().UTC().AddDate(0, 0, 2).Format("20060102")+`') IS NOT NULL`).Scan(&today)
	if !today {
		t.Error("Partition für übermorgen fehlt")
	}
}

// Fehlt die Tagespartition, kommt die Meldung trotzdem an; nur der
// Verlaufswert fehlt.
func TestVerlaufOhnePartition(t *testing.T) {
	agentServer(t)
	ctx := context.Background()
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a, status, body := register(t, tok, "fw-ohne-partition")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	part := "openwacht.metrics_host_raw_" + time.Now().UTC().Format("20060102")
	if _, err := owner.Exec(ctx, `ALTER TABLE openwacht.metrics_host_raw DETACH PARTITION `+part); err != nil {
		t.Fatal(err)
	}
	s, b := a.report("fw-ohne-partition")
	if _, err := owner.Exec(ctx, `ALTER TABLE openwacht.metrics_host_raw ATTACH PARTITION `+part+
		` FOR VALUES FROM (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
		  TO (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' + interval '1 day')`); err != nil {
		t.Fatal(err)
	}
	if s != 200 {
		t.Fatalf("Meldung ohne Partition: %d %s", s, b)
	}
	var seen bool
	owner.QueryRow(ctx, `SELECT last_seen IS NOT NULL FROM openwacht.agents WHERE id = $1`, a.id).Scan(&seen)
	if !seen {
		t.Error("Meldung nicht gespeichert")
	}
}
