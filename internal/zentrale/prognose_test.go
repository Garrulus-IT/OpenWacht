// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPrognoseBewertung(t *testing.T) {
	for _, c := range []struct {
		name    string
		slope   float64
		n       int
		span    float64
		current float64
		stand   string
		tage    int
	}{
		{"steigt", 1, 240, 10, 60, forecastRising, 40},
		{"abgerundet", 3, 100, 5, 50, forecastRising, 16},
		{"schon voll", 1, 100, 5, 100, forecastRising, 0},
		{"über voll", 1, 100, 5, 101, forecastRising, 0},
		{"zu wenige Punkte", 1, forecastMinPoints - 1, 10, 50, forecastTooLittle, 0},
		{"gerade genug Punkte", 1, forecastMinPoints, 10, 50, forecastRising, 50},
		{"zu kurz", 1, 100, forecastMinDays - 0.01, 50, forecastTooLittle, 0},
		{"gerade lang genug", 1, 100, forecastMinDays, 50, forecastRising, 50},
		{"fällt", -2, 100, 10, 50, forecastStable, 0},
		{"flach", forecastMinSlope / 2, 100, 10, 50, forecastStable, 0},
		{"gerade steigend", forecastMinSlope, 100, 10, 99.99, forecastRising, 1},
		{"zu langsam", 0.02, 100, 10, 0, forecastStable, 0},
		{"gerade noch", 100.0 / forecastMaxDays, 100, 10, 0, forecastRising, forecastMaxDays},
		{"ohne Steigung", math.NaN(), 100, 10, 50, forecastTooLittle, 0},
	} {
		stand, tage := forecastResult(c.slope, c.n, c.span, c.current)
		if stand != c.stand {
			t.Errorf("%s: Stand %s, erwartet %s", c.name, stand, c.stand)
			continue
		}
		if (tage != nil) != (stand == forecastRising) {
			t.Errorf("%s: Tage %v bei Stand %s", c.name, tage, stand)
			continue
		}
		if tage != nil && *tage != c.tage {
			t.Errorf("%s: %d Tage, erwartet %d", c.name, *tage, c.tage)
		}
	}
}

// forecastAgent registriert einen Agent und schreibt Stundenwerte für
// Platten: je Platte eine Funktion Stunde (0 = älteste, n-1 = vor zwei
// Stunden) → Belegung, oder < 0 = kein Wert.
func forecastAgent(t *testing.T, user, tenant, host string, hours int, disks map[string]func(h int) float64) string {
	t.Helper()
	agentServer(t)
	tok, r := newAgentToken(t, user, tenant, 1)
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, tok, host)
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	writeHourly(t, "metrics_host_1h", "agent_id", a.id, tenant, hours, disks)
	return a.id
}

func writeHourly(t *testing.T, table, idCol, id, tenant string, hours int, disks map[string]func(h int) float64) {
	t.Helper()
	ctx := context.Background()
	for disk, f := range disks {
		var hs []int
		var vs []float64
		for h := 0; h < hours; h++ {
			if v := f(h); v >= 0 {
				hs, vs = append(hs, h), append(vs, v)
			}
		}
		// Tabellen- und Spaltennamen sind feste Werte der Tests.
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.`+table+` (tenant_id, `+idCol+`, bucket, series, avg, min, max, n)
			SELECT $1, $2, date_bin('1 hour', now(), timestamptz 'epoch') - make_interval(hours => 2 + $3 - 1 - x.h), $4, x.v, x.v, x.v, 1
			  FROM unnest($5::int[], $6::double precision[]) AS x(h, v)`, ids[tenant], id, hours, "platte:"+disk, hs, vs); err != nil {
			t.Fatal(err)
		}
	}
}

type forecastRow struct {
	art, quelle, mandant, geraet, platte, stand string
	belegt                                      float64
	tage                                        *float64
	proTag                                      *float64
	basis                                       float64
	sprung                                      bool
}

func forecastList(t *testing.T, user, query string) (map[string]forecastRow, response) {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/prognose/platten"+query, nil)
	out := map[string]forecastRow{}
	if r.status != 200 {
		return out, r
	}
	for _, x := range r.body["platten"].([]any) {
		m := x.(map[string]any)
		f := forecastRow{art: m["art"].(string), quelle: m["quelle_id"].(string), mandant: m["mandant_id"].(string),
			geraet: m["geraet"].(string), platte: m["platte"].(string), stand: m["stand"].(string), belegt: m["belegt"].(float64),
			basis: m["basis_tage"].(float64), sprung: m["nach_sprung"].(bool)}
		if v, ok := m["tage"].(float64); ok {
			f.tage = &v
		}
		if v, ok := m["pro_tag"].(float64); ok {
			f.proTag = &v
		}
		out[f.quelle+"|"+f.platte] = f
	}
	return out, r
}

func TestPrognosePlatten(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	lz := forecastAgent(t, "v_fw", "Lager Nord", "pg-lz", 241, map[string]func(int) float64{
		// 10 Tage lang 1 Punkt je Tag: 50 → 60 %, voll in ~40 Tagen
		"/": func(h int) float64 { return 50 + float64(h)/24 },
		// erst langsam, dann Löschung (−30), danach 2 Punkte je Tag
		"/daten": func(h int) float64 {
			if h < 120 {
				return 70 + float64(h)/24
			}
			return 40 + float64(h-120)/12
		},
		"/stabil": func(int) float64 { return 30 },
		// erst seit zehn Stunden
		"/neu": func(h int) float64 {
			if h < 231 {
				return -1
			}
			return 10 + float64(h)
		},
		// endete vor drei Tagen (Platte ausgehängt): keine Prognose mehr
		"/alt": func(h int) float64 {
			if h > 170 {
				return -1
			}
			return 50 + float64(h)
		},
	})
	oa := forecastAgent(t, "v_oa", "Organisation", "pg-oa", 100, map[string]func(int) float64{
		"/": func(h int) float64 { return 20 + float64(h)/24 },
	})

	// SNMP-Platte der Fertigung
	r := newDevice(t, "v_fw", "Fertigung", "PG NAS", "")
	expectStatus(t, "Gerät", r, 201)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+r.body["id"].(string)+"/snmp", snmpBody("pg-nas.lan", nil))
	expectStatus(t, "SNMP", r, 201)
	snmpID := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, snmpID) })
	writeHourly(t, "metrics_snmp_1h", "snmp_id", snmpID, "Fertigung", 100, map[string]func(int) float64{
		"Volume 1": func(h int) float64 { return 80 + float64(h)/48 },
	})

	got, r := forecastList(t, "v_fw", "")
	expectStatus(t, "Prognose", r, 200)
	if f := got[lz+"|/"]; f.stand != forecastRising || f.tage == nil || *f.tage < 39 || *f.tage > 40 || f.sprung ||
		f.art != "host" || f.mandant != ids["Lager Nord"] || f.geraet != "pg-lz" || f.belegt != 60 || f.basis != 10 {
		t.Errorf("Platte /: %+v (Tage %v)", f, deref(f.tage))
	}
	if f := got[lz+"|/daten"]; f.stand != forecastRising || !f.sprung || f.proTag == nil || *f.proTag < 1.99 || *f.proTag > 2.01 ||
		f.basis > 5 || f.basis < 4.9 {
		t.Errorf("Platte /daten (nach Löschung): %+v (pro Tag %v)", f, deref(f.proTag))
	}
	if f := got[lz+"|/stabil"]; f.stand != forecastStable || f.tage != nil {
		t.Errorf("Platte /stabil: %+v", f)
	}
	if f := got[lz+"|/neu"]; f.stand != forecastTooLittle || f.proTag != nil || f.tage != nil {
		t.Errorf("Platte /neu: %+v", f)
	}
	if _, ok := got[lz+"|/alt"]; ok {
		t.Error("Platte /alt meldet sich seit Tagen nicht mehr und hat trotzdem eine Prognose")
	}
	if f := got[snmpID+"|Volume 1"]; f.art != "snmp" || f.stand != forecastRising || f.tage == nil || f.geraet != "PG NAS" {
		t.Errorf("SNMP-Platte: %+v", f)
	}

	// Mandantentrennung: eigener Teilbaum ja, Geschwister und Eltern nein.
	for user, want := range map[string][]string{
		"v_lz":      {lz},
		"v_fw":      {lz, snmpID},
		"v_it":      {lz, snmpID, oa},
		"v_oa":      {oa},
		"v_oa_user": {oa},
	} {
		got, r := forecastList(t, user, "")
		expectStatus(t, user, r, 200)
		seen := map[string]bool{}
		for _, f := range got {
			seen[f.quelle] = true
		}
		for _, q := range []string{lz, snmpID, oa} {
			if seen[q] != contains(want, q) {
				t.Errorf("%s sieht Quelle %s: %v, erwartet %v", user, q, seen[q], contains(want, q))
			}
		}
	}

	// Der Filter grenzt nur ein und erweitert nie.
	got, r = forecastList(t, "v_it", "?mandanten="+ids["Organisation"])
	expectStatus(t, "Filter", r, 200)
	for _, f := range got {
		if f.quelle != oa {
			t.Errorf("Filter Organisation liefert %+v", f)
		}
	}
	got, r = forecastList(t, "v_oa", "?mandanten="+ids["Lager Nord"]+","+ids["Fertigung"])
	expectStatus(t, "fremder Filter", r, 200)
	if len(got) != 0 {
		t.Errorf("Geschwister erweitert mit dem Filter: %+v", got)
	}
	got, _ = forecastList(t, "v_fw", "?mandanten="+ids["Fertigung"])
	if _, ok := got[lz+"|/"]; ok || got[snmpID+"|Volume 1"].stand == "" {
		t.Errorf("Filter Fertigung ohne Untermandanten: %+v", got)
	}
	r = as(t, "v_fw").do("GET", "/api/v1/prognose/platten?mandanten=xyz", nil)
	expectStatus(t, "ungültiger Filter", r, 400)
	if !strings.Contains(r.raw, "Mandanten-ID") {
		t.Errorf("ungültiger Filter: %s", r.raw) // erst die Anwendung, nicht erst die Datenbank
	}
	expectStatus(t, "zu langer Filter", as(t, "v_fw").do("GET", "/api/v1/prognose/platten?mandanten="+
		strings.Repeat(ids["Fertigung"]+",", maxTenantFilter)+ids["Fertigung"], nil), 400)

	// Gesperrte Agents fallen heraus.
	owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, oa)
	got, _ = forecastList(t, "v_it", "")
	for _, f := range got {
		if f.quelle == oa {
			t.Error("gesperrter Agent hat noch eine Prognose")
		}
	}

	// Zweite Schicht: dieselbe Abfrage ohne Filter direkt mit Benutzerkontext.
	for user, foreign := range map[string]string{"v_oa": lz, "v_lz": snmpID} {
		err := vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			list, _, err := diskForecasts(ctx, tx, nil, nil)
			for _, f := range list {
				if f.QuelleID == foreign {
					t.Errorf("RLS: %s sieht Prognose von %s", user, foreign)
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
