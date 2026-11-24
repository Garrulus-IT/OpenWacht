// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Routen-Sweep zur Mandantentrennung: Ein Admin eines Mandanten ruft jede
// Route aus server.go mit den IDs von Objekten eines Geschwister- und des
// Elternmandanten auf. Erwartet wird: keine Antwort 2xx, kein interner
// Fehler, kein Name der fremden Objekte in einer Antwort und am Ende
// unveränderte Daten der fremden Mandanten.
//
// Die Routen liest der Test aus server.go: Eine neue Route ist damit
// automatisch abgedeckt. Er ersetzt nicht die Tests je Endpunkt (die auch
// gültige Eingaben prüfen), sondern fängt vergessene Prüfungen ab.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const sweepMarke = "SWEEPGEHEIM"

var sweepRoute = regexp.MustCompile(`mux\.Handle(?:Func)?\("(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^"]*)"`)

// sweepRoutes liest Methode und Pfad aller API-Routen aus server.go.
func sweepRoutes(t *testing.T) [][2]string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	var out [][2]string
	for _, m := range sweepRoute.FindAllStringSubmatch(string(src), -1) {
		out = append(out, [2]string{m[1], m[2]})
	}
	if len(out) < 150 {
		t.Fatalf("nur %d Routen in server.go gefunden: Muster prüfen", len(out))
	}
	return out
}

// sweepTables: fachliche Tabellen mit tenant_id (ohne Partitionen und Messwerte).
func sweepTables(t *testing.T) []string {
	t.Helper()
	rows, err := owner.Query(context.Background(), `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		WHERE n.nspname = 'openwacht' AND c.relkind = 'r' AND NOT c.relispartition AND c.relname NOT LIKE 'metrics\_%'
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// sweepSnapshot: Prüfsumme je Tabelle über alle Zeilen der Mandanten. Spalten,
// die sich ohne Zutun ändern (Planer, Lebenszeichen), bleiben außen vor.
func sweepSnapshot(t *testing.T, tables []string, tenants []string) map[string]string {
	t.Helper()
	ctx := context.Background()
	skip := `- 'next_run' - 'last_run' - 'last_try' - 'last_seen' - 'last_used_at' - 'updated_at' - 'claimed_at'`
	out := map[string]string{}
	for _, tb := range tables {
		var sum *string
		if err := owner.QueryRow(ctx, fmt.Sprintf(`SELECT count(*)::text || ':' || coalesce(md5(string_agg(md5((to_jsonb(x) %s)::text), '' ORDER BY md5((to_jsonb(x) %s)::text))), '')
			FROM openwacht.%s x WHERE x.tenant_id = ANY($1::uuid[])`, skip, skip, tb), tenants).Scan(&sum); err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
		out[tb] = *sum
	}
	return out
}

// sweepIDs: alle UUIDs (Spalte id) der Mandanten, dazu Benutzer und die Mandanten selbst.
func sweepIDs(t *testing.T, tables []string, tenants []string) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	for _, tb := range tables {
		var has bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'openwacht' AND table_name = $1 AND column_name = 'id' AND data_type = 'uuid')`, tb).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if !has {
			continue
		}
		rows, err := owner.Query(ctx, fmt.Sprintf(`SELECT id::text FROM openwacht.%s WHERE tenant_id = ANY($1::uuid[]) ORDER BY id LIMIT 3`, tb), tenants)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; rows.Next(); i++ {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out[id] = fmt.Sprintf("%s#%d", tb, i)
		}
		rows.Close()
	}
	for i, id := range tenants {
		out[id] = fmt.Sprintf("tenants#%d", i)
	}
	return out
}

// sweepSeed legt in einem Mandanten von jeder Art ein Objekt an (als
// Eigentümer bzw. über die API als dessen Admin). Namen tragen die Marke.
func sweepSeed(t *testing.T, tenant, admin string) {
	t.Helper()
	ctx := context.Background()
	n := sweepMarke + " " + tenant
	dev, agent, src := fullDevice(t, tenant, n)
	tid := ids[tenant]
	exec := func(what, q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	_ = agent
	exec("alarm offen", `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, message, started_at, changed_at)
		SELECT $1, c.id, 'check', $3, 'crit', 'crit', $3, now(), now() FROM openwacht.checks c WHERE c.device_id = $2`, tid, dev, n+" Alarm")
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = $1`, n+" Alarm") })
	exec("trap-zustand", `INSERT INTO openwacht.snmp_trap_state (source_id, tenant_id, rule_id, rule_name, instance, status, message, authentic, since, last_at)
		SELECT $1, r.tenant_id, r.id, r.name, '', 'crit', $2, false, now(), now() FROM openwacht.snmp_trap_rules r WHERE r.device_id = $3 AND r.clears IS NULL`, src, n, dev)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_state WHERE source_id = $1`, src) })
	c := as(t, admin)
	post := func(what, path string, body map[string]any, table string) {
		t.Helper()
		r := c.do("POST", path, body)
		if r.status/100 != 2 {
			t.Fatalf("Vorbereitung %s in %s: %d %s", what, tenant, r.status, r.raw)
		}
		if id, ok := r.body["id"].(string); ok && table != "" {
			t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.`+table+` WHERE id = $1`, id) })
		}
	}
	m := "/api/v1/mandanten/" + tid
	post("gruppe", m+"/gruppen", map[string]any{"name": n + " Gruppe", "eltern_id": ""}, "device_groups")
	post("kennfarbe", m+"/kennfarben", map[string]any{"name": n + " Farbe", "farbe": "#c0307a"}, "kennfarben")
	post("vorlage", m+"/sensor-vorlagen", map[string]any{"name": n + " Vorlage", "typ": "ping", "ziel": map[string]any{"host": "{adresse}"}, "intervall_sekunden": 60}, "sensor_templates")
	post("anzeige", m+"/anzeigen", map[string]any{"name": n + " Anzeige"}, "displays")
	post("kanal", m+"/alarm-kanaele", map[string]any{"name": n + " Kanal", "server": vNtfy.URL, "topic": "sweep"}, "alert_channels")
	post("agent-token", m+"/agent-tokens", map[string]any{"notiz": n + " Token", "anzahl": 1, "gueltig_stunden": 1}, "")
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.agent_tokens WHERE note = $1`, n+" Token") })
	post("wartungsfenster", "/api/v1/wartungsfenster", map[string]any{"name": n + " Fenster", "grund": "Sweep", "ziel_art": "geraet", "ziel_id": dev,
		"wiederholung": "einmalig", "beginn": "2031-01-01T10:00:00Z", "ende": "2031-01-01T11:00:00Z", "zeitzone": "Europe/Berlin"}, "maintenance_windows")
	exec("benutzer", `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, $2, $3)`,
		tid, strings.ToLower(sweepMarke+"-"+strings.ReplaceAll(tenant, " ", ""))+"@test.invalid", n+" Person")
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.users WHERE display_name = $1`, n+" Person") })
}

func TestRoutenSweepMandantentrennung(t *testing.T) {
	agentServer(t) // Agent-CA für Registrierungs-Tokens
	// Angreifer: Admin von „Fertigung“. Fremd: Geschwister „Organisation“ und Eltern „IT“.
	sweepSeed(t, "Organisation", "v_oa")
	sweepSeed(t, "IT", "v_it")
	victims := []string{ids["Organisation"], ids["IT"]}
	tables := sweepTables(t)
	cand := sweepIDs(t, tables, victims)
	if len(cand) < 20 {
		t.Fatalf("nur %d fremde IDs: Vorbereitung unvollständig", len(cand))
	}
	// Konten der fremden Mandanten (users.id heißt in Pfaden {id}).
	for _, u := range []string{"v_oa", "v_it", "v_oa_user"} {
		cand[ids[u]] = "users:" + u
	}
	var candIDs []string
	for id := range cand {
		candIDs = append(candIDs, id)
	}
	sort.Strings(candIDs)
	before := sweepSnapshot(t, tables, victims)

	att := as(t, "v_fw")
	// Körper für schreibende Anfragen: leer und mit üblichen Feldern samt fremden IDs.
	bodies := func(id string) []map[string]any {
		return []map[string]any{{}, {"name": "Sweep", "id": id, "mandant_id": ids["Organisation"], "mandant": ids["Organisation"],
			"geraet_id": id, "gruppe_id": id, "kennfarbe_id": id}}
	}
	param := regexp.MustCompile(`\{[a-z]+\}`)
	// Antworten 2xx, die kein Zugriff auf fremde Daten sind: Die Liste der
	// Registrierungs-Tokens filtert RLS, für fremde Mandanten bleibt sie leer.
	emptyList := map[string]string{"GET /api/v1/mandanten/{id}/agent-tokens": `{"tokens":[]}`}
	n := 0
	check := func(method, path string, body map[string]any, pattern, what string) {
		r := att.do(method, path, body)
		n++
		if strings.Contains(r.raw, sweepMarke) {
			t.Errorf("%s %s (%s): Antwort enthält fremde Daten: %.300s", method, path, what, r.raw)
		}
		if r.status >= 500 && r.status != 502 {
			t.Errorf("%s %s (%s): Status %d %.200s", method, path, what, r.status, r.raw)
		}
		if r.status/100 == 2 && strings.TrimSpace(r.raw) != emptyList[method+" "+pattern] {
			t.Errorf("%s %s (%s): Status %d trotz fremder ID %.200s", method, path, what, r.status, r.raw)
		}
	}
	for _, rt := range sweepRoutes(t) {
		method, pattern := rt[0], rt[1]
		params := param.FindAllString(pattern, -1)
		if len(params) == 0 {
			if method == "GET" {
				// Listen: dürfen antworten, aber nichts Fremdes zeigen.
				r := att.do("GET", pattern, nil)
				n++
				// Ausnahme laut Sicherheitskonzept: Kennfarben der Vorfahren sind
				// sichtbar (Name und Farbe), die von Geschwistern nicht.
				raw := r.raw
				if pattern == "/api/v1/kennfarben" {
					raw = strings.ReplaceAll(raw, sweepMarke+" IT Farbe", "")
				}
				if strings.Contains(raw, sweepMarke) {
					t.Errorf("GET %s: Liste enthält fremde Daten: %.300s", pattern, r.raw)
				}
			}
			continue
		}
		if strings.HasPrefix(pattern, "/api/v1/sitzung") || strings.HasPrefix(pattern, "/api/v1/passkeys") {
			continue // eigenes Konto, keine fremden Objekte
		}
		for _, id := range candIDs {
			if len(params) == 2 { // {id}/rollen/{mandant}: fremdes Konto bzw. eigenes Konto im fremden Mandanten
				for _, pair := range [][2]string{{id, ids["Organisation"]}, {ids["v_fw"], id}, {id, ids["Fertigung"]}} {
					p := strings.Replace(strings.Replace(pattern, params[0], pair[0], 1), params[1], pair[1], 1)
					if method == "GET" || method == "DELETE" {
						check(method, p, nil, pattern, pattern)
					} else {
						check(method, p, map[string]any{"rolle": "admin"}, pattern, pattern)
					}
				}
				continue
			}
			path := strings.Replace(pattern, params[0], id, 1)
			if method == "GET" || method == "DELETE" {
				check(method, path, nil, pattern, pattern+" mit "+cand[id])
				continue
			}
			for _, b := range bodies(id) {
				check(method, path, b, pattern, pattern+" mit "+cand[id])
			}
		}
	}
	t.Logf("%d Anfragen mit %d fremden IDs", n, len(candIDs))
	after := sweepSnapshot(t, tables, victims)
	for _, tb := range tables {
		if before[tb] != after[tb] {
			t.Errorf("Tabelle %s der fremden Mandanten hat sich geändert (%s -> %s)", tb, before[tb], after[tb])
		}
	}
}

// Ein Leser darf im eigenen Mandanten nichts ändern: jede schreibende Route
// mit den IDs der eigenen Objekte, ohne Antwort 2xx und ohne Änderung der
// Daten. Ausgenommen sind die Routen für das eigene Konto.
func TestRoutenSweepLeserSchreibtNicht(t *testing.T) {
	agentServer(t)
	sweepSeed(t, "Lager Nord", "v_fw")
	own := []string{ids["Lager Nord"]}
	tables := sweepTables(t)
	cand := sweepIDs(t, tables, own)
	cand[ids["v_lz2"]] = "users:v_lz2"
	var candIDs []string
	for id := range cand {
		candIDs = append(candIDs, id)
	}
	sort.Strings(candIDs)
	// Eigenes Konto und persönliche Einstellungen dürfen sich ändern.
	var data []string
	for _, tb := range tables {
		if tb != "dashboard_layouts" && tb != "users" && tb != "audit_log" {
			data = append(data, tb)
		}
	}
	before := sweepSnapshot(t, data, own)
	att := as(t, "v_lz")
	self := []string{"/api/v1/sitzung", "/api/v1/ich", "/api/v1/zwei-faktor", "/api/v1/passkeys", "/api/v1/dashboard/layout", "/api/v1/anzeige/anmelden"}
	param := regexp.MustCompile(`\{[a-z]+\}`)
	n := 0
	for _, rt := range sweepRoutes(t) {
		method, pattern := rt[0], rt[1]
		if method == "GET" || slicesHasPrefix(self, pattern) {
			continue
		}
		params := param.FindAllString(pattern, -1)
		ids := candIDs
		if len(params) == 0 {
			ids = []string{""}
		}
		for _, id := range ids {
			path := pattern
			for _, p := range params {
				path = strings.Replace(path, p, id, 1)
			}
			if len(params) == 2 {
				path = strings.Replace(strings.Replace(pattern, params[0], id, 1), params[1], own[0], 1)
			}
			bodies := []map[string]any{nil}
			if method != "DELETE" {
				bodies = []map[string]any{{}, {"name": "Sweep", "rolle": "admin", "mandant_id": own[0], "mandant": own[0], "geraet_id": id, "grund": "Sweep"}}
			}
			for _, b := range bodies {
				r := att.do(method, path, b)
				n++
				if r.status/100 == 2 {
					t.Errorf("%s %s (%s mit %s): Leser bekommt Status %d %.200s", method, path, pattern, cand[id], r.status, r.raw)
				}
				if r.status >= 500 && r.status != 502 {
					t.Errorf("%s %s (%s): Status %d %.200s", method, path, pattern, r.status, r.raw)
				}
			}
		}
	}
	t.Logf("%d schreibende Anfragen als Leser", n)
	after := sweepSnapshot(t, data, own)
	for _, tb := range data {
		if before[tb] != after[tb] {
			t.Errorf("Tabelle %s hat sich durch einen Leser geändert (%s -> %s)", tb, before[tb], after[tb])
		}
	}
}

func slicesHasPrefix(prefixes []string, s string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
