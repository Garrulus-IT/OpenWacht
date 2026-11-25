// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Prüft docs/api/openapi.json gegen den Code: Jeder beschriebene Pfad ist
// eine GET-Route in server.go, ein API-Token mit der Rolle Leser bekommt dort
// 200, und die Antwort passt zum Schema. Umgekehrt muss jede lesende Route,
// die ein Leser-Token erreicht, beschrieben oder unten begründet
// ausgenommen sein. Eine neue Route fällt damit von selbst auf.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Lesende Routen, die ein Leser-Token erreicht, die aber nicht für Skripte
// gedacht sind (Oberfläche, persönliche Einstellungen, Verwaltung). Ihre
// Antworten können sich ohne Ankündigung ändern.
var openAPINichtBeschrieben = map[string]string{
	"/api/v1/dashboard/layout":                "persönliches Layout der Oberfläche",
	"/api/v1/hinweise":                        "Hinweise der Oberfläche",
	"/api/v1/ich/alarm-mobilnummer":           "eigenes Konto; das technische Konto eines Tokens hat keine",
	"/api/v1/mandanten-antraege":              "Verwaltung (Anträge auf Untermandanten)",
	"/api/v1/mandanten/{id}/agent-tokens":     "Verwaltung, für Leser immer leer",
	"/api/v1/api-tokens":                      "Verwaltung, für Leser immer leer",
	"/api/v1/verzeichnisse":                   "Verwaltung (AD/SSO)",
	"/api/v1/geraete/{id}/loeschen":           "Vorschau der Oberfläche vor dem Löschen",
	"/api/v1/geraete/{id}/schwellen":          "Formular der Oberfläche",
	"/api/v1/alarm-kanaele":                   "Verwaltung (Alarmwege)",
	"/api/v1/snmp-profile":                    "Verwaltung, für Leser immer leer",
	"/api/v1/anzeigen":                        "Verwaltung (Wandanzeigen)",
	"/api/v1/agent-updates":                   "Verwaltung (Agent-Updates)",
	"/api/v1/agent-updates/automatik":         "Verwaltung (Agent-Updates)",
	"/api/v1/benutzer":                        "Verwaltung (Konten)",
	"/api/v1/sensor-vorlagen":                 "Formular der Oberfläche",
	"/api/v1/trapregeln":                      "Verwaltung (Trap-Regeln); Zustände stehen unter /snmp/{id}/traps",
	"/api/v1/mandanten/{id}/rezertifizierung": "nur Admins (CSV/PDF)",
}

type openAPIDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Paths map[string]struct {
		Get *struct {
			Security   *[]any `json:"security"`
			Parameters []struct {
				Name     string         `json:"name"`
				In       string         `json:"in"`
				Required bool           `json:"required"`
				Objekt   string         `json:"x-openwacht-objekt"`
				Schema   map[string]any `json:"schema"`
			} `json:"parameters"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"get"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func loadOpenAPI(t *testing.T) openAPIDoc {
	t.Helper()
	b, err := os.ReadFile("../../docs/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var d openAPIDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	return d
}

// openAPICheck prüft einen Wert gegen ein Schema (die Teile von JSON
// Schema, die openapi.json benutzt: type, required, properties, items,
// $ref, oneOf, enum, pattern, minItems, maxItems).
func openAPICheck(d openAPIDoc, schema map[string]any, v any, where string) []string {
	if r, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(r, "#/components/schemas/")
		s, ok := d.Components.Schemas[name]
		if !ok {
			return []string{where + ": unbekannter Verweis " + r}
		}
		return openAPICheck(d, s, v, where)
	}
	if alts, ok := schema["oneOf"].([]any); ok {
		var all []string
		for _, a := range alts {
			p := openAPICheck(d, a.(map[string]any), v, where)
			if len(p) == 0 {
				return nil
			}
			all = append(all, p...)
		}
		return []string{fmt.Sprintf("%s: passt zu keiner Variante (%s)", where, strings.Join(all, "; "))}
	}
	var types []string
	switch ty := schema["type"].(type) {
	case string:
		types = []string{ty}
	case []any:
		for _, x := range ty {
			types = append(types, x.(string))
		}
	}
	got := "null"
	switch x := v.(type) {
	case map[string]any:
		got = "object"
	case []any:
		got = "array"
	case string:
		got = "string"
	case bool:
		got = "boolean"
	case float64:
		got = "number"
		if x == float64(int64(x)) {
			got = "integer"
		}
	}
	if len(types) > 0 {
		ok := false
		for _, ty := range types {
			ok = ok || ty == got || (ty == "number" && got == "integer")
		}
		if !ok {
			return []string{fmt.Sprintf("%s: Typ %s, erwartet %v", where, got, types)}
		}
	}
	var out []string
	if enum, ok := schema["enum"].([]any); ok && v != nil {
		found := false
		for _, e := range enum {
			found = found || e == v
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: Wert %v nicht in %v", where, v, enum))
		}
	}
	if p, ok := schema["pattern"].(string); ok {
		if s, isStr := v.(string); isStr && !regexp.MustCompile(p).MatchString(s) {
			out = append(out, fmt.Sprintf("%s: %q passt nicht zu %s", where, s, p))
		}
	}
	switch x := v.(type) {
	case map[string]any:
		for _, r := range anyStrings(schema["required"]) {
			if _, ok := x[r]; !ok {
				out = append(out, where+": Feld "+r+" fehlt")
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for k, ps := range props {
			if val, ok := x[k]; ok {
				out = append(out, openAPICheck(d, ps.(map[string]any), val, where+"."+k)...)
			}
		}
	case []any:
		if n, ok := schema["minItems"].(float64); ok && float64(len(x)) < n {
			out = append(out, fmt.Sprintf("%s: %d Einträge, mindestens %v", where, len(x), n))
		}
		if n, ok := schema["maxItems"].(float64); ok && float64(len(x)) > n {
			out = append(out, fmt.Sprintf("%s: %d Einträge, höchstens %v", where, len(x), n))
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, e := range x {
				if i >= 20 {
					break
				}
				out = append(out, openAPICheck(d, items, e, fmt.Sprintf("%s[%d]", where, i))...)
			}
		}
	}
	return out
}

func anyStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func TestOpenAPIPasstZumCode(t *testing.T) {
	d := loadOpenAPI(t)
	ver, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if d.Info.Version != strings.TrimSpace(string(ver)) {
		t.Errorf("info.version %q, VERSION %q", d.Info.Version, strings.TrimSpace(string(ver)))
	}
	routes := map[string]bool{}
	for _, rt := range sweepRoutes(t) {
		if rt[0] == "GET" {
			routes[rt[1]] = true
		}
	}
	for p, it := range d.Paths {
		if it.Get == nil || !routes[p] {
			t.Errorf("%s: keine GET-Route in server.go", p)
		}
		if openAPINichtBeschrieben[p] != "" {
			t.Errorf("%s steht in openapi.json und bei den Ausnahmen", p)
		}
	}
	for p := range openAPINichtBeschrieben {
		if !routes[p] {
			t.Errorf("Ausnahme %s: keine GET-Route mehr in server.go", p)
		}
	}

	agentServer(t)
	// Eigene Testdaten ohne die Marke des Routen-Sweeps: Was über die API
	// angelegt wird, bleibt im Audit-Log, und der Sweep sucht dort nach ihr.
	dev, _, _ := fullDevice(t, "Fertigung", "OpenAPI Gerät")
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, message, started_at, changed_at)
		SELECT $1, c.id, 'check', 'OpenAPI offen', 'crit', 'crit', 'keine Antwort', now(), now() FROM openwacht.checks c WHERE c.device_id = $2`,
		ids["Fertigung"], dev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = 'OpenAPI offen'`) })
	var grp string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'OpenAPI Gruppe') RETURNING id::text`,
		ids["Fertigung"]).Scan(&grp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id = $1`, grp) })
	fw := as(t, "v_fw")
	r := fw.do("POST", "/api/v1/api-tokens", map[string]any{"mandant": ids["Fertigung"], "name": "OpenAPI", "rolle": "leser",
		"tage": 1, "code": freshCode(t, "v_fw")})
	tok, _ := r.body["token"].(string)
	if tok == "" {
		t.Fatalf("Token: %d %s", r.status, r.raw)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.api_tokens WHERE name = 'OpenAPI'`) })
	var chk, ag, src string
	if err := owner.QueryRow(ctx, `SELECT c.id::text, a.id::text, s.id::text
		FROM openwacht.devices d JOIN openwacht.checks c ON c.device_id = d.id JOIN openwacht.agents a ON a.device_id = d.id
		JOIN openwacht.snmp_sources s ON s.device_id = d.id WHERE d.id = $1 LIMIT 1`, dev).
		Scan(&chk, &ag, &src); err != nil {
		t.Fatal(err)
	}
	obj := map[string]string{"mandant": ids["Fertigung"], "geraet": dev, "check": chk, "agent": ag, "snmp": src}

	var paths []string
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		g := d.Paths[p].Get
		if g == nil {
			continue
		}
		url, q := p, []string{}
		for _, prm := range g.Parameters {
			val := ""
			if prm.Objekt != "" {
				val = obj[prm.Objekt]
				if val == "" {
					t.Fatalf("%s: unbekanntes x-openwacht-objekt %q", p, prm.Objekt)
				}
			} else if prm.Required {
				t.Fatalf("%s: Pflichtparameter %s ohne x-openwacht-objekt", p, prm.Name)
			}
			switch {
			case prm.In == "path":
				url = strings.Replace(url, "{"+prm.Name+"}", val, 1)
			case val != "":
				q = append(q, prm.Name+"="+val)
			}
		}
		if len(q) > 0 {
			url += "?" + strings.Join(q, "&")
		}
		if strings.Contains(url, "{") {
			t.Fatalf("%s: Pfadparameter nicht beschrieben", p)
		}
		res := bearer(t, vSrv, tok, "GET", url, nil)
		if res.status != 200 {
			t.Errorf("GET %s mit Leser-Token: %d %.200s", url, res.status, res.raw)
			continue
		}
		ok := g.Responses["200"]
		for ct, c := range ok.Content {
			if got := res.header.Get("Content-Type"); !strings.HasPrefix(got, ct) {
				t.Errorf("GET %s: Content-Type %q, beschrieben %q", url, got, ct)
			}
			if ct != "application/json" {
				continue
			}
			var v any
			if err := json.Unmarshal([]byte(res.raw), &v); err != nil {
				t.Errorf("GET %s: kein JSON", url)
				continue
			}
			for _, prob := range openAPICheck(d, c.Schema, v, p) {
				t.Error(prob)
			}
		}
		// ohne Token: abgelehnt, außer was ausdrücklich ohne Anmeldung geht
		if g.Security == nil || len(*g.Security) > 0 {
			nc := newClient(t, vSrv)
			nc.origin = ""
			if res := nc.do("GET", url, nil); res.status != 401 {
				t.Errorf("GET %s ohne Token: %d", url, res.status)
			}
		}
	}

	// Umgekehrt: Was ein Leser-Token sonst noch lesen kann, muss beschrieben
	// oder ausgenommen sein.
	tables := sweepTables(t)
	cand := sweepIDs(t, tables, []string{ids["Fertigung"]})
	var candIDs []string
	for id := range cand {
		candIDs = append(candIDs, id)
	}
	sort.Strings(candIDs)
	param := regexp.MustCompile(`\{[a-z]+\}`)
	var rs []string
	for p := range routes {
		rs = append(rs, p)
	}
	sort.Strings(rs)
	for _, p := range rs {
		if _, documented := d.Paths[p]; documented || openAPINichtBeschrieben[p] != "" {
			continue
		}
		try := []string{p}
		if param.MatchString(p) {
			try = nil
			for _, id := range candIDs {
				try = append(try, param.ReplaceAllString(p, id))
			}
		}
		for _, u := range try {
			if res := bearer(t, vSrv, tok, "GET", u, nil); res.status/100 == 2 {
				t.Errorf("GET %s: Leser-Token bekommt %d, aber die Route steht weder in docs/api/openapi.json noch bei den Ausnahmen", p, res.status)
				break
			}
		}
	}
}
