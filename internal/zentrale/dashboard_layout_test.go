// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Dashboard-Layout je Benutzer (Etappe 17): jeder nur sein eigenes Layout,
// Verweise nur auf sichtbare Mandanten und Geräte (eigener Teilbaum, keine
// Geschwister oder Eltern), Prüfung von Typ und Größe in API und Datenbank.
//
//	IT ─┬─ Fertigung ── Lager Nord
//	    └─ Organisation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func layoutDevice(t *testing.T, tenant, name string) string {
	t.Helper()
	var id string
	if err := owner.QueryRow(context.Background(), `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
		ids[tenant], name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(context.Background(), `DELETE FROM openwacht.devices WHERE id = $1`, id)
	})
	return id
}

func resetLayouts(t *testing.T) {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `DELETE FROM openwacht.dashboard_layouts`); err != nil {
		t.Fatal(err)
	}
}

func w(id, typ, groesse string, extra ...string) map[string]any {
	m := map[string]any{"id": id, "typ": typ, "groesse": groesse}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

func layout(ws ...map[string]any) map[string]any {
	if ws == nil {
		ws = []map[string]any{}
	}
	return map[string]any{"widgets": ws}
}

func layoutWidgets(t *testing.T, c *client) []any {
	t.Helper()
	r := c.do("GET", "/api/v1/dashboard/layout", nil)
	expectStatus(t, "Layout lesen", r, 200)
	ws, _ := r.body["widgets"].([]any)
	return ws
}

func TestDashboardLayoutJeBenutzer(t *testing.T) {
	verwaltungSetup(t)
	resetLayouts(t)
	t.Cleanup(func() { resetLayouts(t) })
	fw, lz, lz2 := as(t, "v_fw"), as(t, "v_lz"), as(t, "v_lz2")

	r := fw.do("GET", "/api/v1/dashboard/layout", nil)
	expectStatus(t, "noch kein Layout", r, 200)
	if r.body["widgets"] != nil {
		t.Errorf("ohne Layout erwartet widgets=null, bekam %v", r.body["widgets"])
	}

	expectStatus(t, "speichern", fw.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "zustand", "breit"), w("bbbb", "alarme", "hoch"), w("cccc", "graph", "klein", "zeitraum", "7t", "wert", "speicher"))), 200)
	got := layoutWidgets(t, fw)
	if len(got) != 3 {
		t.Fatalf("eigenes Layout: %d Widgets, erwartet 3", len(got))
	}
	if g := got[2].(map[string]any); g["zeitraum"] != "7t" || g["wert"] != "speicher" || g["groesse"] != "klein" {
		t.Errorf("Graph falsch gespeichert: %v", g)
	}

	// Ein anderer Benutzer (auch im selben Mandanten) sieht es nicht und überschreibt es nicht.
	if ws := layoutWidgets(t, lz); ws != nil {
		t.Errorf("fremder Benutzer sieht ein Layout: %v", ws)
	}
	expectStatus(t, "anderer speichert", lz.do("PUT", "/api/v1/dashboard/layout", layout(w("dddd", "sensoren", "klein"))), 200)
	if ws := layoutWidgets(t, lz2); ws != nil {
		t.Errorf("Kollege im selben Mandanten sieht ein Layout: %v", ws)
	}
	if ws := layoutWidgets(t, fw); len(ws) != 3 {
		t.Errorf("Layout von v_fw wurde verändert: %v", ws)
	}
	if ws := layoutWidgets(t, lz); len(ws) != 1 {
		t.Errorf("Layout von v_lz: %v", ws)
	}

	// Leeres Dashboard ist erlaubt und etwas anderes als „Standard“.
	expectStatus(t, "leer speichern", lz.do("PUT", "/api/v1/dashboard/layout", layout()), 200)
	r = lz.do("GET", "/api/v1/dashboard/layout", nil)
	if ws, ok := r.body["widgets"].([]any); !ok || len(ws) != 0 {
		t.Errorf("leeres Layout erwartet [], bekam %v", r.body["widgets"])
	}

	// Standard wiederherstellen löscht nur das eigene.
	expectStatus(t, "zurücksetzen", fw.do("DELETE", "/api/v1/dashboard/layout", nil), 204)
	if r := fw.do("GET", "/api/v1/dashboard/layout", nil); r.body["widgets"] != nil {
		t.Errorf("nach dem Zurücksetzen noch ein Layout: %v", r.body["widgets"])
	}
	r = lz.do("GET", "/api/v1/dashboard/layout", nil)
	if _, ok := r.body["widgets"].([]any); !ok {
		t.Errorf("Zurücksetzen von v_fw hat das Layout von v_lz gelöscht")
	}

	// Ohne Anmeldung und ohne CSRF-Token nichts.
	anon := newClient(t, vSrv)
	expectStatus(t, "ohne Sitzung lesen", anon.do("GET", "/api/v1/dashboard/layout", nil), 401)
	expectStatus(t, "ohne Sitzung speichern", anon.do("PUT", "/api/v1/dashboard/layout", layout()), 401)
	csrf := fw.csrf
	fw.csrf = ""
	r = fw.do("PUT", "/api/v1/dashboard/layout", layout())
	fw.csrf = csrf
	if r.status != 403 {
		t.Errorf("ohne CSRF-Token: Status %d, erwartet 403", r.status)
	}
}

func TestDashboardLayoutMandantenbaum(t *testing.T) {
	verwaltungSetup(t)
	resetLayouts(t)
	t.Cleanup(func() { resetLayouts(t) })
	fw := as(t, "v_fw") // Admin der Fertigung: sieht Fertigung und Lager Nord
	devs := map[string]string{}
	for _, tn := range []string{"IT", "Fertigung", "Lager Nord", "Organisation"} {
		devs[tn] = layoutDevice(t, tn, "layout-"+tn)
	}
	cases := []struct {
		tenant string
		want   int
	}{
		{"Fertigung", 200},    // eigener Knoten
		{"Lager Nord", 200},   // Kind
		{"IT", 400},           // Eltern
		{"Organisation", 400}, // Geschwister des Elternknotens
	}
	for _, c := range cases {
		expectStatus(t, "Widget-Mandant "+c.tenant, fw.do("PUT", "/api/v1/dashboard/layout",
			layout(w("aaaa", "zustand", "breit", "mandant_id", ids[c.tenant]))), c.want)
		expectStatus(t, "Graph-Gerät "+c.tenant, fw.do("PUT", "/api/v1/dashboard/layout",
			layout(w("aaaa", "graph", "breit", "geraet_id", devs[c.tenant]))), c.want)
	}
	// Unbekannte IDs genauso wie fremde.
	expectStatus(t, "unbekannter Mandant", fw.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "zustand", "breit", "mandant_id", "00000000-0000-4000-8000-000000000001"))), 400)

	// Leser im Lager sieht nur das Lager.
	lz := as(t, "v_lz")
	expectStatus(t, "Leser: eigener Mandant", lz.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "zustand", "breit", "mandant_id", ids["Lager Nord"]))), 200)
	expectStatus(t, "Leser: Elternmandant", lz.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "zustand", "breit", "mandant_id", ids["Fertigung"]))), 400)
	expectStatus(t, "Leser: Gerät im Elternmandanten", lz.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "graph", "breit", "geraet_id", devs["Fertigung"]))), 400)

	// IT sieht alles darunter.
	it := as(t, "v_it")
	expectStatus(t, "IT: Gerät im Organisation", it.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "graph", "breit", "geraet_id", devs["Organisation"]), w("bbbb", "sonne", "klein", "mandant_id", ids["Lager Nord"]))), 200)
}

// Verschwindet ein Verweis (Gerät gelöscht, Rolle entzogen), liefert GET ihn
// leer, und das Layout bleibt speicherbar.
func TestDashboardLayoutVerweisVerschwindet(t *testing.T) {
	verwaltungSetup(t)
	resetLayouts(t)
	t.Cleanup(func() { resetLayouts(t) })
	ctx := context.Background()
	fw := as(t, "v_fw")
	dev := layoutDevice(t, "Lager Nord", "layout-weg")
	expectStatus(t, "speichern", fw.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "graph", "breit", "geraet_id", dev), w("bbbb", "zustand", "breit", "mandant_id", ids["Lager Nord"]))), 200)
	if _, err := owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	ws := layoutWidgets(t, fw)
	if len(ws) != 2 || ws[0].(map[string]any)["geraet_id"] != nil || ws[1].(map[string]any)["mandant_id"] != ids["Lager Nord"] {
		t.Fatalf("nach dem Löschen des Geräts: %v", ws)
	}
	expectStatus(t, "wieder speichern", fw.do("PUT", "/api/v1/dashboard/layout", map[string]any{"widgets": ws}), 200)

	// Rolle entzogen: Der Mandant ist nicht mehr sichtbar und kommt leer zurück.
	lz2 := as(t, "v_lz2")
	expectStatus(t, "Leser speichert", lz2.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "zustand", "breit", "mandant_id", ids["Lager Nord"]))), 200)
	if _, err := owner.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1`, ids["v_lz2"]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'leser')`, ids["v_lz2"], ids["Lager Nord"])
	})
	ws = layoutWidgets(t, lz2)
	if len(ws) != 1 || ws[0].(map[string]any)["mandant_id"] != nil {
		t.Errorf("nach Entzug der Rolle: %v", ws)
	}
}

func TestDashboardLayoutPruefung(t *testing.T) {
	verwaltungSetup(t)
	resetLayouts(t)
	t.Cleanup(func() { resetLayouts(t) })
	fw := as(t, "v_fw")
	dev := layoutDevice(t, "Fertigung", "layout-pruefung")
	viele := []map[string]any{}
	for i := range 31 {
		viele = append(viele, w(fmt.Sprintf("g%03d", i), "graph", "klein"))
	}
	bad := map[string]any{
		"ohne widgets":           map[string]any{},
		"unbekannte Art":         layout(w("aaaa", "skript", "klein")),
		"unbekannte Größe":       layout(w("aaaa", "zustand", "riesig")),
		"Größe fehlt":            layout(map[string]any{"id": "aaaa", "typ": "zustand"}),
		"doppelte Art":           layout(w("aaaa", "zustand", "klein"), w("bbbb", "zustand", "breit")),
		"doppelte Kennung":       layout(w("aaaa", "zustand", "klein"), w("aaaa", "alarme", "breit")),
		"Kennung zu kurz":        layout(w("aa", "zustand", "klein")),
		"Kennung mit Zeichen":    layout(w("AA-<b>", "zustand", "klein")),
		"zu viele":               map[string]any{"widgets": viele},
		"Gerät ohne Graph":       layout(w("aaaa", "zustand", "klein", "geraet_id", dev)),
		"Zeitraum ohne Graph":    layout(w("aaaa", "auslastung", "klein", "zeitraum", "24h")),
		"Wert ohne Graph":        layout(w("aaaa", "platten", "klein", "wert", "cpu")),
		"Zeitraum unbekannt":     layout(w("aaaa", "graph", "klein", "zeitraum", "1j")),
		"Wert unbekannt":         layout(w("aaaa", "graph", "klein", "wert", "temperatur")),
		"Gerät und Mandant":      layout(w("aaaa", "graph", "klein", "geraet_id", dev, "mandant_id", ids["Fertigung"])),
		"Mandant keine UUID":     layout(w("aaaa", "zustand", "klein", "mandant_id", "Fertigung")),
		"Gerät keine UUID":       layout(w("aaaa", "graph", "klein", "geraet_id", "1 OR 1=1")),
		"unbekanntes Feld":       layout(w("aaaa", "zustand", "klein", "skript", "x")),
		"unbekanntes Feld außen": map[string]any{"widgets": []any{}, "benutzer_id": ids["v_it"]},
		"Widget kein Objekt":     map[string]any{"widgets": []any{"zustand"}},
	}
	for name, body := range bad {
		r := fw.do("PUT", "/api/v1/dashboard/layout", body)
		if r.status != 400 {
			t.Errorf("%s: Status %d, erwartet 400 (%s)", name, r.status, r.raw)
		}
	}
	if ws := layoutWidgets(t, fw); ws != nil {
		t.Errorf("abgelehnte Layouts wurden gespeichert: %v", ws)
	}
	// Die Anwendung prüft selbst (verständliche Meldung), nicht erst die Datenbank („Ungültige Eingabe.“).
	for name, want := range map[string]string{
		"doppelte Art":       "nur einmal",
		"zu viele":           "Höchstens 30",
		"Gerät und Mandant":  "entweder ein Gerät",
		"Gerät ohne Graph":   "nur beim Graphen",
		"unbekannte Größe":   "klein, breit oder hoch",
		"Zeitraum unbekannt": "Zeitraum",
	} {
		r := fw.do("PUT", "/api/v1/dashboard/layout", bad[name])
		if !strings.Contains(r.raw, want) {
			t.Errorf("%s: Meldung %q enthält nicht %q", name, strings.TrimSpace(r.raw), want)
		}
	}
	// Grenzfälle, die gehen müssen: 30 Widgets, mehrere Graphen, leere Einstellungen.
	expectStatus(t, "30 Graphen", fw.do("PUT", "/api/v1/dashboard/layout", map[string]any{"widgets": viele[:30]}), 200)
	expectStatus(t, "leere Einstellungen", fw.do("PUT", "/api/v1/dashboard/layout",
		layout(w("aaaa", "graph", "hoch", "geraet_id", "", "mandant_id", "", "zeitraum", "", "wert", ""))), 200)
	expectStatus(t, "alle Arten", fw.do("PUT", "/api/v1/dashboard/layout", layout(
		w("a001", "zustand", "breit"), w("a002", "alarme", "breit"), w("a003", "sensoren", "klein"), w("a004", "auslastung", "hoch"),
		w("a005", "platten", "klein"), w("a006", "prognose", "klein"), w("a007", "alarme_je_tag", "klein"),
		w("a008", "verfuegbarkeit", "klein"), w("a009", "graph", "breit", "geraet_id", dev, "zeitraum", "30t", "wert", "cpu"),
		w("a010", "sonne", "klein"), w("a011", "ereignisse", "hoch"))), 200)
}

// TestDashboardLayoutDatenbank prüft RLS und CHECK direkt mit der App-Rolle,
// ohne die Anwendung davor.
func TestDashboardLayoutDatenbank(t *testing.T) {
	verwaltungSetup(t)
	resetLayouts(t)
	t.Cleanup(func() { resetLayouts(t) })
	ctx := context.Background()
	ok := `[{"id":"aaaa","typ":"zustand","groesse":"breit"}]`
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets) VALUES ($1, $2, $3)`,
		ids["v_fw"], ids["Fertigung"], ok); err != nil {
		t.Fatal(err)
	}
	inTx := func(user string, fn func(tx pgx.Tx) error) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if user != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[user]); err != nil {
					return err
				}
			}
			return fn(tx)
		})
	}
	count := func(user string) int {
		var n int
		if err := inTx(user, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.dashboard_layouts`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("v_fw"); n != 1 {
		t.Errorf("Eigentümer sieht %d Zeilen, erwartet 1", n)
	}
	// Auch der Admin des Hauptmandanten sieht fremde Layouts nicht.
	for _, u := range []string{"v_it", "v_lz", "v_oa", ""} {
		if n := count(u); n != 0 {
			t.Errorf("%q sieht %d fremde Layouts", u, n)
		}
	}
	code := func(err error) string {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe.Code
		}
		if err == nil {
			return ""
		}
		return err.Error()
	}
	// Fremde Zeile anlegen: RLS (42501).
	err := inTx("v_it", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets) VALUES ($1, $2, '[]')`,
			ids["v_lz"], ids["Lager Nord"])
		return err
	})
	if code(err) != "42501" {
		t.Errorf("fremde Zeile anlegen: %v, erwartet 42501", err)
	}
	// Eigene Zeile mit falschem Mandanten: Fremdschlüssel (23503).
	err = inTx("v_lz", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets) VALUES ($1, $2, '[]')`,
			ids["v_lz"], ids["IT"])
		return err
	})
	if code(err) != "23503" {
		t.Errorf("falscher Mandant: %v, erwartet 23503", err)
	}
	// Fremde Zeile ändern oder löschen: trifft nichts.
	for _, q := range []string{
		`UPDATE openwacht.dashboard_layouts SET widgets = '[]' WHERE user_id = $1`,
		`DELETE FROM openwacht.dashboard_layouts WHERE user_id = $1`,
	} {
		var n int64
		err := inTx("v_it", func(tx pgx.Tx) error {
			ct, err := tx.Exec(ctx, q, ids["v_fw"])
			n = ct.RowsAffected()
			return err
		})
		if err != nil || n != 0 {
			t.Errorf("%s: %d Zeilen, %v", q, n, err)
		}
	}
	// Eigene Zeile umhängen auf einen anderen Benutzer: nicht erlaubt (Spalte gesperrt).
	err = inTx("v_fw", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.dashboard_layouts SET user_id = $1`, ids["v_lz"])
		return err
	})
	if code(err) != "42501" {
		t.Errorf("Zeile umhängen: %v, erwartet 42501", err)
	}
	var same bool
	if err := owner.QueryRow(ctx, `SELECT widgets = $2::jsonb FROM openwacht.dashboard_layouts WHERE user_id = $1`, ids["v_fw"], ok).Scan(&same); err != nil || !same {
		t.Errorf("Layout von v_fw verändert: %v", err)
	}

	// CHECK in der Datenbank: dieselben Regeln wie in der API.
	uuid := ids["Fertigung"]
	bad := []string{
		`{}`, `"x"`, `[1]`, `[{"id":"aaaa","typ":"skript","groesse":"klein"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"riesig"}]`,
		`[{"id":"aaaa","typ":"zustand"}]`,
		`[{"typ":"zustand","groesse":"klein"}]`,
		`[{"id":"AAAA","typ":"zustand","groesse":"klein"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein"},{"id":"aaaa","typ":"alarme","groesse":"klein"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein"},{"id":"bbbb","typ":"zustand","groesse":"klein"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","x":1}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","geraet_id":"` + uuid + `"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","zeitraum":"24h"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","wert":"cpu"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","mandant_id":"kein-uuid"}]`,
		`[{"id":"aaaa","typ":"zustand","groesse":"klein","mandant_id":5}]`,
		`[{"id":"aaaa","typ":"graph","groesse":"klein","zeitraum":"1j"}]`,
		`[{"id":"aaaa","typ":"graph","groesse":"klein","wert":"temperatur"}]`,
		`[{"id":"aaaa","typ":"graph","groesse":"klein","geraet_id":"` + uuid + `","mandant_id":"` + uuid + `"}]`,
		`[{"id":"aaaa","typ":["zustand"],"groesse":"klein"}]`,
	}
	many := "["
	for i := range 31 {
		if i > 0 {
			many += ","
		}
		many += fmt.Sprintf(`{"id":"g%03d","typ":"graph","groesse":"klein"}`, i)
	}
	bad = append(bad, many+"]")
	for _, b := range bad {
		err := inTx("v_lz", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets) VALUES ($1, $2, $3::jsonb)`,
				ids["v_lz"], ids["Lager Nord"], b)
			return err
		})
		if code(err) != "23514" {
			t.Errorf("CHECK ließ durch oder anderer Fehler: %s → %v", b, err)
		}
	}
	good := `[{"id":"g001","typ":"graph","groesse":"hoch","geraet_id":"` + uuid + `","zeitraum":"7t","wert":"speicher","mandant_id":null},` +
		`{"id":"g002","typ":"graph","groesse":"klein","mandant_id":"` + uuid + `","geraet_id":null},{"id":"z001","typ":"zustand","groesse":"breit"}]`
	if err := inTx("v_lz", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets) VALUES ($1, $2, $3::jsonb)`,
			ids["v_lz"], ids["Lager Nord"], good)
		return err
	}); err != nil {
		t.Errorf("gültiges Layout abgelehnt: %v", err)
	}
	// Mit dem Benutzer verschwindet das Layout.
	var n int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.dashboard_layouts l JOIN openwacht.users u ON u.id = l.user_id AND u.tenant_id = l.tenant_id`).Scan(&n); err != nil || n != 2 {
		t.Errorf("Zeilen passend zum Benutzer: %d, %v", n, err)
	}
}
