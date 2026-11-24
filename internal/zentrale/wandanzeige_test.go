// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func newDisplay(t *testing.T, user, tenant string, body map[string]any) response {
	t.Helper()
	return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/anzeigen", body)
}

// displayKey holt den Schlüssel aus dem Link.
func displayKey(t *testing.T, r response) string {
	t.Helper()
	link, _ := r.body["link"].(string)
	i := strings.Index(link, "/anzeige#")
	if i < 0 {
		t.Fatalf("Link ohne Schlüssel: %q", link)
	}
	return link[i+len("/anzeige#"):]
}

func TestAnzeigeVerwaltungMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newDisplay(t, "v_fw", "Fertigung", map[string]any{"name": "AM Flur", "mit_untermandanten": true})
	expectStatus(t, "Admin legt an", r, 201)
	id := r.body["id"].(string)
	if link, _ := r.body["link"].(string); !strings.HasPrefix(link, vSrv.URL+"/anzeige#") || len(displayKey(t, r)) != 43 {
		t.Errorf("Link: %q", link)
	}

	expectStatus(t, "Leser legt an", newDisplay(t, "v_lz", "Lager Nord", map[string]any{"name": "x"}), 403)
	expectStatus(t, "Geschwister legt an", newDisplay(t, "v_oa", "Fertigung", map[string]any{"name": "x"}), 403)
	expectStatus(t, "Kind legt bei Eltern an", newDisplay(t, "v_fw", "IT", map[string]any{"name": "x"}), 403)
	r = newDisplay(t, "v_fw", "Lager Nord", map[string]any{"name": "AM LZ", "netz": "172.16.0.7"})
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	idLZ := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := listEntry(t, user, "/api/v1/anzeigen", "anzeigen", id); got != want {
			t.Errorf("%s sieht Anzeige: %v, erwartet %v", user, got, want)
		}
	}
	// Leser sehen Anzeigen nicht, auch nicht im eigenen Mandanten.
	if _, got := listEntry(t, "v_lz", "/api/v1/anzeigen", "anzeigen", idLZ); got {
		t.Error("Leser sieht Anzeige im eigenen Mandanten")
	}
	e, _ := listEntry(t, "v_fw", "/api/v1/anzeigen", "anzeigen", idLZ)
	if e["netz"] != "172.16.0.7/32" || e["mit_untermandanten"] != false || e["mandant_id"] != ids["Lager Nord"] || e["zuletzt_da"] != nil {
		t.Errorf("Eintrag: %+v", e)
	}
	if _, ok := e["schluessel"]; ok {
		t.Error("Liste verrät den Schlüssel")
	}

	for name, body := range map[string]map[string]any{
		"leerer Name":  {"name": " "},
		"Steuerzeiche": {"name": "a\x01"},
		"Netz kaputt":  {"name": "x", "netz": "172.16.0.0/33"},
		"Netz Text":    {"name": "x", "netz": "lan"},
		"Netz Zone":    {"name": "x", "netz": "fe80::1%eth0"},
		"unbekannt":    {"name": "x", "token": "abc"},
	} {
		expectStatus(t, name, newDisplay(t, "v_fw", "Fertigung", body), 400)
	}

	expectStatus(t, "Geschwister löscht", as(t, "v_oa").do("DELETE", "/api/v1/anzeigen/"+id, nil), 404)
	expectStatus(t, "Leser löscht", as(t, "v_lz").do("DELETE", "/api/v1/anzeigen/"+idLZ, nil), 404)
	expectStatus(t, "Eltern löschen", as(t, "v_it").do("DELETE", "/api/v1/anzeigen/"+id, nil), 204)
	expectStatus(t, "Admin löscht", as(t, "v_fw").do("DELETE", "/api/v1/anzeigen/"+idLZ, nil), 204)
	expectStatus(t, "zweimal löschen", as(t, "v_fw").do("DELETE", "/api/v1/anzeigen/"+idLZ, nil), 404)

	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('anzeige.angelegt', 'anzeige.geloescht')
		AND details->>'id' IN ($1, $2)`, id, idLZ).Scan(&n)
	if n != 4 {
		t.Errorf("Audit-Einträge: %d, erwartet 4", n)
	}
}

// wandSetup: eigener Teilbaum, damit andere Tests die Bäume nicht stören.
//
//	IT ─┬─ Wand A ── Wand A1
//	    └─ Wand B
func wandSetup(t *testing.T) (crit string) {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	if _, ok := ids["Wand A"]; !ok {
		for _, tn := range []struct{ name, parent string }{{"Wand A", "IT"}, {"Wand A1", "Wand A"}, {"Wand B", "IT"}} {
			var id string
			if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2) RETURNING id::text`,
				ids[tn.parent], tn.name).Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids[tn.name] = id
		}
	}
	dev := func(tenant, name string, group *string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, $2, $3) RETURNING id::text`,
			ids[tenant], name, group).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	check := func(device, name, status string) string {
		var id string
		// Der Insert-Trigger setzt den Zustand zurück, daher danach setzen.
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, $2, 'ping', '{"host":"x.lan"}', 60) RETURNING id::text`, device, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET status = $2, message = 'geheime Meldung', since = now(),
			next_run = now() + interval '1 day' WHERE id = $1`, id, status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// Gruppen in Gruppen: Netzwerk → Switche → Lancom bzw. Aruba
	g, g2 := ownerGroupPath(t, ids["Wand A"], "Netzwerk/Switche/Lancom"), ownerGroupPath(t, ids["Wand A"], "Netzwerk/Switche/Aruba")
	ownerGroupPath(t, ids["Wand A"], "Leer/Auch leer") // leere Gruppen zeigt die Anzeige nicht
	sw := dev("Wand A", "WA Switch", g)
	check(sw, "WA Ping Switch", "ok")
	check(dev("Wand A", "WA Switch Aruba", g2), "WA Ping Aruba", "ok")
	srvDev := dev("Wand A", "WA Server", nil)
	check(srvDev, "WA HTTPS Server", "ok")
	crit = check(srvDev, "WA Ping Server", "crit")
	dev("Wand A", "WA Leer", nil)
	check(dev("Wand A1", "WA1 Pumpe", nil), "WA1 Ping", "warn")
	check(dev("Wand B", "WB Geheim", nil), "WB Ping", "ok")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id IN ($1, $2, $3)`, ids["Wand A"], ids["Wand A1"], ids["Wand B"])
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id IN ($1, $2, $3)`, ids["Wand A"], ids["Wand A1"], ids["Wand B"])
		deleteGroups(t, ids["Wand A"], ids["Wand A1"], ids["Wand B"])
		owner.Exec(ctx, `DELETE FROM openwacht.displays WHERE tenant_id IN ($1, $2, $3)`, ids["Wand A"], ids["Wand A1"], ids["Wand B"])
	})
	return crit
}

type knoten struct {
	Name   string    `json:"name"`
	Art    string    `json:"art"`
	Status string    `json:"status"`
	Kinder []*knoten `json:"kinder"`
}

func (k *knoten) find(path ...string) *knoten {
	cur := k
	for _, p := range path {
		var next *knoten
		for _, c := range cur.Kinder {
			if c.Name == p {
				next = c
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

func displayData(t *testing.T, c *client) (*knoten, response) {
	t.Helper()
	r := c.do("GET", "/api/v1/anzeige/daten", nil)
	if r.status != 200 {
		return nil, r
	}
	var out struct {
		Baum *knoten `json:"baum"`
	}
	if err := json.Unmarshal([]byte(r.raw), &out); err != nil {
		t.Fatal(err)
	}
	return out.Baum, r
}

func TestAnzeigeAnmeldungUndDaten(t *testing.T) {
	critCheck := wandSetup(t)
	r := newDisplay(t, "v_it", "Wand A", map[string]any{"name": "WA Leitstelle", "mit_untermandanten": true})
	expectStatus(t, "anlegen", r, 201)
	key, id := displayKey(t, r), r.body["id"].(string)

	wall := newClient(t, vSrv)
	expectStatus(t, "ohne Cookie", wall.do("GET", "/api/v1/anzeige/daten", nil), 401)
	for name, k := range map[string]string{
		"falscher Schlüssel": strings.Repeat("A", 43), "kein Base64": "!!", "leer": "", "zu kurz": key[:20],
	} {
		expectStatus(t, name, wall.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": k}), 401)
	}
	if _, ok := wall.cookies[displayCookie]; ok {
		t.Fatal("Cookie trotz falschem Schlüssel")
	}
	expectStatus(t, "fremder Ursprung", (&client{t: t, base: vSrv.URL, cookies: map[string]*http.Cookie{}, origin: "https://evil.invalid"}).
		do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": key}), 403)

	r = wall.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": key})
	expectStatus(t, "anmelden", r, 200)
	ck := wall.cookies[displayCookie]
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.MaxAge < 300*24*3600 {
		t.Fatalf("Cookie: %+v", ck)
	}

	tree, r := displayData(t, wall)
	if tree == nil {
		t.Fatalf("Daten: %d %s", r.status, r.raw)
	}
	if tree.Name != "Wand A" || tree.Art != "mandant" || tree.Status != "crit" {
		t.Errorf("Wurzel: %s %s %s", tree.Name, tree.Art, tree.Status)
	}
	if k := tree.find("Netzwerk", "Switche", "Lancom", "WA Switch"); k == nil || k.Status != "ok" || k.Art != "geraet" || len(k.Kinder) != 0 {
		t.Errorf("Gruppe in Gruppe: %+v", k)
	}
	if k := tree.find("Netzwerk", "Switche", "Aruba", "WA Switch Aruba"); k == nil || k.Status != "ok" {
		t.Errorf("zweite Untergruppe: %+v", k)
	}
	if k := tree.find("Netzwerk", "Switche"); k == nil || k.Art != "gruppe" || len(k.Kinder) != 2 {
		t.Errorf("Switche: %+v", k)
	}
	if k := tree.find("Netzwerk"); k == nil || k.Art != "gruppe" || k.Status != "ok" {
		t.Errorf("Gruppe Netzwerk: %+v", k)
	}
	if k := tree.find("Wand A1"); k == nil || k.Art != "mandant" || k.Status != "warn" || k.find("WA1 Pumpe") == nil || k.find("WA1 Pumpe").Kinder != nil {
		t.Errorf("Untermandant: %+v", k)
	}
	if tree.find("Leer") != nil {
		t.Error("leere Gruppe in der Anzeige")
	}
	if k := tree.find("WA Leer"); k == nil || k.Status != "unknown" {
		t.Errorf("Gerät ohne Sensoren: %+v", k)
	}
	// Nur Hosts: Das Gerät trägt den schlimmsten Zustand seiner Sensoren, ohne sie zu zeigen.
	if k := tree.find("WA Server"); k == nil || k.Status != "crit" || k.Art != "geraet" || len(k.Kinder) != 0 {
		t.Errorf("Server: %+v", k)
	}
	// Reihenfolge: Untermandanten, dann Gruppen, dann Geräte ohne Gruppe.
	var order []string
	for _, c := range tree.Kinder {
		order = append(order, c.Art)
	}
	if strings.Join(order, ",") != "mandant,gruppe,geraet,geraet" {
		t.Errorf("Reihenfolge: %v", order)
	}
	for _, bad := range []string{"Wand B", "WB Geheim", "geheime Meldung", "IT", "mandant_id", "v_it", "WA Ping", "WA HTTPS", "WA1 Ping", "sensor"} {
		if strings.Contains(r.raw, `"`+bad) {
			t.Errorf("Antwort enthält %q: %s", bad, r.raw)
		}
	}

	// Bestätigter Alarm wird hellrot, Wartung blau (Alarme und Wartung sind für die Anzeige lesbar).
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at, ack_at, ack_by_name)
		VALUES ($1, $2, 'check', 'WA Ping Server', 'crit', 'crit', now(), now(), now(), 'v_it')`, ids["Wand A"], critCheck); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.maintenance (tenant_id, device_id, ends_at, created_by_name)
		SELECT tenant_id, id, now() + interval '1 hour', 'v_it' FROM openwacht.devices WHERE name = 'WA Leer'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE check_id = $1`, critCheck)
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE tenant_id = $1`, ids["Wand A"])
	})
	tree, r = displayData(t, wall)
	if k := tree.find("WA Server"); k == nil || k.Status != "quittiert" {
		t.Errorf("bestätigter Alarm: %+v", k)
	}
	if k := tree.find("WA Leer"); k == nil || k.Status != "wartung" {
		t.Errorf("Gerät in Wartung: %+v", k)
	}
	if tree.Status != "quittiert" {
		t.Errorf("Wurzel nach Bestätigen: %s", tree.Status)
	}
	if strings.Contains(r.raw, "v_it") {
		t.Errorf("Antwort enthält Personennamen: %s", r.raw)
	}

	// Das Anzeige-Cookie öffnet keine andere API, die Benutzersitzung nicht die Anzeige.
	for _, p := range []string{"/api/v1/geraete", "/api/v1/sensoren", "/api/v1/ich", "/api/v1/anzeigen"} {
		expectStatus(t, "Anzeige ruft "+p, wall.do("GET", p, nil), 401)
	}
	expectStatus(t, "Benutzer ruft Anzeige", as(t, "v_it").do("GET", "/api/v1/anzeige/daten", nil), 401)

	// zuletzt_da wird gesetzt
	if e, _ := listEntry(t, "v_it", "/api/v1/anzeigen", "anzeigen", id); e["zuletzt_da"] == nil {
		t.Error("zuletzt_da fehlt")
	}

	// Ohne Untermandanten
	r = newDisplay(t, "v_it", "Wand A", map[string]any{"name": "WA ohne"})
	expectStatus(t, "anlegen ohne", r, 201)
	solo := newClient(t, vSrv)
	expectStatus(t, "anmelden ohne", solo.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": displayKey(t, r)}), 200)
	if tree, r := displayData(t, solo); tree == nil || tree.find("Wand A1") != nil || strings.Contains(r.raw, "WA1 Pumpe") {
		t.Errorf("ohne Untermandanten: %s", r.raw)
	}

	// Gelöscht: sofort ausgesperrt, Cookie wird entfernt.
	expectStatus(t, "löschen", as(t, "v_it").do("DELETE", "/api/v1/anzeigen/"+id, nil), 204)
	expectStatus(t, "nach Löschen", wall.do("GET", "/api/v1/anzeige/daten", nil), 401)
	if _, ok := wall.cookies[displayCookie]; ok {
		t.Error("Cookie nach Löschen nicht entfernt")
	}
}

func TestAnzeigeNetz(t *testing.T) {
	wandSetup(t)
	r := newDisplay(t, "v_it", "Wand B", map[string]any{"name": "WB fremdes Netz", "netz": "10.99.0.0/16"})
	expectStatus(t, "anlegen", r, 201)
	c := newClient(t, vSrv)
	expectStatus(t, "falsches Netz", c.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": displayKey(t, r)}), 403)

	r = newDisplay(t, "v_it", "Wand B", map[string]any{"name": "WB Loopback", "netz": "127.0.0.0/8"})
	expectStatus(t, "anlegen", r, 201)
	expectStatus(t, "richtiges Netz", c.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": displayKey(t, r)}), 200)
	if tree, _ := displayData(t, c); tree == nil || tree.Name != "Wand B" {
		t.Errorf("Daten: %+v", tree)
	}
}

// Datenbank: Was darf der Kontext einer Anzeige?
func TestAnzeigeDatenbankRechte(t *testing.T) {
	wandSetup(t)
	r := newDisplay(t, "v_it", "Wand A", map[string]any{"name": "WA DB", "mit_untermandanten": true})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	ctx := context.Background()
	run := func(fn func(tx pgx.Tx) error, user string) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.display_id', $1, true)`, id); err != nil {
				return err
			}
			if user != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[user]); err != nil {
					return err
				}
			}
			return fn(tx)
		})
	}
	count := func(q string, user string) int {
		t.Helper()
		var n int
		if err := run(func(tx pgx.Tx) error { return tx.QueryRow(ctx, q).Scan(&n) }, user); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM openwacht.tenants`:                                           2, // Wand A, Wand A1
		`SELECT count(*) FROM openwacht.devices`:                                           5,
		`SELECT count(*) FROM openwacht.checks`:                                            5,
		`SELECT count(*) FROM openwacht.users`:                                             0,
		`SELECT count(*) FROM openwacht.role_assignments`:                                  0,
		`SELECT count(*) FROM openwacht.audit_log`:                                         0,
		`SELECT count(*) FROM openwacht.alert_channels`:                                    0,
		`SELECT count(*) FROM openwacht.agent_tokens`:                                      0,
		`SELECT count(*) FROM openwacht.displays`:                                          0,
		`SELECT count(*) FROM openwacht.metrics_check_raw`:                                 0,
		`SELECT count(*) FROM openwacht.devices WHERE tenant_id = '` + ids["Wand B"] + `'`: 0,
		`SELECT count(*) FROM openwacht.device_groups`:                                     6, // Netzwerk, Switche, Lancom, Aruba, Leer, Auch leer
	} {
		if got := count(q, ""); got != want {
			t.Errorf("%s: %d, erwartet %d", q, got, want)
		}
	}
	// Benutzer und Anzeige zugleich: Die Anzeige zählt nicht (Leser im Lager sieht Wand A nicht).
	if got := count(`SELECT count(*) FROM openwacht.devices WHERE tenant_id = '`+ids["Wand A"]+`'`, "v_lz"); got != 0 {
		t.Errorf("Mischkontext sieht %d Geräte", got)
	}
	// Schreiben geht nicht.
	for _, q := range []string{
		`INSERT INTO openwacht.devices (tenant_id, name) VALUES ('` + ids["Wand A"] + `', 'x')`,
		`UPDATE openwacht.checks SET enabled = false`,
		`INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ('` + ids["Wand A"] + `', 'x')`,
		`UPDATE openwacht.device_groups SET name = 'x'`,
		`UPDATE openwacht.devices SET group_id = NULL`,
		`DELETE FROM openwacht.device_groups`,
		`DELETE FROM openwacht.displays`,
		`SELECT token_hash FROM openwacht.displays`,
	} {
		err := run(func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, q)
			if err == nil && tag.RowsAffected() > 0 {
				return errors.New("Zeilen verändert")
			}
			return err
		}, "")
		var pe *pgconn.PgError
		denied := errors.As(err, &pe) && pe.Code == "42501"
		mayBeEmpty := strings.HasPrefix(q, "UPDATE") || strings.HasPrefix(q, "DELETE")
		if !denied && !(mayBeEmpty && err == nil) {
			t.Errorf("%s: %v", q, err)
		}
	}
}

func TestGeraetGruppe(t *testing.T) {
	wandSetup(t)
	srv := ownerGroupPath(t, ids["Wand A"], "Server")
	sw := ownerGroupPath(t, ids["Wand A"], "Netzwerk/Switche")
	fremd := ownerGroupPath(t, ids["Wand B"], "Fremd")
	r := newDevice(t, "v_it", "Wand A", "WA Gruppentest", "")
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	put := func(body map[string]any) response {
		body["name"], body["adresse"] = "WA Gruppentest", ""
		return as(t, "v_it").do("PUT", "/api/v1/geraete/"+id, body)
	}
	group := func() any { d, _ := deviceEntry(t, "v_it", id); return d["gruppe_id"] }
	expectStatus(t, "Gruppe setzen", put(map[string]any{"gruppe_id": *sw}), 204)
	if g := group(); g != *sw {
		t.Errorf("Gruppe: %v", g)
	}
	expectStatus(t, "ohne Feld bleibt die Gruppe", put(map[string]any{}), 204)
	if g := group(); g != *sw {
		t.Errorf("Gruppe nach Ändern ohne Feld: %v", g)
	}
	expectStatus(t, "Gruppe anderer Mandant", put(map[string]any{"gruppe_id": *fremd}), 400)
	expectStatus(t, "Gruppe unbekannt", put(map[string]any{"gruppe_id": "00000000-0000-0000-0000-000000000001"}), 404)
	expectStatus(t, "Gruppe kein UUID", put(map[string]any{"gruppe_id": "Netzwerk/Switche"}), 400)
	expectStatus(t, "alter Pfad abgelehnt", put(map[string]any{"gruppe": "Server"}), 400)
	expectStatus(t, "Gruppe leeren", put(map[string]any{"gruppe_id": ""}), 204)
	if g := group(); g != nil {
		t.Errorf("Gruppe nach Leeren: %v", g)
	}
	r = as(t, "v_it").do("POST", "/api/v1/mandanten/"+ids["Wand A"]+"/geraete", map[string]any{"name": "WA mit Gruppe", "gruppe_id": *srv})
	expectStatus(t, "anlegen mit Gruppe", r, 201)
	if d, _ := deviceEntry(t, "v_it", r.body["id"].(string)); d["gruppe_id"] != *srv {
		t.Errorf("Gruppe beim Anlegen: %v", d["gruppe_id"])
	}
	r = as(t, "v_it").do("POST", "/api/v1/mandanten/"+ids["Wand A"]+"/geraete", map[string]any{"name": "WA fremde Gruppe", "gruppe_id": *fremd})
	expectStatus(t, "anlegen mit fremder Gruppe", r, 400)
	// Die Datenbank prüft auch ohne Anwendung.
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.devices SET group_id = $2 WHERE id = $1`, id, *fremd); err == nil {
		t.Error("DB nimmt Gruppe eines anderen Mandanten an")
	}
}

func TestAnzeigeZustaende(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		sn   sensorOut
		want string
	}{
		{sensorOut{Status: "ok"}, "ok"},
		{sensorOut{Status: "warn"}, "warn"},
		{sensorOut{Status: "crit"}, "crit"},
		{sensorOut{Status: "crit", Alarm: &alarmOut{}}, "crit"},
		{sensorOut{Status: "crit", Alarm: &alarmOut{BestaetigtAm: &now}}, "quittiert"},
		{sensorOut{Status: "warn", Alarm: &alarmOut{BestaetigtAm: &now}}, "warn"},
		{sensorOut{Status: "unknown"}, "unknown"},
		{sensorOut{Status: "neu"}, "unknown"},
		{sensorOut{Status: "pause"}, "wartung"},
		{sensorOut{Status: "crit", Wartung: &wartungOut{}}, "wartung"},
		{sensorOut{Status: "komisch"}, "unknown"},
	} {
		if got := sensorDisplayStatus(&c.sn); got != c.want {
			t.Errorf("%+v: %s, erwartet %s", c.sn, got, c.want)
		}
	}
	leaf := func(s string) *anzeigeKnoten { return &anzeigeKnoten{Status: s} }
	for _, c := range []struct {
		kinder []string
		want   string
	}{
		{[]string{"ok", "wartung"}, "ok"},
		{[]string{"wartung", "wartung"}, "wartung"},
		{[]string{"ok", "warn"}, "warn"},
		{[]string{"warn", "unknown"}, "unknown"},
		{[]string{"unknown", "quittiert"}, "quittiert"},
		{[]string{"quittiert", "crit", "ok"}, "crit"},
	} {
		k := &anzeigeKnoten{}
		for _, s := range c.kinder {
			k.Kinder = append(k.Kinder, leaf(s))
		}
		// verschachtelt: Zustand wandert durch alle Ebenen
		top := &anzeigeKnoten{Kinder: []*anzeigeKnoten{{Kinder: []*anzeigeKnoten{k}}}}
		if got := top.worst(); got != c.want {
			t.Errorf("%v: %s, erwartet %s", c.kinder, got, c.want)
		}
	}
	if got := (&anzeigeKnoten{}).worst(); got != "unknown" {
		t.Errorf("leer: %s", got)
	}
}

// Vorschau und „Neuer Link“ (0.99.2): nur Admins der Anzeige; die Vorschau
// zeigt genau den Ausschnitt der Wand; der neue Link sperrt den alten sofort.
func TestAnzeigeVorschauUndNeuerLink(t *testing.T) {
	wandSetup(t)
	r := newDisplay(t, "v_it", "Wand A", map[string]any{"name": "WA Vorschau"}) // ohne Untermandanten
	expectStatus(t, "anlegen", r, 201)
	id, oldKey := r.body["id"].(string), displayKey(t, r)

	expectStatus(t, "Vorschau Geschwister", as(t, "v_oa").do("GET", "/api/v1/anzeigen/"+id+"/vorschau", nil), 404)
	expectStatus(t, "Vorschau anderer Ast", as(t, "v_fw").do("GET", "/api/v1/anzeigen/"+id+"/vorschau", nil), 404)
	p := as(t, "v_it").do("GET", "/api/v1/anzeigen/"+id+"/vorschau", nil)
	expectStatus(t, "Vorschau", p, 200)
	var out struct {
		Anzeige string  `json:"anzeige"`
		Baum    *knoten `json:"baum"`
	}
	if err := json.Unmarshal([]byte(p.raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Anzeige != "WA Vorschau" || out.Baum == nil || out.Baum.Name != "Wand A" || out.Baum.find("WA Server") == nil {
		t.Fatalf("Vorschau: %s", p.raw)
	}
	if out.Baum.find("Wand A1") != nil || strings.Contains(p.raw, "geheime Meldung") {
		t.Error("Vorschau zeigt mehr als die Wand (Untermandant oder Meldungen)")
	}

	wall := newClient(t, vSrv)
	expectStatus(t, "Wand anmelden", wall.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": oldKey}), 200)
	expectStatus(t, "Wand Daten", wall.do("GET", "/api/v1/anzeige/daten", nil), 200)

	expectStatus(t, "neuer Link Geschwister", as(t, "v_oa").do("POST", "/api/v1/anzeigen/"+id+"/neuer-link", nil), 404)
	n := as(t, "v_it").do("POST", "/api/v1/anzeigen/"+id+"/neuer-link", nil)
	expectStatus(t, "neuer Link", n, 200)
	newKey := displayKey(t, n)
	if newKey == oldKey {
		t.Fatal("Schlüssel unverändert")
	}
	expectStatus(t, "alte Wand gesperrt", wall.do("GET", "/api/v1/anzeige/daten", nil), 401)
	expectStatus(t, "alter Link", newClient(t, vSrv).do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": oldKey}), 401)
	fresh := newClient(t, vSrv)
	expectStatus(t, "neuer Link anmelden", fresh.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": newKey}), 200)
	expectStatus(t, "neue Wand Daten", fresh.do("GET", "/api/v1/anzeige/daten", nil), 200)
	var audits int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'anzeige.neuer_link' AND details->>'id' = $1`, id).Scan(&audits)
	if audits != 1 {
		t.Errorf("Audit: %d", audits)
	}
}
