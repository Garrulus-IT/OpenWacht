// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func newDevice(t *testing.T, user, tenant, name, addr string) response {
	t.Helper()
	return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/geraete", map[string]any{"name": name, "adresse": addr})
}

func deviceEntry(t *testing.T, user, id string) (map[string]any, bool) {
	t.Helper()
	return listEntry(t, user, "/api/v1/geraete", "geraete", id)
}

func TestGeraeteMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "GM NAS", "NAS.example.org.")
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	// Sehen: eigener Mandant und Eltern ja, Geschwister und Kinder nein.
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := deviceEntry(t, user, id); got != want {
			t.Errorf("%s sieht Gerät: %v, erwartet %v", user, got, want)
		}
	}
	d, _ := deviceEntry(t, "v_fw", id)
	if d["adresse"] != "nas.example.org" || d["mandant_id"] != ids["Fertigung"] || d["agent_id"] != nil || d["checks"] != 0.0 {
		t.Errorf("Gerät: %+v", d)
	}

	// Anlegen: nur Admin/Operator im eigenen Teilbaum.
	expectStatus(t, "Leser legt an", newDevice(t, "v_lz", "Lager Nord", "x", ""), 403)
	expectStatus(t, "Geschwister legt an", newDevice(t, "v_oa", "Fertigung", "x", ""), 403)
	expectStatus(t, "Kind legt bei Eltern an", newDevice(t, "v_fw", "IT", "x", ""), 403)
	expectStatus(t, "Eltern legen beim Kind an", newDevice(t, "v_fw", "Lager Nord", "GM LZ", ""), 201)

	// Eingaben
	for name, addr := range map[string]string{
		"mit Protokoll": "http://nas", "mit Port": "nas:5001", "Leerzeichen": "a b", "Zone": "fe80::1%eth0", "zu lang": strings.Repeat("a.", 130),
	} {
		expectStatus(t, name, newDevice(t, "v_fw", "Fertigung", "x", addr), 400)
	}
	expectStatus(t, "leerer Name", newDevice(t, "v_fw", "Fertigung", " ", ""), 400)
	r = newDevice(t, "v_fw", "Fertigung", "GM v6", "FD00:0:0::1")
	expectStatus(t, "IPv6", r, 201)
	if d, _ := deviceEntry(t, "v_fw", r.body["id"].(string)); d["adresse"] != "fd00::1" {
		t.Errorf("IPv6 nicht kanonisch: %v", d["adresse"])
	}

	// Ändern: Fremde 404, Leser 404, Eltern ja.
	upd := map[string]any{"name": "GM NAS neu", "adresse": ""}
	for _, u := range []string{"v_oa", "v_lz"} {
		expectStatus(t, u+" ändert", as(t, u).do("PUT", "/api/v1/geraete/"+id, upd), 404)
		expectStatus(t, u+" löscht", as(t, u).do("DELETE", "/api/v1/geraete/"+id, nil), 404)
	}
	expectStatus(t, "IT ändert", as(t, "v_it").do("PUT", "/api/v1/geraete/"+id, upd), 204)
	if d, _ := deviceEntry(t, "v_fw", id); d["name"] != "GM NAS neu" || d["adresse"] != nil {
		t.Errorf("nach Ändern: %+v", d)
	}

	// Check am Gerät: Mandant kommt vom Gerät; Löschen erst, wenn leer.
	c := as(t, "v_it").do("POST", "/api/v1/geraete/"+id+"/checks", map[string]any{"name": "GM Ping", "typ": "ping",
		"ziel": map[string]any{"host": "nas.lan"}})
	expectStatus(t, "Check am Gerät", c, 201)
	if e, _ := listEntry(t, "v_fw", "/api/v1/checks", "checks", c.body["id"].(string)); e["mandant_id"] != ids["Fertigung"] ||
		e["geraet_id"] != id {
		t.Errorf("Check: %+v", e)
	}
	if d, _ := deviceEntry(t, "v_fw", id); d["checks"] != 1.0 {
		t.Errorf("Zahl der Checks: %v", d["checks"])
	}
	expectStatus(t, "löschen mit Check", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+id, nil), 409)
	expectStatus(t, "Check löschen", as(t, "v_fw").do("DELETE", "/api/v1/checks/"+c.body["id"].(string), nil), 204)
	expectStatus(t, "Leser im Kind löscht Gerät der Eltern", as(t, "v_lz").do("DELETE", "/api/v1/geraete/"+id, nil), 404)
	expectStatus(t, "leer löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+id, nil), 204)
	expectStatus(t, "nochmal löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+id, nil), 404)

	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id = $1
		AND action IN ('geraet.angelegt', 'geraet.geaendert', 'geraet.geloescht') AND details->>'id' = $2`, ids["Fertigung"], id).Scan(&n)
	if n != 3 {
		t.Errorf("Audit: %d Einträge, erwartet 3", n)
	}
}

// Leser im eigenen Mandanten: sieht, darf aber nichts ändern.
func TestGeraeteLeser(t *testing.T) {
	agentServer(t) // Agent-CA für das Token
	r := newDevice(t, "v_fw", "Lager Nord", "GL Pumpe", "")
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	if _, ok := deviceEntry(t, "v_lz", id); !ok {
		t.Fatal("Leser sieht Gerät im eigenen Mandanten nicht")
	}
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/geraete/"+id, map[string]any{"name": "x"}), 404)
	expectStatus(t, "Leser löscht", as(t, "v_lz").do("DELETE", "/api/v1/geraete/"+id, nil), 403)
	expectStatus(t, "Leser Wartung", as(t, "v_lz").do("PUT", "/api/v1/geraete/"+id+"/wartung", map[string]any{"minuten": 30}), 403)
	expectStatus(t, "Leser Token", as(t, "v_lz").do("POST", "/api/v1/geraete/"+id+"/agent-token", map[string]any{}), 403)
	expectStatus(t, "Leser Check", as(t, "v_lz").do("POST", "/api/v1/geraete/"+id+"/checks", map[string]any{"name": "GL",
		"typ": "ping", "ziel": map[string]any{"host": "x.lan"}}), 403)
	r = newDevice(t, "v_fw", "Lager Nord", "GL Pumpe 2", "")
	expectStatus(t, "zweites Gerät", r, 201)
	expectStatus(t, "Leser führt zusammen", as(t, "v_lz").do("POST", "/api/v1/geraete/"+id+"/zusammenfuehren",
		map[string]any{"mit": r.body["id"]}), 403)
	if _, ok := deviceEntry(t, "v_lz", r.body["id"].(string)); !ok {
		t.Error("Gerät nach verweigertem Zusammenführen verschwunden")
	}
}

func TestGeraeteZusammenfuehren(t *testing.T) {
	agentServer(t)
	ctx := context.Background()
	// Agent in der Fertigung, meldet sich von 127.0.0.1 (Testserver).
	tok, r := newAgentToken(t, "v_fw", "Fertigung", 1)
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, tok, "gz-pve")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	if s, b := a.report("gz-pve"); s != 200 {
		t.Fatalf("Meldung: %d %s", s, b)
	}
	agentDev := agentDevice(t, a.id)
	if e, _ := listEntry(t, "v_fw", "/api/v1/agents", "agents", a.id); e["adresse"] != "127.0.0.1" || e["geraet_id"] != agentDev {
		t.Errorf("Agent: Adresse %v, Gerät %v", e["adresse"], e["geraet_id"])
	}
	if d, _ := deviceEntry(t, "v_fw", agentDev); d["name"] != "gz-pve" || d["agent_id"] != a.id {
		t.Errorf("Gerät des Agents: %+v", d)
	}

	// Andere Tests melden sich auch von 127.0.0.1; für den Vorschlag eine
	// eigene Adresse, als hätte sich der Agent von dort gemeldet.
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_addr = '10.77.0.1' WHERE id = $1`, a.id)

	// Gerät ohne Agent mit derselben Adresse und einem Check.
	r = newDevice(t, "v_fw", "Fertigung", "GZ Server im Keller", "10.77.0.1")
	expectStatus(t, "Gerät nur IP", r, 201)
	ipDev := r.body["id"].(string)
	c := as(t, "v_fw").do("POST", "/api/v1/geraete/"+ipDev+"/checks", map[string]any{"name": "GZ SSH", "typ": "tcp",
		"ziel": map[string]any{"host": "gz-pve.lan", "port": 22}})
	expectStatus(t, "Check", c, 201)
	byName := newDevice(t, "v_fw", "Fertigung", "gz-pve.example.org", "")
	expectStatus(t, "Gerät gleicher Name", byName, 201)
	// Gleicher Name im Geschwister-Mandanten: kein Vorschlag über Mandanten hinweg.
	foreign := newDevice(t, "v_it", "Organisation", "gz-pve", "10.77.0.1")
	expectStatus(t, "fremdes Gerät", foreign, 201)

	vorschlag := func(user, dev string) []any {
		t.Helper()
		d, ok := deviceEntry(t, user, dev)
		if !ok {
			t.Fatalf("%s sieht %s nicht", user, dev)
		}
		return d["vorschlaege"].([]any)
	}
	if v := vorschlag("v_fw", ipDev); len(v) != 1 || v[0].(map[string]any)["geraet_id"] != agentDev ||
		v[0].(map[string]any)["grund"] != "adresse" {
		t.Errorf("Vorschlag über Adresse: %+v", v)
	}
	if v := vorschlag("v_fw", byName.body["id"].(string)); len(v) != 1 || v[0].(map[string]any)["grund"] != "name" {
		t.Errorf("Vorschlag über Namen: %+v", v)
	}
	if v := vorschlag("v_it", foreign.body["id"].(string)); len(v) != 0 {
		t.Errorf("Vorschlag über Mandanten hinweg: %+v", v)
	}
	if v := vorschlag("v_fw", agentDev); len(v) != 0 {
		t.Errorf("Vorschlag am Agent-Gerät: %+v", v)
	}

	// NAT: Meldet sich ein zweiter Agent von derselben Adresse, zählt sie nicht mehr.
	tok2, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a2, _, _ := register(t, tok2, "gz-nachbar")
	if s, _ := a2.report("gz-nachbar"); s != 200 {
		t.Fatal("zweiter Agent meldet nicht")
	}
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_addr = '10.77.0.1' WHERE id = $1`, a2.id)
	if v := vorschlag("v_fw", ipDev); len(v) != 0 {
		t.Errorf("Vorschlag trotz geteilter Adresse: %+v", v)
	}

	merge := func(user, into, from string) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+into+"/zusammenfuehren", map[string]any{"mit": from})
	}
	expectStatus(t, "mit sich selbst", merge("v_fw", ipDev, ipDev), 400)
	expectStatus(t, "Geschwister", merge("v_oa", ipDev, agentDev), 404)
	expectStatus(t, "über Mandanten", merge("v_it", ipDev, foreign.body["id"].(string)), 409)
	r = merge("v_fw", agentDev, agentDevice(t, a2.id))
	expectStatus(t, "zwei Agents", r, 409)
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "Beide Geräte haben einen Agent") {
		t.Errorf("Meldung bei zwei Agents: %q", r.raw)
	}
	expectStatus(t, "Leser", merge("v_lz", ipDev, agentDev), 404) // Fertigung ist für das Lager unsichtbar

	// Richtung egal: Es bleibt das Gerät mit Agent; Checks und Adresse wandern.
	r = merge("v_fw", ipDev, agentDev)
	expectStatus(t, "zusammenführen", r, 200)
	if r.body["id"] != agentDev {
		t.Errorf("bleibendes Gerät %v, erwartet %s", r.body["id"], agentDev)
	}
	if _, ok := deviceEntry(t, "v_fw", ipDev); ok {
		t.Error("abgegebenes Gerät noch da")
	}
	d, _ := deviceEntry(t, "v_fw", agentDev)
	if d["checks"] != 1.0 || d["adresse"] != "10.77.0.1" || d["name"] != "gz-pve" {
		t.Errorf("nach Zusammenführen: %+v", d)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'geraet.zusammengefuehrt'
		AND tenant_id = $1 AND details->>'entfernt' = $2`, ids["Fertigung"], ipDev).Scan(&n)
	if n != 1 {
		t.Errorf("Audit: %d", n)
	}
}

func TestGeraeteToken(t *testing.T) {
	agentServer(t)
	r := newDevice(t, "v_fw", "Fertigung", "GT Rechner", "10.0.0.5")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	token := func(user string) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+dev+"/agent-token", map[string]any{"gueltig_stunden": 2})
	}
	expectStatus(t, "Geschwister", token("v_oa"), 404)
	expectStatus(t, "Gültigkeit", as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/agent-token", map[string]any{"gueltig_stunden": 999}), 400)
	r = token("v_fw")
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, r.body["token"].(string), "gt-host")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	if got := agentDevice(t, a.id); got != dev {
		t.Errorf("Agent im Gerät %s, erwartet %s", got, dev)
	}
	expectStatus(t, "zweites Token", token("v_fw"), 409)

	// Ein gebundenes Token gilt für genau einen Rechner; der Mandant kommt vom Gerät.
	ctx := context.Background()
	tryAs := func(user, sql string, args ...any) error {
		return vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	if err := tryAs("v_fw", `INSERT INTO openwacht.agent_tokens (token_hash, device_id, uses_left, expires_at)
		VALUES (decode(repeat('ab', 32), 'hex'), $1, 2, now() + interval '1 hour')`, dev); err == nil {
		t.Error("gebundenes Token für zwei Rechner")
	}
	if err := tryAs("v_oa", `INSERT INTO openwacht.agent_tokens (token_hash, tenant_id, device_id, uses_left, expires_at)
		VALUES (decode(repeat('cd', 32), 'hex'), $2, $1, 1, now() + interval '1 hour')`, dev, ids["Organisation"]); err == nil {
		t.Error("Token für fremdes Gerät über SQL")
	}

	// Gesperrt: Ein neues Token für dasselbe Gerät geht wieder, der neue Agent landet dort.
	expectStatus(t, "sperren", as(t, "v_fw").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 204)
	r = token("v_fw")
	expectStatus(t, "Token nach Sperre", r, 201)
	b, status, _ := register(t, r.body["token"].(string), "gt-host")
	if status != 200 || agentDevice(t, b.id) != dev {
		t.Errorf("neuer Agent: %d, Gerät %s", status, agentDevice(t, b.id))
	}
}

// Schichten einzeln: Die Datenbank allein verhindert Zugriffe über Mandanten hinweg.
func TestGeraetePruefungJeSchicht(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "GS Schicht", "")
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	tryAs := func(user string, sql string, args ...any) int64 {
		var n int64
		err := vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return -1
		}
		return n
	}
	if n := tryAs("v_oa", `UPDATE openwacht.devices SET name = 'übernommen' WHERE id = $1`, id); n != 0 {
		t.Errorf("Geschwister ändert: %d", n)
	}
	if n := tryAs("v_oa", `DELETE FROM openwacht.devices WHERE id = $1`, id); n != 0 {
		t.Errorf("Geschwister löscht: %d", n)
	}
	if n := tryAs("v_lz", `DELETE FROM openwacht.devices WHERE id = $1`, id); n != 0 {
		t.Errorf("Kind löscht: %d", n)
	}
	if n := tryAs("v_oa", `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'fremd')`, ids["Fertigung"]); n != -1 {
		t.Errorf("Geschwister legt an: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.devices SET tenant_id = $2 WHERE id = $1`, id, ids["Lager Nord"]); n != -1 {
		t.Errorf("Mandant geändert: %d", n)
	}
	// Agents: Gerät und Adresse ändert die Anwendung nicht, auch nicht bei
	// gesperrten (für die gilt die UPDATE-Policy des Sperrens).
	for _, revoked := range []bool{false, true} {
		agent, _ := newUUID()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, revoked_at)
			VALUES ($1, $2, 'gs-agent', 's', now() + interval '30 days', CASE WHEN $3 THEN now() END)`,
			agent, ids["Fertigung"], revoked); err != nil {
			t.Fatal(err)
		}
		if n := tryAs("v_fw", `UPDATE openwacht.agents SET device_id = $2 WHERE id = $1`, agent, id); n != -1 {
			t.Errorf("Gerät eines Agents über SQL geändert (gesperrt %v): %d", revoked, n)
		}
		if n := tryAs("v_fw", `UPDATE openwacht.agents SET last_addr = '10.9.9.9' WHERE id = $1`, agent); n != -1 {
			t.Errorf("Adresse eines Agents über SQL geändert (gesperrt %v): %d", revoked, n)
		}
	}
	var visible int
	vServer.withUser(ctx, ids["v_oa"], func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.devices WHERE id = $1`, id).Scan(&visible)
	})
	if visible != 0 {
		t.Error("Geschwister sieht Gerät über SQL")
	}
}
