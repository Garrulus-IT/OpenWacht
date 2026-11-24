// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"strings"
	"testing"
)

// Etappe 18c: Name optional, eindeutig je Gerät, automatische Nummer.
func TestCheckNamenJeGeraet(t *testing.T) {
	verwaltungSetup(t)
	mk := func(user, tenant, name string) string {
		r := newDevice(t, user, tenant, name, "")
		expectStatus(t, "Gerät "+name, r, 201)
		return r.body["id"].(string)
	}
	a := mk("v_fw", "Fertigung", "NA Router")
	b := mk("v_fw", "Fertigung", "NA Switch")
	cleanupChecks(t, a, b)

	post := func(user, dev string, body map[string]any) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+dev+"/checks", body)
	}
	created := func(what string, r response, want string) string {
		t.Helper()
		expectStatus(t, what, r, 201)
		if got, _ := r.body["name"].(string); got != want {
			t.Errorf("%s: Name %q, erwartet %q", what, got, want)
		}
		id, _ := r.body["id"].(string)
		return id
	}
	ping := map[string]any{"host": "router.lan"}
	created("Ping ohne Name", post("v_fw", a, map[string]any{"typ": "ping", "ziel": ping}), "Ping")
	p2 := created("zweiter Ping", post("v_fw", a, map[string]any{"name": "  ", "typ": "ping", "ziel": ping}), "Ping 2")
	created("dritter Ping", post("v_fw", a, map[string]any{"typ": "ping", "ziel": ping}), "Ping 3")
	created("TCP", post("v_fw", a, map[string]any{"typ": "tcp", "ziel": map[string]any{"host": "router.lan", "port": 53}}), "TCP 53")
	created("HTTPS", post("v_fw", a, map[string]any{"typ": "http", "ziel": map[string]any{"url": "https://router.lan/"}}), "HTTP 443")
	created("HTTP Port", post("v_fw", a, map[string]any{"typ": "http", "ziel": map[string]any{"url": "http://router.lan:8080/x"}}), "HTTP 8080")
	created("DNS", post("v_fw", a, map[string]any{"typ": "dns", "ziel": map[string]any{"name": "heise.de"}}), "DNS heise.de")

	// Je Gerät eindeutig: derselbe Name am anderen Gerät desselben Mandanten geht.
	created("anderes Gerät", post("v_fw", b, map[string]any{"typ": "ping", "ziel": ping}), "Ping")
	created("eigener Name anderes Gerät", post("v_fw", b, map[string]any{"name": "Ping 2", "typ": "ping", "ziel": ping}), "Ping 2")

	// Selbst eingetippt und vergeben (auch anders geschrieben): klare Meldung.
	r := post("v_fw", a, map[string]any{"name": "ping 2", "typ": "ping", "ziel": ping})
	expectStatus(t, "doppelt eingetippt", r, 409)
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "Am Gerät gibt es schon") {
		t.Errorf("Meldung: %s", r.raw)
	}

	// Ändern mit leerem Name: automatisch, der eigene Name zählt nicht mit.
	upd := func(id string, body map[string]any) response {
		return as(t, "v_fw").do("PUT", "/api/v1/checks/"+id, body)
	}
	expectStatus(t, "leer ändern", upd(p2, map[string]any{"name": "", "typ": "ping", "ziel": ping}), 204)
	if n := checkName(t, p2); n != "Ping 2" {
		t.Errorf("nach Ändern: %q", n)
	}
	expectStatus(t, "umbenennen", upd(p2, map[string]any{"name": "Ping extern", "typ": "ping", "ziel": ping}), 204)
	expectStatus(t, "auf vergebenen Namen", upd(p2, map[string]any{"name": "TCP 53", "typ": "ping", "ziel": ping}), 409)
	expectStatus(t, "zurück auf leer", upd(p2, map[string]any{"name": "", "typ": "ping", "ziel": ping}), 204)
	if n := checkName(t, p2); n != "Ping 2" {
		t.Errorf("Lücke füllen: %q", n)
	}

	// Mandantentrennung: Geschwister sieht das Gerät nicht, Eltern legt an.
	expectStatus(t, "Geschwister", post("v_oa", a, map[string]any{"typ": "ping", "ziel": ping}), 404)
	created("Eltern", post("v_it", a, map[string]any{"typ": "ping", "ziel": ping}), "Ping 4")
	expectStatus(t, "Leser", post("v_lz", a, map[string]any{"typ": "ping", "ziel": ping}), 404)
}

func checkName(t *testing.T, id string) string {
	t.Helper()
	var n string
	if err := owner.QueryRow(context.Background(), `SELECT name FROM openwacht.checks WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Anzeigename in Alarmen: „Gerät · Sensor“, ohne Doppelung.
func TestCheckLabel(t *testing.T) {
	verwaltungSetup(t)
	for _, c := range [][3]string{
		{"pve-1", "Ping", "pve-1 · Ping"},
		{"pve-1", "pve-1 Ping", "pve-1 Ping"},
		{"PVE-1", "pve-1 ping", "pve-1 ping"},
		{"pve-1", "pve-10 Ping", "pve-1 · pve-10 Ping"},
		{"pve-1", "pve-1", "pve-1"},
		{"", "Ping", "Ping"},
		{"a%_b", "a%_b Ping", "a%_b Ping"},
	} {
		var got string
		if err := owner.QueryRow(context.Background(), `SELECT openwacht.check_label($1, $2)`, c[0], c[1]).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c[2] {
			t.Errorf("check_label(%q, %q) = %q, erwartet %q", c[0], c[1], got, c[2])
		}
	}
	// Die Kandidaten für ntfy tragen den Gerätenamen.
	r := newDevice(t, "v_fw", "Fertigung", "NL Box", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	cleanupChecks(t, dev)
	c := as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{"typ": "ping", "ziel": map[string]any{"host": "box.lan"}})
	expectStatus(t, "Check", c, 201)
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET status = 'crit', message = 'weg' WHERE id = $1`, c.body["id"]); err != nil {
		t.Fatal(err)
	}
	var name string
	err := owner.QueryRow(ctx, `SELECT name FROM openwacht.alarm_check_sources() WHERE check_id = $1`, c.body["id"]).Scan(&name)
	if err != nil || name != "NL Box · Ping" {
		t.Errorf("alarm_check_sources: %q %v", name, err)
	}
}
