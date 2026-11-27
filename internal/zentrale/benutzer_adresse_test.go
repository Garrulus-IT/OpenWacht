// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6, Pentest-Hinweis H3: vergebene Adresse beim Anlegen.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestBenutzerAnlegenAdresseNeutralUndGebremst(t *testing.T) {
	_, srv := settingsServer(t, Config{})
	ctx := context.Background()
	kontoMitRollen(t, "h3_admin", "Fertigung", map[string]string{"Fertigung": "admin"}, false, false)
	c := newClient(t, srv)
	expectStatus(t, "Anmeldung", c.login("h3_admin"), 200)
	totpEinrichten(t, c)
	create := func(email string) response {
		return c.do("POST", "/api/v1/benutzer", map[string]string{
			"mandant_id": ids["Lager Nord"], "email": email, "anzeigename": "Neu", "passwort": "ein-neues-passwort"})
	}
	var before int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'benutzer.anlegen_abgelehnt'`).Scan(&before)

	// Adresse im fremden Mandanten (v_it gehört zur IT) und im eigenen Teilbaum:
	// dieselbe Antwort.
	foreign := create("v_it@test.invalid")
	own := create("v_lz@test.invalid")
	expectStatus(t, "fremde Adresse", foreign, 409)
	expectStatus(t, "eigene Adresse", own, 409)
	if foreign.body["fehler"] != own.body["fehler"] || foreign.body["fehler"] != errEmailUnusable.msg {
		t.Errorf("Meldungen unterscheiden sich: %s / %s", foreign.raw, own.raw)
	}
	var after int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'benutzer.anlegen_abgelehnt'`).Scan(&after)
	if after-before != 2 {
		t.Errorf("Audit-Einträge: %d", after-before)
	}
	// Bis 20 Ablehnungen je Stunde, danach 429, auch für freie Adressen.
	for i := 3; i <= maxUserCreateRejects; i++ {
		expectStatus(t, fmt.Sprintf("Ablehnung %d", i), create("v_it@test.invalid"), 409)
	}
	expectStatus(t, "über der Grenze", create("v_it@test.invalid"), 429)
	expectStatus(t, "freie Adresse über der Grenze", create("h3.frei@test.invalid"), 429)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.users WHERE email = 'h3.frei@test.invalid'`).Scan(&n)
	if n != 0 {
		t.Error("trotz Grenze angelegt")
	}
}

func TestRejectCounterVergisst(t *testing.T) {
	var c rejectCounter
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	for range 3 {
		c.add("a", now)
	}
	if c.count("a", now.Add(59*time.Minute)) != 3 || c.count("b", now) != 0 {
		t.Fatal("zählt falsch")
	}
	if c.count("a", now.Add(61*time.Minute)) != 0 {
		t.Fatal("vergisst nach einer Stunde nicht")
	}
}
