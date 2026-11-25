// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestHinweiseTonBenutzer(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.users SET alarm_ui = DEFAULT`)
	})
	// Ab Werk: Hinweise an, Ton aus.
	me := as(t, "v_lz").do("GET", "/api/v1/ich", nil)
	ui, _ := me.body["hinweise_ton"].(map[string]any)
	if ui["hinweise"] != true || ui["ton"] != "aus" || ui["klang"] != "bling" || ui["lautstaerke"] != float64(60) {
		t.Fatalf("Vorgabe: %v", ui)
	}

	ok := map[string]any{"hinweise": false, "ton": "warn", "klang": "gong", "lautstaerke": 35, "entwarnung": true}
	// Auch ein Leser stellt für sich selbst ein.
	expectStatus(t, "Leser stellt ein", as(t, "v_lz").do("PUT", "/api/v1/ich/hinweise-ton", ok), 200)
	ui, _ = as(t, "v_lz").do("GET", "/api/v1/ich", nil).body["hinweise_ton"].(map[string]any)
	if ui["hinweise"] != false || ui["ton"] != "warn" || ui["klang"] != "gong" || ui["lautstaerke"] != float64(35) || ui["entwarnung"] != true {
		t.Errorf("gespeichert: %v", ui)
	}
	// Nur für sich selbst: andere Konten bleiben unverändert.
	ui, _ = as(t, "v_lz2").do("GET", "/api/v1/ich", nil).body["hinweise_ton"].(map[string]any)
	if ui["ton"] != "aus" || ui["hinweise"] != true {
		t.Errorf("anderes Konto geändert: %v", ui)
	}

	for name, body := range map[string]map[string]any{
		"Ton falsch":        {"hinweise": true, "ton": "laut", "klang": "bling", "lautstaerke": 50, "entwarnung": false},
		"Klang falsch":      {"hinweise": true, "ton": "krit", "klang": "../x.mp3", "lautstaerke": 50, "entwarnung": false},
		"zu laut":           {"hinweise": true, "ton": "krit", "klang": "bling", "lautstaerke": 101, "entwarnung": false},
		"negativ":           {"hinweise": true, "ton": "krit", "klang": "bling", "lautstaerke": -1, "entwarnung": false},
		"Kommazahl":         {"hinweise": true, "ton": "krit", "klang": "bling", "lautstaerke": 5.5, "entwarnung": false},
		"hinweise fehlt":    {"ton": "krit", "klang": "bling", "lautstaerke": 50, "entwarnung": false},
		"lautstaerke fehlt": {"hinweise": true, "ton": "krit", "klang": "bling", "entwarnung": false},
		"unbekanntes Feld":  {"hinweise": true, "ton": "krit", "klang": "bling", "lautstaerke": 50, "entwarnung": false, "benutzer": ids["v_fw"]},
	} {
		expectStatus(t, name, as(t, "v_lz").do("PUT", "/api/v1/ich/hinweise-ton", body), 400)
	}
	expectStatus(t, "ohne Sitzung", newClient(t, vSrv).do("PUT", "/api/v1/ich/hinweise-ton", ok), 401)
}

// Die Datenbank schützt auch ohne die Prüfung in der Anwendung.
func TestHinweiseTonDatenbank(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	t.Cleanup(func() { owner.Exec(ctx, `UPDATE openwacht.users SET alarm_ui = DEFAULT`) })
	for name, v := range map[string]string{
		"zusätzlicher Schlüssel": `{"hinweise":true,"ton":"aus","klang":"bling","lautstaerke":5,"entwarnung":false,"x":1}`,
		"Ton falsch":             `{"hinweise":true,"ton":"x","klang":"bling","lautstaerke":5,"entwarnung":false}`,
		"Lautstärke Text":        `{"hinweise":true,"ton":"aus","klang":"bling","lautstaerke":"5","entwarnung":false}`,
		"Lautstärke 1000":        `{"hinweise":true,"ton":"aus","klang":"bling","lautstaerke":1000,"entwarnung":false}`,
		"kein Objekt":            `[1]`,
	} {
		if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET alarm_ui = $1::jsonb WHERE id = $2`, v, ids["v_lz"]); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
	// Die Anwendung darf die Spalte nicht direkt schreiben, nur über set_alarm_ui.
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE openwacht.users SET alarm_ui = alarm_ui WHERE id = $1`, ids["v_lz"])
		return err
	})
	if err == nil {
		t.Error("direktes UPDATE auf users.alarm_ui erlaubt")
	}
	// Ohne Benutzer: set_alarm_ui verweigert.
	_, err = pool.Exec(ctx, `SELECT openwacht.set_alarm_ui('{"hinweise":true,"ton":"aus","klang":"bling","lautstaerke":5,"entwarnung":false}')`)
	if err == nil {
		t.Error("set_alarm_ui ohne Benutzer")
	}
	// Anzeige ohne Kontext oder mit Benutzer: kein Ton.
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT openwacht.display_sound()`).Scan(&raw); err != nil || raw != nil {
		t.Errorf("display_sound ohne Kontext: %s %v", raw, err)
	}
}

func TestHinweiseTonAnzeige(t *testing.T) {
	wandSetup(t)
	r := newDisplay(t, "v_it", "Wand A", map[string]any{"name": "WA Ton"})
	expectStatus(t, "anlegen", r, 201)
	id, key := r.body["id"].(string), displayKey(t, r)
	e, _ := listEntry(t, "v_it", "/api/v1/anzeigen", "anzeigen", id)
	if ton, _ := e["ton"].(map[string]any); ton["ton"] != "krit" || ton["lautstaerke"] != float64(70) {
		t.Fatalf("Vorgabe: %v", e["ton"])
	} else if _, ok := ton["hinweise"]; ok {
		t.Error("Anzeige hat „hinweise“")
	}

	body := map[string]any{"ton": "warn", "klang": "doppel", "lautstaerke": 90, "entwarnung": true}
	path := "/api/v1/anzeigen/" + id + "/ton"
	expectStatus(t, "Geschwister", as(t, "v_oa").do("PUT", path, body), 404)
	expectStatus(t, "anderer Ast", as(t, "v_fw").do("PUT", path, body), 404)
	expectStatus(t, "Leser", as(t, "v_lz").do("PUT", path, body), 404)
	expectStatus(t, "mit hinweise", as(t, "v_it").do("PUT", path,
		map[string]any{"hinweise": true, "ton": "warn", "klang": "doppel", "lautstaerke": 90, "entwarnung": true}), 200)
	expectStatus(t, "Klang falsch", as(t, "v_it").do("PUT", path,
		map[string]any{"ton": "warn", "klang": "sirene", "lautstaerke": 90, "entwarnung": true}), 400)
	expectStatus(t, "Admin", as(t, "v_it").do("PUT", path, body), 200)

	wall := newClient(t, vSrv)
	expectStatus(t, "Wand anmelden", wall.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": key}), 200)
	d := wall.do("GET", "/api/v1/anzeige/daten", nil)
	expectStatus(t, "Wand Daten", d, 200)
	ton, _ := d.body["ton"].(map[string]any)
	if ton["ton"] != "warn" || ton["klang"] != "doppel" || ton["lautstaerke"] != float64(90) || ton["entwarnung"] != true {
		t.Errorf("Wand-Ton: %v", d.body["ton"])
	}
	if _, ok := ton["hinweise"]; ok {
		t.Error("Wand-Ton mit „hinweise“")
	}
	// Anzeige und Benutzer zugleich: Die Anzeige zählt nicht.
	ctx := context.Background()
	var raw []byte
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tx.Exec(ctx, `SELECT set_config('app.display_id', $1, true), set_config('app.user_id', $2, true)`, id, ids["v_it"])
		return tx.QueryRow(ctx, `SELECT openwacht.display_sound()`).Scan(&raw)
	}); err != nil || raw != nil {
		t.Errorf("display_sound mit Benutzer: %s %v", raw, err)
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'anzeige.ton' AND details->>'id' = $1`, id).Scan(&audits)
	if audits != 2 {
		t.Errorf("Audit: %d", audits)
	}
}
