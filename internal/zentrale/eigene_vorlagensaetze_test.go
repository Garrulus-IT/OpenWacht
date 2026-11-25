// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/checks"
)

// DC und SQL (0.46.0): Datenbanknamen nur zusammengefasst, Objekte in der
// Freigabe genannt.
func TestVorlagensaetzeDCundSQL(t *testing.T) {
	for _, id := range []string{"satz-dc", "satz-sql"} {
		set, ok := builtinSet(id)
		if !ok {
			t.Fatalf("%s fehlt", id)
		}
		for _, v := range set.Sensoren {
			spec, err := checks.Parse(v.Typ, checks.Substitute(v.Ziel, "dc01.beispiel.example"))
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if v.Typ == "leistungsindikator" && !strings.Contains(set.Notiz, spec.Object) {
				t.Errorf("%s: Objekt %q fehlt in der Freigabe", v.Name, spec.Object)
			}
			if spec.Object == "SQLServer:Databases" && (spec.Instance != "*" || spec.Aggregate != "maximum") {
				t.Errorf("Datenbank einzeln: %s", v.Ziel)
			}
		}
	}
}

func setBody(name string, items ...map[string]any) map[string]any {
	return map[string]any{"name": name, "notiz": "Test", "sensoren": items}
}

func setItem(name, kind, target string, interval int) map[string]any {
	return map[string]any{"name": name, "typ": kind, "ziel": json.RawMessage(target), "intervall_sekunden": interval}
}

func TestEigeneVorlagensaetze(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.sensor_template_sets WHERE name LIKE 'ES %'`)
	})
	base := "/api/v1/mandanten/" + ids["Fertigung"] + "/sensor-vorlagensaetze"
	ok := setBody("ES Standard",
		setItem("ES Ping", "ping", `{"host":"{adresse}"}`, 60),
		setItem("ES Dienst Spooler", "dienst", `{"name":"Spooler"}`, 60),
		setItem("ES Pools", "leistungsindikator", `{"objekt":"APP_POOL_WAS","indikator":"Current Application Pool State","instanz":"*","zusammenfassung":"maximum","kritisch_ueber":3}`, 60))

	// Rechte: Leser nein, Geschwister nein, eigener Admin ja
	expectStatus(t, "Leser", as(t, "v_lz").do("POST", "/api/v1/mandanten/"+ids["Lager Nord"]+"/sensor-vorlagensaetze", ok), 403)
	expectStatus(t, "Geschwister", as(t, "v_oa").do("POST", base, ok), 403)
	r := as(t, "v_fw").do("POST", base, ok)
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	expectStatus(t, "doppelt", as(t, "v_fw").do("POST", base, ok), 409)

	// ungültige Eingaben
	many := make([]map[string]any, 51)
	for i := range many {
		many[i] = setItem("ES "+itoa(i), "ping", `{"host":"{adresse}"}`, 60)
	}
	type badCase struct {
		body map[string]any
		msg  string
	}
	for name, bad := range map[string]badCase{
		"leer":            {setBody("ES leer"), "1 bis 50"},
		"zu viele":        {setBody("ES viele", many...), "1 bis 50"},
		"Name doppelt":    {setBody("ES dop", setItem("ES A", "ping", `{"host":"x"}`, 60), setItem("es a", "tcp", `{"host":"x","port":1}`, 60)), "doppelt"},
		"Ziel falsch":     {setBody("ES ziel", setItem("ES A", "tcp", `{"host":"x"}`, 60)), "Sensor 1: Port"},
		"Agent 30 s":      {setBody("ES int", setItem("ES A", "dienst", `{"name":"x"}`, 30)), "Sensor 1: Intervall"},
		"Art unbekannt":   {setBody("ES art", setItem("ES A", "skript", `{}`, 60)), "Sensor 1: unbekannter Typ"},
		"Platzhalter":     {setBody("ES pl", setItem("ES A", "datei", `{"pfad":"/srv/{adresse}","kritisch_stunden":1}`, 300)), "{adresse}"},
		"ohne Name":       {setBody("", setItem("ES A", "ping", `{"host":"x"}`, 60)), "Name: 1 bis 60"},
		"Indikator Stern": {setBody("ES st", setItem("ES A", "leistungsindikator", `{"objekt":"*","indikator":"x"}`, 60)), "Objekt"},
	} {
		r := as(t, "v_fw").do("POST", base, bad.body)
		expectStatus(t, name, r, 400)
		if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, bad.msg) {
			t.Errorf("%s: Meldung %q, erwartet %q", name, msg, bad.msg)
		}
	}

	// Sichtbarkeit: eigener Mandant und Eltern ja, Geschwister und Kinder-Leser … wie Vorlagen
	sees := func(user string) bool {
		r := as(t, user).do("GET", "/api/v1/sensor-vorlagen", nil)
		expectStatus(t, "Liste "+user, r, 200)
		for _, x := range r.body["eigene_saetze"].([]any) {
			if x.(map[string]any)["id"] == id {
				if n := len(x.(map[string]any)["sensoren"].([]any)); n != 3 {
					t.Errorf("Sensoren im Satz: %d", n)
				}
				return true
			}
		}
		return false
	}
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if got := sees(user); got != want {
			t.Errorf("%s sieht Satz: %v, erwartet %v", user, got, want)
		}
	}

	// ändern: Geschwister nein, Eltern ja
	upd := setBody("ES Standard", setItem("ES Ping", "ping", `{"host":"{adresse}","anzahl":5}`, 60),
		setItem("ES Dienst Spooler", "dienst", `{"name":"Spooler"}`, 60))
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/sensor-vorlagensaetze/"+id, upd), 404)
	expectStatus(t, "Eltern ändert", as(t, "v_it").do("PUT", "/api/v1/sensor-vorlagensaetze/"+id, upd), 204)

	// anwenden
	ag := collectorAgent(t, "v_fw", "Fertigung", "es-agent")
	dev := agentDevice(t, ag.id)
	owner.Exec(ctx, `UPDATE openwacht.devices SET address = 'es.fw.test' WHERE id = $1`, dev)
	r = newDevice(t, "v_oa", "Organisation", "ES OA", "es.oa.test")
	expectStatus(t, "Gerät OA", r, 201)
	oaDev := r.body["id"].(string)
	cleanupChecks(t, dev, oaDev)
	apply := func(user string, in map[string]any) response {
		return as(t, user).do("POST", "/api/v1/sensor-vorlagen/anwenden", in)
	}
	r = apply("v_fw", map[string]any{"satz_id": id, "geraete": []string{dev}})
	expectStatus(t, "anwenden", r, 200)
	if r.body["angelegt"].(float64) != 2 {
		t.Errorf("anwenden: %v", r.body)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE device_id = $1 AND origin = 'ES Standard'`, dev).Scan(&n)
	if n != 2 {
		t.Errorf("Herkunft: %d", n)
	}
	expectStatus(t, "Geschwister wendet an", apply("v_oa", map[string]any{"satz_id": id, "geraete": []string{oaDev}}), 404)
	expectStatus(t, "Leser wendet an", apply("v_lz", map[string]any{"satz_id": id, "geraete": []string{dev}}), 404)
	expectStatus(t, "ungültige ID", apply("v_fw", map[string]any{"satz_id": "kein-satz", "geraete": []string{dev}}), 400)

	// zweite Schicht: die Datenbank prüft die Form der Einträge selbst
	for name, items := range map[string]string{
		"keine Liste":    `{"a":1}`,
		"Art unbekannt":  `[{"name":"x","typ":"skript","ziel":{},"intervall_sekunden":60,"notiz":""}]`,
		"Agent 30 s":     `[{"name":"x","typ":"dienst","ziel":{"name":"y"},"intervall_sekunden":30,"notiz":""}]`,
		"Feld zu viel":   `[{"name":"x","typ":"ping","ziel":{},"intervall_sekunden":60,"notiz":"","befehl":"rm"}]`,
		"Name doppelt":   `[{"name":"x","typ":"ping","ziel":{},"intervall_sekunden":60,"notiz":""},{"name":"X","typ":"ping","ziel":{},"intervall_sekunden":60,"notiz":""}]`,
		"Steuerzeichen":  `[{"name":"x\u0007","typ":"ping","ziel":{},"intervall_sekunden":60,"notiz":""}]`,
		"Intervall Text": `[{"name":"x","typ":"ping","ziel":{},"intervall_sekunden":"60","notiz":""}]`,
	} {
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO openwacht.sensor_template_sets (tenant_id, name, items) VALUES ($1, 'ES db', $2)`,
				ids["Fertigung"], items)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "23514") {
			t.Errorf("DB %s: %v", name, err)
		}
	}
	// Leser im selben Mandanten: sieht den Satz, darf ihn aber weder ändern noch löschen
	r = as(t, "v_oa").do("POST", "/api/v1/mandanten/"+ids["Organisation"]+"/sensor-vorlagensaetze", setBody("ES Organisation",
		setItem("ES Ping", "ping", `{"host":"{adresse}"}`, 60)))
	expectStatus(t, "Organisation", r, 201)
	oaSet := r.body["id"].(string)
	if lr := as(t, "v_oa_user").do("GET", "/api/v1/sensor-vorlagen", nil); !strings.Contains(lr.raw, oaSet) {
		t.Error("Leser sieht den Satz seines Mandanten nicht")
	}
	expectStatus(t, "Leser ändert", as(t, "v_oa_user").do("PUT", "/api/v1/sensor-vorlagensaetze/"+oaSet,
		setBody("ES Organisation", setItem("ES Ping", "ping", `{"host":"x"}`, 60))), 404)
	expectStatus(t, "Leser löscht im eigenen Mandanten", as(t, "v_oa_user").do("DELETE", "/api/v1/sensor-vorlagensaetze/"+oaSet, nil), 404)
	var still int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.sensor_template_sets WHERE id = $1 AND name = 'ES Organisation'
		AND items->0->'ziel'->>'host' = '{adresse}'`, oaSet).Scan(&still)
	if still != 1 {
		t.Error("Leser hat den Satz geändert oder gelöscht")
	}
	// Trigger: Mandant unveränderlich, auch für den Eigentümer der Tabellen
	if _, err := owner.Exec(ctx, `UPDATE openwacht.sensor_template_sets SET tenant_id = $2 WHERE id = $1`, oaSet, ids["Fertigung"]); err == nil ||
		!strings.Contains(err.Error(), "unveränderlich") {
		t.Errorf("Trigger Mandant: %v", err)
	}

	// Mandant und ID unveränderlich
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_it"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE openwacht.sensor_template_sets SET tenant_id = $2 WHERE id = $1`, id, ids["Organisation"])
		return err
	})
	if err == nil {
		t.Error("Mandant eines Satzes geändert")
	}

	// „Als eigenen“: jeder eingebaute Satz lässt sich unverändert speichern
	for _, set := range builtinSets {
		items := make([]map[string]any, len(set.Sensoren))
		for i, v := range set.Sensoren {
			items[i] = map[string]any{"name": v.Name, "typ": v.Typ, "ziel": v.Ziel, "intervall_sekunden": v.Intervall, "notiz": v.Notiz}
		}
		body := map[string]any{"name": "ES Kopie " + set.Name, "notiz": set.Notiz, "sensoren": items}
		expectStatus(t, "Kopie "+set.Name, as(t, "v_fw").do("POST", base, body), 201)
	}

	// löschen: Geschwister nein, Eigentümer ja; Sensoren bleiben (Kopie)
	expectStatus(t, "Geschwister löscht", as(t, "v_oa").do("DELETE", "/api/v1/sensor-vorlagensaetze/"+id, nil), 404)
	expectStatus(t, "Leser löscht", as(t, "v_lz").do("DELETE", "/api/v1/sensor-vorlagensaetze/"+id, nil), 404)
	expectStatus(t, "löschen", as(t, "v_fw").do("DELETE", "/api/v1/sensor-vorlagensaetze/"+id, nil), 204)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE device_id = $1 AND origin = 'ES Standard'`, dev).Scan(&n)
	if n != 2 {
		t.Errorf("Sensoren nach Löschen: %d", n)
	}
	var actions []string
	rows, _ := owner.Query(ctx, `SELECT action FROM openwacht.audit_log WHERE action LIKE 'vorlagensatz.%' AND details->>'id' = $1 ORDER BY id`, id)
	actions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(actions, ",") != "vorlagensatz.angelegt,vorlagensatz.geaendert,vorlagensatz.geloescht" {
		t.Errorf("Audit: %v", actions)
	}
}

// 1.0.1: Kennfarben in eigenen Vorlagensätzen (A) und für alle Sensoren einer
// Herkunft (B).
func TestVorlagensatzKennfarbe(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.sensor_template_sets WHERE name LIKE 'VK %'`)
		owner.Exec(ctx, `DELETE FROM openwacht.kennfarben WHERE name LIKE 'VK %'`)
	})
	mkColor := func(user, tenant, name, farbe string) string {
		t.Helper()
		r := as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/kennfarben", map[string]any{"name": name, "farbe": farbe})
		expectStatus(t, "Kennfarbe "+name, r, 201)
		return r.body["id"].(string)
	}
	fw := mkColor("v_fw", "Fertigung", "VK Pink", "#c0307a")
	fw2 := mkColor("v_fw", "Fertigung", "VK Türkis", "#00838a")
	oa := mkColor("v_oa", "Organisation", "VK Orga", "#7b5cd6")
	base := "/api/v1/mandanten/" + ids["Fertigung"] + "/sensor-vorlagensaetze"

	// A: Kennfarbe eines Geschwisters im Satz: abgelehnt; eigene: angenommen
	withColor := func(k string) map[string]any {
		it := setItem("VK Ping", "ping", `{"host":"{adresse}"}`, 60)
		it["kennfarbe_id"] = k
		return setBody("VK Satz", it, setItem("VK TCP", "tcp", `{"host":"{adresse}","port":22}`, 60))
	}
	r := as(t, "v_fw").do("POST", base, withColor(oa))
	expectStatus(t, "fremde Kennfarbe im Satz", r, 400)
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "Sensor 1") {
		t.Errorf("Meldung: %q", msg)
	}
	expectStatus(t, "Kennfarbe keine ID", as(t, "v_fw").do("POST", base, withColor("rot")), 400)
	r = as(t, "v_fw").do("POST", base, withColor(fw))
	expectStatus(t, "Satz mit Kennfarbe", r, 201)
	set := r.body["id"].(string)
	l := as(t, "v_fw").do("GET", "/api/v1/sensor-vorlagen", nil)
	if !strings.Contains(l.raw, `"kennfarbe_id":"`+fw+`"`) {
		t.Errorf("Liste zeigt die Kennfarbe nicht")
	}

	// Anwenden: Der Ping bekommt die Farbe, der TCP-Sensor keine
	r = newDevice(t, "v_fw", "Fertigung", "VK Gerät 1", "vk1.fw.test")
	expectStatus(t, "Gerät 1", r, 201)
	d1 := r.body["id"].(string)
	r = newDevice(t, "v_fw", "Fertigung", "VK Gerät 2", "vk2.fw.test")
	expectStatus(t, "Gerät 2", r, 201)
	d2 := r.body["id"].(string)
	cleanupChecks(t, d1, d2)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = ANY($1::uuid[])`, []string{d1, d2}) })
	r = as(t, "v_fw").do("POST", "/api/v1/sensor-vorlagen/anwenden", map[string]any{"satz_id": set, "geraete": []string{d1, d2}})
	expectStatus(t, "anwenden", r, 200)
	color := func(dev, name string) string {
		t.Helper()
		var k *string
		if err := owner.QueryRow(ctx, `SELECT kennfarbe_id::text FROM openwacht.checks WHERE device_id = $1 AND name = $2`, dev, name).Scan(&k); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k == nil {
			return ""
		}
		return *k
	}
	if color(d1, "VK Ping") != fw || color(d2, "VK Ping") != fw || color(d1, "VK TCP") != "" {
		t.Errorf("nach dem Anwenden: %q %q %q", color(d1, "VK Ping"), color(d2, "VK Ping"), color(d1, "VK TCP"))
	}

	// B: alle Sensoren der Herkunft an einem Gerät
	url := "/api/v1/sensoren/herkunft-kennfarbe"
	expectStatus(t, "Leser", as(t, "v_lz").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": fw2, "geraet": d1}), 404)
	expectStatus(t, "Geschwister", as(t, "v_oa").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": oa, "geraet": d1}), 404)
	r = as(t, "v_fw").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": fw2, "geraet": d1})
	expectStatus(t, "ein Gerät", r, 200)
	if r.body["geaendert"].(float64) != 2 {
		t.Errorf("ein Gerät: %v", r.body)
	}
	if color(d1, "VK Ping") != fw2 || color(d1, "VK TCP") != fw2 || color(d2, "VK Ping") != fw {
		t.Error("ein Gerät: falsche Sensoren geändert")
	}
	// fremde Kennfarbe: nichts geändert
	r = as(t, "v_fw").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": oa})
	if r.status == 200 && r.body["geaendert"].(float64) != 0 {
		t.Errorf("fremde Kennfarbe gesetzt: %v", r.body)
	}
	// alle Geräte, dann entfernen
	r = as(t, "v_fw").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": fw})
	expectStatus(t, "alle Geräte", r, 200)
	if color(d1, "VK TCP") != fw || color(d2, "VK TCP") != fw {
		t.Error("alle Geräte: nicht gesetzt")
	}
	expectStatus(t, "entfernen", as(t, "v_fw").do("PUT", url, map[string]any{"herkunft": "VK Satz", "kennfarbe_id": nil}), 200)
	if color(d1, "VK Ping") != "" || color(d2, "VK TCP") != "" {
		t.Error("entfernen: Farbe noch da")
	}
	expectStatus(t, "Herkunft unbekannt", as(t, "v_fw").do("PUT", url, map[string]any{"herkunft": "VK gibt es nicht", "kennfarbe_id": fw}), 404)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'check.herkunft_kennfarbe' AND details->>'herkunft' = 'VK Satz'`).Scan(&n)
	if n < 3 {
		t.Errorf("Audit: %d Einträge", n)
	}
}
