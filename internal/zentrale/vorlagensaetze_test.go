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

// Jeder Sensor eines eingebauten Satzes ist ein gültiges Vorlagenziel.
func TestVorlagensaetzeGueltig(t *testing.T) {
	seen := map[string]bool{}
	if len(builtinSets) != 15 {
		t.Fatalf("Sätze: %d", len(builtinSets))
	}
	for _, set := range builtinSets {
		if !strings.HasPrefix(set.ID, "satz-") || set.Name == "" || len(set.Sensoren) == 0 || len(set.Sensoren) > maxSetItems ||
			len([]rune(set.Notiz)) > maxSetNote || len([]rune(set.Name)) > 60 {
			t.Errorf("Satz %+v", set)
		}
		names := map[string]bool{}
		for _, v := range set.Sensoren {
			if seen[v.ID] || names[v.Name] {
				t.Errorf("doppelt: %s %s", v.ID, v.Name)
			}
			seen[v.ID], names[v.Name] = true, true
			if _, err := checks.ParseTemplate(v.Typ, v.Ziel); err != nil {
				t.Errorf("%s: %v", v.Name, err)
			}
			if v.Intervall < 60 || len([]rune(v.Name)) > checks.MaxName || len([]rune(v.Notiz)) > 200 {
				t.Errorf("%s: Intervall %d", v.Name, v.Intervall)
			}
		}
	}
	// Leitprinzip 5: Sätze lesen keine Instanznamen einzeln aus, wo es um
	// Leitungen geht (nur „*“ mit Zusammenfassung).
	for _, v := range builtinSets[0].Sensoren {
		if strings.Contains(string(v.Ziel), "Trunk\"") && !strings.Contains(string(v.Ziel), `"instanz":"*"`) {
			t.Errorf("Leitung einzeln: %s", v.Ziel)
		}
	}
}

func TestVorlagensaetzeAnwenden(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()

	r := as(t, "v_lz").do("GET", "/api/v1/sensor-vorlagen", nil)
	expectStatus(t, "Liste Leser", r, 200)
	if sets, _ := r.body["saetze"].([]any); len(sets) != len(builtinSets) {
		t.Fatalf("Sätze in der Liste: %v", r.body["saetze"])
	}

	ag := collectorAgent(t, "v_fw", "Fertigung", "vs-swyx")
	agDev := agentDevice(t, ag.id)
	ag2 := collectorAgent(t, "v_fw", "Fertigung", "vs-iq")
	agDev2 := agentDevice(t, ag2.id)
	r = newDevice(t, "v_fw", "Fertigung", "VS ohne Agent", "vs.fw.test")
	expectStatus(t, "Gerät", r, 201)
	bare := r.body["id"].(string)
	r = newDevice(t, "v_oa", "Organisation", "VS OA", "vs.oa.test")
	expectStatus(t, "Gerät OA", r, 201)
	oaDev := r.body["id"].(string)
	cleanupChecks(t, agDev, agDev2, bare, oaDev)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.audit_log WHERE action = 'vorlage.angewandt' AND details->>'satz' IS NOT NULL`)
	})

	apply := func(user string, in map[string]any) response {
		return as(t, user).do("POST", "/api/v1/sensor-vorlagen/anwenden", in)
	}
	swyx := len(builtinSets[0].Sensoren)

	// Satz Swyx: alles am Gerät mit Agent, nichts am Gerät ohne
	r = apply("v_fw", map[string]any{"satz_id": "satz-swyx", "geraete": []string{agDev, bare}})
	expectStatus(t, "Swyx", r, 200)
	if int(r.body["angelegt"].(float64)) != swyx || len(r.body["uebersprungen"].([]any)) != swyx {
		t.Fatalf("Swyx: %v", r.body)
	}
	first := r.body["uebersprungen"].([]any)[0].(map[string]any)
	if first["sensor"] != "Swyx: Dienst SwyxServer" || !strings.Contains(first["grund"].(string), "keinen Agent") {
		t.Errorf("übersprungen: %v", first)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE device_id = $1 AND origin = 'Swyx'`, agDev).Scan(&n)
	if n != swyx {
		t.Errorf("Swyx angelegt: %d", n)
	}
	var target []byte
	owner.QueryRow(ctx, `SELECT target FROM openwacht.checks WHERE device_id = $1 AND name = 'Swyx: Leitung abgemeldet'`, agDev).Scan(&target)
	var spec checks.Spec
	if err := json.Unmarshal(target, &spec); err != nil || spec.Object != "SwyxWare Trunk" || spec.Instance != "*" || spec.Aggregate != "minimum" {
		t.Errorf("Leitung: %s %v", target, err)
	}
	// die Sensoren gehen an den Agent des Geräts, mit der neuen Art
	_, jobs := ag.sensorJobs("")
	kinds := map[string]int{}
	for _, j := range jobs.Sensors {
		kinds[j.Kind]++
	}
	if kinds["leistungsindikator"] != 7 || kinds["dienst"] != 3 {
		t.Errorf("Liste am Agent: %v", kinds)
	}
	// Audit mit Satz
	var details []byte
	if err := owner.QueryRow(ctx, `SELECT details FROM openwacht.audit_log WHERE action = 'vorlage.angewandt' AND details->>'satz' = 'satz-swyx'
		ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil || !strings.Contains(string(details), `"vorlage": "Swyx"`) {
		t.Errorf("Audit: %s %v", details, err)
	}

	// zweimal: alles vergeben, nichts doppelt
	r = apply("v_fw", map[string]any{"satz_id": "satz-swyx", "geraete": []string{agDev}})
	if r.status != 200 || r.body["angelegt"].(float64) != 0 || len(r.body["uebersprungen"].([]any)) != swyx {
		t.Errorf("zweimal: %v", r.body)
	}

	// Ferrari: SNMP-Sensor nur mit SNMP-Abfrage am Gerät
	r = apply("v_fw", map[string]any{"satz_id": "satz-ferrari", "geraete": []string{agDev2}})
	expectStatus(t, "Ferrari", r, 200)
	if r.body["angelegt"].(float64) != 2 || !strings.Contains(r.body["uebersprungen"].([]any)[0].(map[string]any)["grund"].(string), "SNMP") {
		t.Errorf("Ferrari: %v", r.body)
	}

	// Mandanten: Geschwister unsichtbar, Leser darf nicht, Eltern dürfen bei Kindern
	expectStatus(t, "fremdes Gerät", apply("v_fw", map[string]any{"satz_id": "satz-iq4docs", "geraete": []string{oaDev}}), 400)
	expectStatus(t, "Geschwister", apply("v_oa", map[string]any{"satz_id": "satz-iq4docs", "geraete": []string{agDev2}}), 400)
	expectStatus(t, "Leser", apply("v_oa_user", map[string]any{"satz_id": "satz-iq4docs", "geraete": []string{oaDev}}), 403)
	expectStatus(t, "Leser Kind", apply("v_lz", map[string]any{"satz_id": "satz-iq4docs", "geraete": []string{agDev2}}), 400)
	r = apply("v_it", map[string]any{"satz_id": "satz-iq4docs", "geraete": []string{agDev2}})
	expectStatus(t, "Eltern", r, 200)
	if r.body["angelegt"].(float64) < 4 {
		t.Errorf("IQ4docs durch Eltern: %v", r.body)
	}
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE device_id = $1 AND origin = 'IQ4docs'`, oaDev).Scan(&n)
	if n != 0 {
		t.Errorf("fremdes Gerät bekam Sensoren: %d", n)
	}

	// Eingaben
	expectStatus(t, "beides", apply("v_fw", map[string]any{"satz_id": "satz-swyx", "vorlage_id": "std-ping", "geraete": []string{agDev}}), 400)
	expectStatus(t, "unbekannt", apply("v_fw", map[string]any{"satz_id": "satz-gibtsnicht", "geraete": []string{agDev}}), 400)
	expectStatus(t, "ohne Geräte", apply("v_fw", map[string]any{"satz_id": "satz-swyx"}), 400)
}

// Exchange (0.45.0): DAG gehört dazu, Webdienste nur mit Status 200, keine
// Namen von Datenbanken oder Warteschlangen.
func TestVorlagensatzExchange(t *testing.T) {
	set, ok := builtinSet("satz-exchange")
	if !ok {
		t.Fatal("Satz Exchange fehlt")
	}
	var dag, health, queues int
	for _, v := range set.Sensoren {
		spec, err := checks.Parse(v.Typ, checks.Substitute(v.Ziel, "mail.beispiel.example"))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		switch {
		case spec.Object == "MSExchange Replication":
			dag++
			if spec.Instance != "*" || spec.Aggregate != "maximum" {
				t.Errorf("DAG einzeln: %s", v.Ziel)
			}
		case spec.Object == "MSExchangeTransport Queues":
			queues++
			if spec.Instance != "_Total" {
				t.Errorf("Warteschlange einzeln: %s", v.Ziel)
			}
		case strings.HasSuffix(spec.URL, "/healthcheck.htm"):
			health++
			if len(spec.ExpectStatus) != 1 || spec.ExpectStatus[0] != 200 || !strings.HasPrefix(spec.URL, "https://mail.beispiel.example/") {
				t.Errorf("Healthcheck: %s", spec.URL)
			}
		}
	}
	if dag != 2 || health != 6 || queues != 6 {
		t.Errorf("DAG %d, Healthchecks %d, Warteschlangen %d", dag, health, queues)
	}
	if !strings.Contains(set.Notiz, "MSExchange Replication") {
		t.Errorf("Freigabe ohne DAG-Objekt: %s", set.Notiz)
	}
}

// Die neue Art über die normale Sensor-API: Prüfung der Parameter und nur am
// Gerät mit Agent.
func TestLeistungsindikatorAPI(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ag := collectorAgent(t, "v_fw", "Fertigung", "li-api")
	dev := agentDevice(t, ag.id)
	r := newDevice(t, "v_fw", "Fertigung", "LI ohne Agent", "li.fw.test")
	expectStatus(t, "Gerät", r, 201)
	bare := r.body["id"].(string)
	cleanupChecks(t, dev, bare)
	sensor := func(user, device, target string) response {
		return as(t, user).do("POST", "/api/v1/geraete/"+device+"/checks", map[string]any{
			"typ": "leistungsindikator", "ziel": json.RawMessage(target), "intervall_sekunden": 60})
	}
	ok := `{"objekt":"SwyxServer","indikator":"Active Calls","warnung_ueber":50}`
	expectStatus(t, "ohne Agent", sensor("v_fw", bare, ok), 409)
	// zweite Schicht: auch die Datenbank lehnt die Art ohne Agent ab
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, 'LI db', 'leistungsindikator', $2, 60)`, bare, ok)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "brauchen ein Gerät mit Agent") {
		t.Errorf("DB ohne Agent: %v", err)
	}
	for _, bad := range []string{
		`{"objekt":"SwyxServer\\..\\x","indikator":"Active Calls"}`,
		`{"objekt":"SwyxServer","indikator":"Active Calls","instanz":"a(b)"}`,
		`{"objekt":"SwyxServer","indikator":"*"}`,
		`{"objekt":"SwyxServer","indikator":"Active Calls","zusammenfassung":"summe"}`,
		`{"objekt":"SwyxServer","indikator":"Active Calls","gleich":"1"}`,
		`{"objekt":"SwyxServer","indikator":"Active Calls","bezug":"Active Calls"}`,
		`{"objekt":"SwyxServer","indikator":"Active Calls","oid":"1.3.6"}`,
	} {
		expectStatus(t, "ungültig "+bad, sensor("v_fw", dev, bad), 400)
	}
	expectStatus(t, "Geschwister", sensor("v_oa", dev, ok), 404)
	expectStatus(t, "Leser", sensor("v_lz", dev, ok), 404)
	r = sensor("v_it", dev, ok)
	expectStatus(t, "Eltern", r, 201)
	var name string
	owner.QueryRow(context.Background(), `SELECT name FROM openwacht.checks WHERE id = $1`, r.body["id"]).Scan(&name)
	if name != "SwyxServer Active Calls" {
		t.Errorf("Name: %q", name)
	}
}
