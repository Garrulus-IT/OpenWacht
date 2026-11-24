// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agent"
	"github.com/garrulus-it/openwacht/internal/agentproto"
)

func (a *testAgent) sensorJobs(state string) (int, agentproto.SensorJobsResponse) {
	a.t.Helper()
	vServer.sensorListLimit = perKeyLimit{every: time.Nanosecond}
	var out agentproto.SensorJobsResponse
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathSensorJobs, agentproto.SensorJobsRequest{State: state})
	if err != nil {
		a.t.Fatal(err)
	}
	if status == 200 {
		if err := json.Unmarshal(body, &out); err != nil {
			a.t.Fatal(err)
		}
	}
	return status, out
}

func (a *testAgent) sensorResults(res ...agentproto.SensorResult) (int, string) {
	a.t.Helper()
	vServer.sensorResultLimit = perKeyLimit{every: time.Nanosecond}
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathSensorResults, agentproto.SensorResultsRequest{Results: res})
	if err != nil {
		a.t.Fatal(err)
	}
	return status, string(body)
}

func checkState(t *testing.T, id string) (status, message, metric *string, revision int) {
	t.Helper()
	if err := owner.QueryRow(context.Background(), `SELECT status, message, metric, revision FROM openwacht.checks WHERE id = $1`, id).
		Scan(&status, &message, &metric, &revision); err != nil {
		t.Fatal(err)
	}
	return
}

func cleanupChecks(t *testing.T, devices ...string) {
	t.Cleanup(func() {
		ctx := context.Background()
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE check_id IN (SELECT id FROM openwacht.checks WHERE device_id = ANY($1::uuid[]))`, devices)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id = ANY($1::uuid[])`, devices)
	})
}

func TestSensorenAmAgent(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	fw := collectorAgent(t, "v_fw", "Fertigung", "se-fw")
	fw2 := collectorAgent(t, "v_fw", "Fertigung", "se-fw2")
	oa := collectorAgent(t, "v_oa", "Organisation", "se-oa")
	dev := agentDevice(t, fw.id)
	dev2 := agentDevice(t, fw2.id)
	r := newDevice(t, "v_fw", "Fertigung", "SE ohne Agent", "se.test")
	expectStatus(t, "Gerät", r, 201)
	bare := r.body["id"].(string)
	cleanupChecks(t, dev, dev2, bare)

	sensor := func(device, name, kind, target string, interval int) response {
		return as(t, "v_fw").do("POST", "/api/v1/geraete/"+device+"/checks", map[string]any{
			"name": name, "typ": kind, "ziel": json.RawMessage(target), "intervall_sekunden": interval})
	}
	// ohne Agent: API lehnt ab, und die Datenbank auch (zweite Schicht)
	r = sensor(bare, "SE Dienst ohne", "dienst", `{"name":"nginx"}`, 60)
	expectStatus(t, "ohne Agent", r, 409)
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) VALUES ($1, 'SE db', 'dienst', '{"name":"x"}', 60)`, bare)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "brauchen ein Gerät mit Agent") {
		t.Errorf("DB ohne Agent: %v", err)
	}
	// Intervall unter 60 s
	expectStatus(t, "30 s", sensor(dev, "SE Dienst schnell", "dienst", `{"name":"nginx"}`, 30), 400)
	// ungültige Parameter
	expectStatus(t, "Name mit -", sensor(dev, "SE Dienst böse", "dienst", `{"name":"--help"}`, 60), 400)

	r = sensor(dev, "SE Dienst", "dienst", `{"name":"nginx"}`, 60)
	expectStatus(t, "Dienst", r, 201)
	svc := r.body["id"].(string)
	r = sensor(dev, "SE Datei", "datei", `{"pfad":"/var/backups/x","kritisch_stunden":50}`, 300)
	expectStatus(t, "Datei", r, 201)
	file := r.body["id"].(string)

	// Liste: nur der eigene Agent bekommt die Sensoren seines Geräts.
	status, jobs := fw.sensorJobs("")
	if status != 200 || len(jobs.Sensors) != 2 || len(jobs.Due) != 2 {
		t.Fatalf("Liste fw: %d %+v", status, jobs)
	}
	for _, other := range []*testAgent{fw2, oa} {
		if _, j := other.sensorJobs(""); len(j.Sensors) != 0 {
			t.Errorf("fremder Agent sieht Sensoren: %+v", j)
		}
	}
	// Stand unverändert: keine Liste
	if _, j := fw.sensorJobs(jobs.State); !j.Unchanged || j.Sensors != nil {
		t.Errorf("unverändert: %+v", j)
	}
	// Der Planer der Zentrale führt Agent-Sensoren nicht aus.
	var claimed int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks_claim(1000) WHERE id = ANY($1::uuid[])`,
		[]string{svc, file}).Scan(&claimed); err != nil || claimed != 0 {
		t.Errorf("checks_claim: %d %v", claimed, err)
	}

	rev := jobs.Sensors[0].Revision
	ok := agentproto.SensorResult{ID: svc, Revision: rev, Status: "crit", Message: "Dienst gestoppt", Metric: "dead"}
	if st, body := fw.sensorResults(ok); st != 204 {
		t.Fatalf("Ergebnis: %d %s", st, body)
	}
	if s, m, _, _ := checkState(t, svc); s == nil || *s != "crit" || *m != "Dienst gestoppt" {
		t.Errorf("Zustand nach Ergebnis: %v %v", s, m)
	}
	// Fremder Agent (gleicher und anderer Mandant): wird verworfen.
	for _, other := range []*testAgent{fw2, oa} {
		if st, _ := other.sensorResults(agentproto.SensorResult{ID: svc, Revision: rev, Status: "ok", Message: "gefälscht"}); st != 204 {
			t.Errorf("fremd: %d", st)
		}
		if s, _, _, _ := checkState(t, svc); *s != "crit" {
			t.Errorf("fremder Agent hat Zustand geändert: %v", *s)
		}
	}
	// alte Revision: verworfen
	fw.sensorResults(agentproto.SensorResult{ID: svc, Revision: rev + 5, Status: "ok", Message: "alt"})
	if s, _, _, _ := checkState(t, svc); *s != "crit" {
		t.Error("alte Revision übernommen")
	}
	// ungültige Ergebnisse: 400, nichts gespeichert
	for _, bad := range []agentproto.SensorResult{
		{ID: svc, Revision: rev, Status: "super", Message: "x"},
		{ID: svc, Revision: rev, Status: "ok", Message: "a\x1bb"},
		{ID: svc, Revision: rev, Status: "ok", Message: strings.Repeat("x", 301)},
		{ID: "kein-uuid", Revision: rev, Status: "ok"},
	} {
		if st, _ := fw.sensorResults(bad, ok); st != 400 {
			t.Errorf("ungültig %+v: %d", bad, st)
		}
	}
	if st, _ := fw.sensorResults(); st != 400 {
		t.Errorf("leer: %d", st)
	}

	// „Jetzt prüfen“ macht den Sensor beim Agent fällig.
	owner.Exec(ctx, `UPDATE openwacht.checks SET last_run = now() - interval '1 minute' WHERE id = $1`, svc)
	_, jobs = fw.sensorJobs(jobs.State)
	for _, d := range jobs.Due {
		if d == svc {
			t.Errorf("nach Messung noch fällig")
		}
	}
	expectStatus(t, "jetzt", as(t, "v_fw").do("POST", "/api/v1/checks/"+svc+"/jetzt", nil), 202)
	_, jobs = fw.sensorJobs(jobs.State)
	found := false
	for _, d := range jobs.Due {
		found = found || d == svc
	}
	if !found {
		t.Errorf("jetzt prüfen: nicht fällig %+v", jobs.Due)
	}

	// Liste in der Oberfläche: am_agent, veraltet
	owner.Exec(ctx, `UPDATE openwacht.checks SET last_run = now() - interval '1 hour' WHERE id = $1`, svc)
	e, okEntry := listEntry(t, "v_fw", "/api/v1/checks", "checks", svc)
	if !okEntry || e["am_agent"] != true || e["veraltet"] != true {
		t.Errorf("Liste: %v", e)
	}
	// Gesperrter Agent bekommt nichts und kann nichts melden.
	owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, fw.id)
	if st, _ := fw.sensorJobs(""); st != 401 {
		t.Errorf("gesperrt Liste: %d", st)
	}
}

func TestSensorFreigabeImSnapshot(t *testing.T) {
	snap := validSnapshot("x")
	snap.Sensors = &agentproto.SensorRelease{Kinds: []string{"dienst", "datei"}, Folders: []string{"/var/backups", `D:\Backup`}}
	if err := snap.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []agentproto.SensorRelease{
		{Kinds: nil},
		{Kinds: []string{"skript"}},
		{Kinds: []string{"dienst", "dienst"}},
		{Kinds: []string{"datei"}},
		{Kinds: []string{"dienst"}, Folders: []string{"/var"}},
		{Kinds: []string{"datei"}, Folders: []string{"var/x"}},
		{Kinds: []string{"datei"}, Folders: []string{"/var/../etc"}},
	} {
		s := validSnapshot("x")
		s.Sensors = &rel
		if err := s.Validate(time.Now()); err == nil {
			t.Errorf("angenommen: %+v", rel)
		}
	}
}

func TestSensorVorlagen(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.sensor_templates WHERE name LIKE 'SV %'`) })

	// eigene Vorlage der Fertigung
	body := map[string]any{"name": "SV HTTPS 5001", "typ": "http", "ziel": json.RawMessage(`{"url":"https://{adresse}:5001/"}`),
		"intervall_sekunden": 120, "notiz": "DSM"}
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("POST", "/api/v1/mandanten/"+ids["Lager Nord"]+"/sensor-vorlagen", body), 403)
	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/sensor-vorlagen", body), 403)
	r := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/sensor-vorlagen", body)
	expectStatus(t, "Fertigung legt an", r, 201)
	tpl := r.body["id"].(string)
	expectStatus(t, "doppelt", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/sensor-vorlagen", body), 409)
	for _, bad := range []map[string]any{
		{"name": "SV x", "typ": "datei", "ziel": json.RawMessage(`{"pfad":"/srv/{adresse}","kritisch_stunden":1}`)},
		{"name": "SV y", "typ": "dienst", "ziel": json.RawMessage(`{"name":"x"}`), "intervall_sekunden": 30},
		{"name": "SV z", "typ": "skript", "ziel": json.RawMessage(`{}`)},
		{"name": "", "typ": "tcp", "ziel": json.RawMessage(`{"host":"{adresse}","port":1}`)},
	} {
		expectStatus(t, "ungültig", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/sensor-vorlagen", bad), 400)
	}

	// Sichtbarkeit: eigener Mandant, Eltern und Kinder (lesend) ja, Geschwister nein
	sees := func(user string) bool {
		r := as(t, user).do("GET", "/api/v1/sensor-vorlagen", nil)
		expectStatus(t, "Liste", r, 200)
		if len(r.body["eingebaut"].([]any)) < 5 {
			t.Errorf("eingebaute Vorlagen fehlen")
		}
		for _, x := range r.body["eigene"].([]any) {
			if x.(map[string]any)["id"] == tpl {
				return true
			}
		}
		return false
	}
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if got := sees(user); got != want {
			t.Errorf("%s sieht Vorlage: %v, erwartet %v", user, got, want)
		}
	}
	upd := map[string]any{"name": "SV HTTPS 5001", "typ": "http", "ziel": json.RawMessage(`{"url":"https://{adresse}:5001/","erwarte_status":[200]}`)}
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/sensor-vorlagen/"+tpl, upd), 404)
	expectStatus(t, "Eltern ändert", as(t, "v_it").do("PUT", "/api/v1/sensor-vorlagen/"+tpl, upd), 204)

	// Anwenden auf Geräte
	mk := func(name, addr string) string {
		r := newDevice(t, "v_fw", "Fertigung", name, addr)
		expectStatus(t, "Gerät "+name, r, 201)
		return r.body["id"].(string)
	}
	nas := mk("SV NAS", "nas.fw.test")
	noAddr := mk("SV ohne", "")
	ag := collectorAgent(t, "v_fw", "Fertigung", "sv-agent")
	agDev := agentDevice(t, ag.id)
	oaDev := func() string {
		r := newDevice(t, "v_oa", "Organisation", "SV OA", "oa.test")
		expectStatus(t, "Gerät OA", r, 201)
		return r.body["id"].(string)
	}()
	cleanupChecks(t, nas, noAddr, agDev, oaDev)

	apply := func(user string, in map[string]any) response {
		return as(t, user).do("POST", "/api/v1/sensor-vorlagen/anwenden", in)
	}
	r = apply("v_fw", map[string]any{"vorlage_id": tpl, "geraete": []string{nas, noAddr}})
	expectStatus(t, "anwenden", r, 200)
	if r.body["angelegt"].(float64) != 1 || len(r.body["uebersprungen"].([]any)) != 1 {
		t.Errorf("anwenden: %v", r.body)
	}
	var name, origin string
	var target []byte
	if err := owner.QueryRow(ctx, `SELECT name, origin, target FROM openwacht.checks WHERE device_id = $1`, nas).Scan(&name, &origin, &target); err != nil {
		t.Fatal(err)
	}
	if name != "SV HTTPS 5001" || origin != "SV HTTPS 5001" || !strings.Contains(string(target), "https://nas.fw.test:5001/") {
		t.Errorf("angelegt: %s %s %s", name, origin, target)
	}
	// nochmal: Name vergeben → übersprungen, nichts doppelt
	r = apply("v_fw", map[string]any{"vorlage_id": tpl, "geraete": []string{nas}})
	if r.body["angelegt"].(float64) != 0 || !strings.Contains(r.body["uebersprungen"].([]any)[0].(map[string]any)["grund"].(string), "vergeben") {
		t.Errorf("doppelt: %v", r.body)
	}
	// fremdes Gerät (Geschwister): unsichtbar → keine Geräte
	expectStatus(t, "fremdes Gerät", apply("v_fw", map[string]any{"vorlage_id": tpl, "geraete": []string{oaDev}}), 400)
	// Geschwister kann die Vorlage nicht anwenden (unsichtbar)
	expectStatus(t, "fremde Vorlage", apply("v_oa", map[string]any{"vorlage_id": tpl, "geraete": []string{oaDev}}), 404)
	// Leser darf nicht anlegen
	expectStatus(t, "Leser", apply("v_oa_user", map[string]any{"vorlage_id": "std-ssh", "geraete": []string{oaDev}}), 403)

	// eingebaute Agent-Vorlage: nur am Gerät mit Agent
	r = apply("v_fw", map[string]any{"vorlage_id": "std-dienst-ssh", "geraete": []string{nas, agDev}})
	expectStatus(t, "Agent-Vorlage", r, 200)
	if r.body["angelegt"].(float64) != 1 || !strings.Contains(r.body["uebersprungen"].([]any)[0].(map[string]any)["grund"].(string), "keinen Agent") {
		t.Errorf("Agent-Vorlage: %v", r.body)
	}
	// Gruppe mit Untergruppen
	g := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/gruppen", map[string]any{"name": "SV Gruppe"})
	expectStatus(t, "Gruppe", g, 201)
	gid := g.body["id"].(string)
	sub := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/gruppen", map[string]any{"name": "SV Unter", "eltern_id": gid})
	expectStatus(t, "Untergruppe", sub, 201)
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.devices SET group_id = NULL WHERE group_id IN (SELECT id FROM openwacht.device_groups WHERE name LIKE 'SV %')`)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE name = 'SV Unter'`)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE name = 'SV Gruppe'`)
	})
	expectStatus(t, "zuordnen", as(t, "v_fw").do("POST", "/api/v1/geraete/gruppe", map[string]any{"geraete": []string{noAddr}, "gruppe_id": gid}), 204)
	expectStatus(t, "zuordnen unter", as(t, "v_fw").do("POST", "/api/v1/geraete/gruppe", map[string]any{"geraete": []string{nas}, "gruppe_id": sub.body["id"]}), 204)
	r = apply("v_fw", map[string]any{"vorlage_id": "std-ping", "gruppe_id": gid})
	if r.status != 200 || r.body["angelegt"].(float64) != 0 || len(r.body["uebersprungen"].([]any)) != 1 {
		t.Errorf("Gruppe ohne Untergruppen: %v", r.body)
	}
	r = apply("v_fw", map[string]any{"vorlage_id": "std-ping", "gruppe_id": gid, "mit_untergruppen": true})
	if r.status != 200 || r.body["angelegt"].(float64) != 1 {
		t.Errorf("Gruppe mit Untergruppen: %v", r.body)
	}
	expectStatus(t, "beides", apply("v_fw", map[string]any{"vorlage_id": "std-ping", "gruppe_id": gid, "geraete": []string{nas}}), 400)
	expectStatus(t, "unbekannt", apply("v_fw", map[string]any{"vorlage_id": "std-gibtsnicht", "geraete": []string{nas}}), 400)

	// Löschen: Geschwister nein, Eigentümer ja; Sensoren bleiben (Kopie)
	expectStatus(t, "Geschwister löscht", as(t, "v_oa").do("DELETE", "/api/v1/sensor-vorlagen/"+tpl, nil), 404)
	expectStatus(t, "löschen", as(t, "v_fw").do("DELETE", "/api/v1/sensor-vorlagen/"+tpl, nil), 204)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE origin = 'SV HTTPS 5001'`).Scan(&n)
	if n != 1 {
		t.Errorf("Sensor nach Löschen der Vorlage: %d", n)
	}
}

// TestSensorenEndeZuEnde: echter Agent-Code (Freigabe, Meldung, Liste,
// Messung, Ergebnis) gegen die Zentrale, mit einem Datei- und einem nicht
// freigegebenen Dienst-Sensor.
func TestSensorenEndeZuEnde(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	srv := agentServer(t)
	ctx := context.Background()
	dir := t.TempDir()
	tok, r := newAgentToken(t, "v_fw", "Fertigung", 1)
	expectStatus(t, "Token", r, 201)
	vServer.agent.limiter = newIPLimiter(vServer.cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
	agentID, err := agent.Register(ctx, dir, srv.URL, tok, "fw-sens-e2e", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE agent_id = $1`, agentID) })
	backups := filepath.Join(dir, "backups")
	os.Mkdir(backups, 0o755)
	os.WriteFile(filepath.Join(backups, "nacht.dump"), []byte("x"), 0o644)
	if _, err := agent.WriteSensorConfig(dir, []string{"datei"}, []string{backups}, ""); err != nil {
		t.Fatal(err)
	}
	runner, err := agent.NewRunner(dir, func() (agentproto.Snapshot, error) { return validSnapshot("fw-sens-e2e"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runner.Report(ctx); err != nil {
		t.Fatal(err)
	}
	dev := agentDevice(t, agentID)
	cleanupChecks(t, dev)
	// Die Freigabe steht in den Messwerten und damit in der Oberfläche.
	var kinds string
	owner.QueryRow(ctx, `SELECT snapshot -> 'sensoren' ->> 'arten' FROM openwacht.agents WHERE id = $1`, agentID).Scan(&kinds)
	if kinds != `["datei"]` {
		t.Errorf("Freigabe im Snapshot: %q", kinds)
	}
	mk := func(name, kind, target string) string {
		r := as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{"name": name, "typ": kind,
			"ziel": json.RawMessage(target), "intervall_sekunden": 60})
		expectStatus(t, name, r, 201)
		return r.body["id"].(string)
	}
	file := mk("E2E Backup", "datei", `{"pfad":"`+backups+`","ordner":true,"warnung_stunden":26,"kritisch_stunden":50}`)
	svc := mk("E2E Dienst", "dienst", `{"name":"nginx"}`)

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	vServer.sensorListLimit = perKeyLimit{every: time.Nanosecond}
	vServer.sensorResultLimit = perKeyLimit{every: time.Nanosecond}
	done := make(chan struct{})
	go func() { runner.Run(runCtx); close(done) }()
	var fs, ss *string
	for runCtx.Err() == nil {
		fs, _, _, _ = checkState(t, file)
		ss, _, _, _ = checkState(t, svc)
		if fs != nil && ss != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done
	if fs == nil || *fs != "ok" {
		_, m, _, _ := checkState(t, file)
		t.Errorf("Datei-Sensor: %v %v", fs, m)
	}
	if s, m, _, _ := checkState(t, svc); s == nil || *s != "unknown" || !strings.Contains(*m, "nicht freigegeben") {
		t.Errorf("Dienst-Sensor: %v %v", s, m)
	}
}
