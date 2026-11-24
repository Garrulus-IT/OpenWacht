// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

const testCommunity = "geheim-gemeinschaft"

func snmpEntry(t *testing.T, user, id string) (map[string]any, bool) {
	t.Helper()
	return listEntry(t, user, "/api/v1/snmp", "snmp", id)
}

func snmpBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"version": "2c", "adresse": addr, "community": testCommunity}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestSNMPMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "SM Switch", "switch.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/snmp"

	// Anlegen: nur Admins des Teilbaums; Geschwister sehen das Gerät nicht.
	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, snmpBody("switch.lan", nil)), 404)
	r = as(t, "v_fw").do("PUT", path, snmpBody("switch.lan", map[string]any{"ueberwacht": []string{"Port 1", "Port 1", " Port 2 "}}))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)
	if strings.Contains(r.raw, testCommunity) {
		t.Error("Community in der Antwort")
	}

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht SNMP: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["mandant_id"] != ids["Fertigung"] || e["geraet_id"] != dev || e["hat_community"] != true || e["port"] != 161.0 ||
		e["intervall_sekunden"] != 60.0 || len(e["ueberwacht"].([]any)) != 2 {
		t.Errorf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	if strings.Contains(list.raw, testCommunity) || strings.Contains(list.raw, "secret") {
		t.Error("Community oder Geheimnis in der Liste")
	}
	if d, _ := deviceEntry(t, "v_fw", dev); d["snmp_id"] != id {
		t.Errorf("Gerät kennt SNMP nicht: %+v", d)
	}

	// Zweites Mal PUT ändert; Eltern dürfen ändern, ohne die Community zu kennen.
	expectStatus(t, "IT ändert", as(t, "v_it").do("PUT", path, map[string]any{"version": "1", "adresse": "switch.lan",
		"intervall_sekunden": 300}), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["version"] != "1" || e["hat_community"] != true || e["intervall_sekunden"] != 300.0 {
		t.Errorf("nach Ändern: %+v", e)
	}
	// Neue Adresse ohne Community: abgelehnt, die alte Community bleibt beim alten Ziel.
	expectStatus(t, "Adresse ohne Community", as(t, "v_it").do("PUT", path, map[string]any{"version": "2c", "adresse": "anders.lan"}), 400)
	expectStatus(t, "Port ohne Community", as(t, "v_it").do("PUT", path, map[string]any{"version": "2c", "adresse": "switch.lan", "port": 1161}), 400)

	// Leser und Operatoren dürfen nicht einrichten; Operatoren dürfen „jetzt abfragen“.
	lz := newDevice(t, "v_fw", "Lager Nord", "SM LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/snmp"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, snmpBody("lz.lan", nil)), 403)
	_, _, op := wartungZiele(t, "SM")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, snmpBody("lz.lan", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, snmpBody("lz.lan", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzID := r.body["id"].(string)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"version": "2c", "adresse": "lz.lan", "aktiv": false}), 403)
	expectStatus(t, "Operator jetzt", opc.do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 202)
	expectStatus(t, "Leser jetzt", as(t, "v_lz").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 403)
	expectStatus(t, "Geschwister jetzt", as(t, "v_oa").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", lzPath, nil), 403)
	expectStatus(t, "Verlauf Leser", as(t, "v_lz").do("GET", "/api/v1/snmp/"+lzID+"/verlauf", nil), 200)
	expectStatus(t, "Verlauf Geschwister", as(t, "v_oa").do("GET", "/api/v1/snmp/"+lzID+"/verlauf", nil), 404)
	expectStatus(t, "Verlauf Kind beim Eltern", as(t, "v_lz").do("GET", "/api/v1/snmp/"+id+"/verlauf", nil), 404)

	// Verbindung prüfen: nur Admins; Ziel außerhalb der Freigabe wird abgelehnt.
	probe := "/api/v1/geraete/" + dev + "/snmp/pruefen"
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", "/api/v1/geraete/"+lz.body["id"].(string)+"/snmp/pruefen",
		snmpBody("lz.lan", nil)), 403)
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", probe, snmpBody("switch.lan", nil)), 404)
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", probe, snmpBody("127.0.0.1", nil)), 400)
	time.Sleep(3100 * time.Millisecond) // Rate Limit je Person
	expectStatus(t, "gespeicherte Community, andere Adresse", as(t, "v_fw").do("POST", probe,
		map[string]any{"version": "2c", "adresse": "anders.lan"}), 400)

	// Gerät löschen erst ohne SNMP.
	expectStatus(t, "Gerät mit SNMP löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 409)
	expectStatus(t, "Geschwister entfernt SNMP", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt SNMP", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)
	expectStatus(t, "SNMP beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)

	// Audit ohne Community
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'snmp.%'
		AND details::text LIKE '%'||$1||'%'`, testCommunity).Scan(&n)
	if n != 0 {
		t.Errorf("Community im Audit-Log: %d", n)
	}
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'snmp.angelegt'
		AND details->>'geraet' = $1`, dev).Scan(&n)
	if n != 1 {
		t.Errorf("Audit angelegt: %d", n)
	}
}

func TestSNMPEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "SE Drucker", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/snmp"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	bad := map[string]map[string]any{
		"v3":                {"version": "3", "adresse": "d.lan", "community": "x"},
		"Version":           {"version": "4", "adresse": "d.lan", "community": "x"},
		"ohne Adresse":      {"version": "2c", "adresse": "", "community": "x"},
		"Adresse mit Port":  {"version": "2c", "adresse": "d.lan:161", "community": "x"},
		"Port":              {"version": "2c", "adresse": "d.lan", "port": 70000, "community": "x"},
		"Intervall":         {"version": "2c", "adresse": "d.lan", "intervall_sekunden": 10, "community": "x"},
		"ohne Community":    {"version": "2c", "adresse": "d.lan"},
		"Community Umbruch": {"version": "2c", "adresse": "d.lan", "community": "a\nb"},
		"Community lang":    {"version": "2c", "adresse": "d.lan", "community": strings.Repeat("x", 65)},
		"Schnittstelle":     {"version": "2c", "adresse": "d.lan", "community": "x", "ueberwacht": []string{"a\x07"}},
		"IP nicht frei":     {"version": "2c", "adresse": "10.1.2.3", "community": "x"},
	}
	for name, b := range bad {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, b), 400)
	}
}

func TestSNMPPruefungJeSchicht(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "SS NAS", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("nas.lan", nil))
	expectStatus(t, "SNMP", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id) })
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
	// Das Geheimnis ist für die Anwendung nie lesbar, auch nicht für Admins.
	if n := tryAs("v_fw", `SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, id); n != -1 {
		t.Errorf("secret_enc lesbar: %d", n)
	}
	if n := tryAs("v_oa", `UPDATE openwacht.snmp_sources SET interval_s = 30 WHERE id = $1`, id); n != 0 {
		t.Errorf("Geschwister ändert: %d", n)
	}
	if n := tryAs("v_lz", `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id); n != 0 {
		t.Errorf("Kind löscht: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.snmp_sources SET tenant_id = $2 WHERE id = $1`, id, ids["Lager Nord"]); n != -1 {
		t.Errorf("Mandant geändert: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.snmp_sources SET snapshot = '{}', last_ok = now() WHERE id = $1`, id); n != -1 {
		t.Errorf("Zustand geändert: %d", n)
	}
	// Geschwister legt eine Quelle für ein fremdes Gerät an: Gerät „nicht gefunden“.
	x, _ := newUUID()
	if n := tryAs("v_oa", `INSERT INTO openwacht.snmp_sources (id, device_id, version, host) VALUES ($1, $2, '2c', 'x.lan')`, x, dev); n != -1 {
		t.Errorf("Geschwister legt an: %d", n)
	}
	// Gespeicherte Community für „Verbindung prüfen“: nur Admins, nur gleiches Ziel.
	count := func(user, host string, port int) int {
		var c int
		vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_secret_for_probe($1, $2, $3)`, dev, host, port).Scan(&c)
		})
		return c
	}
	// „leser“ ist Leser in der Fertigung: sieht die Quelle, bekommt das Geheimnis aber nicht.
	if count("v_fw", "nas.lan", 161) != 1 || count("leser", "nas.lan", 161) != 0 || count("v_oa", "nas.lan", 161) != 0 ||
		count("v_fw", "anders.lan", 161) != 0 || count("v_fw", "nas.lan", 162) != 0 {
		t.Error("snmp_secret_for_probe gibt das Geheimnis zu freizügig heraus")
	}
	// Neue Adresse über SQL ohne neues Geheimnis: Die Datenbank verwirft es.
	if n := tryAs("v_fw", `UPDATE openwacht.snmp_sources SET host = 'angreifer.lan' WHERE id = $1`, id); n != 1 {
		t.Fatalf("Adresse ändern: %d", n)
	}
	var has bool
	owner.QueryRow(ctx, `SELECT secret_enc IS NOT NULL FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&has)
	if has {
		t.Error("Geheimnis nach Adresswechsel noch da")
	}
	// Das Geheimnis ist an Quelle, Mandant, Adresse und Port gebunden.
	enc, _ := vServer.sealSNMP(id, ids["Fertigung"], "nas.lan", 161, snmpSecret{Community: testCommunity})
	if _, err := vServer.openSNMP(id, ids["Fertigung"], "nas.lan", 161, "2c", enc); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id, tenant, host string
		port             int
	}{{x, ids["Fertigung"], "nas.lan", 161}, {id, ids["Organisation"], "nas.lan", 161}, {id, ids["Fertigung"], "angreifer.lan", 161},
		{id, ids["Fertigung"], "nas.lan", 1161}} {
		if _, err := vServer.openSNMP(c.id, c.tenant, c.host, c.port, "2c", enc); err == nil {
			t.Errorf("Geheimnis passt zu %+v", c)
		}
	}
}

// TestSNMPPlanerUndAlarme: Abfrage gegen eine Gegenstelle, Verlauf, Alarme
// je Kanal, Alarmprotokoll, Sensoren, Wartung und „antwortet nicht“.
func TestSNMPPlanerUndAlarme(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	s.snmp.Timeout, s.snmp.Retries = 300*time.Millisecond, -1
	server, _ := alarm.NormalizeServer(f.URL)

	agent := snmptest.New(t, testCommunity,
		snmptest.Str("1.3.6.1.2.1.2.2.1.2.1", "Port 1"), snmptest.Num("1.3.6.1.2.1.2.2.1.7.1", 1), snmptest.Num("1.3.6.1.2.1.2.2.1.8.1", 1),
		snmptest.Str("1.3.6.1.2.1.2.2.1.2.2", "Port 2"), snmptest.Num("1.3.6.1.2.1.2.2.1.7.2", 1), snmptest.Num("1.3.6.1.2.1.2.2.1.8.2", 2),
		snmptest.Num("1.3.6.1.4.1.6574.1.1.0", 1),
		snmptest.Str("1.3.6.1.4.1.6574.3.1.1.2.0", "Speicherpool 1"), snmptest.Num("1.3.6.1.4.1.6574.3.1.1.3.0", 11),
		gosnmp.SnmpPDU{Name: "1.3.6.1.4.1.6574.3.1.1.4.0", Type: gosnmp.Counter64, Value: uint64(1)},
	)

	var tenant string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'SNMP A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	var dev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'nas-a') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'sa')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	enc, _ := s.sealSNMP(id, tenant, "127.0.0.1", int(agent.Port()), snmpSecret{Community: testCommunity})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc, watched)
		VALUES ($1, $2, '2c', '127.0.0.1', $3, $4, ARRAY['Port 1', 'Port 2'])`, id, dev, int(agent.Port()), enc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tenant)
	})
	poll := func() {
		t.Helper()
		owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, id)
		due, err := s.claimSNMP(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range due {
			if c.id == id {
				found = true
				s.pollSNMP(ctx, c)
			} else { // fremde Quellen anderer Tests zurückgeben
				owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
			}
		}
		if !found {
			t.Fatal("Quelle nicht fällig")
		}
	}
	poll()
	var lastErr *string
	var okAt *time.Time
	var nSeries int
	owner.QueryRow(ctx, `SELECT last_error, last_ok FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr, &okAt)
	if lastErr != nil || okAt == nil {
		t.Fatalf("Abfrage: Fehler %v, ok %v", lastErr, okAt)
	}

	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := f.take()["sa"]
	if len(msgs) != 1 || !strings.Contains(msgs[0].Message, "Port 2") || !strings.Contains(msgs[0].Message, "Speicherpool 1") ||
		strings.Contains(msgs[0].Message, "Port 1") {
		t.Fatalf("Alarm: %+v", msgs)
	}
	var open []string
	rows, _ := owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "if:Port 2,raid:Speicherpool 1" {
		t.Errorf("Alarmprotokoll: %v", open)
	}
	// Kein zweiter Alarm beim nächsten Durchlauf.
	s.alertRoundN(ctx)
	if m := f.take()["sa"]; len(m) != 0 {
		t.Errorf("doppelt gemeldet: %+v", m)
	}

	// Sensoren: IT sieht sie, Fertigung (Geschwister von SNMP A) nicht.
	r := as(t, "v_it").do("GET", "/api/v1/sensoren", nil)
	var seen []string
	for _, x := range r.body["sensoren"].([]any) {
		sn := x.(map[string]any)
		if sn["quelle_id"] == id {
			seen = append(seen, sn["gegenstand"].(string)+"="+sn["status"].(string))
			if sn["art"] != "snmp" || sn["geraet_id"] != dev {
				t.Errorf("Sensor: %+v", sn)
			}
		}
	}
	got := strings.Join(seen, ",")
	for _, want := range []string{"stumm=ok", "if:Port 1=ok", "if:Port 2=crit", "raid:Speicherpool 1=crit", "system=ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("Sensor %s fehlt: %s", want, got)
		}
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/sensoren", nil); strings.Contains(r.raw, id) {
		t.Error("Fertigung sieht fremde SNMP-Sensoren")
	}

	// Wartung des Geräts: keine Erinnerung, keine neuen Alarme; Port 1 fällt aus.
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.maintenance (tenant_id, device_id, ends_at) VALUES ($1, $2, now() + interval '1 hour')`,
		tenant, dev); err != nil {
		t.Fatal(err)
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET watched = ARRAY['Port 1', 'Port 2', 'Port 9'] WHERE id = $1`, id)
	s.alertRoundN(ctx)
	if m := f.take()["sa"]; len(m) != 0 {
		t.Errorf("in der Wartung gemeldet: %+v", m)
	}
	owner.Exec(ctx, `DELETE FROM openwacht.maintenance WHERE device_id = $1`, dev)
	s.alertRoundN(ctx)
	if m := f.take()["sa"]; len(m) != 1 || !strings.Contains(m[0].Message, "Port 9") {
		t.Errorf("nach der Wartung: %+v", m)
	}

	// Falsche Community: Abfrage scheitert, nach der Schwelle „antwortet nicht“.
	enc2, _ := s.sealSNMP(id, tenant, "127.0.0.1", int(agent.Port()), snmpSecret{Community: "falsch"})
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc2)
	poll()
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "keine Antwort") {
		t.Errorf("Fehler: %v", lastErr)
	}
	// Neue Zugangsdaten setzen den Zustand zurück (Revision); „stumm“ zählt ab der Änderung.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET changed_at = now() - interval '10 minutes' WHERE id = $1`, id)
	s.alertRoundN(ctx)
	m := f.take()["sa"]
	if len(m) != 1 || !strings.Contains(m[0].Message, "antwortet nicht") {
		t.Errorf("stumm: %+v", m)
	}
	// Ein Ergebnis zu einer alten Revision wird verworfen.
	var stored bool
	pool.QueryRow(ctx, `SELECT openwacht.snmp_record($1, 0, true, '', '{}', false, ARRAY[]::text[], ARRAY[]::float8[])`, id).Scan(&stored)
	if stored {
		t.Error("Ergebnis zu alter Revision gespeichert")
	}
	// Abfrage ausschalten: letzte Entwarnung für alles Gemeldete.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET enabled = false WHERE id = $1`, id)
	s.alertRoundN(ctx)
	if m := f.take()["sa"]; len(m) != 1 || !strings.Contains(m[0].Message, "ausgeschaltet") {
		t.Errorf("Entwarnung beim Ausschalten: %+v", m)
	}
	var left int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alert_state_snmp WHERE snmp_id = $1`, id).Scan(&left)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL`, id).Scan(&nSeries)
	if left != 0 || nSeries != 0 {
		t.Errorf("nach dem Ausschalten: %d Meldezustände, %d offene Alarme", left, nSeries)
	}
}

func TestSNMPVerlauf(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "SV Switch", "")
	dev := r.body["id"].(string)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("sv.lan", nil))
	expectStatus(t, "SNMP", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id) })
	var rev int
	owner.QueryRow(ctx, `SELECT revision FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&rev)
	var stored bool
	if err := pool.QueryRow(ctx, `SELECT openwacht.snmp_record($1, $2, true, '', '{"system":{}}', false,
		ARRAY['cpu', 'if_ein:Port 1', 'if_ein:Port 1', 'kaputt'], ARRAY[12.5, 1e9, 2e9, 1])`, id, rev).Scan(&stored); err != nil || !stored {
		t.Fatalf("speichern: %v %v", stored, err)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1`, id).Scan(&n)
	if n != 0 {
		t.Errorf("ungültige Reihe nicht abgewiesen: %d Werte", n) // eine ungültige Reihe verwirft alle (wie beim Agent)
	}
	pool.QueryRow(ctx, `SELECT openwacht.snmp_record($1, $2, true, '', '{"system":{}}', false,
		ARRAY['cpu', 'if_ein:Port 1'], ARRAY[12.5, 1e9])`, id, rev).Scan(&stored)
	r = as(t, "v_it").do("GET", "/api/v1/snmp/"+id+"/verlauf?zeitraum=1h", nil)
	expectStatus(t, "Verlauf", r, 200)
	reihen := r.body["reihen"].([]any)
	if len(reihen) != 2 {
		t.Fatalf("Reihen: %+v", reihen)
	}
	if !strings.Contains(r.raw, `"if_ein:Port 1"`) || !strings.Contains(r.raw, "1000000000") {
		t.Errorf("Verlauf: %s", r.raw)
	}
}
