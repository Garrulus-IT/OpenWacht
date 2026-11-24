// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/ontap"
	"github.com/garrulus-it/openwacht/internal/ontap/ontaptest"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const naPin = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"

func naBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "benutzer": ontaptest.User, "passwort": ontaptest.Password, "fingerabdruck": naPin}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestNetAppMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "NA aff-1", "aff-1.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/netapp"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, naBody("aff-1.lan", nil)), 404)
	expectStatus(t, "ohne Fingerabdruck", as(t, "v_fw").do("PUT", path, naBody("aff-1.lan", map[string]any{"fingerabdruck": ""})), 400)
	r = as(t, "v_fw").do("PUT", path, naBody("aff-1.lan", nil))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht NetApp: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["version"] != "ontap" || e["port"] != 443.0 || e["hat_community"] != true || e["intervall_sekunden"] != 120.0 {
		t.Errorf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	if strings.Contains(list.raw, ontaptest.Password) {
		t.Error("Passwort in der Liste")
	}

	// Ändern ohne Passwort: bleibt, aber nur bei gleichem Ziel, Benutzer und Fingerabdruck.
	keep := map[string]any{"adresse": "aff-1.lan", "benutzer": ontaptest.User, "intervall_sekunden": 300}
	expectStatus(t, "IT ändert Intervall", as(t, "v_it").do("PUT", path, keep), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["hat_community"] != true || e["intervall_sekunden"] != 300.0 {
		t.Errorf("nach Ändern: %+v", e)
	}
	other := strings.Repeat("12", 32)
	for name, b := range map[string]map[string]any{
		"Adresse":          {"adresse": "anders.lan", "benutzer": ontaptest.User, "fingerabdruck": naPin},
		"Port":             {"adresse": "aff-1.lan", "port": 8443, "benutzer": ontaptest.User, "fingerabdruck": naPin},
		"Benutzer":         {"adresse": "aff-1.lan", "benutzer": "admin"},
		"Fingerabdruck":    {"adresse": "aff-1.lan", "benutzer": ontaptest.User, "fingerabdruck": other},
		"Adresse ohne Pin": {"adresse": "anders.lan", "benutzer": ontaptest.User},
	} {
		expectStatus(t, name+" ohne Passwort", as(t, "v_it").do("PUT", path, b), 400)
	}
	// Neuer Fingerabdruck mit Passwort: geht.
	expectStatus(t, "neuer Fingerabdruck", as(t, "v_fw").do("PUT", path, naBody("aff-1.lan", map[string]any{"fingerabdruck": other})), 200)

	// Keine Vermischung mit anderen Abfragen.
	expectStatus(t, "SNMP auf NetApp-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("aff-1.lan", nil)), 409)
	expectStatus(t, "Proxmox auf NetApp-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/proxmox", pveBody("aff-1.lan", nil)), 409)
	expectStatus(t, "vCenter auf NetApp-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/vcenter", vcBody("aff-1.lan", nil)), 409)
	sw := newDevice(t, "v_fw", "Fertigung", "NA Switch", "")
	swPath := "/api/v1/geraete/" + sw.body["id"].(string)
	expectStatus(t, "SNMP anlegen", as(t, "v_fw").do("PUT", swPath+"/snmp", snmpBody("sw.lan", nil)), 201)
	r = as(t, "v_fw").do("PUT", swPath+"/netapp", naBody("sw.lan", nil))
	expectStatus(t, "NetApp auf SNMP-Gerät", r, 409)
	if !strings.Contains(r.raw, "SNMP") {
		t.Errorf("Meldung: %s", r.raw)
	}
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", swPath+"/snmp", nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", swPath, nil), 204)

	// Leser und Operatoren dürfen nicht einrichten; Eltern beim Kind schon.
	lz := newDevice(t, "v_fw", "Lager Nord", "NA LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/netapp"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, naBody("lz.lan", nil)), 403)
	_, _, op := wartungZiele(t, "NA")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, naBody("lz.lan", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, naBody("lz.lan", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzID := r.body["id"].(string)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"adresse": "lz.lan", "benutzer": ontaptest.User, "aktiv": false}), 403)
	expectStatus(t, "Operator jetzt", opc.do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 202)
	expectStatus(t, "Geschwister jetzt", as(t, "v_oa").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", lzPath, nil), 403)
	// Ein Kind sieht seine Eltern nicht: Lager Nord kann beim Gerät der Fertigung nichts.
	expectStatus(t, "Kind beim Elternteil", as(t, "v_lz").do("PUT", path, naBody("aff-1.lan", nil)), 404)

	// Verbindung prüfen: nur Admins, nur freigegebene Netze, nicht bei Geschwistern.
	probe := path + "/pruefen"
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", lzPath+"/pruefen", naBody("lz.lan", nil)), 403)
	resetProbeLimit()
	expectStatus(t, "Operator prüft", opc.do("POST", lzPath+"/pruefen", naBody("lz.lan", nil)), 403)
	resetProbeLimit()
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", probe, naBody("aff-1.lan", nil)), 404)
	resetProbeLimit()
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", probe, naBody("127.0.0.1", nil)), 400)
	resetProbeLimit()

	// Löschen
	expectStatus(t, "Geschwister entfernt", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "NetApp entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)

	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'netapp.%' AND details::text LIKE '%'||$1||'%'`,
		ontaptest.Password).Scan(&n)
	if n != 0 {
		t.Errorf("Passwort im Audit-Log: %d", n)
	}
	for _, action := range []string{"netapp.angelegt", "netapp.geaendert", "netapp.geloescht"} {
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = $1 AND details->>'geraet' = $2`, action, dev).Scan(&n)
		if n < 1 {
			t.Errorf("Audit %s fehlt", action)
		}
	}
}

func TestNetAppEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "NE aff", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/netapp"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	u, pw := ontaptest.User, ontaptest.Password
	bad := map[string]map[string]any{
		"ohne Adresse":           {"adresse": "", "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
		"Adresse mit URL":        {"adresse": "https://aff.lan", "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
		"Port":                   {"adresse": "aff.lan", "port": 0x10000, "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
		"Intervall klein":        {"adresse": "aff.lan", "intervall_sekunden": 30, "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
		"Intervall groß":         {"adresse": "aff.lan", "intervall_sekunden": 7200, "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
		"ohne Passwort":          {"adresse": "aff.lan", "benutzer": u, "fingerabdruck": naPin},
		"ohne Benutzer":          {"adresse": "aff.lan", "passwort": pw, "fingerabdruck": naPin},
		"Benutzer Umbruch":       {"adresse": "aff.lan", "benutzer": u + "\nX", "passwort": pw, "fingerabdruck": naPin},
		"Benutzer Leerzeichen":   {"adresse": "aff.lan", "benutzer": "a b", "passwort": pw, "fingerabdruck": naPin},
		"Passwort Umbruch":       {"adresse": "aff.lan", "benutzer": u, "passwort": "a\nb", "fingerabdruck": naPin},
		"Passwort zu lang":       {"adresse": "aff.lan", "benutzer": u, "passwort": strings.Repeat("x", 300), "fingerabdruck": naPin},
		"Fingerabdruck kurz":     {"adresse": "aff.lan", "benutzer": u, "passwort": pw, "fingerabdruck": "AB:CD"},
		"Fingerabdruck kein Hex": {"adresse": "aff.lan", "benutzer": u, "passwort": pw, "fingerabdruck": strings.Repeat("zz", 32)},
		"IP nicht frei":          {"adresse": "10.1.2.3", "benutzer": u, "passwort": pw, "fingerabdruck": naPin},
	}
	for name, b := range bad {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, b), 400)
	}
	expectStatus(t, "gültig", as(t, "v_fw").do("PUT", path, naBody("aff.lan", nil)), 201)
}

func TestNetAppPruefen(t *testing.T) {
	verwaltungSetup(t)
	allowLoopback(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	f := ontaptest.NewFake()
	srv := ontaptest.Start(t, f)
	r := newDevice(t, "v_fw", "Fertigung", "NP aff", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/netapp"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	probe := func(b map[string]any) response {
		t.Helper()
		resetProbeLimit()
		return as(t, "v_fw").do("POST", path+"/pruefen", b)
	}

	// Ohne Fingerabdruck: nur der Fingerabdruck, keine Anfrage und kein Passwort beim Cluster.
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": ontaptest.User, "passwort": ontaptest.Password})
	if r.status != 200 || r.body["ok"] != false || r.body["fingerabdruck_neu"] != ontap.FormatPin(srv.Pin) {
		t.Fatalf("Fingerabdruck: %s", r.raw)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d Anfragen vor Bestätigung des Fingerabdrucks", n)
	}

	body := naBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": ontap.FormatPin(srv.Pin)})
	r = probe(body)
	info, _ := r.body["netapp"].(map[string]any)
	if r.body["ok"] != true || info["knoten"] != 2.0 || info["aggregate"] != 2.0 || info["cluster"] != "aff-test" {
		t.Fatalf("prüfen: %s", r.raw)
	}
	expectStatus(t, "anlegen", as(t, "v_fw").do("PUT", path, body), 201)

	// Gespeichertes Passwort und gespeicherter Fingerabdruck, wenn beides fehlt.
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": ontaptest.User})
	if r.body["ok"] != true {
		t.Fatalf("gespeichert: %s", r.raw)
	}
	expectStatus(t, "anderer Benutzer", probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": "admin"}), 400)

	// Anderes Zertifikat (z. B. untergeschobener Server): Abbruch, neuer Fingerabdruck wird gezeigt, kein Passwort gesendet.
	f.ResetCalls()
	r = probe(naBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": strings.Repeat("12", 32)}))
	if r.body["ok"] != false || r.body["fingerabdruck_neu"] != ontap.FormatPin(srv.Pin) || len(f.Calls()) != 0 {
		t.Fatalf("fremdes Zertifikat: %s %v", r.raw, f.Calls())
	}
	// Anderer Fingerabdruck ohne Passwort: Das gespeicherte geht nicht an ein anderes Zertifikat.
	expectStatus(t, "anderer Pin ohne Passwort", probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port,
		"benutzer": ontaptest.User, "fingerabdruck": strings.Repeat("12", 32)}), 400)

	// Falsches Passwort: verständlich, ohne das Passwort im Text.
	r = probe(naBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": srv.Pin, "passwort": "falsch-999"}))
	if r.body["ok"] != false || strings.Contains(r.raw, "falsch-999") || !strings.Contains(r.raw, "401") {
		t.Fatalf("falsches Passwort: %s", r.raw)
	}

	// Schreibrecht erkannt: abgelehnt, mit Kennzeichen für die Oberfläche.
	f.Writable("/api/storage/volumes", "all")
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": ontaptest.User})
	if r.body["ok"] != false || r.body["schreibrecht"] != true || !strings.Contains(r.raw, "Schreibrecht") {
		t.Fatalf("Schreibrecht: %s", r.raw)
	}
}

func TestNetAppPlanerUndAlarme(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	nt := newFakeNtfy()
	defer nt.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(nt.URL)
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(nt.URL)

	f := ontaptest.NewFake()
	srv := ontaptest.Start(t, f)
	port := int(srv.Port)

	var tenant, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'NA A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'aff-1') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'na')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	enc, _ := s.sealONTAP(id, tenant, "127.0.0.1", port, ontapSecret{User: ontaptest.User, Password: ontaptest.Password, Pin: srv.Pin})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc)
		VALUES ($1, $2, 'ontap', '127.0.0.1', $3, $4)`, id, dev, port, enc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tenant)
	})
	// Die Datenbank nimmt NetApp nicht über einen Sammler und ohne Traps.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = true WHERE id = $1`, id); err == nil {
		t.Error("Traps für NetApp angenommen")
	}
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
			} else {
				owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
			}
		}
		if !found {
			t.Fatal("Quelle nicht fällig")
		}
	}
	poll()
	var lastErr *string
	var raw []byte
	owner.QueryRow(ctx, `SELECT last_error, snapshot FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr, &raw)
	if lastErr != nil || raw == nil {
		t.Fatalf("Abfrage: %v", lastErr)
	}
	var snap snmp.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil || snap.ONTAP == nil || len(snap.ONTAP.Nodes) != 2 {
		t.Fatalf("Snapshot: %v %s", err, raw)
	}
	for _, c := range f.Calls() {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("unerwarteter Aufruf: %s", c)
		}
	}
	// Verlauf: IOPS, Latenz und Belegung gespeichert
	var series []string
	rows, _ := owner.Query(ctx, `SELECT DISTINCT series FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1 ORDER BY 1`, id)
	series, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	joined := strings.Join(series, ",")
	for _, want := range []string{"iops:aggr1", "latenz:aggr2", "platte:Aggregat aggr2", "platte:Volume svm1/daten"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Reihe %s fehlt: %s", want, joined)
		}
	}

	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := nt.take()["na"]
	if len(msgs) != 1 {
		t.Fatalf("Alarm: %+v", msgs)
	}
	for _, want := range []string{"Aggregat aggr2", "Platten", "Shelf 1.0", "SnapMirror svm2:spiegel", "EMS disk.outOfService", "Volume svm1/archiv"} {
		if !strings.Contains(msgs[0].Message, want) {
			t.Errorf("Alarm ohne %q: %s", want, msgs[0].Message)
		}
	}
	for _, not := range []string{"Knoten aff-01", "Aggregat aggr1"} {
		if strings.Contains(msgs[0].Message, not) {
			t.Errorf("gesundes %s gemeldet: %s", not, msgs[0].Message)
		}
	}
	rows, _ = owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "ems:disk.outOfService,platte:Aggregat aggr2,platten,shelf:1.0,snapmirror:svm2:spiegel,volume:svm1/archiv" {
		t.Errorf("Alarmprotokoll: %v", open)
	}

	// Sensoren: IT sieht sie, Fertigung nicht.
	r := as(t, "v_it").do("GET", "/api/v1/sensoren", nil)
	var seen []string
	for _, x := range r.body["sensoren"].([]any) {
		sn := x.(map[string]any)
		if sn["quelle_id"] == id {
			seen = append(seen, sn["name"].(string)+"="+sn["status"].(string))
		}
	}
	got := strings.Join(seen, ",")
	for _, want := range []string{"NetApp=ok", "Knoten aff-01=ok", "Aggregat aggr2=crit", "Platten=crit", "Shelf 1.0=crit"} {
		if !strings.Contains(got, want) {
			t.Errorf("Sensor %s fehlt: %s", want, got)
		}
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/sensoren", nil); strings.Contains(r.raw, id) {
		t.Error("Fertigung sieht fremde NetApp-Sensoren")
	}

	// Konto bekommt Schreibrecht: Abfrage scheitert mit klarer Meldung, nichts wird gelesen.
	f.Writable("/api", "all")
	f.ResetCalls()
	poll()
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "Schreibrecht") {
		t.Errorf("Fehler: %v", lastErr)
	}
	for _, c := range f.Calls() {
		if !strings.Contains(c, "/api/security/") {
			t.Errorf("trotz Schreibrecht gelesen: %s", c)
		}
	}
	// Anderer Port ohne neues Geheimnis: Die Datenbank verwirft es.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET port = port + 1 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	var hasSecret bool
	owner.QueryRow(ctx, `SELECT has_secret FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&hasSecret)
	if hasSecret {
		t.Error("Passwort nach Portwechsel behalten")
	}
}
