// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/pve/pvetest"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/vcenter/vcentertest"
)

const vcPass = "lese-pass-123" // Testwert der Attrappe

func vcBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "benutzer": "svc-openwacht@vsphere.local", "passwort": vcPass}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func vcPort(t *testing.T, f *vcentertest.Fake) int {
	t.Helper()
	u, _ := url.Parse(f.Server.URL)
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVCenterMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	ca := vcentertest.Start(t).CAPEM
	r := newDevice(t, "v_fw", "Fertigung", "VC vc-1", "vc-1.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/vcenter"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, vcBody("vc-1.lan", nil)), 404)
	r = as(t, "v_fw").do("PUT", path, vcBody("vc-1.lan", map[string]any{"ca": ca}))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht vCenter: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["version"] != "vcenter" || e["port"] != 443.0 || e["hat_community"] != true || e["ca"] == nil {
		t.Errorf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	if strings.Contains(list.raw, vcPass) || strings.Contains(list.raw, "BEGIN CERTIFICATE") {
		t.Error("Passwort oder CA-Text in der Liste")
	}

	// Ändern ohne Passwort: bleibt, aber nur bei gleichem Ziel und Benutzer.
	keep := map[string]any{"adresse": "vc-1.lan", "benutzer": "svc-openwacht@vsphere.local", "intervall_sekunden": 120}
	expectStatus(t, "IT ändert Intervall", as(t, "v_it").do("PUT", path, keep), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["hat_community"] != true || e["intervall_sekunden"] != 120.0 || e["ca"] == nil {
		t.Errorf("nach Ändern: %+v", e)
	}
	for name, b := range map[string]map[string]any{
		"Adresse":   {"adresse": "anders.lan", "benutzer": "svc-openwacht@vsphere.local"},
		"Port":      {"adresse": "vc-1.lan", "port": 8443, "benutzer": "svc-openwacht@vsphere.local"},
		"Benutzer":  {"adresse": "vc-1.lan", "benutzer": "administrator@vsphere.local"},
		"CA weg":    {"adresse": "vc-1.lan", "benutzer": "svc-openwacht@vsphere.local", "ca": ""},
		"andere CA": {"adresse": "vc-1.lan", "benutzer": "svc-openwacht@vsphere.local", "ca": pvetest.Start(t, pvetest.NewFake()).CAPEM},
	} {
		expectStatus(t, name+" ohne Passwort", as(t, "v_it").do("PUT", path, b), 400)
	}

	// Keine Vermischung mit SNMP oder Proxmox.
	expectStatus(t, "SNMP auf vCenter-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("vc-1.lan", nil)), 409)
	expectStatus(t, "Proxmox auf vCenter-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/proxmox", pveBody("vc-1.lan", nil)), 409)
	sw := newDevice(t, "v_fw", "Fertigung", "VC Switch", "")
	swPath := "/api/v1/geraete/" + sw.body["id"].(string)
	expectStatus(t, "SNMP anlegen", as(t, "v_fw").do("PUT", swPath+"/snmp", snmpBody("sw.lan", nil)), 201)
	expectStatus(t, "vCenter auf SNMP-Gerät", as(t, "v_fw").do("PUT", swPath+"/vcenter", vcBody("sw.lan", nil)), 409)
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", swPath+"/snmp", nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", swPath, nil), 204)

	// Leser und Operatoren dürfen nicht einrichten.
	lz := newDevice(t, "v_fw", "Lager Nord", "VC LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/vcenter"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, vcBody("lz.lan", nil)), 403)
	_, _, op := wartungZiele(t, "VC")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, vcBody("lz.lan", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, vcBody("lz.lan", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzID := r.body["id"].(string)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"adresse": "lz.lan",
		"benutzer": "svc-openwacht@vsphere.local", "aktiv": false}), 403)
	expectStatus(t, "Operator jetzt", opc.do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 202)
	expectStatus(t, "Geschwister jetzt", as(t, "v_oa").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", lzPath, nil), 403)

	// Verbindung prüfen: nur Admins, nur freigegebene Netze.
	probe := path + "/pruefen"
	resetProbeLimit()
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", lzPath+"/pruefen", vcBody("lz.lan", nil)), 403)
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", probe, vcBody("vc-1.lan", nil)), 404)
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", probe, vcBody("127.0.0.1", nil)), 400)
	resetProbeLimit()

	// Löschen
	expectStatus(t, "Geschwister entfernt", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "vCenter entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)

	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'vcenter.%' AND details::text LIKE '%'||$1||'%'`,
		vcPass).Scan(&n)
	if n != 0 {
		t.Errorf("Passwort im Audit-Log: %d", n)
	}
	for _, action := range []string{"vcenter.angelegt", "vcenter.geaendert", "vcenter.geloescht"} {
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = $1 AND details->>'geraet' = $2`, action, dev).Scan(&n)
		if n < 1 {
			t.Errorf("Audit %s fehlt", action)
		}
	}
}

func TestVCenterEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "VE vc", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/vcenter"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	u := "svc-openwacht@vsphere.local"
	bad := map[string]map[string]any{
		"ohne Adresse":         {"adresse": "", "benutzer": u, "passwort": vcPass},
		"Adresse mit URL":      {"adresse": "https://vc.lan", "benutzer": u, "passwort": vcPass},
		"Port":                 {"adresse": "vc.lan", "port": 0x10000, "benutzer": u, "passwort": vcPass},
		"Intervall":            {"adresse": "vc.lan", "intervall_sekunden": 5, "benutzer": u, "passwort": vcPass},
		"ohne Passwort":        {"adresse": "vc.lan", "benutzer": u},
		"ohne Benutzer":        {"adresse": "vc.lan", "passwort": vcPass},
		"Benutzer Umbruch":     {"adresse": "vc.lan", "benutzer": u + "\nX", "passwort": vcPass},
		"Benutzer Doppelpunkt": {"adresse": "vc.lan", "benutzer": "a:b", "passwort": vcPass},
		"Passwort Umbruch":     {"adresse": "vc.lan", "benutzer": u, "passwort": "a\nb"},
		"Passwort zu lang":     {"adresse": "vc.lan", "benutzer": u, "passwort": strings.Repeat("x", 300)},
		"Schlüssel":            {"adresse": "vc.lan", "benutzer": u, "passwort": vcPass, "ca": "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----"},
		"IP nicht frei":        {"adresse": "10.1.2.3", "benutzer": u, "passwort": vcPass},
	}
	for name, b := range bad {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, b), 400)
	}
	expectStatus(t, "gültig", as(t, "v_fw").do("PUT", path, vcBody("vc.lan", nil)), 201)
}

func TestVCenterPruefen(t *testing.T) {
	verwaltungSetup(t)
	allowLoopback(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	f := vcentertest.Start(t)
	port := vcPort(t, f)
	r := newDevice(t, "v_fw", "Fertigung", "VP vc", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/vcenter"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	body := vcBody("127.0.0.1", map[string]any{"port": port, "ca": f.CAPEM})

	r = as(t, "v_fw").do("POST", path+"/pruefen", body)
	expectStatus(t, "prüfen", r, 200)
	info, _ := r.body["vcenter"].(map[string]any)
	if r.body["ok"] != true || info["hosts"] != 2.0 || info["vms"] != 2.0 || info["datastores"] != 2.0 {
		t.Fatalf("%s", r.raw)
	}
	if f.Sessions != 0 {
		t.Errorf("Sitzung nicht abgemeldet: %d", f.Sessions)
	}
	expectStatus(t, "anlegen", as(t, "v_fw").do("PUT", path, body), 201)

	// Gespeichertes Passwort und gespeicherte CA, wenn beides fehlt.
	resetProbeLimit()
	r = as(t, "v_fw").do("POST", path+"/pruefen", map[string]any{"adresse": "127.0.0.1", "port": port,
		"benutzer": "svc-openwacht@vsphere.local"})
	if r.status != 200 || r.body["ok"] != true {
		t.Fatalf("gespeichert: %s", r.raw)
	}
	// Anderer Benutzer ohne Passwort: Das gespeicherte gilt nicht.
	resetProbeLimit()
	expectStatus(t, "anderer Benutzer", as(t, "v_fw").do("POST", path+"/pruefen", map[string]any{"adresse": "127.0.0.1",
		"port": port, "benutzer": "administrator@vsphere.local"}), 400)
	// Andere CA ohne Passwort: abgelehnt.
	resetProbeLimit()
	other := pvetest.Start(t, pvetest.NewFake()).CAPEM // anderes Zertifikat (httptest nutzt immer dasselbe)
	expectStatus(t, "andere CA", as(t, "v_fw").do("POST", path+"/pruefen", map[string]any{"adresse": "127.0.0.1",
		"port": port, "benutzer": "svc-openwacht@vsphere.local", "ca": other}), 400)
	// Andere CA mit Passwort: Zertifikat passt nicht, das Passwort geht nicht raus.
	resetProbeLimit()
	f.Methods = nil
	r = as(t, "v_fw").do("POST", path+"/pruefen", vcBody("127.0.0.1", map[string]any{"port": port, "ca": other}))
	if r.body["ok"] != false || len(f.Methods) != 0 {
		t.Fatalf("fremde CA: %s %v", r.raw, f.Methods)
	}
	// Falsches Passwort: verständlicher Fehler.
	resetProbeLimit()
	r = as(t, "v_fw").do("POST", path+"/pruefen", vcBody("127.0.0.1", map[string]any{"port": port, "ca": f.CAPEM, "passwort": "falsch"}))
	if r.body["ok"] != false || strings.Contains(r.raw, "falsch") {
		t.Fatalf("falsches Passwort: %s", r.raw)
	}
}

func TestVCenterPlanerUndAlarme(t *testing.T) {
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

	f := vcentertest.Start(t)
	f.Set("datastores", []map[string]any{{"datastore": "datastore-15", "name": "ds-ssd", "type": "VMFS", "capacity": 1000, "free_space": 20},
		{"datastore": "datastore-16", "name": "ds-nfs", "type": "NFS", "capacity": 1000, "free_space": 600}})
	port := vcPort(t, f)

	var tenant, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'VC A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'vc-1') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'va')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	caPEM := strings.TrimSpace(f.CAPEM) + "\n"
	enc, _ := s.sealVC(id, tenant, "127.0.0.1", port, caPEM, vcSecret{User: f.User, Password: f.Password})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc, ca_pem)
		VALUES ($1, $2, 'vcenter', '127.0.0.1', $3, $4, $5)`, id, dev, port, enc, caPEM); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tenant)
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
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Proxmox == nil || len(snap.Proxmox.Guests) != 4 ||
		snap.Proxmox.Version != "vCenter" {
		t.Fatalf("Snapshot: %v %s", err, raw)
	}
	if f.Sessions != 0 {
		t.Errorf("Sitzung offen: %d", f.Sessions)
	}
	for _, m := range f.Methods {
		if !strings.HasPrefix(m, "GET ") && m != "POST /api/session" && m != "DELETE /api/session" {
			t.Errorf("unerwarteter Aufruf: %s", m)
		}
	}

	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := nt.take()["va"]
	if len(msgs) != 1 {
		t.Fatalf("Alarm: %+v", msgs)
	}
	for _, want := range []string{"ESXi-Host esx02", "antwortet dem vCenter nicht", "Speicher ds-ssd"} {
		if !strings.Contains(msgs[0].Message, want) {
			t.Errorf("Alarm ohne %q: %s", want, msgs[0].Message)
		}
	}
	for _, not := range []string{"esx01", "dc01", "ds-nfs"} {
		if strings.Contains(msgs[0].Message, not) {
			t.Errorf("gesundes %s gemeldet: %s", not, msgs[0].Message)
		}
	}
	var open []string
	rows, _ := owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "gast:900000013,platte:ds-ssd" {
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
	// VMs nur in der Übersicht, nicht als Sensor: Ob eine VM laufen soll, weiß vCenter nicht.
	if strings.Contains(got, "VM ") {
		t.Errorf("VM als Sensor: %s", got)
	}
	for _, want := range []string{"vCenter=ok", "ESXi-Host esx01=ok", "ESXi-Host esx02=crit", "Speicher ds-ssd=crit"} {
		if !strings.Contains(got, want) {
			t.Errorf("Sensor %s fehlt: %s", want, got)
		}
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/sensoren", nil); strings.Contains(r.raw, id) {
		t.Error("Fertigung sieht fremde vCenter-Sensoren")
	}

	// Passwort geändert: Abfrage scheitert verständlich, das Passwort steht nicht im Fehler.
	enc2, _ := s.sealVC(id, tenant, "127.0.0.1", port, caPEM, vcSecret{User: f.User, Password: "veraltet-999"})
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc2)
	poll()
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || strings.Contains(*lastErr, "veraltet-999") {
		t.Errorf("Fehler: %v", lastErr)
	}
	// Anderer Port ohne neues Geheimnis: Die Datenbank verwirft es.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET port = port + 1 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	var hasSecret bool
	owner.QueryRow(ctx, `SELECT has_secret FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&hasSecret)
	if hasSecret {
		t.Error("Passwort nach Portwechsel behalten")
	}
}
