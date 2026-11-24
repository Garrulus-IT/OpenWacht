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
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve/pvetest"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const tokenSecret = "0b8f1c2e-1111-4222-8333-944455556666"

func pveBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "token": pvetest.Token}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// allowLoopback gibt 127.0.0.1 für den gemeinsamen Testserver frei, solange der
// Test läuft (für „Verbindung prüfen“ gegen die Attrappe).
func allowLoopback(t *testing.T) {
	t.Helper()
	old, oldPVE := vServer.guard, vServer.pve.Guard
	g := checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	vServer.guard, vServer.pve.Guard = g, g
	t.Cleanup(func() { vServer.guard, vServer.pve.Guard = old, oldPVE })
}

// resetProbeLimit: Die Wartezeit für „Verbindung prüfen“ (3 s je Person)
// testet TestSNMPMandantentrennung; hier stört sie nur.
func resetProbeLimit() {
	vServer.snmpProbeLimit.mu.Lock()
	vServer.snmpProbeLimit.last = nil
	vServer.snmpProbeLimit.mu.Unlock()
}

func TestProxmoxMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	ca := pvetest.Start(t, pvetest.NewFake()).CAPEM
	r := newDevice(t, "v_fw", "Fertigung", "PX pve-1", "pve-1.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/proxmox"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, pveBody("pve-1.lan", nil)), 404)
	r = as(t, "v_fw").do("PUT", path, pveBody("pve-1.lan", map[string]any{"ca": ca}))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht Proxmox: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	caOut, _ := e["ca"].(map[string]any)
	if e["version"] != "pve" || e["port"] != 8006.0 || e["hat_community"] != true || caOut == nil ||
		len(caOut["fingerabdruck"].(string)) != 95 {
		t.Errorf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	if strings.Contains(list.raw, tokenSecret) || strings.Contains(list.raw, "BEGIN CERTIFICATE") {
		t.Error("Token oder CA-Text in der Liste")
	}

	// Ändern ohne Token und ohne CA-Feld: Token und CA bleiben.
	expectStatus(t, "IT ändert Intervall", as(t, "v_it").do("PUT", path, map[string]any{"adresse": "pve-1.lan", "intervall_sekunden": 120}), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["hat_community"] != true || e["intervall_sekunden"] != 120.0 || e["ca"] == nil {
		t.Errorf("nach Ändern: %+v", e)
	}
	// Neues Ziel oder neue CA ohne Token: abgelehnt.
	for name, b := range map[string]map[string]any{
		"Adresse":   {"adresse": "anders.lan"},
		"Port":      {"adresse": "pve-1.lan", "port": 8007},
		"CA weg":    {"adresse": "pve-1.lan", "ca": ""},
		"andere CA": {"adresse": "pve-1.lan", "ca": pvetest.Start(t, pvetest.NewFake()).CAPEM},
	} {
		expectStatus(t, name+" ohne Token", as(t, "v_it").do("PUT", path, b), 400)
	}

	// Keine Vermischung mit SNMP.
	expectStatus(t, "SNMP auf Proxmox-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("pve-1.lan", nil)), 409)
	sw := newDevice(t, "v_fw", "Fertigung", "PX Switch", "")
	swPath := "/api/v1/geraete/" + sw.body["id"].(string)
	expectStatus(t, "SNMP anlegen", as(t, "v_fw").do("PUT", swPath+"/snmp", snmpBody("sw.lan", nil)), 201)
	expectStatus(t, "Proxmox auf SNMP-Gerät", as(t, "v_fw").do("PUT", swPath+"/proxmox", pveBody("sw.lan", nil)), 409)
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", swPath+"/snmp", nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", swPath, nil), 204)

	// Leser und Operatoren dürfen nicht einrichten, Operatoren „jetzt abfragen“.
	lz := newDevice(t, "v_fw", "Lager Nord", "PX LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/proxmox"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, pveBody("lz.lan", nil)), 403)
	_, _, op := wartungZiele(t, "PX")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, pveBody("lz.lan", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, pveBody("lz.lan", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzID := r.body["id"].(string)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"adresse": "lz.lan", "aktiv": false}), 403)
	expectStatus(t, "Operator jetzt", opc.do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 202)
	expectStatus(t, "Geschwister jetzt", as(t, "v_oa").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", lzPath, nil), 403)
	expectStatus(t, "Kind sieht Eltern nicht", as(t, "v_lz").do("GET", "/api/v1/snmp/"+id+"/verlauf", nil), 404)

	// Verbindung prüfen: nur Admins, nur freigegebene Netze.
	probe := path + "/pruefen"
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", lzPath+"/pruefen", pveBody("lz.lan", nil)), 403)
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", probe, pveBody("pve-1.lan", nil)), 404)
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", probe, pveBody("127.0.0.1", nil)), 400)
	resetProbeLimit()

	// Löschen
	expectStatus(t, "Geschwister entfernt", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "Proxmox entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)

	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'proxmox.%' AND details::text LIKE '%'||$1||'%'`,
		tokenSecret).Scan(&n)
	if n != 0 {
		t.Errorf("Token-Geheimnis im Audit-Log: %d", n)
	}
	for _, action := range []string{"proxmox.angelegt", "proxmox.geaendert", "proxmox.geloescht"} {
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = $1 AND details->>'geraet' = $2`, action, dev).Scan(&n)
		if n < 1 {
			t.Errorf("Audit %s fehlt", action)
		}
	}
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'proxmox.angelegt' AND details->>'token_id' = 'openwacht@pve!monitor'`).Scan(&n)
	if n < 1 {
		t.Error("Token-ID fehlt im Audit-Log")
	}
}

func TestProxmoxEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "PE pve", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/proxmox"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	leaf := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	bad := map[string]map[string]any{
		"ohne Adresse":    {"adresse": "", "token": pvetest.Token},
		"Adresse mit URL": {"adresse": "https://pve.lan:8006", "token": pvetest.Token},
		"Port":            {"adresse": "pve.lan", "port": 0x10000, "token": pvetest.Token},
		"Intervall":       {"adresse": "pve.lan", "intervall_sekunden": 5, "token": pvetest.Token},
		"ohne Token":      {"adresse": "pve.lan"},
		"Token ohne ID":   {"adresse": "pve.lan", "token": tokenSecret},
		"Token Umbruch":   {"adresse": "pve.lan", "token": pvetest.Token + "\nX: y"},
		"CA kaputt":       {"adresse": "pve.lan", "token": pvetest.Token, "ca": leaf},
		"Schlüssel":       {"adresse": "pve.lan", "token": pvetest.Token, "ca": "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----"},
		"IP nicht frei":   {"adresse": "10.1.2.3", "token": pvetest.Token},
	}
	for name, b := range bad {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, b), 400)
	}
	// „PVEAPIToken=“ davor (aus einer curl-Zeile kopiert) wird angenommen.
	expectStatus(t, "mit Präfix", as(t, "v_fw").do("PUT", path, pveBody("pve.lan", map[string]any{"token": "PVEAPIToken=" + pvetest.Token})), 201)
}

func TestProxmoxPruefen(t *testing.T) {
	verwaltungSetup(t)
	allowLoopback(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	f := pvetest.NewFake()
	px := pvetest.Start(t, f)
	r := newDevice(t, "v_fw", "Fertigung", "PP pve", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/proxmox"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	body := pveBody("127.0.0.1", map[string]any{"port": px.Port, "ca": px.CAPEM})

	r = as(t, "v_fw").do("POST", path+"/pruefen", body)
	expectStatus(t, "prüfen", r, 200)
	info, _ := r.body["proxmox"].(map[string]any)
	if r.body["ok"] != true || info["knoten"] != "pve-1" || info["version"] != "9.2.2" {
		t.Fatalf("%s", r.raw)
	}
	expectStatus(t, "anlegen", as(t, "v_fw").do("PUT", path, body), 201)

	// Gespeichertes Token und gespeicherte CA, wenn beides fehlt.
	resetProbeLimit()
	r = as(t, "v_fw").do("POST", path+"/pruefen", map[string]any{"adresse": "127.0.0.1", "port": px.Port})
	if r.status != 200 || r.body["ok"] != true {
		t.Fatalf("gespeichert: %s", r.raw)
	}
	// Andere CA ohne Token: Das gespeicherte Token gilt nicht.
	resetProbeLimit()
	other := pvetest.Start(t, pvetest.NewFake()).CAPEM
	expectStatus(t, "andere CA", as(t, "v_fw").do("POST", path+"/pruefen",
		map[string]any{"adresse": "127.0.0.1", "port": px.Port, "ca": other}), 400)
	// Andere CA mit Token: Zertifikat passt nicht, das Token geht nicht raus.
	resetProbeLimit()
	before := f.Count("/")
	r = as(t, "v_fw").do("POST", path+"/pruefen", pveBody("127.0.0.1", map[string]any{"port": px.Port, "ca": other}))
	if r.body["ok"] != false || !strings.Contains(r.raw, "CA") || f.Count("/") != before {
		t.Fatalf("fremde CA: %s", r.raw)
	}
	// Zu viele Rechte werden gemeldet.
	resetProbeLimit()
	f.Mu.Lock()
	f.Privs["/"]["Sys.Modify"] = 1
	f.Mu.Unlock()
	r = as(t, "v_fw").do("POST", path+"/pruefen", body)
	if !strings.Contains(r.raw, "Sys.Modify") {
		t.Fatalf("Rechte: %s", r.raw)
	}
}

func TestProxmoxPlanerUndAlarme(t *testing.T) {
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

	f := pvetest.NewFake()
	now := time.Now()
	f.AddTask("UPID:pve-1:0001:01:A:vzdump::root@pam:", "", "job errors", now.Add(-5*time.Hour).Unix(),
		"INFO: Finished Backup of VM 100 (00:00:12)",
		"ERROR: Backup of VM 101 failed - Permission denied")
	px := pvetest.Start(t, f)

	var tenant, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'PVE A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'pve-1') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'pa')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	caPEM := strings.TrimSpace(px.CAPEM) + "\n"
	enc, _ := s.sealPVE(id, tenant, "127.0.0.1", px.Port, caPEM, pvetest.Token)
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc, ca_pem)
		VALUES ($1, $2, 'pve', '127.0.0.1', $3, $4, $5)`, id, dev, px.Port, enc, caPEM); err != nil {
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
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Proxmox == nil || len(snap.Proxmox.Guests) != 3 {
		t.Fatalf("Snapshot: %v %s", err, raw)
	}
	var series []string
	rows, _ := owner.Query(ctx, `SELECT series FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1 ORDER BY series`, id)
	series, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(series, ",") != "meta:pve/data,platte:local,platte:local-lvm" {
		t.Errorf("Verlauf: %v", series)
	}

	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := nt.take()["pa"]
	if len(msgs) != 1 {
		t.Fatalf("Alarm: %+v", msgs)
	}
	for _, want := range []string{"CT 101 (openwacht)", "Backup CT 101", "Permission denied", "Speicher nas-backup", "Speicher local-lvm"} {
		if !strings.Contains(msgs[0].Message, want) {
			t.Errorf("Alarm ohne %q: %s", want, msgs[0].Message)
		}
	}
	if strings.Contains(msgs[0].Message, "srv-dms") {
		t.Errorf("laufender Gast mit frischem Backup gemeldet: %s", msgs[0].Message)
	}
	var open []string
	rows, _ = owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "backup:101,gast:101,platte:local-lvm,pvespeicher:nas-backup" {
		t.Errorf("Alarmprotokoll: %v", open)
	}

	// Sensoren: IT sieht sie mit Gastnamen, Fertigung nicht.
	r := as(t, "v_it").do("GET", "/api/v1/sensoren", nil)
	var seen []string
	for _, x := range r.body["sensoren"].([]any) {
		sn := x.(map[string]any)
		if sn["quelle_id"] == id {
			seen = append(seen, sn["name"].(string)+"="+sn["status"].(string))
		}
	}
	got := strings.Join(seen, ",")
	for _, want := range []string{"Proxmox=ok", "CT 101 (openwacht)=crit", "Backup VM 100 (srv-dms)=ok", "Speicher local-lvm=crit",
		"Thin-Pool pve/data Metadaten=ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("Sensor %s fehlt: %s", want, got)
		}
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/sensoren", nil); strings.Contains(r.raw, id) {
		t.Error("Fertigung sieht fremde Proxmox-Sensoren")
	}

	// Neustart des Knotens wird erkannt.
	f.Mu.Lock()
	f.Uptime = 30
	f.Mu.Unlock()
	poll()
	var rebooted *time.Time
	owner.QueryRow(ctx, `SELECT rebooted_at FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&rebooted)
	if rebooted == nil {
		t.Error("Neustart nicht erkannt")
	}

	// Token widerrufen: Abfrage scheitert mit verständlichem Fehler; „stumm“ mit Proxmox-Text.
	enc2, _ := s.sealPVE(id, tenant, "127.0.0.1", px.Port, caPEM, "openwacht@pve!monitor=00000000-0000-4000-8000-000000000000")
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc2)
	poll()
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "Token abgelehnt") {
		t.Errorf("Fehler: %v", lastErr)
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET changed_at = now() - interval '10 minutes' WHERE id = $1`, id)
	nt.take()
	s.alertRoundN(ctx)
	if m := nt.take()["pa"]; len(m) != 1 || !strings.Contains(m[0].Message, "Proxmox-API") {
		t.Errorf("stumm: %+v", m)
	}

	// Neue CA oder anderer Port ohne neues Token: Die Datenbank verwirft das Token.
	for _, sql := range []string{
		`UPDATE openwacht.snmp_sources SET ca_pem = NULL WHERE id = $1`,
		`UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`,
		`UPDATE openwacht.snmp_sources SET port = port + 1 WHERE id = $1`,
	} {
		var args []any
		args = append(args, id)
		if strings.Contains(sql, "$2") {
			args = append(args, enc)
		}
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var hasSecret bool
	owner.QueryRow(ctx, `SELECT has_secret FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&hasSecret)
	if hasSecret {
		t.Error("Token nach Portwechsel behalten")
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2, ca_pem = $3 WHERE id = $1`, id, enc, caPEM)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET ca_pem = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `SELECT has_secret FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&hasSecret)
	if hasSecret {
		t.Error("Token nach CA-Wechsel behalten")
	}
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = '2c' WHERE id = $1`, id); err == nil {
		owner.QueryRow(ctx, `SELECT has_secret FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&hasSecret)
		if hasSecret {
			t.Error("Token nach Wechsel zu SNMP behalten")
		}
	}
	// CA nur bei Proxmox und ohne privaten Schlüssel.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = '2c', ca_pem = $2 WHERE id = $1`, id, caPEM); err == nil {
		t.Error("CA bei SNMP angenommen")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = 'pve', ca_pem = $2 WHERE id = $1`, id,
		caPEM+"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"); err == nil {
		t.Error("Schlüssel in der CA angenommen")
	}
}
