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
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
	"github.com/garrulus-it/openwacht/internal/tr064/tr064test"
)

func fritzBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "benutzer": tr064test.User, "passwort": tr064test.Password}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func allowLoopbackFritz(t *testing.T) {
	t.Helper()
	old, oldTR := vServer.guard, vServer.tr064.Guard
	g := checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	vServer.guard, vServer.tr064.Guard = g, g
	t.Cleanup(func() { vServer.guard, vServer.tr064.Guard = old, oldTR })
}

func TestFritzBoxMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "FB Box", "router.example.org")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/fritzbox"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, fritzBody("router.example.org", nil)), 404)
	r = as(t, "v_fw").do("PUT", path, fritzBody("router.example.org", nil))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht FRITZ!Box: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["version"] != "tr064" || e["port"] != 49000.0 || e["hat_community"] != true {
		t.Errorf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	if strings.Contains(list.raw, tr064test.Password) {
		t.Error("Passwort in der Liste")
	}

	// Ändern ohne Zugangsdaten: bleiben. Neues Ziel ohne: abgelehnt.
	expectStatus(t, "Intervall", as(t, "v_it").do("PUT", path, map[string]any{"adresse": "router.example.org", "intervall_sekunden": 120}), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["hat_community"] != true || e["intervall_sekunden"] != 120.0 {
		t.Errorf("nach Ändern: %+v", e)
	}
	for name, b := range map[string]map[string]any{
		"Adresse":            {"adresse": "anders.box"},
		"Port":               {"adresse": "router.example.org", "port": 49001},
		"HTTPS ohne Abdruck": {"adresse": "router.example.org", "port": 49000, "https": true},
		"HTTPS mit Abdruck":  {"adresse": "router.example.org", "port": 49000, "https": true, "fingerabdruck": strings.Repeat("ab", 32)},
		"nur Benutzer":       {"adresse": "router.example.org", "benutzer": "x"},
		"nur Passwort":       {"adresse": "router.example.org", "passwort": "x"},
	} {
		expectStatus(t, name, as(t, "v_it").do("PUT", path, b), 400)
	}

	// Keine Vermischung mit SNMP und Proxmox.
	expectStatus(t, "SNMP auf FRITZ!Box", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("router.example.org", nil)), 409)
	expectStatus(t, "Proxmox auf FRITZ!Box", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/proxmox", pveBody("router.example.org", nil)), 409)
	sw := newDevice(t, "v_fw", "Fertigung", "FB Switch", "")
	swPath := "/api/v1/geraete/" + sw.body["id"].(string)
	expectStatus(t, "SNMP anlegen", as(t, "v_fw").do("PUT", swPath+"/snmp", snmpBody("sw.lan", nil)), 201)
	expectStatus(t, "FRITZ!Box auf SNMP-Gerät", as(t, "v_fw").do("PUT", swPath+"/fritzbox", fritzBody("sw.lan", nil)), 409)
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", swPath+"/snmp", nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", swPath, nil), 204)
	// Auch der Trigger verwirft Zugangsdaten beim Wechsel der Art.
	var kept bool
	owner.QueryRow(ctx, `WITH u AS (UPDATE openwacht.snmp_sources SET version = '2c' WHERE id = $1 RETURNING secret_enc IS NOT NULL)
		SELECT * FROM u`, id).Scan(&kept)
	if kept {
		t.Error("Wechsel von tr064 auf 2c behält das Geheimnis")
	}
	owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id)
	r = as(t, "v_fw").do("PUT", path, fritzBody("router.example.org", nil))
	expectStatus(t, "neu anlegen", r, 201)
	id = r.body["id"].(string)

	// Leser und Operatoren richten nicht ein; Eltern beim Kind ja.
	lz := newDevice(t, "v_fw", "Lager Nord", "FB LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/fritzbox"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, fritzBody("lz.box", nil)), 403)
	_, _, op := wartungZiele(t, "FB")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, fritzBody("lz.box", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, fritzBody("lz.box", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"adresse": "lz.box", "aktiv": false}), 403)
	expectStatus(t, "Operator mit Zugang", opc.do("PUT", lzPath, fritzBody("lz.box", nil)), 403)
	expectStatus(t, "Kind sieht Eltern nicht", as(t, "v_lz").do("GET", "/api/v1/snmp/"+id+"/verlauf", nil), 404)

	// Prüfen: nur Admins, nur freigegebene Netze.
	resetProbeLimit()
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", lzPath+"/pruefen", fritzBody("lz.box", nil)), 403)
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", path+"/pruefen", fritzBody("router.example.org", nil)), 404)
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", path+"/pruefen", fritzBody("127.0.0.1", nil)), 400)
	resetProbeLimit()

	expectStatus(t, "Geschwister entfernt", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)

	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'fritzbox.%' AND details::text LIKE '%'||$1||'%'`,
		tr064test.Password).Scan(&n)
	if n != 0 {
		t.Errorf("Passwort im Audit-Log: %d", n)
	}
	for _, action := range []string{"fritzbox.angelegt", "fritzbox.geaendert", "fritzbox.geloescht"} {
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = $1 AND details->>'geraet' = $2`, action, dev).Scan(&n)
		if n < 1 {
			t.Errorf("Audit %s fehlt", action)
		}
	}
}

func TestFritzBoxEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "FE Box", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/fritzbox"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	for name, b := range map[string]map[string]any{
		"ohne Adresse":       fritzBody("", nil),
		"IP nicht frei":      fritzBody("192.168.178.1", nil),
		"Port":               fritzBody("router.example.org", map[string]any{"port": 70000}),
		"Intervall":          fritzBody("router.example.org", map[string]any{"intervall_sekunden": 5}),
		"Benutzer":           fritzBody("router.example.org", map[string]any{"benutzer": "a b"}),
		"Steuerzeichen":      fritzBody("router.example.org", map[string]any{"passwort": "a\nb"}),
		"ohne Zugang":        {"adresse": "router.example.org"},
		"Abdruck ohne TLS":   fritzBody("router.example.org", map[string]any{"fingerabdruck": strings.Repeat("ab", 32)}),
		"Abdruck kaputt":     fritzBody("router.example.org", map[string]any{"https": true, "fingerabdruck": "zz"}),
		"HTTPS ohne Abdruck": fritzBody("router.example.org", map[string]any{"https": true}),
		"fremdes Feld":       fritzBody("router.example.org", map[string]any{"community": "public"}),
	} {
		if r := as(t, "v_fw").do("PUT", path, b); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	r = as(t, "v_fw").do("PUT", path, fritzBody("router.example.org", map[string]any{"https": true,
		"fingerabdruck": tr064.FormatPin(strings.Repeat("ab", 32))}))
	expectStatus(t, "HTTPS mit Doppelpunkten", r, 201)
	if e, _ := snmpEntry(t, "v_fw", r.body["id"].(string)); e["port"] != 49443.0 {
		t.Errorf("HTTPS-Port: %+v", e)
	}
	// Ändern ohne Zugang mit HTTPS ohne Abdruck: der gespeicherte gilt.
	expectStatus(t, "Abdruck bleibt", as(t, "v_fw").do("PUT", path, map[string]any{"adresse": "router.example.org", "https": true, "intervall_sekunden": 300}), 200)
	// Wechsel auf HTTP ohne Passwort: abgelehnt (Port anders).
	expectStatus(t, "HTTP ohne Zugang", as(t, "v_fw").do("PUT", path, map[string]any{"adresse": "router.example.org", "https": false, "port": 49443}), 400)
}

func TestFritzBoxPruefen(t *testing.T) {
	verwaltungSetup(t)
	allowLoopbackFritz(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	f := tr064test.NewFake()
	box := tr064test.StartTLS(t, f)
	r := newDevice(t, "v_fw", "Fertigung", "FP Box", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/fritzbox"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })

	// HTTPS ohne Abdruck: nur der Abdruck, ohne Anmeldung.
	r = as(t, "v_fw").do("POST", path+"/pruefen", fritzBody("127.0.0.1", map[string]any{"port": box.Port, "https": true}))
	if r.status != 200 || r.body["ok"] != false || r.body["fingerabdruck_neu"] != tr064.FormatPin(box.Pin) {
		t.Fatalf("Abdruck: %s", r.raw)
	}
	if f.Unauth != 0 || len(f.AllCalls()) != 0 {
		t.Error("beim Abdruck angemeldet")
	}
	// Mit Abdruck: vollständig.
	resetProbeLimit()
	body := fritzBody("127.0.0.1", map[string]any{"port": box.Port, "https": true, "fingerabdruck": r.body["fingerabdruck_neu"]})
	r = as(t, "v_fw").do("POST", path+"/pruefen", body)
	info, _ := r.body["fritzbox"].(map[string]any)
	if r.body["ok"] != true || info["modell"] != "FRITZ!Box 7590" || info["verbunden"] != true {
		t.Fatalf("prüfen: %s", r.raw)
	}
	expectStatus(t, "anlegen", as(t, "v_fw").do("PUT", path, body), 201)
	// Gespeichertes ohne Zugang und Abdruck.
	resetProbeLimit()
	r = as(t, "v_fw").do("POST", path+"/pruefen", map[string]any{"adresse": "127.0.0.1", "port": box.Port, "https": true})
	if r.body["ok"] != true {
		t.Fatalf("gespeichert: %s", r.raw)
	}
	// Anderer Abdruck ohne Zugang: Das Gespeicherte gilt nicht.
	resetProbeLimit()
	expectStatus(t, "anderer Abdruck", as(t, "v_fw").do("POST", path+"/pruefen",
		map[string]any{"adresse": "127.0.0.1", "port": box.Port, "https": true, "fingerabdruck": strings.Repeat("cd", 32)}), 400)
	// Anderer Abdruck mit Zugang: abgelehnt, bevor die Box angefragt wird.
	resetProbeLimit()
	before := len(f.AllCalls()) + f.Unauth
	r = as(t, "v_fw").do("POST", path+"/pruefen", fritzBody("127.0.0.1", map[string]any{"port": box.Port, "https": true,
		"fingerabdruck": strings.Repeat("cd", 32)}))
	if r.body["ok"] != false || r.body["fingerabdruck_neu"] != tr064.FormatPin(box.Pin) || len(f.AllCalls())+f.Unauth != before {
		t.Fatalf("fremder Abdruck: %s", r.raw)
	}
	// Falsches Passwort: verständliche Meldung.
	resetProbeLimit()
	r = as(t, "v_fw").do("POST", path+"/pruefen", fritzBody("127.0.0.1", map[string]any{"port": box.Port, "https": true,
		"fingerabdruck": box.Pin, "passwort": "falsch"}))
	if r.body["ok"] != false || !strings.Contains(r.raw, "Benutzer und Passwort") {
		t.Fatalf("falsches Passwort: %s", r.raw)
	}
}

func TestFritzBoxPlanerUndAlarme(t *testing.T) {
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

	f := tr064test.NewFake()
	box := tr064test.Start(t, f)
	var tenant, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'FB A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'fritz') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'fb')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	enc, _ := s.sealFritz(id, tenant, "127.0.0.1", int(box.Port), fritzSecret{User: tr064test.User, Password: tr064test.Password})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc)
		VALUES ($1, $2, 'tr064', '127.0.0.1', $3, $4)`, id, dev, box.Port, enc); err != nil {
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
	snapshot := func() (snmp.Snapshot, *string) {
		var lastErr *string
		var raw []byte
		owner.QueryRow(ctx, `SELECT last_error, snapshot FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr, &raw)
		var snap snmp.Snapshot
		json.Unmarshal(raw, &snap)
		return snap, lastErr
	}
	poll()
	snap, lastErr := snapshot()
	if lastErr != nil || snap.FritzBox == nil || snap.FritzBox.Model != "FRITZ!Box 7590" {
		t.Fatalf("Abfrage: %v %+v", lastErr, snap)
	}
	// Zweite Abfrage: Rate für den Verkehr und Verlauf.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET snapshot = jsonb_set(jsonb_set(snapshot, '{zaehler,zeit}', to_jsonb(now() - interval '60 seconds')),
		'{erfasst}', to_jsonb(now() - interval '60 seconds')) WHERE id = $1`, id)
	f.Set("WANCommonInterfaceConfig#GetAddonInfos", "NewX_AVM_DE_TotalBytesReceived64", "90075000000")
	f.Set("WANPPPConnection#GetStatusInfo", "NewUptime", "3660")
	poll()
	var series []string
	rows, _ := owner.Query(ctx, `SELECT DISTINCT series FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1 ORDER BY series`, id)
	series, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(series, ",") != "dsl_ab,dsl_auf,if_aus:WAN,if_ein:WAN" {
		t.Errorf("Verlauf: %v", series)
	}
	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	if msgs := nt.take()["fb"]; len(msgs) != 0 {
		t.Errorf("Alarm ohne Grund: %+v", msgs)
	}

	// Getrennt und neu gestartet.
	f.Set("WANPPPConnection#GetStatusInfo", "NewConnectionStatus", "Disconnected")
	f.Set("WANPPPConnection#GetStatusInfo", "NewLastConnectionError", "ERROR_NO_CARRIER")
	f.Set("DeviceInfo#GetInfo", "NewUpTime", "100")
	poll()
	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := nt.take()["fb"]
	if len(msgs) != 1 || !strings.Contains(msgs[0].Message, "fritz · Internet") || !strings.Contains(msgs[0].Message, "ERROR_NO_CARRIER") ||
		!strings.Contains(msgs[0].Message, "fritz · Neustart") {
		t.Fatalf("Alarm: %+v", msgs)
	}
	var open []string
	rows, _ = owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "neustart,wan" {
		t.Errorf("Alarmprotokoll: %v", open)
	}

	// Falsches Passwort gespeichert: Fehler steht an der Quelle, kein Absturz.
	enc, _ = s.sealFritz(id, tenant, "127.0.0.1", int(box.Port), fritzSecret{User: tr064test.User, Password: "falsch"})
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc)
	poll()
	if _, lastErr := snapshot(); lastErr == nil || !strings.Contains(*lastErr, "Benutzer und Passwort") {
		t.Errorf("falsches Passwort: %v", lastErr)
	}
	// An andere Adresse gebunden: nicht entschlüsselbar.
	enc, _ = s.sealFritz(id, tenant, "127.0.0.2", int(box.Port), fritzSecret{User: tr064test.User, Password: tr064test.Password})
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET secret_enc = $2 WHERE id = $1`, id, enc)
	poll()
	if _, lastErr := snapshot(); lastErr == nil || !strings.Contains(*lastErr, "entschlüsselbar") {
		t.Errorf("fremde Bindung: %v", lastErr)
	}
}
