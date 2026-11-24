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
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/xapi"
	"github.com/garrulus-it/openwacht/internal/xapi/xapitest"
)

const xsPin = "12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0"

func xsBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "benutzer": xapitest.User, "passwort": xapitest.Password, "fingerabdruck": xsPin}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestXenServerMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "XS pool-1", "xs-01.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/xenserver"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, xsBody("xs-01.lan", nil)), 404)
	expectStatus(t, "ohne Fingerabdruck", as(t, "v_fw").do("PUT", path, xsBody("xs-01.lan", map[string]any{"fingerabdruck": ""})), 400)
	r = as(t, "v_fw").do("PUT", path, xsBody("xs-01.lan", nil))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)

	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht XenServer: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["version"] != "xapi" || e["port"] != 443.0 || e["hat_community"] != true || e["intervall_sekunden"] != 120.0 {
		t.Errorf("Eintrag: %+v", e)
	}
	if list := as(t, "v_it").do("GET", "/api/v1/snmp", nil); strings.Contains(list.raw, xapitest.Password) {
		t.Error("Passwort in der Liste")
	}

	// Ändern ohne Passwort: bleibt, aber nur bei gleichem Ziel, Benutzer und Fingerabdruck.
	keep := map[string]any{"adresse": "xs-01.lan", "benutzer": xapitest.User, "intervall_sekunden": 300}
	expectStatus(t, "IT ändert Intervall", as(t, "v_it").do("PUT", path, keep), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["hat_community"] != true || e["intervall_sekunden"] != 300.0 {
		t.Errorf("nach Ändern: %+v", e)
	}
	other := strings.Repeat("ab", 32)
	for name, b := range map[string]map[string]any{
		"Adresse":          {"adresse": "xs-02.lan", "benutzer": xapitest.User, "fingerabdruck": xsPin},
		"Port":             {"adresse": "xs-01.lan", "port": 8443, "benutzer": xapitest.User, "fingerabdruck": xsPin},
		"Benutzer":         {"adresse": "xs-01.lan", "benutzer": "anderer@beispiel.example"},
		"Fingerabdruck":    {"adresse": "xs-01.lan", "benutzer": xapitest.User, "fingerabdruck": other},
		"Adresse ohne Pin": {"adresse": "xs-02.lan", "benutzer": xapitest.User},
	} {
		expectStatus(t, name+" ohne Passwort", as(t, "v_it").do("PUT", path, b), 400)
	}
	expectStatus(t, "neuer Fingerabdruck", as(t, "v_fw").do("PUT", path, xsBody("xs-01.lan", map[string]any{"fingerabdruck": other})), 200)
	// root wird schon beim Speichern abgelehnt.
	r = as(t, "v_fw").do("PUT", path, xsBody("xs-01.lan", map[string]any{"benutzer": "root"}))
	expectStatus(t, "root", r, 400)
	if !strings.Contains(r.raw, "root wird abgelehnt") {
		t.Errorf("Meldung: %s", r.raw)
	}

	// Keine Vermischung mit anderen Abfragen.
	expectStatus(t, "SNMP auf XenServer-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("xs-01.lan", nil)), 409)
	expectStatus(t, "Proxmox auf XenServer-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/proxmox", pveBody("xs-01.lan", nil)), 409)
	expectStatus(t, "NetApp auf XenServer-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/netapp", naBody("xs-01.lan", nil)), 409)
	expectStatus(t, "vCenter auf XenServer-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/vcenter", vcBody("xs-01.lan", nil)), 409)
	sw := newDevice(t, "v_fw", "Fertigung", "XS NetApp", "")
	swPath := "/api/v1/geraete/" + sw.body["id"].(string)
	expectStatus(t, "NetApp anlegen", as(t, "v_fw").do("PUT", swPath+"/netapp", naBody("aff.lan", nil)), 201)
	r = as(t, "v_fw").do("PUT", swPath+"/xenserver", xsBody("aff.lan", nil))
	expectStatus(t, "XenServer auf NetApp-Gerät", r, 409)
	if !strings.Contains(r.raw, "NetApp") {
		t.Errorf("Meldung: %s", r.raw)
	}
	expectStatus(t, "NetApp entfernen", as(t, "v_fw").do("DELETE", swPath+"/netapp", nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", swPath, nil), 204)

	// Leser und Operatoren dürfen nicht einrichten; Eltern beim Kind schon.
	lz := newDevice(t, "v_fw", "Lager Nord", "XS LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/xenserver"
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", lzPath, xsBody("lz.lan", nil)), 403)
	_, _, op := wartungZiele(t, "XS")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	expectStatus(t, "Operator legt an", opc.do("PUT", lzPath, xsBody("lz.lan", nil)), 403)
	r = as(t, "v_fw").do("PUT", lzPath, xsBody("lz.lan", nil))
	expectStatus(t, "Eltern legen beim Kind an", r, 201)
	lzID := r.body["id"].(string)
	expectStatus(t, "Operator ändert", opc.do("PUT", lzPath, map[string]any{"adresse": "lz.lan", "benutzer": xapitest.User, "aktiv": false}), 403)
	expectStatus(t, "Operator jetzt", opc.do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 202)
	expectStatus(t, "Geschwister jetzt", as(t, "v_oa").do("POST", "/api/v1/snmp/"+lzID+"/jetzt", nil), 404)
	expectStatus(t, "Operator löscht", opc.do("DELETE", lzPath, nil), 403)
	// Ein Kind sieht seine Eltern nicht.
	expectStatus(t, "Kind beim Elternteil", as(t, "v_lz").do("PUT", path, xsBody("xs-01.lan", nil)), 404)

	// Verbindung prüfen: nur Admins, nur freigegebene Netze, nicht bei Geschwistern.
	probe := path + "/pruefen"
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	expectStatus(t, "Leser prüft", as(t, "v_lz").do("POST", lzPath+"/pruefen", xsBody("lz.lan", nil)), 403)
	resetProbeLimit()
	expectStatus(t, "Operator prüft", opc.do("POST", lzPath+"/pruefen", xsBody("lz.lan", nil)), 403)
	resetProbeLimit()
	expectStatus(t, "Geschwister prüft", as(t, "v_oa").do("POST", probe, xsBody("xs-01.lan", nil)), 404)
	resetProbeLimit()
	expectStatus(t, "Kind prüft beim Elternteil", as(t, "v_lz").do("POST", probe, xsBody("xs-01.lan", nil)), 404)
	resetProbeLimit()
	expectStatus(t, "nicht freigegeben", as(t, "v_fw").do("POST", probe, xsBody("127.0.0.1", nil)), 400)
	resetProbeLimit()
	expectStatus(t, "root prüfen", as(t, "v_fw").do("POST", probe, xsBody("xs-01.lan", map[string]any{"benutzer": "root"})), 400)
	resetProbeLimit()

	// Löschen
	expectStatus(t, "Geschwister entfernt", as(t, "v_oa").do("DELETE", path, nil), 404)
	expectStatus(t, "Leser entfernt", as(t, "v_lz").do("DELETE", lzPath, nil), 403)
	expectStatus(t, "Kind entfernt beim Elternteil", as(t, "v_lz").do("DELETE", path, nil), 404)
	expectStatus(t, "XenServer entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "beim Kind entfernen", as(t, "v_it").do("DELETE", lzPath, nil), 204)
	expectStatus(t, "Gerät löschen", as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil), 204)

	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'xenserver.%' AND details::text LIKE '%'||$1||'%'`,
		xapitest.Password).Scan(&n)
	if n != 0 {
		t.Errorf("Passwort im Audit-Log: %d", n)
	}
	for _, action := range []string{"xenserver.angelegt", "xenserver.geaendert", "xenserver.geloescht"} {
		owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = $1 AND details->>'geraet' = $2`, action, dev).Scan(&n)
		if n < 1 {
			t.Errorf("Audit %s fehlt", action)
		}
	}
}

// RLS: Die Datenbank trennt XenServer-Quellen wie alle Abfragequellen, auch
// ohne die Prüfungen der Anwendung.
func TestXenServerRLS(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "XS RLS", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/xenserver"
	r = as(t, "v_fw").do("PUT", path, xsBody("rls.lan", nil))
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", "/api/v1/geraete/"+dev, nil) })
	count := func(user string) (visible int, secret bool, updated int64) {
		t.Helper()
		asDB(t, user, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_sources WHERE id = $1 AND version = 'xapi'`, id).Scan(&visible)
		})
		asDB(t, user, func(tx pgx.Tx) error {
			var n int
			err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_secret_for_admin($1, 'rls.lan', 443) WHERE secret_enc IS NOT NULL`,
				dev).Scan(&n)
			secret = err == nil && n > 0
			return nil
		})
		asDB(t, user, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = 600 WHERE id = $1`, id)
			if err == nil {
				updated = tag.RowsAffected()
			} else if !isDenied(err) {
				t.Errorf("%s: %v", user, err)
			}
			return nil
		})
		return
	}
	for user, want := range map[string]struct {
		visible int
		secret  bool
		update  int64
	}{
		"v_fw": {1, true, 1}, "v_it": {1, true, 1}, "v_oa": {0, false, 0}, "v_lz": {0, false, 0},
	} {
		v, s, u := count(user)
		if v != want.visible || s != want.secret || u != want.update {
			t.Errorf("%s: sichtbar %d, Geheimnis %v, geändert %d; erwartet %+v", user, v, s, u, want)
		}
	}
}

func TestXenServerEingabe(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "XE pool", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/xenserver"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	u, pw := xapitest.User, xapitest.Password
	bad := map[string]map[string]any{
		"ohne Adresse":           {"adresse": "", "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
		"Adresse mit URL":        {"adresse": "https://xs.lan", "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
		"Port":                   {"adresse": "xs.lan", "port": 0x10000, "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
		"Intervall klein":        {"adresse": "xs.lan", "intervall_sekunden": 30, "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
		"Intervall groß":         {"adresse": "xs.lan", "intervall_sekunden": 7200, "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
		"ohne Passwort":          {"adresse": "xs.lan", "benutzer": u, "fingerabdruck": xsPin},
		"ohne Benutzer":          {"adresse": "xs.lan", "passwort": pw, "fingerabdruck": xsPin},
		"root":                   {"adresse": "xs.lan", "benutzer": "root", "passwort": pw, "fingerabdruck": xsPin},
		"Root groß":              {"adresse": "xs.lan", "benutzer": "Root", "passwort": pw, "fingerabdruck": xsPin},
		"Benutzer Umbruch":       {"adresse": "xs.lan", "benutzer": u + "\nX", "passwort": pw, "fingerabdruck": xsPin},
		"Benutzer Leerzeichen":   {"adresse": "xs.lan", "benutzer": "a b", "passwort": pw, "fingerabdruck": xsPin},
		"Passwort Umbruch":       {"adresse": "xs.lan", "benutzer": u, "passwort": "a\nb", "fingerabdruck": xsPin},
		"Passwort zu lang":       {"adresse": "xs.lan", "benutzer": u, "passwort": strings.Repeat("x", 300), "fingerabdruck": xsPin},
		"Fingerabdruck kurz":     {"adresse": "xs.lan", "benutzer": u, "passwort": pw, "fingerabdruck": "AB:CD"},
		"Fingerabdruck kein Hex": {"adresse": "xs.lan", "benutzer": u, "passwort": pw, "fingerabdruck": strings.Repeat("zz", 32)},
		"IP nicht frei":          {"adresse": "10.1.2.3", "benutzer": u, "passwort": pw, "fingerabdruck": xsPin},
	}
	for name, b := range bad {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, b), 400)
	}
	expectStatus(t, "gültig", as(t, "v_fw").do("PUT", path, xsBody("xs.lan", nil)), 201)
	expectStatus(t, "Domäne\\Name", as(t, "v_fw").do("PUT", path, xsBody("xs.lan", map[string]any{"benutzer": `BEISPIEL\svc-ow`})), 200)
}

func TestXenServerPruefen(t *testing.T) {
	verwaltungSetup(t)
	allowLoopback(t) // nur 127.0.0.1: Der zweite Host (127.0.0.2) ist nicht freigegeben
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	r := newDevice(t, "v_fw", "Fertigung", "XP pool", "")
	expectStatus(t, "Gerät", r, 201)
	path := "/api/v1/geraete/" + r.body["id"].(string) + "/xenserver"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	probe := func(b map[string]any) response {
		t.Helper()
		resetProbeLimit()
		return as(t, "v_fw").do("POST", path+"/pruefen", b)
	}

	// Ohne Fingerabdruck: nur der Fingerabdruck, keine Anfrage und kein Passwort beim Pool.
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": xapitest.User, "passwort": xapitest.Password})
	if r.status != 200 || r.body["ok"] != false || r.body["fingerabdruck_neu"] != xapi.FormatPin(srv.Pin) {
		t.Fatalf("Fingerabdruck: %s", r.raw)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d Anfragen vor Bestätigung des Fingerabdrucks", n)
	}

	body := xsBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": xapi.FormatPin(srv.Pin)})
	r = probe(body)
	info, _ := r.body["xenserver"].(map[string]any)
	if r.body["ok"] != true || info["hosts"] != 2.0 || info["vms"] != 5.0 || info["pool"] != "pool-test" || info["master"] != "xs-01" ||
		info["hosts_mit_messwerten"] != 1.0 || info["produkt"] != "XenServer 8.4.0" {
		t.Fatalf("prüfen: %s", r.raw)
	}
	if f.OpenSessions() != 0 {
		t.Error("Sitzung nach Prüfen nicht abgemeldet")
	}
	// Der zweite Host liegt nicht in der Netzfreigabe: keine Verbindung dorthin.
	for _, c := range f.Calls() {
		if c == "GET /rrd_updates@"+xapitest.Host2Ref {
			t.Error("nicht freigegebener Host abgefragt")
		}
	}
	expectStatus(t, "anlegen", as(t, "v_fw").do("PUT", path, body), 201)

	// Gespeichertes Passwort und gespeicherter Fingerabdruck, wenn beides fehlt.
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": xapitest.User})
	if r.body["ok"] != true {
		t.Fatalf("gespeichert: %s", r.raw)
	}
	expectStatus(t, "anderer Benutzer", probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": "anderer@beispiel.example"}), 400)

	// Anderes Zertifikat: Abbruch, neuer Fingerabdruck wird gezeigt, kein Passwort gesendet.
	f.ResetCalls()
	r = probe(xsBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": strings.Repeat("12", 32)}))
	if r.body["ok"] != false || r.body["fingerabdruck_neu"] != xapi.FormatPin(srv.Pin) || len(f.Calls()) != 0 {
		t.Fatalf("fremdes Zertifikat: %s %v", r.raw, f.Calls())
	}
	expectStatus(t, "anderer Pin ohne Passwort", probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port,
		"benutzer": xapitest.User, "fingerabdruck": strings.Repeat("12", 32)}), 400)

	// Falsches Passwort: verständlich, ohne das Passwort im Text.
	r = probe(xsBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": srv.Pin, "passwort": "falsch-999"}))
	if r.body["ok"] != false || strings.Contains(r.raw, "falsch-999") || !strings.Contains(r.raw, "Anmeldung abgelehnt") {
		t.Fatalf("falsches Passwort: %s", r.raw)
	}

	// Schreibrecht erkannt: abgelehnt, mit Kennzeichen für die Oberfläche.
	f.Writable("vm-operator", "vm.start")
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": xapitest.User})
	if r.body["ok"] != false || r.body["schreibrecht"] != true || !strings.Contains(r.raw, "Schreibrecht") {
		t.Fatalf("Schreibrecht: %s", r.raw)
	}

	// Pool-Master gewechselt: Meldung mit neuem Master, keine Anmeldung woanders.
	f2 := xapitest.NewFake()
	srv2 := xapitest.Start(t, f2)
	f2.SlaveOf("10.20.0.12")
	r = probe(xsBody("127.0.0.1", map[string]any{"port": srv2.Port, "fingerabdruck": srv2.Pin}))
	if r.body["ok"] != false || r.body["neuer_master"] != "10.20.0.12" || !strings.Contains(r.raw, "Pool-Master gewechselt") {
		t.Fatalf("HOST_IS_SLAVE: %s", r.raw)
	}
}

func TestXenServerPlanerUndAlarme(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	nt := newFakeNtfy()
	defer nt.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(nt.URL)
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("127.0.0.2/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(nt.URL)

	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	port := int(srv.Port)

	var tenant, dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'XS A') RETURNING id::text`,
		ids["IT"]).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'pool-1') RETURNING id::text`, tenant).Scan(&dev)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'A', $3, 'xs')`,
		chID, tenant, server); err != nil {
		t.Fatal(err)
	}
	id, _ := newUUID()
	enc, _ := s.sealXAPI(id, tenant, "127.0.0.1", port, xapiSecret{User: xapitest.User, Password: xapitest.Password, Pin: srv.Pin})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc)
		VALUES ($1, $2, 'xapi', '127.0.0.1', $3, $4)`, id, dev, port, enc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tenant)
	})
	// Die Datenbank nimmt XenServer nicht über einen Sammler und ohne Traps.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = true WHERE id = $1`, id); err == nil {
		t.Error("Traps für XenServer angenommen")
	}
	// Gegenstände und Reihen: nur bekannte (CHECK in der Datenbank)
	var okSub, badSub, okSeries bool
	owner.QueryRow(ctx, `SELECT openwacht.valid_snmp_subject('xenvm:aaaaaaaa-0000-4000-8000-000000000001'),
		openwacht.valid_snmp_subject('xenvm:srv-dc01'), openwacht.valid_snmp_series('vmcpu:srv-dc01')`).Scan(&okSub, &badSub, &okSeries)
	if !okSub || badSub || !okSeries {
		t.Errorf("Gegenstände/Reihen: %v %v %v", okSub, badSub, okSeries)
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
	if err := json.Unmarshal(raw, &snap); err != nil || snap.XAPI == nil || len(snap.XAPI.Hosts) != 2 {
		t.Fatalf("Snapshot: %v %s", err, raw)
	}
	if snap.XAPI.Hosts[1].CPUPct == nil {
		t.Errorf("Messwerte des zweiten Hosts fehlen: %s", snap.XAPI.Hosts[1].MetricsError)
	}
	for _, c := range f.Calls() {
		if !xapi.AllowedMethod(c) && !strings.HasPrefix(c, "GET /rrd_updates@") {
			t.Errorf("unerwarteter Aufruf: %s", c)
		}
	}
	if f.OpenSessions() != 0 {
		t.Error("Sitzung nach der Abfrage nicht abgemeldet")
	}
	// Verlauf: CPU/RAM des Pools und je Host, Belegung, VMs
	rows, _ := owner.Query(ctx, `SELECT DISTINCT series FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1 ORDER BY 1`, id)
	series, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	joined := strings.Join(series, ",")
	for _, want := range []string{"cpu", "speicher", "xcpu:xs-01", "xram:xs-02", "platte:SR NFS VM-Speicher", "vmcpu:srv-db01", "vmram:srv-dc01"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Reihe %s fehlt: %s", want, joined)
		}
	}

	if _, err := s.alertRoundN(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := nt.take()["xs"]
	if len(msgs) != 1 {
		t.Fatalf("Alarm: %+v", msgs)
	}
	for _, want := range []string{"SR NFS VM-Speicher", "SR iSCSI Daten Anbindung", "VM srv-app01", "HA", "Updates", "Host xs-02 RAM"} {
		if !strings.Contains(msgs[0].Message, want) {
			t.Errorf("Alarm ohne %q: %s", want, msgs[0].Message)
		}
	}
	for _, not := range []string{"Host xs-01 ", "VM srv-dc01", "test-vm", "ISO-Bibliothek", "srv-print"} {
		if strings.Contains(msgs[0].Message, not) {
			t.Errorf("gesundes %s gemeldet: %s", not, msgs[0].Message)
		}
	}
	rows, _ = owner.Query(ctx, `SELECT subject FROM openwacht.alarms WHERE snmp_id = $1 AND ended_at IS NULL ORDER BY subject`, id)
	open, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if strings.Join(open, ",") != "platte:SR NFS VM-Speicher,xenha,xenram:xs-02,xensr:iSCSI Daten,xenupdates,"+
		"xenvm:aaaaaaaa-0000-4000-8000-000000000003" {
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
	for _, want := range []string{"XenServer=ok", "Host xs-01=ok", "SR NFS VM-Speicher=warn", "HA=warn", "VM srv-app01=crit"} {
		if !strings.Contains(got, want) {
			t.Errorf("Sensor %s fehlt: %s", want, got)
		}
	}
	if r := as(t, "v_fw").do("GET", "/api/v1/sensoren", nil); strings.Contains(r.raw, id) {
		t.Error("Fertigung sieht fremde XenServer-Sensoren")
	}

	// Konto bekommt Schreibrecht: Abfrage scheitert mit klarer Meldung, nichts wird gelesen, Sitzung abgemeldet.
	f.Writable("pool-operator")
	f.ResetCalls()
	poll()
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "Schreibrecht") {
		t.Errorf("Fehler: %v", lastErr)
	}
	for _, c := range f.Calls() {
		if !strings.HasPrefix(c, "session.") && !strings.HasPrefix(c, "role.") {
			t.Errorf("trotz Schreibrecht gelesen: %s", c)
		}
	}
	if f.OpenSessions() != 0 {
		t.Error("Sitzung nach Ablehnung nicht abgemeldet")
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
