// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/traps"
)

const (
	v3AuthPass = "auth-pass-123"
	v3PrivPass = "priv-pass-123"
)

func v3Body(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"version": "3", "adresse": addr, "v3": map[string]any{"benutzer": "wtest", "auth": "SHA-256",
		"auth_passwort": v3AuthPass, "priv": "AES-128", "priv_passwort": v3PrivPass}}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// tryAsUser: SQL mit den Rechten eines Testbenutzers; -1 = Fehler.
func tryAsUser(user string, sql string, args ...any) int64 {
	ctx := context.Background()
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

// allowLoopbackSNMP: wie allowLoopback, zusätzlich für den SNMP-Client.
func allowLoopbackSNMP(t *testing.T) {
	t.Helper()
	allowLoopback(t)
	old := vServer.snmp.Guard
	vServer.snmp.Guard = vServer.guard
	t.Cleanup(func() { vServer.snmp.Guard = old })
}

// snmpdTarget: Net-SNMP-Gegenstelle wie in internal/snmp (mit v3-Benutzern).
func snmpdTarget(t *testing.T) (string, int) {
	t.Helper()
	addr := os.Getenv("OPENWACHT_TEST_SNMPD")
	if addr == "" {
		if os.Getenv("OPENWACHT_REQUIRE_SNMPD") == "1" {
			t.Fatal("OPENWACHT_TEST_SNMPD fehlt")
		}
		t.Skip("kein snmpd (OPENWACHT_TEST_SNMPD)")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

func TestSNMPv3API(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "V3 Switch", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/snmp"

	// Unsichere Verfahren und unvollständige Daten: abgelehnt.
	for name, body := range map[string]map[string]any{
		"MD5":          v3Body("v3.lan", map[string]any{"v3": map[string]any{"benutzer": "u", "auth": "MD5", "auth_passwort": v3AuthPass, "priv": "AES", "priv_passwort": v3PrivPass}}),
		"DES":          v3Body("v3.lan", map[string]any{"v3": map[string]any{"benutzer": "u", "auth": "SHA", "auth_passwort": v3AuthPass, "priv": "DES", "priv_passwort": v3PrivPass}}),
		"ohne Priv":    v3Body("v3.lan", map[string]any{"v3": map[string]any{"benutzer": "u", "auth": "SHA", "auth_passwort": v3AuthPass, "priv": "", "priv_passwort": v3PrivPass}}),
		"kurz":         v3Body("v3.lan", map[string]any{"v3": map[string]any{"benutzer": "u", "auth": "SHA", "auth_passwort": "kurz", "priv": "AES", "priv_passwort": v3PrivPass}}),
		"ohne Daten":   {"version": "3", "adresse": "v3.lan"},
		"mit Communty": v3Body("v3.lan", map[string]any{"community": testCommunity}),
		"v3 bei v2c":   {"version": "2c", "adresse": "v3.lan", "community": testCommunity, "v3": map[string]any{"benutzer": "u", "auth_passwort": v3AuthPass}},
	} {
		res := as(t, "v_fw").do("PUT", path, body)
		expectStatus(t, name, res, 400)
		if strings.Contains(res.raw, v3AuthPass) || strings.Contains(res.raw, v3PrivPass) {
			t.Errorf("%s: Passwort in der Antwort", name)
		}
	}
	r = as(t, "v_fw").do("PUT", path, v3Body("v3.lan", map[string]any{"traps": true}))
	expectStatus(t, "v3 anlegen", r, 201)
	id := r.body["id"].(string)
	e, _ := snmpEntry(t, "v_fw", id)
	if e["version"] != "3" || e["v3_auth"] != snmp.AuthSHA256 || e["v3_priv"] != snmp.PrivAES || e["hat_community"] != true || e["traps"] != true {
		t.Fatalf("Eintrag: %+v", e)
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp", nil)
	for _, secret := range []string{v3AuthPass, v3PrivPass, "wtest"} {
		if strings.Contains(list.raw, secret) {
			t.Errorf("%q in der Liste", secret)
		}
	}

	// Trap-Zugangsdaten: mit dem Trap-Schlüssel lesbar, nicht mit dem Hauptschlüssel-Box-Schlüssel.
	var tenant string
	var trapEnc, secEnc []byte
	owner.QueryRow(ctx, `SELECT tenant_id::text, trap_secret_enc, secret_enc FROM openwacht.snmp_sources WHERE id = $1`, id).
		Scan(&tenant, &trapEnc, &secEnc)
	sec, err := traps.Open(vServer.trapKey, trapEnc, id, tenant, "v3.lan", 161, "3")
	if err != nil || sec.V3 == nil || sec.V3.User != "wtest" || sec.V3.AuthPass != v3AuthPass {
		t.Fatalf("Trap-Zugangsdaten: %+v %v", sec, err)
	}
	if _, err := traps.Open(vServer.boxKey, trapEnc, id, tenant, "v3.lan", 161, "3"); err == nil {
		t.Error("Trap-Zugangsdaten mit dem Box-Schlüssel lesbar")
	}
	if _, err := traps.Open(vServer.trapKey, secEnc, id, tenant, "v3.lan", 161, "3"); err == nil {
		t.Error("Abfrage-Zugangsdaten mit dem Trap-Schlüssel lesbar")
	}
	if _, err := traps.Open(vServer.trapKey, trapEnc, id, tenant, "v3.lan", 161, "2c"); err == nil {
		t.Error("Trap-Zugangsdaten passen zu einer anderen Version")
	}
	// Die v3-Daten werden nie als Community gelesen.
	if _, err := vServer.openSNMP(id, tenant, "v3.lan", 161, "2c", secEnc); err == nil {
		t.Error("v3-Daten als Community lesbar")
	}

	// Wechsel auf v2c ohne Community: abgelehnt; mit Community: v3-Spalten leer.
	expectStatus(t, "v2c ohne Community", as(t, "v_fw").do("PUT", path, map[string]any{"version": "2c", "adresse": "v3.lan"}), 400)
	// Ändern ohne neue Daten: bleibt, Trap-Zugangsdaten werden neu verschlüsselt.
	expectStatus(t, "Intervall", as(t, "v_it").do("PUT", path, map[string]any{"version": "3", "adresse": "v3.lan", "intervall_sekunden": 300}), 200)
	owner.QueryRow(ctx, `SELECT trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&trapEnc)
	if _, err := traps.Open(vServer.trapKey, trapEnc, id, tenant, "v3.lan", 161, "3"); err != nil {
		t.Errorf("nach Ändern: %v", err)
	}
	// Traps aus: Trap-Zugangsdaten weg.
	expectStatus(t, "Traps aus", as(t, "v_fw").do("PUT", path, map[string]any{"version": "3", "adresse": "v3.lan", "traps": false}), 200)
	var has bool
	owner.QueryRow(ctx, `SELECT trap_secret_enc IS NOT NULL FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&has)
	if has {
		t.Error("Trap-Zugangsdaten nach „Traps aus“ noch da")
	}
	// Traps wieder an, ohne neue Zugangsdaten: aus den gespeicherten.
	expectStatus(t, "Traps an", as(t, "v_fw").do("PUT", path, map[string]any{"version": "3", "adresse": "v3.lan", "traps": true}), 200)
	owner.QueryRow(ctx, `SELECT trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&trapEnc)
	if _, err := traps.Open(vServer.trapKey, trapEnc, id, tenant, "v3.lan", 161, "3"); err != nil {
		t.Errorf("Traps wieder an: %v", err)
	}
	// Operator darf Traps nicht schalten.
	_, _, op := wartungZiele(t, "V3")
	opc := newClient(t, vSrv)
	expectStatus(t, "Operator anmelden", opc.login(op), 200)
	lz := newDevice(t, "v_fw", "Lager Nord", "V3 LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/snmp"
	expectStatus(t, "LZ anlegen", as(t, "v_fw").do("PUT", lzPath, snmpBody("lz3.lan", nil)), 201)
	expectStatus(t, "Operator schaltet Traps", opc.do("PUT", lzPath, map[string]any{"version": "2c", "adresse": "lz3.lan", "traps": true}), 403)

	// Datenbank: Adresswechsel per SQL verwirft beide Geheimnisse, Artwechsel ebenso.
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET host = 'angreifer.lan' WHERE id = $1`, id); n != 1 {
		t.Fatalf("Adresse ändern: %d", n)
	}
	var s1, s2 bool
	owner.QueryRow(ctx, `SELECT secret_enc IS NOT NULL, trap_secret_enc IS NOT NULL FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&s1, &s2)
	if s1 || s2 {
		t.Errorf("nach Adresswechsel: secret=%v trap=%v", s1, s2)
	}
	expectStatus(t, "neu mit Daten", as(t, "v_fw").do("PUT", path, v3Body("v3.lan", map[string]any{"traps": true})), 200)
	// Neue Adresse mit neuem Abfrage-Geheimnis, aber altem Trap-Geheimnis: Das Trap-Geheimnis fällt weg.
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET host = 'neu.lan', secret_enc = '\x0102030405060708091011121314151617181920212223242526272829' WHERE id = $1`, id); n != 1 {
		t.Fatalf("Adresse und Geheimnis ändern: %d", n)
	}
	owner.QueryRow(ctx, `SELECT trap_secret_enc IS NOT NULL FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&has)
	if has {
		t.Error("altes Trap-Geheimnis nach Adresswechsel noch da")
	}
	expectStatus(t, "wieder mit Daten", as(t, "v_fw").do("PUT", path, v3Body("v3.lan", map[string]any{"traps": true})), 200)
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET version = '2c', v3_auth = NULL, v3_priv = NULL WHERE id = $1`, id); n != 1 {
		t.Fatalf("Art ändern: %d", n)
	}
	owner.QueryRow(ctx, `SELECT secret_enc IS NOT NULL, trap_secret_enc IS NOT NULL FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&s1, &s2)
	if s1 || s2 {
		t.Errorf("nach Artwechsel: secret=%v trap=%v", s1, s2)
	}
	// v3 ohne Verfahren: Prüfung der Datenbank
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET version = '3' WHERE id = $1`, id); n != -1 {
		t.Errorf("v3 ohne Verfahren: %d", n)
	}
	// MD5 auch per SQL nicht
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET version = '3', v3_auth = 'md5', v3_priv = 'aes' WHERE id = $1`, id); n != -1 {
		t.Errorf("MD5 per SQL: %d", n)
	}
	// Die App darf trap_secret_enc nicht lesen.
	if n := tryAsUser("v_fw", `SELECT trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, id); n != -1 {
		t.Errorf("trap_secret_enc lesbar: %d", n)
	}

	// Audit ohne Passwörter und Benutzer
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'snmp.%'
		AND (details::text LIKE '%'||$1||'%' OR details::text LIKE '%'||$2||'%' OR details::text LIKE '%wtest%')`, v3AuthPass, v3PrivPass).Scan(&n)
	if n != 0 {
		t.Errorf("v3-Daten im Audit-Log: %d", n)
	}
	expectStatus(t, "aufräumen", as(t, "v_fw").do("DELETE", path, nil), 204)
	expectStatus(t, "aufräumen LZ", as(t, "v_fw").do("DELETE", lzPath, nil), 204)
}

// TestSNMPv3GegenSnmpd: Verbindung prüfen und Planer mit SNMPv3 gegen Net-SNMP.
func TestSNMPv3GegenSnmpd(t *testing.T) {
	verwaltungSetup(t)
	host, port := snmpdTarget(t)
	allowLoopbackSNMP(t)
	resetProbeLimit()
	ctx := context.Background()
	r := newDevice(t, "v_fw", "Fertigung", "V3 snmpd", "")
	dev := r.body["id"].(string)
	probe := "/api/v1/geraete/" + dev + "/snmp/pruefen"
	path := "/api/v1/geraete/" + dev + "/snmp"

	res := as(t, "v_fw").do("POST", probe, v3Body(host, map[string]any{"port": port}))
	expectStatus(t, "prüfen", res, 200)
	if res.body["ok"] != true {
		t.Fatalf("prüfen: %s", res.raw)
	}
	resetProbeLimit()
	bad := v3Body(host, map[string]any{"port": port, "v3": map[string]any{"benutzer": "wtest", "auth": "sha256",
		"auth_passwort": "falsch-falsch", "priv": "aes", "priv_passwort": v3PrivPass}})
	res = as(t, "v_fw").do("POST", probe, bad)
	if res.body["ok"] != false || !strings.Contains(res.raw, "Anmeldung abgelehnt") || strings.Contains(res.raw, "falsch-falsch") {
		t.Fatalf("falsches Passwort: %s", res.raw)
	}
	r = as(t, "v_fw").do("PUT", path, v3Body(host, map[string]any{"port": port}))
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id) })
	// Verbindung prüfen mit gespeicherten v3-Daten
	resetProbeLimit()
	res = as(t, "v_fw").do("POST", probe, map[string]any{"version": "3", "adresse": host, "port": port})
	if res.body["ok"] != true {
		t.Fatalf("prüfen gespeichert: %s", res.raw)
	}
	resetProbeLimit()
	// gespeicherte v3-Daten nie als Community
	expectStatus(t, "gespeichert als v2c", as(t, "v_fw").do("POST", probe, map[string]any{"version": "2c", "adresse": host, "port": port}), 400)

	// Planer: Abfrage über v3
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, id)
	due, err := vServer.claimSNMP(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range due {
		if c.id == id {
			found = true
			vServer.pollSNMP(ctx, c)
		} else {
			owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
		}
	}
	if !found {
		t.Fatal("Quelle nicht fällig")
	}
	var ok bool
	var lastErr *string
	owner.QueryRow(ctx, `SELECT last_ok IS NOT NULL, last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&ok, &lastErr)
	if !ok {
		t.Fatalf("Abfrage gescheitert: %v", *lastErr)
	}
}
