// SPDX-License-Identifier: AGPL-3.0-only

package traps

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const (
	testCommunity = "trap-gemeinschaft"
	testAuthPass  = "auth-pass-123"
	testPrivPass  = "priv-pass-123"
	ifIndex       = "1.3.6.1.2.1.2.2.1.1"
	linkDown      = "1.3.6.1.6.3.1.1.5.3"
	linkUp        = "1.3.6.1.6.3.1.1.5.4"
)

type env struct {
	t                *testing.T
	owner            *pgx.Conn
	pool             *pgxpool.Pool
	tdb              *dbtest.DB
	key              []byte
	svc              *Service
	addr             *net.UDPAddr
	root, fw, sib    string // Mandanten
	devV2, devV3     string
	srcV2, srcV3     string
	ruleDown, ruleUp string
	cancel           func()
	done             chan error
}

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"snmptrap", "snmpinform"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("OPENWACHT_REQUIRE_SNMPD") == "1" {
				t.Fatalf("%s fehlt", tool)
			}
			t.Skipf("%s fehlt (Net-SNMP)", tool)
		}
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tdb.Close)
	owner, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close(ctx) })
	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, owner: owner, tdb: tdb, key: make([]byte, 32)}
	rand.Read(e.key)
	q := func(sql string, args ...any) string {
		t.Helper()
		var id string
		if err := owner.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return id
	}
	e.root = q(`INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`)
	e.fw = q(`INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Fertigung') RETURNING id::text`, e.root)
	e.sib = q(`INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Organisation') RETURNING id::text`, e.root)
	grp := q(`INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'Switche') RETURNING id::text`, e.fw)
	e.devV2 = q(`INSERT INTO openwacht.devices (tenant_id, name, group_id) VALUES ($1, 'switch-v2', $2) RETURNING id::text`, e.fw, grp)
	e.devV3 = q(`INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'switch-v3') RETURNING id::text`, e.fw)
	e.srcV2 = e.source(e.devV2, e.fw, "2c", Secret{Community: testCommunity})
	e.srcV3 = e.source(e.devV3, e.fw, "3", Secret{V3: &snmp.V3Auth{User: "wtest", Auth: snmp.AuthSHA256, AuthPass: testAuthPass,
		Priv: snmp.PrivAES, PrivPass: testPrivPass}})
	// Regeln: Eltern (IT) für alle: linkDown → Fehler je ifIndex, linkUp → Entwarnung.
	e.ruleDown = q(`INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, position, name, trap_oid, action, key_oid, duration_min)
		VALUES (gen_random_uuid(), $1, 10, 'Port getrennt', $2, 'crit', $3, 0) RETURNING id::text`, e.root, linkDown, ifIndex)
	e.ruleUp = q(`INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, position, name, trap_oid, action, key_oid, clears)
		VALUES (gen_random_uuid(), $1, 20, 'Port verbunden', $2, 'ok', $3, $4) RETURNING id::text`, e.root, linkUp, ifIndex, e.ruleDown)
	q(`INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, position, name, trap_oid, action)
		VALUES (gen_random_uuid(), $1, 30, 'Neustart', '1.3.6.1.6.3.1.1.5.*', 'warn') RETURNING id::text`, e.root)

	e.pool, err = pgxpool.New(ctx, tdb.TrapsCfg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	cfgPool, _ := pgxpool.ParseConfig("")
	cfgPool.ConnConfig = tdb.TrapsCfg
	if e.pool, err = pgxpool.NewWithConfig(ctx, cfgPool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.pool.Close)
	if err := CheckRole(ctx, e.pool); err != nil {
		t.Fatal(err)
	}
	e.start()
	return e
}

func (e *env) source(dev, tenant, version string, sec Secret) string {
	e.t.Helper()
	ctx := context.Background()
	var id string
	rand := make([]byte, 40)
	var auth, priv *string
	if sec.V3 != nil {
		auth, priv = &sec.V3.Auth, &sec.V3.Priv
	}
	if err := e.owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc, v3_auth, v3_priv, traps)
		VALUES (gen_random_uuid(), $1, $2, '127.0.0.1', 161, $3, $4, $5, true) RETURNING id::text`, dev, version, rand, auth, priv).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	enc, err := Seal(e.key, sec, id, tenant, "127.0.0.1", 161, version)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET trap_secret_enc = $2 WHERE id = $1`, id, enc); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) start() {
	e.t.Helper()
	ctx := context.Background()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	e.addr = conn.LocalAddr().(*net.UDPAddr)
	e.svc, err = New(ctx, Config{Pool: e.pool, Key: e.key, Conn: conn, Reload: time.Hour})
	if err != nil {
		e.t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	e.cancel, e.done = cancel, make(chan error, 1)
	go func() { e.done <- e.svc.Run(rctx) }()
	e.t.Cleanup(e.stop)
}

func (e *env) stop() {
	if e.cancel != nil {
		e.cancel()
		<-e.done
		e.svc.cfg.Conn.Close()
		e.cancel = nil
	}
}

func (e *env) target() string { return "127.0.0.1:" + strconv.Itoa(e.addr.Port) }

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "SNMPCONFPATH="+t.TempDir(), "MIBS=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func v3Args(user, auth, authPass, priv, privPass, level string) []string {
	return []string{"-v3", "-l", level, "-u", user, "-a", auth, "-A", authPass, "-x", priv, "-X", privPass}
}

// logRows wartet, bis die Quelle n Protokolleinträge hat.
func (e *env) logRows(src string, n int) []map[string]any {
	e.t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, _ := e.owner.Query(ctx, `SELECT version, inform, authentic, trap_oid, varbinds::text, coalesce(rule_id::text, ''), result
			FROM openwacht.snmp_trap_log WHERE source_id = $1 ORDER BY id`, src)
		var out []map[string]any
		for rows.Next() {
			var v, oid, vb, rule, res string
			var inform, authentic bool
			rows.Scan(&v, &inform, &authentic, &oid, &vb, &rule, &res)
			out = append(out, map[string]any{"version": v, "inform": inform, "authentic": authentic, "oid": oid, "varbinds": vb,
				"rule": rule, "result": res})
		}
		rows.Close()
		if len(out) >= n || time.Now().After(deadline) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *env) states(src string) map[string]string {
	e.t.Helper()
	rows, _ := e.owner.Query(context.Background(), `SELECT instance, status FROM openwacht.snmp_trap_state WHERE source_id = $1`, src)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var i, s string
		rows.Scan(&i, &s)
		out[i] = s
	}
	return out
}

func TestTrapsV2cUndV1(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	// linkDown für ifIndex 3 → Fehler „3“
	if out, err := run(t, "snmptrap", "-v2c", "-c", testCommunity, e.target(), "", linkDown,
		ifIndex+".3", "i", "3", "1.3.6.1.2.1.2.2.1.2.3", "s", "Port 3"); err != nil {
		t.Fatalf("snmptrap: %v %s", err, out)
	}
	rows := e.logRows(e.srcV2, 1)
	if len(rows) != 1 || rows[0]["oid"] != linkDown || rows[0]["authentic"] != false || rows[0]["result"] != "crit" ||
		rows[0]["rule"] != e.ruleDown || !strings.Contains(rows[0]["varbinds"].(string), "Port 3") {
		t.Fatalf("Protokoll: %+v", rows)
	}
	if st := e.states(e.srcV2); st["3"] != "crit" || len(st) != 1 {
		t.Fatalf("Zustand: %+v", st)
	}
	// falsche Community: verworfen
	run(t, "snmptrap", "-v2c", "-c", "falsch", e.target(), "", linkDown, ifIndex+".4", "i", "4")
	// linkUp für einen anderen Port: Zustand bleibt
	run(t, "snmptrap", "-v2c", "-c", testCommunity, e.target(), "", linkUp, ifIndex+".5", "i", "5")
	e.logRows(e.srcV2, 2)
	if st := e.states(e.srcV2); st["3"] != "crit" {
		t.Fatalf("Zustand nach linkUp 5: %+v", st)
	}
	// linkUp Port 3: Entwarnung
	run(t, "snmptrap", "-v2c", "-c", testCommunity, e.target(), "", linkUp, ifIndex+".3", "i", "3")
	rows = e.logRows(e.srcV2, 3)
	if len(rows) != 3 || rows[2]["result"] != "ok" {
		t.Fatalf("Protokoll: %+v", rows)
	}
	if st := e.states(e.srcV2); len(st) != 0 {
		t.Fatalf("Zustand nach Entwarnung: %+v", st)
	}
	// v1-Trap coldStart (generisch 0) → Trap-OID nach RFC 3584
	if out, err := run(t, "snmptrap", "-v1", "-c", testCommunity, e.target(), "1.3.6.1.4.1.8072.2.3", "127.0.0.1", "0", "0", ""); err != nil {
		t.Fatalf("snmptrap v1: %v %s", err, out)
	}
	rows = e.logRows(e.srcV2, 4)
	if len(rows) != 4 || rows[3]["oid"] != "1.3.6.1.6.3.1.1.5.1" || rows[3]["version"] != "1" || rows[3]["result"] != "warn" {
		t.Fatalf("v1: %+v", rows)
	}
	// v2c-Inform wird beantwortet (snmpinform wartet auf die Antwort)
	if out, err := run(t, "snmpinform", "-v2c", "-c", testCommunity, "-t", "2", "-r", "0", e.target(), "", "1.3.6.1.4.1.99.1"); err != nil {
		t.Fatalf("snmpinform v2c: %v %s", err, out)
	}
	rows = e.logRows(e.srcV2, 5)
	if len(rows) != 5 || rows[4]["inform"] != true || rows[4]["result"] != "none" {
		t.Fatalf("Inform: %+v", rows)
	}
	// Die falsche Community steht nirgends; an die v3-Quelle ging nichts.
	if rows := e.logRows(e.srcV3, 0); len(rows) != 0 {
		t.Fatalf("v3-Quelle hat v2c-Traps: %+v", rows)
	}
	if e.svc.cnt.community.Load() != 1 {
		t.Errorf("Community-Zähler: %d", e.svc.cnt.community.Load())
	}
}

func TestTrapsV3(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	engine := "0x8000000001020304"
	args := append([]string{"-e", engine}, v3Args("wtest", "SHA-256", testAuthPass, "AES", testPrivPass, "authPriv")...)
	if out, err := run(t, "snmptrap", append(args, e.target(), "", linkDown, ifIndex+".7", "i", "7")...); err != nil {
		t.Fatalf("snmptrap v3: %v %s", err, out)
	}
	rows := e.logRows(e.srcV3, 1)
	if len(rows) != 1 || rows[0]["authentic"] != true || rows[0]["version"] != "3" || rows[0]["result"] != "crit" {
		t.Fatalf("v3: %+v", rows)
	}
	// falsches Passwort, authNoPriv, MD5: verworfen
	run(t, "snmptrap", append(append([]string{"-e", engine}, v3Args("wtest", "SHA-256", "falsch-falsch", "AES", testPrivPass, "authPriv")...),
		e.target(), "", linkDown, ifIndex+".8", "i", "8")...)
	run(t, "snmptrap", append(append([]string{"-e", engine}, v3Args("wtest", "SHA-256", testAuthPass, "AES", testPrivPass, "authNoPriv")...),
		e.target(), "", linkDown, ifIndex+".9", "i", "9")...)
	run(t, "snmptrap", append(append([]string{"-e", engine}, v3Args("wtest", "MD5", testAuthPass, "DES", testPrivPass, "authPriv")...),
		e.target(), "", linkDown, ifIndex+".10", "i", "10")...)
	run(t, "snmptrap", "-v2c", "-c", testCommunity, e.target(), "", linkDown, ifIndex+".11", "i", "11") // geht an die v2c-Quelle
	e.logRows(e.srcV2, 1)
	time.Sleep(300 * time.Millisecond)
	if rows := e.logRows(e.srcV3, 1); len(rows) != 1 {
		t.Fatalf("abgelehnte v3-Traps im Protokoll: %+v", rows)
	}
	if e.svc.cnt.auth.Load() < 3 {
		t.Errorf("v3 abgelehnt: %d", e.svc.cnt.auth.Load())
	}

	// v3-Inform: Engine-Ermittlung, dann authentifizierte Antwort.
	if out, err := run(t, "snmpinform", append(v3Args("wtest", "SHA-256", testAuthPass, "AES", testPrivPass, "authPriv"),
		"-t", "2", "-r", "1", e.target(), "", "1.3.6.1.4.1.99.2", "1.3.6.1.4.1.99.2.1", "s", "hallo")...); err != nil {
		t.Fatalf("snmpinform v3: %v %s", err, out)
	}
	rows = e.logRows(e.srcV3, 2)
	if len(rows) != 2 || rows[1]["inform"] != true || rows[1]["authentic"] != true || !strings.Contains(rows[1]["varbinds"].(string), "hallo") {
		t.Fatalf("v3-Inform: %+v", rows)
	}
	if e.svc.cnt.discovery.Load() == 0 {
		t.Error("keine Engine-Ermittlung")
	}
	// Inform mit falschem Passwort: keine Antwort (snmpinform läuft in den Timeout)
	if _, err := run(t, "snmpinform", append(v3Args("wtest", "SHA-256", "falsch-falsch", "AES", testPrivPass, "authPriv"),
		"-t", "1", "-r", "0", e.target(), "", "1.3.6.1.4.1.99.3")...); err == nil {
		t.Error("Inform mit falschem Passwort beantwortet")
	}
	// Wiederholung: Die gemerkte Engine-Zeit liegt in der Datenbank.
	var n int
	e.owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.snmp_trap_engines WHERE source_id = $1`, e.srcV3).Scan(&n)
	if n != 1 {
		t.Errorf("gemerkte Engines: %d", n)
	}
}

// TestTrapsWiederholung: dasselbe v3-Paket zweimal, ein älteres danach.
func TestTrapsWiederholung(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	// Paket abfangen: snmptrap an einen eigenen Socket.
	catcher, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer catcher.Close()
	capture := func(extra ...string) []byte {
		t.Helper()
		args := append([]string{"-e", "0x8000000001020399"}, v3Args("wtest", "SHA-256", testAuthPass, "AES", testPrivPass, "authPriv")...)
		args = append(args, extra...)
		args = append(args, catcher.LocalAddr().String(), "", "1.3.6.1.4.1.99.5")
		if out, err := run(t, "snmptrap", args...); err != nil {
			t.Fatalf("snmptrap: %v %s", err, out)
		}
		buf := make([]byte, 9000)
		catcher.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := catcher.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	send := func(b []byte) {
		c, err := net.Dial("udp", e.target())
		if err != nil {
			t.Fatal(err)
		}
		c.Write(b)
		c.Close()
	}
	// net-snmp setzt bei snmptrap -v3 Boots/Zeit aus -Z (boots,time).
	newer := capture("-Z", "5,1000")
	older := capture("-Z", "4,5000")
	send(newer)
	e.logRows(e.srcV3, 1)
	send(newer) // identisch: verworfen
	send(older) // ältere Boots: verworfen
	time.Sleep(300 * time.Millisecond)
	if rows := e.logRows(e.srcV3, 1); len(rows) != 1 {
		t.Fatalf("Wiederholung angenommen: %d Einträge", len(rows))
	}
	if e.svc.cnt.replay.Load() != 1 || e.svc.cnt.window.Load() != 1 {
		t.Errorf("Zähler: wiederholt %d, zeitfenster %d", e.svc.cnt.replay.Load(), e.svc.cnt.window.Load())
	}
	// Nach einem Neustart des Dienstes gilt der gemerkte Stand aus der Datenbank.
	e.stop()
	e.start()
	send(older)
	time.Sleep(300 * time.Millisecond)
	if rows := e.logRows(e.srcV3, 1); len(rows) != 1 {
		t.Fatalf("nach Neustart angenommen: %d", len(rows))
	}
	// Engine-Boots der eigenen Engine zählen mit.
	var boots int
	e.owner.QueryRow(context.Background(), `SELECT engine_boots FROM openwacht.snmp_engine`).Scan(&boots)
	if boots != 2 {
		t.Errorf("engine_boots = %d, erwartet 2", boots)
	}
}

// TestTrapsUnbekannterAbsender: von 127.0.0.2 ist keine Quelle bekannt.
func TestTrapsUnbekannterAbsender(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, e.addr)
	if err != nil {
		t.Skip("127.0.0.2 nicht nutzbar:", err)
	}
	defer c.Close()
	catcher, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer catcher.Close()
	run(t, "snmptrap", "-v2c", "-c", testCommunity, catcher.LocalAddr().String(), "", linkDown)
	buf := make([]byte, 2000)
	catcher.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := catcher.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(buf[:n])
	deadline := time.Now().Add(2 * time.Second)
	for e.svc.cnt.unknown.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if e.svc.cnt.unknown.Load() != 1 {
		t.Fatalf("unbekannt: %d", e.svc.cnt.unknown.Load())
	}
	if rows := e.logRows(e.srcV2, 0); len(rows) != 0 {
		t.Fatalf("angenommen: %+v", rows)
	}
}

// TestTrapsRechte: Die Trap-Rolle sieht keine Tabellen und ruft keine
// Funktionen der Anwendung; traps_record nimmt keine fremden Regeln an.
func TestTrapsRechte(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	ctx := context.Background()
	for _, sql := range []string{
		`SELECT secret_enc FROM openwacht.snmp_sources LIMIT 1`,
		`SELECT trap_secret_enc FROM openwacht.snmp_sources LIMIT 1`,
		`SELECT * FROM openwacht.users LIMIT 1`,
		`SELECT * FROM openwacht.snmp_trap_rules LIMIT 1`,
		`SELECT * FROM openwacht.snmp_trap_log LIMIT 1`,
		`SELECT * FROM openwacht.snmp_engine`,
		`INSERT INTO openwacht.snmp_trap_state (source_id, tenant_id, rule_id, rule_name, status, message, authentic, since, last_at)
			VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'x', 'crit', 'x', true, now(), now())`,
		`SELECT * FROM openwacht.snmp_claim(1)`,
		`SELECT openwacht.snmp_trap_reset(gen_random_uuid(), gen_random_uuid(), '')`,
		`SELECT * FROM openwacht.alert_snmp_candidates()`,
	} {
		if _, err := e.pool.Exec(ctx, sql); err == nil {
			t.Errorf("Trap-Rolle darf: %s", sql)
		}
	}
	// Die App-Rolle darf die Trap-Funktionen nicht.
	app, err := pgx.ConnectConfig(ctx, e.tdb.AppCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)
	for _, sql := range []string{`SELECT * FROM openwacht.traps_sources()`, `SELECT * FROM openwacht.traps_engine_start()`,
		`SELECT openwacht.traps_maintain()`} {
		if _, err := app.Exec(ctx, sql); err == nil {
			t.Errorf("App-Rolle darf: %s", sql)
		}
	}
	// Regel eines Geschwister-Mandanten: wirkt nicht, nur Protokoll.
	var sib string
	e.owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_trap_rules (id, tenant_id, name, trap_oid, action)
		VALUES (gen_random_uuid(), $1, 'fremd', '*', 'crit') RETURNING id::text`, e.sib).Scan(&sib)
	var res string
	if err := e.pool.QueryRow(ctx, `SELECT openwacht.traps_record($1, '2c', false, false, '1.3.6.1.4.1.1', '[]', $2, '', 'x')`,
		e.srcV2, sib).Scan(&res); err != nil || res != "none" {
		t.Errorf("fremde Regel: %q %v", res, err)
	}
	// v1/v2c als „authentisch“ ausgeben: abgelehnt.
	if _, err := e.pool.Exec(ctx, `SELECT openwacht.traps_record($1, '2c', false, true, '1.3.6.1.4.1.1', '[]', NULL, '', 'x')`, e.srcV2); err == nil {
		t.Error("v2c als authentisch angenommen")
	}
	// v3-Trap an eine v2c-Quelle: abgelehnt.
	if err := e.pool.QueryRow(ctx, `SELECT openwacht.traps_record($1, '3', false, true, '1.3.6.1.4.1.1', '[]', NULL, '', 'x')`,
		e.srcV2).Scan(&res); err != nil || res != "fehlt" {
		t.Errorf("v3 an v2c-Quelle: %q %v", res, err)
	}
	// Traps aus: nichts mehr.
	e.owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = false WHERE id = $1`, e.srcV2)
	if err := e.pool.QueryRow(ctx, `SELECT openwacht.traps_record($1, '2c', false, false, '1.3.6.1.4.1.1', '[]', NULL, '', 'x')`,
		e.srcV2).Scan(&res); err != nil || res != "fehlt" {
		t.Errorf("Traps aus: %q %v", res, err)
	}
	var enc *[]byte
	e.owner.QueryRow(ctx, `SELECT trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, e.srcV2).Scan(&enc)
	if enc != nil {
		t.Error("Trap-Zugangsdaten nach „Traps aus“ noch da")
	}
	// Aufräumen: alte Einträge weg.
	e.owner.Exec(ctx, `UPDATE openwacht.snmp_trap_log SET received_at = now() - interval '31 days'`)
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT openwacht.traps_maintain()`).Scan(&n); err != nil || n < 1 {
		t.Errorf("Aufräumen: %d %v", n, err)
	}
}

// Eine Panik beim Auswerten eines Pakets beendet den Dienst nicht (M3):
// Das Paket zählt als unlesbar, der nächste Trap wird normal angenommen.
func TestTrapsPanikImPaket(t *testing.T) {
	needTools(t)
	e := newEnv(t)
	safe.ResetForTest()
	hook := func(msg []byte) {
		if bytes.Equal(msg, []byte("kaputt")) {
			var m map[string]int
			m["x"]++ // Panik: Schreiben in nil-Map
		}
	}
	testPanicHook.Store(&hook)
	t.Cleanup(func() { testPanicHook.Store(nil) })
	c, err := net.Dial("udp", e.target())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("kaputt"))
	deadline := time.Now().Add(5 * time.Second)
	for safe.Counts()["traps"] == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := safe.Counts()["traps"]; n != 1 {
		t.Fatalf("Panik nicht gezählt: %d", n)
	}
	if out, err := run(t, "snmptrap", "-v2c", "-c", testCommunity, e.target(), "", linkDown, ifIndex+".7", "i", "7"); err != nil {
		t.Fatalf("snmptrap: %v %s", err, out)
	}
	if rows := e.logRows(e.srcV2, 1); len(rows) != 1 {
		t.Fatalf("Dienst nimmt nach der Panik nichts mehr an: %+v", rows)
	}
	select {
	case err := <-e.done:
		t.Fatalf("Dienst beendet: %v", err)
	default:
	}
}
