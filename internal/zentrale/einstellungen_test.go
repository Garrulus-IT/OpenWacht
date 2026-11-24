// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
)

// freshCode: ein gültiger, noch nicht verbrauchter 2FA-Code (der letzte
// Schritt wird dafür zurückgesetzt; im Betrieb wartet man 30 s).
func freshCode(t *testing.T, user string) string {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.users SET totp_last_step = 0 WHERE id = $1`, ids[user]); err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCode(vSecrets[user], auth.TOTPStep(time.Now()))
}

func setOperator(t *testing.T, user string, on bool) {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.users SET platform_operator = $2 WHERE id = $1`, ids[user], on); err != nil {
		t.Fatal(err)
	}
}

func resetSettings(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`UPDATE openwacht.settings SET check_nets = NULL, alert_targets = NULL, deadman_enc = NULL, silent_s = NULL,
			disk_warn = NULL, disk_crit = NULL, mem_warn = NULL, mem_crit = NULL, cpu_warn = NULL, cpu_crit = NULL,
			keep_raw_days = NULL, keep_5m_days = NULL, keep_1h_days = NULL`,
		`DELETE FROM openwacht.tenant_settings`,
		`DELETE FROM openwacht.device_limits`,
		`UPDATE openwacht.users SET platform_operator = false`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := vServer.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
}

// settingsServer: eigener Server mit Einstellungen aus der Datenbank.
func settingsServer(t *testing.T, cfg Config) (*Server, *httptest.Server) {
	t.Helper()
	verwaltungSetup(t)
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	cfg.BaseURL, cfg.PasswordParams, cfg.LoginsPerMinutePerIP, cfg.SettingsFromDB = mustURL(srv.URL), &testParams, 1000, true
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s.Handler()
	if err := s.ReloadSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, srv
}

func loginOn(t *testing.T, srv *httptest.Server, user string) *client {
	t.Helper()
	c := newClient(t, srv)
	r := c.login(user)
	expectStatus(t, "Anmeldung "+user, r, 200)
	if r.body["zweiter_faktor"] == true {
		r = c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": freshCode(t, user)})
		expectStatus(t, "2FA "+user, r, 200)
		c.csrf, _ = r.body["csrf"].(string)
	}
	return c
}

func TestBetreiberKennzeichen(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	ctx := context.Background()
	it := as(t, "v_it")

	// Admin des Hauptmandanten ist nicht automatisch Betreiber.
	expectStatus(t, "Admin ohne Kennzeichen", it.do("GET", "/api/v1/einstellungen", nil), 403)
	if r := it.do("GET", "/api/v1/ich", nil); r.body["betreiber"] != false {
		t.Errorf("ich: betreiber=%v", r.body["betreiber"])
	}
	setOperator(t, "v_it", true)
	r := it.do("GET", "/api/v1/einstellungen", nil)
	expectStatus(t, "Betreiber", r, 200)
	if r := it.do("GET", "/api/v1/ich", nil); r.body["betreiber"] != true {
		t.Errorf("ich: betreiber=%v", r.body["betreiber"])
	}
	// Alle Mandanten mit Namen
	names := map[string]bool{}
	for _, m := range r.body["mandanten"].([]any) {
		names[m.(map[string]any)["name"].(string)] = true
	}
	for _, n := range []string{"IT", "Fertigung", "Lager Nord", "Organisation"} {
		if !names[n] {
			t.Errorf("Mandant %s fehlt: %v", n, names)
		}
	}

	// Ohne Zwei-Faktor wirkt das Kennzeichen nicht.
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = false WHERE id = $1`, ids["v_it"])
	var op bool
	tx, _ := pool.Begin(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_it"])
	tx.QueryRow(ctx, `SELECT openwacht.is_platform_operator()`).Scan(&op)
	tx.Rollback(ctx)
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = true WHERE id = $1`, ids["v_it"])
	if op {
		t.Error("Betreiber ohne Zwei-Faktor")
	}

	// Nur Benutzer des Hauptmandanten.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true WHERE id = $1`, ids["v_fw"]); err == nil ||
		!strings.Contains(err.Error(), "Hauptmandanten") {
		t.Errorf("Betreiber im Untermandanten: %v", err)
	}
	// Die Anwendung kann das Kennzeichen nicht setzen.
	tx, _ = pool.Begin(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_it"])
	_, err := tx.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true WHERE id = $1`, ids["v_it"])
	tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("App setzt Kennzeichen: %v", err)
	}
	// Andere Benutzer: kein Zugriff auf Seite, Tabelle und Mandantenliste.
	for _, u := range []string{"v_fw", "v_oa", "v_lz"} {
		expectStatus(t, u+" liest", as(t, u).do("GET", "/api/v1/einstellungen", nil), 403)
		expectStatus(t, u+" ändert Mandant", as(t, u).do("PUT", "/api/v1/einstellungen/mandanten/"+ids["Fertigung"],
			map[string]any{"netze": []string{"10.0.0.0/8"}, "code": "000000"}), 403)
		tx, _ := pool.Begin(ctx)
		tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[u])
		var n int
		tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.settings`).Scan(&n)
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.settings_tenants()`)
		tx.Rollback(ctx)
		if n != 0 || err == nil {
			t.Errorf("%s: settings %d, settings_tenants %v", u, n, err)
		}
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'betreiber.vergeben' AND details->>'benutzer' = $1`,
		ids["v_it"]).Scan(&audits)
	if audits == 0 {
		t.Error("kein Audit-Eintrag für den Betreiber")
	}
}

func TestEinstellungenGlobal(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	ctx := context.Background()
	s, srv := settingsServer(t, Config{AlertTargets: alarm.NewTargets("https://ntfy.start.invalid"),
		CheckNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Pinned: map[string]bool{setTargets: true}})
	setOperator(t, "v_it", true)
	c := loginOn(t, srv, "v_it")

	r := c.do("GET", "/api/v1/einstellungen", nil)
	expectStatus(t, "lesen", r, 200)
	g := r.body["global"].(map[string]any)
	if q := g[setNets].(map[string]any)["quelle"]; q != "standard" {
		t.Errorf("Netze: Quelle %v", q)
	}
	if q := g[setTargets].(map[string]any)["quelle"]; q != "startoption" {
		t.Errorf("Alarmziele: Quelle %v", q)
	}

	// Netze: nur mit frischem Code.
	body := map[string]any{"netze": []string{"10.0.0.0/8", "172.16.0.10"}}
	if r := c.do("PUT", "/api/v1/einstellungen", body); r.status != 403 || !strings.Contains(r.raw, "aktuellen Code") {
		t.Errorf("ohne Code: %d %s", r.status, r.raw)
	}
	body["code"] = "123456"
	if r := c.do("PUT", "/api/v1/einstellungen", body); r.status != 403 || !strings.Contains(r.raw, "Code") {
		t.Errorf("falscher Code: %d %s", r.status, r.raw)
	}
	body["netze"] = []string{"10.0.0.0/8", "kein-netz"}
	body["code"] = freshCode(t, "v_it")
	expectStatus(t, "ungültiges Netz", c.do("PUT", "/api/v1/einstellungen", body), 400)
	body["netze"] = []string{"10.0.0.0/8", "172.16.0.10"}
	expectStatus(t, "Netze", c.do("PUT", "/api/v1/einstellungen", body), 204)
	if got := s.CheckNetworks(); strings.Join(got, ",") != "10.0.0.0/8,172.16.0.10/32" {
		t.Errorf("wirksame Netze: %v", got)
	}
	// Derselbe Code ein zweites Mal geht nicht.
	expectStatus(t, "Code doppelt", c.do("PUT", "/api/v1/einstellungen", body), 403)

	// Per Startoption gesetzt: gesperrt.
	expectStatus(t, "Alarmziele gesperrt", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"alarmziele": []string{"https://ntfy.sh"}, "code": freshCode(t, "v_it")}), 409)

	// Schwellen ohne Code, aber geprüft.
	expectStatus(t, "Paar falsch", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"schwellen": map[string]any{setDiskWarn: 80, setDiskCrit: 70}}), 400)
	expectStatus(t, "stumm zu kurz", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"schwellen": map[string]any{setSilent: 60}}), 400)
	expectStatus(t, "unbekannt", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"schwellen": map[string]any{"ram": 50}}), 400)
	expectStatus(t, "Schwellen", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"schwellen": map[string]any{setDiskWarn: 80, setDiskCrit: 90, setCPUWarn: 0, setSilent: 600}}), 204)
	if l := s.hostLimits(); l.DiskWarn != 80 || l.DiskCrit != 90 || l.CPUWarn != 0 || l.CPUCrit != 98 || l.SilentAfter != 10*time.Minute {
		t.Errorf("wirksame Schwellen: %+v", l)
	}
	// null = Standard
	expectStatus(t, "Standard", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"schwellen": map[string]any{setCPUWarn: nil}}), 204)
	if l := s.hostLimits(); l.CPUWarn != 90 {
		t.Errorf("CPU-Warnung nach Standard: %v", l.CPUWarn)
	}

	// Totmann: verschlüsselt, nie im Klartext in DB, Audit oder Antwort.
	expectStatus(t, "Totmann http", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"totmann": "http://hc-ping.com/geheim", "code": freshCode(t, "v_it")}), 400)
	expectStatus(t, "Totmann", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"totmann": "https://hc-ping.com/geheim-123", "code": freshCode(t, "v_it")}), 204)
	if !s.DeadManOn() {
		t.Error("Totmann nicht an")
	}
	var enc []byte
	var auditText string
	owner.QueryRow(ctx, `SELECT deadman_enc FROM openwacht.settings`).Scan(&enc)
	owner.QueryRow(ctx, `SELECT string_agg(details::text, ' ') FROM openwacht.audit_log WHERE action LIKE 'einstellungen.%'`).Scan(&auditText)
	if len(enc) == 0 || bytes.Contains(enc, []byte("geheim")) || strings.Contains(auditText, "geheim") {
		t.Errorf("Ping-Adresse im Klartext: enc=%q audit=%s", enc, auditText)
	}
	r = c.do("GET", "/api/v1/einstellungen", nil)
	if strings.Contains(r.raw, "geheim") || !strings.Contains(r.raw, "hc-ping.com") {
		t.Errorf("Antwort: %s", r.raw)
	}
	expectStatus(t, "Totmann aus", c.do("PUT", "/api/v1/einstellungen",
		map[string]any{"totmann": "", "code": freshCode(t, "v_it")}), 204)
	if s.DeadManOn() {
		t.Error("Totmann noch an")
	}

	// Nicht-Betreiber verbrauchen keinen Code und ändern nichts.
	fw := loginOn(t, srv, "v_fw")
	code := freshCode(t, "v_fw")
	expectStatus(t, "Fertigung", fw.do("PUT", "/api/v1/einstellungen", map[string]any{"netze": []string{"0.0.0.0/0"}, "code": code}), 403)
	var last int64
	owner.QueryRow(ctx, `SELECT totp_last_step FROM openwacht.users WHERE id = $1`, ids["v_fw"]).Scan(&last)
	if last != 0 {
		t.Error("Code eines Nicht-Betreibers verbraucht")
	}

	// Übernahme der Startoptionen: nur leere Felder.
	s2, _ := settingsServer(t, Config{CheckNetworks: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}, DiskWarn: 70,
		Pinned: map[string]bool{setNets: true, setDiskWarn: true, setMemWarn: true}})
	n, err := s2.ImportStartOptions(ctx)
	if err != nil || n != 1 { // nur speicher_warn war leer
		t.Errorf("Übernahme: %d %v", n, err)
	}
	var nets []netip.Prefix
	var memWarn *float64
	owner.QueryRow(ctx, `SELECT check_nets, mem_warn FROM openwacht.settings`).Scan(&nets, &memWarn)
	if len(nets) != 2 || memWarn == nil || *memWarn != 90 {
		t.Errorf("nach Übernahme: %v %v", nets, memWarn)
	}
	if got := s2.CheckNetworks(); strings.Join(got, ",") != "172.16.0.0/12" {
		t.Errorf("Startoption gewinnt nicht: %v", got)
	}
	if l := s2.hostLimits(); l.DiskWarn != 70 || l.DiskCrit != 90 {
		t.Errorf("Startoption/DB gemischt: %+v", l)
	}
	if n, _ := s2.ImportStartOptions(ctx); n != 0 {
		t.Errorf("zweite Übernahme: %d", n)
	}
	var imported int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'einstellungen.uebernommen'`).Scan(&imported)
	if imported == 0 {
		t.Error("Übernahme ohne Audit")
	}
}

func TestEinstellungenJeMandant(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	ctx := context.Background()
	s, srv := settingsServer(t, Config{CheckNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.1/32")}, Pinned: map[string]bool{setNets: true}})
	setOperator(t, "v_it", true)
	c := loginOn(t, srv, "v_it")
	path := "/api/v1/einstellungen/mandanten/"

	expectStatus(t, "ohne Code", c.do("PUT", path+ids["Fertigung"], map[string]any{"netze": []string{"10.20.0.0/16"}}), 403)
	expectStatus(t, "unbekannter Mandant", c.do("PUT", path+"00000000-0000-0000-0000-000000000001",
		map[string]any{"netze": []string{"10.20.0.0/16"}, "code": freshCode(t, "v_it")}), 404)
	expectStatus(t, "Fertigung", c.do("PUT", path+ids["Fertigung"],
		map[string]any{"netze": []string{"10.20.0.0/16"}, "schwellen": map[string]any{setDiskWarn: 70}, "code": freshCode(t, "v_it")}), 204)
	// Schwellen ändern ohne Netzänderung: ohne Code.
	expectStatus(t, "nur Schwellen", c.do("PUT", path+ids["Fertigung"],
		map[string]any{"netze": []string{"10.20.0.0/16"}, "schwellen": map[string]any{setDiskWarn: 75}}), 204)
	expectStatus(t, "Lager", c.do("PUT", path+ids["Lager Nord"],
		map[string]any{"netze": []string{"10.20.5.0/24"}, "schwellen": map[string]any{setDiskCrit: 85}, "code": freshCode(t, "v_it")}), 204)

	allowed := func(tenant, addr string) bool { return s.guardFor(ids[tenant]).Allowed(netip.MustParseAddr(addr)) }
	for _, x := range []struct {
		tenant, addr string
		want         bool
	}{
		{"Fertigung", "10.20.1.1", true}, {"Fertigung", "10.30.0.1", false}, {"Fertigung", "127.0.0.1", false},
		{"Lager Nord", "10.20.5.1", true}, {"Lager Nord", "10.20.6.1", false},
		{"Organisation", "10.30.0.1", true}, {"IT", "127.0.0.1", true},
	} {
		if got := allowed(x.tenant, x.addr); got != x.want {
			t.Errorf("%s → %s: %v, erwartet %v", x.tenant, x.addr, got, x.want)
		}
	}
	// Der Check eines Fertigung-Geräts erreicht 127.0.0.1 nicht mehr, der der IT schon.
	spec, _ := checks.Parse("tcp", []byte(`{"host":"127.0.0.1","port":1}`))
	if res := s.runnerFor(ids["Fertigung"]).Run(ctx, "tcp", spec); !strings.Contains(res.Message, "nicht freigegeben") {
		t.Errorf("Fertigung-Check: %+v", res)
	}
	if res := s.runnerFor(ids["IT"]).Run(ctx, "tcp", spec); strings.Contains(res.Message, "nicht freigegeben") {
		t.Errorf("IT-Check: %+v", res)
	}

	// Schwellen entlang des Baums: Lager erbt die Warnung der Fertigung.
	var lzDev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'ES Pumpe') RETURNING id::text`, ids["Lager Nord"]).Scan(&lzDev)
	agent, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, device_id, hostname, cert_serial, cert_not_after, last_seen)
		VALUES ($1, $2, $3, 'es-pumpe', 'es', now() + interval '30 days', now())`, agent, ids["Lager Nord"], lzDev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, agent)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, lzDev)
	})
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if l := s.limitsFor("agent", agent); l.DiskWarn != 75 || l.DiskCrit != 85 || l.MemWarn != 90 {
		t.Errorf("Lager-Agent: %+v", l)
	}
	// Gerät gewinnt über den Mandanten.
	expectStatus(t, "Gerät", as(t, "v_it").do("PUT", "/api/v1/geraete/"+lzDev+"/schwellen",
		map[string]any{"schwellen": map[string]any{setDiskWarn: 50, setSilent: 900}}), 204)
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if l := s.limitsFor("agent", agent); l.DiskWarn != 50 || l.DiskCrit != 85 || l.SilentAfter != 15*time.Minute {
		t.Errorf("mit Geräteschwelle: %+v", l)
	}
	r := as(t, "v_lz").do("GET", "/api/v1/geraete/"+lzDev+"/schwellen", nil)
	expectStatus(t, "Leser liest", r, 200)
	if r.body["darf_aendern"] != false || r.body["mandant"].(map[string]any)[setDiskWarn] != 75.0 ||
		r.body["eigene"].(map[string]any)[setDiskWarn] != 50.0 || r.body["wirksam"].(map[string]any)[setDiskWarn] != 50.0 {
		t.Errorf("Schwellen Gerät: %s", r.raw)
	}

	// Alles auf null: Zeile weg.
	expectStatus(t, "zurücksetzen", c.do("PUT", path+ids["Lager Nord"], map[string]any{"code": freshCode(t, "v_it")}), 204)
	var rows int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.tenant_settings WHERE tenant_id = $1`, ids["Lager Nord"]).Scan(&rows)
	if rows != 0 {
		t.Error("Mandantenzeile bleibt")
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'einstellungen.mandant%' AND tenant_id = $1`,
		ids["Lager Nord"]).Scan(&audits)
	if audits < 2 {
		t.Errorf("Audit je Mandant: %d", audits)
	}
}

func TestGeraetSchwellenRechte(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	r := newDevice(t, "v_fw", "Fertigung", "GS Server", "")
	expectStatus(t, "Gerät", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(context.Background(), `DELETE FROM openwacht.devices WHERE id = $1`, id) })
	path := "/api/v1/geraete/" + id + "/schwellen"
	body := map[string]any{"schwellen": map[string]any{setMemWarn: 80}}

	expectStatus(t, "Geschwister liest", as(t, "v_oa").do("GET", path, nil), 404)
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", path, body), 404)
	expectStatus(t, "Kind liest", as(t, "v_lz").do("GET", path, nil), 404)
	expectStatus(t, "Eltern liest", as(t, "v_it").do("GET", path, nil), 200)
	expectStatus(t, "Fertigung ändert", as(t, "v_fw").do("PUT", path, body), 204)
	expectStatus(t, "Paar falsch", as(t, "v_fw").do("PUT", path, map[string]any{"schwellen": map[string]any{setMemWarn: 99, setMemCrit: 95}}), 400)

	// RLS: Leser im eigenen Mandanten schreibt nicht.
	ctx := context.Background()
	lzDev := ""
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'GS Leser') RETURNING id::text`, ids["Lager Nord"]).Scan(&lzDev)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, lzDev) })
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/geraete/"+lzDev+"/schwellen", body), 403)
	tx, _ := pool.Begin(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_lz"])
	_, err := tx.Exec(ctx, `INSERT INTO openwacht.device_limits (device_id, mem_warn) VALUES ($1, 50)`, lzDev)
	tx.Rollback(ctx)
	if err == nil {
		t.Error("Leser schreibt device_limits")
	}
	// Mandant kommt aus dem Gerät, nicht aus der Anfrage.
	var tenant string
	owner.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.device_limits WHERE device_id = $1`, id).Scan(&tenant)
	if tenant != ids["Fertigung"] {
		t.Errorf("Mandant der Schwellen: %s", tenant)
	}
}
