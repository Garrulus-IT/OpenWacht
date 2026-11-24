// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/safe"
)

// watchServer: eigener Server mit eigenem ntfy, Kanal im Hauptmandanten
// (Hinweise an den Betreiber) und in der Fertigung (Hinweise an Mandanten).
func watchServer(t *testing.T) (*Server, *fakeNtfy) {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	t.Cleanup(f.Close)
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	cfg.SelfWatchDisks = []string{t.TempDir()}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := alarm.NormalizeServer(f.URL)
	for _, c := range []struct{ tenant, topic string }{{"IT", "betrieb"}, {"Fertigung", "fw"}} {
		id, _ := newUUID()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, $3, $4, $5)`,
			id, ids[c.tenant], "w31-"+c.topic, server, c.topic); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, id) })
	}
	clean := func() {
		owner.Exec(ctx, `DELETE FROM openwacht.notices`)
		owner.Exec(ctx, `DELETE FROM openwacht.backup_log`)
		owner.Exec(ctx, `DELETE FROM openwacht.trap_service_state`)
	}
	clean()
	t.Cleanup(clean)
	safe.ResetForTest()
	t.Cleanup(safe.ResetForTest)
	return s, f
}

func round(t *testing.T, s *Server, f *fakeNtfy) map[string][]ntfyMsg {
	t.Helper()
	if err := s.SelfWatchRound(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f.take()
}

func TestHinweisSicherungAnBetreiber(t *testing.T) {
	s, f := watchServer(t)
	ctx := context.Background()
	// Ohne jede Sicherung: kein Hinweis (Installation ohne Timer).
	if got := round(t, s, f); len(got) != 0 {
		t.Fatalf("ohne Sicherungen: %+v", got)
	}
	owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, ok, message) VALUES (now() - interval '1 hour', false, 'pg_dump: Platte voll')`)
	got := round(t, s, f)
	if len(got["betrieb"]) != 1 || len(got["fw"]) != 0 {
		t.Fatalf("Versand: %+v", got)
	}
	m := got["betrieb"][0]
	if !strings.Contains(m.Title, "Sicherung fehlgeschlagen") || !strings.Contains(m.Message, "Platte voll") || m.Priority != 5 {
		t.Fatalf("Meldung: %+v", m)
	}
	// Kein zweites Mal, solange sich nichts ändert.
	if got := round(t, s, f); len(got) != 0 {
		t.Fatalf("doppelt: %+v", got)
	}
	// Sichtbar für den Betreiber, nicht für andere Admins.
	setOperator(t, "v_it", true)
	t.Cleanup(func() { setOperator(t, "v_it", false) })
	r := as(t, "v_it").do("GET", "/api/v1/hinweise", nil)
	if !strings.Contains(r.raw, "zentrale:sicherung") {
		t.Errorf("Betreiber sieht den Hinweis nicht: %s", r.raw)
	}
	for _, u := range []string{"v_fw", "v_oa"} {
		if r := as(t, u).do("GET", "/api/v1/hinweise", nil); r.status != 200 || strings.Contains(r.raw, "zentrale:") {
			t.Errorf("%s sieht Hinweise der Zentrale: %s", u, r.raw)
		}
	}
	setOperator(t, "v_it", false)
	if r := as(t, "v_it").do("GET", "/api/v1/hinweise", nil); strings.Contains(r.raw, "zentrale:") {
		t.Error("Admin ohne Betreiber-Kennzeichen sieht Hinweise der Zentrale")
	}
	// Neue erfolgreiche Sicherung: Entwarnung.
	owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok) VALUES (now(), 'openwacht-20261122T020000Z.dump', 1000, true)`)
	got = round(t, s, f)
	if len(got["betrieb"]) != 1 || !strings.HasPrefix(strings.TrimLeft(got["betrieb"][0].Title, "✅ "), "OpenWacht: Erledigt") {
		t.Fatalf("Entwarnung: %+v", got)
	}
	// Überfällig: letzte erfolgreiche älter als 26 Stunden
	owner.Exec(ctx, `UPDATE openwacht.backup_log SET started_at = started_at - interval '2 days'`)
	got = round(t, s, f)
	if len(got["betrieb"]) != 1 || !strings.Contains(got["betrieb"][0].Title, "überfällig") {
		t.Fatalf("überfällig: %+v", got)
	}
}

// Konnte ein Hinweis nie zugestellt werden und ist das Problem vorbei, kommt
// auch keine Entwarnung (sie wäre für etwas, das niemand erfahren hat).
func TestHinweisKeineEntwarnungOhneMeldung(t *testing.T) {
	s, f := watchServer(t)
	ctx := context.Background()
	owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, ok, message) VALUES (now(), false, 'kaputt')`)
	f.setFail("betrieb", true)
	if err := s.SelfWatchRound(ctx); err == nil {
		t.Fatal("Fehler beim Versand nicht gemeldet")
	}
	f.take()
	owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok) VALUES (now() + interval '1 second', 'openwacht-20261122T030000Z.dump', 1, true)`)
	f.setFail("betrieb", false)
	if got := round(t, s, f); len(got) != 0 {
		t.Fatalf("Entwarnung ohne vorige Meldung: %+v", got)
	}
}

func TestHinweisProgrammfehlerUndTraps(t *testing.T) {
	s, f := watchServer(t)
	ctx := context.Background()
	safe.Handle("snmp", "Test")
	// Trap-Dienst hat sich vor 10 Minuten zuletzt gemeldet
	owner.Exec(ctx, `INSERT INTO openwacht.trap_service_state (seen_at) VALUES (now() - interval '10 minutes')`)
	got := round(t, s, f)
	var titles []string
	for _, m := range got["betrieb"] {
		titles = append(titles, m.Title)
	}
	all := strings.Join(titles, "|")
	if !strings.Contains(all, "Programmfehler abgefangen") || !strings.Contains(all, "Trap-Dienst meldet sich nicht") {
		t.Fatalf("Hinweise: %v", titles)
	}
	for _, m := range got["betrieb"] {
		if strings.Contains(m.Title, "Programmfehler") && !strings.Contains(m.Message, "snmp") {
			t.Errorf("Bereich fehlt: %s", m.Message)
		}
	}
	// Trap-Dienst meldet sich wieder (über die Funktion der Trap-Rolle)
	if _, err := owner.Exec(ctx, `SELECT openwacht.traps_heartbeat()`); err != nil {
		t.Fatal(err)
	}
	got = round(t, s, f)
	if len(got["betrieb"]) != 1 || !strings.Contains(got["betrieb"][0].Title, "Erledigt: Trap-Dienst") {
		t.Fatalf("Entwarnung Traps: %+v", got)
	}
	// Die App-Rolle kann das Lebenszeichen nicht fälschen.
	if _, err := pool.Exec(ctx, `SELECT openwacht.traps_heartbeat()`); err == nil {
		t.Error("App-Rolle darf das Lebenszeichen des Trap-Dienstes setzen")
	}
}

func TestHinweisZertifikateUndPlatte(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		left time.Duration
		want string
	}{{30 * 24 * time.Hour, ""}, {20 * 24 * time.Hour, alarm.Warn}, {6 * 24 * time.Hour, alarm.Crit}, {-time.Hour, alarm.Crit}} {
		if got := expiryStatus(now.Add(c.left), now, certWarnDays, certCritDays); got != c.want {
			t.Errorf("%v: %q, erwartet %q", c.left, got, c.want)
		}
	}
	d := diskUsage([]string{"/", "/", t.TempDir(), "/gibt/es/nicht"})
	if len(d) == 0 || d[0].path != "/" || d[0].pct <= 0 || d[0].pct > 100 {
		t.Fatalf("Platten: %+v", d)
	}
	for _, x := range d[1:] {
		if x.path == "/" {
			t.Error("gleiches Dateisystem doppelt")
		}
	}
	if k := diskKey("/var/lib/postgresql"); k != "var_lib_postgresql" || diskKey("/") != "wurzel" {
		t.Errorf("Schlüssel: %q %q", k, diskKey("/"))
	}
	// Agent-CA kurz vor Ablauf
	s, _ := watchServer(t)
	if err := s.InitAgentCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.agent.mu.Lock()
	notAfter := s.agent.ca.Cert.NotAfter
	s.agent.mu.Unlock()
	if !hasNotice(s.selfNotices(context.Background(), notAfter.Add(-30*24*time.Hour)), "zentrale:agent-ca", alarm.Crit) {
		t.Error("kein Hinweis zur Agent-CA")
	}
	if hasNotice(s.selfNotices(context.Background(), time.Now()), "zentrale:agent-ca", alarm.Crit) {
		t.Error("Hinweis zur frischen Agent-CA")
	}
}

// N2: Alarme, die eine Abhängigkeit seit 7 Tagen unterdrückt, ergeben einen
// Hinweis an den Mandanten; die Liste zeigt jede Unterdrückung mit Beginn.
func TestHinweisUnterdrueckteAlarme(t *testing.T) {
	s, f := watchServer(t)
	ctx := context.Background()
	var router, cRouter, server string
	if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'w31-router') RETURNING id)
		INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, 'Ping', 'ping', '{"host":"x.lan"}', 60 FROM d
		RETURNING device_id::text, id::text`, ids["Lager Nord"]).Scan(&router, &cRouter); err != nil {
		t.Fatal(err)
	}
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, parent_id) VALUES ($1, 'w31-server', $2) RETURNING id::text`,
		ids["Lager Nord"], router).Scan(&server)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE check_id = $1`, cRouter)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id IN ($1, $2)`, server, router)
	})
	// Router seit 3 Tagen ausgefallen
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at)
		VALUES ($1, $2, 'check', 'w31-router · Ping', 'crit', 'crit', now() - interval '3 days', now())`, ids["Lager Nord"], cRouter); err != nil {
		t.Fatal(err)
	}
	list := func(user string) string { return as(t, user).do("GET", "/api/v1/hinweise", nil).raw }
	if l := list("v_fw"); !strings.Contains(l, `"geraet":"w31-router"`) || !strings.Contains(l, `"w31-server"`) {
		t.Fatalf("Fertigung sieht die Unterdrückung nicht: %s", l)
	}
	if l := list("v_it"); !strings.Contains(l, `"geraet":"w31-router"`) {
		t.Error("Eltern sieht die Unterdrückung nicht")
	}
	if l := list("v_oa"); strings.Contains(l, "w31-router") {
		t.Error("Geschwister sieht die Unterdrückung")
	}
	if got := round(t, s, f); len(got["fw"]) != 0 {
		t.Fatalf("Hinweis vor 7 Tagen: %+v", got)
	}
	var early int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.notices WHERE key LIKE 'unterdrueckt:%'`).Scan(&early)
	if early != 0 {
		t.Fatalf("Hinweis nach 3 Tagen angelegt")
	}
	// seit 8 Tagen
	owner.Exec(ctx, `UPDATE openwacht.alarms SET started_at = now() - interval '8 days' WHERE check_id = $1`, cRouter)
	// Der Lager hat keinen Kanal; der Hinweis geht an den Mandanten der
	// Geräte, nicht an die Eltern: Versand an niemanden, aber vermerkt.
	if got := round(t, s, f); len(got) != 0 {
		t.Fatalf("Versand: %+v", got)
	}
	var sent *string
	owner.QueryRow(ctx, `SELECT sent_status FROM openwacht.notices WHERE key = 'unterdrueckt:' || $1`, router).Scan(&sent)
	if sent == nil || *sent != "warn" {
		t.Fatalf("Hinweis nicht als verschickt vermerkt: %v", sent)
	}
	if l := list("v_lz"); !strings.Contains(l, "Alarme seit 8 Tagen unterdrückt") {
		t.Errorf("Leser im Lager sieht den Hinweis nicht: %s", l)
	}
	if l := list("v_oa"); strings.Contains(l, "unterdrückt") {
		t.Error("Geschwister sieht den Hinweis")
	}
	// Mit Kanal im Lager wird er nach einer Entwarnung erneut gemeldet.
	owner.Exec(ctx, `UPDATE openwacht.devices SET parent_id = NULL WHERE id = $1`, server)
	round(t, s, f)
	server2, _ := alarm.NormalizeServer(f.URL)
	owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, server, topic) VALUES ($1, 'w31-lz', $2, 'lz')`, ids["Lager Nord"], server2)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE name = 'w31-lz'`) })
	owner.Exec(ctx, `UPDATE openwacht.devices SET parent_id = $2 WHERE id = $1`, server, router)
	got := round(t, s, f)
	if len(got["lz"]) != 1 || !strings.Contains(got["lz"][0].Message, "w31-router") || len(got["fw"]) != 0 {
		t.Fatalf("an das Lager: %+v", got)
	}
}

func TestGesund(t *testing.T) {
	s, _ := watchServer(t)
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	get := func() response { return newClient(t, hs).do("GET", "/api/v1/gesund", nil) }
	r := get()
	expectStatus(t, "gesund", r, 200)
	if r.body["status"] != "ok" || r.body["datenbank"] != "ok" || r.body["planer"] != "aus" || r.body["traps"] != "aus" {
		t.Fatalf("Zustand: %s", r.raw)
	}
	beat(&s.beats.checks, time.Now())
	beat(&s.beats.alerts, time.Now())
	owner.Exec(context.Background(), `SELECT openwacht.traps_heartbeat()`)
	if r := get(); r.body["planer"] != "ok" || r.body["traps"] != "ok" {
		t.Fatalf("laufend: %s", r.raw)
	}
	beat(&s.beats.checks, time.Now().Add(-time.Hour))
	owner.Exec(context.Background(), `UPDATE openwacht.trap_service_state SET seen_at = now() - interval '1 hour'`)
	r = get()
	expectStatus(t, "Planer steht", r, 503)
	if r.body["planer"] != "verzoegert" || r.body["traps"] != "stumm" || r.body["status"] != "gestoert" {
		t.Fatalf("gestört: %s", r.raw)
	}
	// keine Interna
	for _, k := range []string{"fehler", "version", "eintraege"} {
		if strings.Contains(r.raw, k) {
			t.Errorf("Ausgabe enthält %q: %s", k, r.raw)
		}
	}
}
