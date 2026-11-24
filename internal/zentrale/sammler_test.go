// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/agent"
	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

// resetLimits: Die Sammler-Tests registrieren viele Agents und prüfen eine
// Verbindung; danach sollen andere Tests nicht in die Rate Limits laufen.
func resetLimits(t *testing.T) {
	t.Cleanup(func() {
		vServer.agent.limiter = newIPLimiter(vServer.cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
		vServer.snmpProbeLimit = perKeyLimit{every: 3 * time.Second}
	})
}

// collectorAgent registriert einen Agent und meldet ihn mit Netzen als
// Sammler (nets leer = ohne Freigabe).
func collectorAgent(t *testing.T, user, tenant, host string, nets ...string) *testAgent {
	t.Helper()
	tok, r := newAgentToken(t, user, tenant, 1)
	expectStatus(t, "Token", r, 201)
	vServer.agent.limiter = newIPLimiter(vServer.cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
	a, status, body := register(t, tok, host)
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	a.reportNets(host, nets...)
	t.Cleanup(func() {
		ctx := context.Background()
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE agent_id = $1 OR snmp_id IN (SELECT id FROM openwacht.snmp_sources WHERE collector_id = $1)`, a.id)
		owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = NULL WHERE collector_id = $1`, a.id)
	})
	return a
}

func (a *testAgent) reportNets(host string, nets ...string) {
	a.t.Helper()
	snap := validSnapshot(host)
	if len(nets) > 0 {
		snap.Collector = &agentproto.Collector{Nets: nets}
	}
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathReport, snap)
	if err != nil || status != 200 {
		a.t.Fatalf("Meldung: %d %s %v", status, body, err)
	}
}

func (a *testAgent) devices(state string) (int, agentproto.CollectorDevicesResponse, string) {
	a.t.Helper()
	vServer.collectorListLimit = perKeyLimit{every: time.Nanosecond} // in Tests ohne Wartezeit
	var out agentproto.CollectorDevicesResponse
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathCollectorDevices, agentproto.CollectorDevicesRequest{State: state})
	if err != nil {
		a.t.Fatal(err)
	}
	if status == 200 {
		if err := json.Unmarshal(body, &out); err != nil {
			a.t.Fatal(err)
		}
	}
	return status, out, string(body)
}

func (a *testAgent) result(res agentproto.CollectorResult) (int, string) {
	a.t.Helper()
	vServer.collectorResultLimit = perKeyLimit{every: time.Nanosecond}
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathCollectorResult, res)
	if err != nil {
		a.t.Fatal(err)
	}
	return status, string(body)
}

// collectedSnapshot: ein Snapshot, wie ihn ein ehrlicher Sammler schickt.
func collectedSnapshot(t *testing.T, at time.Time, ticks uint32, inOctets uint64) json.RawMessage {
	t.Helper()
	s := snmp.Snapshot{CollectedAt: at.UTC(), System: snmp.System{Descr: "Switch", Name: "sw-fw", UptimeTicks: ticks, UptimeS: uint64(ticks) / 100},
		Disks: []snmp.Disk{}, Supplies: []snmp.Supply{},
		Interfaces: []snmp.Interface{{Index: 1, Name: "Port 1", Oper: "up", AdminUp: true, SpeedBps: 1e9, HC: true, InOctets: inOctets, OutOctets: inOctets}},
		Memory:     &snmp.Memory{TotalBytes: 100, AvailableBytes: 50},
		Counters:   &snmp.CounterInfo{At: at.UTC(), UptimeTicks: ticks}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSammlerZuweisung(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	plain := collectorAgent(t, "v_fw", "Fertigung", "fw-ohne")
	coll := collectorAgent(t, "v_fw", "Fertigung", "fw-sammler", "10.20.0.0/16", "127.0.0.1/32")
	oa := collectorAgent(t, "v_oa", "Organisation", "oa-sammler", "10.30.0.0/16")

	// Wer sieht welchen Sammler zur Auswahl?
	sees := func(user, id string) bool {
		r := as(t, user).do("GET", "/api/v1/snmp", nil)
		expectStatus(t, "Liste "+user, r, 200)
		for _, x := range r.body["sammler"].([]any) {
			if e := x.(map[string]any); e["id"] == id {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		user, id string
		want     bool
	}{{"v_fw", coll.id, true}, {"v_it", coll.id, true}, {"v_oa", coll.id, false}, {"v_lz", coll.id, false},
		{"v_fw", plain.id, false}, {"v_oa", oa.id, true}, {"v_fw", oa.id, false}} {
		if got := sees(c.user, c.id); got != c.want {
			t.Errorf("%s sieht Sammler %s: %v, erwartet %v", c.user, c.id, got, c.want)
		}
	}

	r := newDevice(t, "v_fw", "Fertigung", "SA Switch", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/snmp"
	with := func(addr, collector string, extra map[string]any) map[string]any {
		b := snmpBody(addr, extra)
		b["sammler"] = collector
		return b
	}
	expectStatus(t, "ohne Freigabe", as(t, "v_fw").do("PUT", path, with("10.20.1.1", plain.id, nil)), 400)
	expectStatus(t, "fremder Mandant", as(t, "v_fw").do("PUT", path, with("10.20.1.1", oa.id, nil)), 400)
	expectStatus(t, "unbekannt", as(t, "v_fw").do("PUT", path, with("10.20.1.1", "00000000-0000-4000-8000-000000000000", nil)), 400)
	expectStatus(t, "keine ID", as(t, "v_fw").do("PUT", path, with("10.20.1.1", "x", nil)), 400)
	expectStatus(t, "außerhalb der Netze", as(t, "v_fw").do("PUT", path, with("10.21.1.1", coll.id, nil)), 400)
	expectStatus(t, "mit Traps", as(t, "v_fw").do("PUT", path, with("10.20.1.1", coll.id, map[string]any{"traps": true})), 400)
	// Ohne Sammler gilt -check-netze der Zentrale (hier: nichts freigegeben)
	expectStatus(t, "Zentrale ohne Freigabe", as(t, "v_fw").do("PUT", path, snmpBody("10.20.1.1", nil)), 400)
	r = as(t, "v_fw").do("PUT", path, with("10.20.1.1", coll.id, nil))
	expectStatus(t, "mit Sammler", r, 201)
	id := r.body["id"].(string)
	if e, _ := snmpEntry(t, "v_it", id); e["sammler"] != coll.id {
		t.Errorf("Eintrag: %+v", e)
	}
	// Ändern ohne Feld „sammler“ lässt ihn stehen; Namen prüft erst der Sammler.
	expectStatus(t, "ändern", as(t, "v_fw").do("PUT", path, map[string]any{"version": "2c", "adresse": "10.20.1.1", "intervall_sekunden": 120}), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["sammler"] != coll.id || e["intervall_sekunden"] != 120.0 || e["hat_community"] != true {
		t.Errorf("nach Ändern: %+v", e)
	}
	// Eltern dürfen zuweisen, aber nur einen Sammler im Mandanten des Geräts.
	lz := newDevice(t, "v_fw", "Lager Nord", "SA LZ", "")
	lzPath := "/api/v1/geraete/" + lz.body["id"].(string) + "/snmp"
	expectStatus(t, "Sammler der Eltern für das Kind", as(t, "v_fw").do("PUT", lzPath, with("10.20.1.2", coll.id, nil)), 400)
	// Geschwister sieht den Sammler nicht
	oaDev := newDevice(t, "v_oa", "Organisation", "SA OA", "")
	expectStatus(t, "Geschwister nimmt fremden Sammler", as(t, "v_oa").do("PUT", "/api/v1/geraete/"+oaDev.body["id"].(string)+"/snmp",
		with("10.20.1.3", coll.id, nil)), 400)

	// Verbindung prüfen geht nur von der Zentrale aus.
	time.Sleep(3100 * time.Millisecond)
	expectStatus(t, "prüfen mit Sammler", as(t, "v_fw").do("POST", path+"/pruefen", with("10.20.1.1", coll.id, nil)), 400)

	// Die Zentrale fragt Quellen mit Sammler nicht selbst ab.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() - interval '1 hour' WHERE id = $1`, id)
	due, err := vServer.claimSNMP(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range due {
		if c.id == id {
			t.Error("Zentrale beansprucht Quelle mit Sammler")
		}
		owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
	}

	// Datenbank: kein Sammler aus einem anderen Mandanten, kein Proxmox mit Sammler.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = $2 WHERE id = $1`, id, oa.id); err == nil {
		t.Error("Datenbank nimmt Sammler aus anderem Mandanten")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = true WHERE id = $1`, id); err == nil {
		t.Error("Datenbank nimmt Traps mit Sammler")
	}

	// Gesperrter Sammler lässt sich nicht löschen, solange er Geräte hat, und nicht neu zuweisen.
	expectStatus(t, "sperren", as(t, "v_fw").do("POST", "/api/v1/agents/"+coll.id+"/sperren", nil), 204)
	expectStatus(t, "löschen mit Geräten", as(t, "v_fw").do("DELETE", "/api/v1/agents/"+coll.id, nil), 409)
	dev2 := newDevice(t, "v_fw", "Fertigung", "SA Switch 2", "")
	expectStatus(t, "gesperrter Sammler", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev2.body["id"].(string)+"/snmp",
		with("10.20.1.4", coll.id, nil)), 400)
	// zurück auf die Zentrale: Sammler leer
	expectStatus(t, "Zentrale wählen ohne Freigabe", as(t, "v_fw").do("PUT", path, map[string]any{"version": "2c", "adresse": "10.20.1.1", "sammler": ""}), 400)
	vServer.guard = checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	defer func() { vServer.guard = checks.NewGuard(nil) }()
	expectStatus(t, "Zentrale wählen", as(t, "v_fw").do("PUT", path, map[string]any{"version": "2c", "adresse": "10.20.1.1", "sammler": ""}), 200)
	if e, _ := snmpEntry(t, "v_fw", id); e["sammler"] != nil || e["hat_community"] != true {
		t.Errorf("zurück zur Zentrale: %+v", e)
	}
	expectStatus(t, "löschen ohne Geräte", as(t, "v_fw").do("DELETE", "/api/v1/agents/"+coll.id, nil), 204)
	expectStatus(t, "SNMP entfernen", as(t, "v_fw").do("DELETE", path, nil), 204)
}

func TestSammlerAgentPort(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	coll := collectorAgent(t, "v_fw", "Fertigung", "fw-port", "10.40.0.0/16")
	other := collectorAgent(t, "v_fw", "Fertigung", "fw-port-2", "10.40.0.0/16")
	plain := collectorAgent(t, "v_fw", "Fertigung", "fw-port-ohne")

	r := newDevice(t, "v_fw", "Fertigung", "SP Switch", "")
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/snmp"
	r = as(t, "v_fw").do("PUT", path, map[string]any{"version": "2c", "adresse": "10.40.0.9", "community": testCommunity, "sammler": coll.id})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	r3 := newDevice(t, "v_fw", "Fertigung", "SP NAS", "")
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+r3.body["id"].(string)+"/snmp", map[string]any{"version": "3", "adresse": "nas.fw.lan",
		"v3":      map[string]any{"benutzer": "monitor", "auth": "sha256", "auth_passwort": "auth-pass-123", "priv": "aes", "priv_passwort": "priv-pass-123"},
		"sammler": coll.id})
	expectStatus(t, "v3 anlegen", r, 201)
	id3 := r.body["id"].(string)

	// Liste mit Zugangsdaten, danach „unverändert“ ohne
	status, list, body := coll.devices("")
	if status != 200 || len(list.Devices) != 2 || list.Unchanged {
		t.Fatalf("Liste: %d %s", status, body)
	}
	for _, d := range list.Devices {
		switch d.ID {
		case id:
			if d.Community != testCommunity || d.V3 != nil || d.Host != "10.40.0.9" || d.Port != 161 || d.IntervalSeconds != 60 || d.Revision < 1 {
				t.Errorf("Gerät: %+v", d)
			}
		case id3:
			if d.V3 == nil || d.V3.User != "monitor" || d.V3.PrivPass != "priv-pass-123" || d.Community != "" {
				t.Errorf("v3-Gerät: %+v", d)
			}
		default:
			t.Errorf("fremdes Gerät %s", d.ID)
		}
	}
	status, again, body := coll.devices(list.State)
	if status != 200 || !again.Unchanged || len(again.Devices) != 0 || strings.Contains(body, testCommunity) || again.State != list.State {
		t.Errorf("unverändert: %d %s", status, body)
	}
	var seen *time.Time
	owner.QueryRow(ctx, `SELECT collector_seen_at FROM openwacht.agents WHERE id = $1`, coll.id).Scan(&seen)
	if seen == nil || time.Since(*seen) > time.Minute {
		t.Errorf("Abruf nicht vermerkt: %v", seen)
	}

	// Andere Agents bekommen nichts und dürfen nichts melden.
	if _, l, _ := other.devices(""); len(l.Devices) != 0 {
		t.Errorf("anderer Sammler sieht %d Geräte", len(l.Devices))
	}
	if _, l, _ := plain.devices(""); len(l.Devices) != 0 {
		t.Error("Agent ohne Freigabe bekommt Geräte")
	}
	owner.QueryRow(ctx, `SELECT collector_seen_at FROM openwacht.agents WHERE id = $1`, plain.id).Scan(&seen)
	if seen != nil {
		t.Error("Abruf ohne Freigabe vermerkt")
	}
	rev := list.Devices[0].Revision
	for _, d := range list.Devices {
		if d.ID == id {
			rev = d.Revision
		}
	}
	now := time.Now()
	ok := agentproto.CollectorResult{ID: id, Revision: rev, OK: true, Snapshot: collectedSnapshot(t, now, 100000, 1000)}
	if st, b := other.result(ok); st != 404 {
		t.Errorf("fremder Sammler meldet: %d %s", st, b)
	}
	if st, _ := plain.result(ok); st != 404 {
		t.Errorf("Agent ohne Freigabe meldet: %d", st)
	}
	// Zweite Schicht: Auch die Datenbank speichert nur für den zugewiesenen Sammler.
	var dbStored bool
	var serial string
	owner.QueryRow(ctx, `SELECT cert_serial FROM openwacht.agents WHERE id = $1`, other.id).Scan(&serial)
	if err := pool.QueryRow(ctx, `SELECT openwacht.collector_record($1, $2, $3, $4, false, 'x', NULL, false, '{}', '{}')`,
		other.id, serial, id, rev).Scan(&dbStored); err != nil || dbStored {
		t.Errorf("collector_record für fremden Sammler: %v %v", dbStored, err)
	}
	if err := pool.QueryRow(ctx, `SELECT openwacht.collector_record($1, 'falsch', $2, $3, false, 'x', NULL, false, '{}', '{}')`,
		coll.id, id, rev).Scan(&dbStored); err != nil || dbStored {
		t.Errorf("collector_record mit falscher Seriennummer: %v %v", dbStored, err)
	}

	// Ergebnis speichern; die Zentrale rechnet die Raten selbst.
	if st, b := coll.result(ok); st != 204 {
		t.Fatalf("Ergebnis: %d %s", st, b)
	}
	second := collectedSnapshot(t, now.Add(60*time.Second), 106000, 1000+7_500_000)
	var s2 snmp.Snapshot
	json.Unmarshal(second, &s2)
	fake := 1e12
	s2.Interfaces[0].InBps = &fake // gefälschte Rate wird verworfen
	second, _ = json.Marshal(s2)
	vServer.now = func() time.Time { return now.Add(60 * time.Second) }
	st, b := coll.result(agentproto.CollectorResult{ID: id, Revision: rev, OK: true, Snapshot: second})
	vServer.now = time.Now
	if st != 204 {
		t.Fatalf("zweites Ergebnis: %d %s", st, b)
	}
	var raw []byte
	var lastOK *time.Time
	var nRaw int
	owner.QueryRow(ctx, `SELECT snapshot, last_ok FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&raw, &lastOK)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.metrics_snmp_raw WHERE snmp_id = $1`, id).Scan(&nRaw)
	var stored snmp.Snapshot
	json.Unmarshal(raw, &stored)
	if lastOK == nil || len(stored.Interfaces) != 1 || stored.Interfaces[0].InBps == nil || *stored.Interfaces[0].InBps != 1e6 || nRaw == 0 {
		t.Errorf("gespeichert: ok %v, Schnittstellen %+v, Verlauf %d", lastOK, stored.Interfaces, nRaw)
	}

	// Negativfälle
	bad := func(what string, mod func(*snmp.Snapshot), want int) {
		t.Helper()
		var s snmp.Snapshot
		json.Unmarshal(collectedSnapshot(t, time.Now(), 200000, 5), &s)
		mod(&s)
		raw, _ := json.Marshal(s)
		if st, b := coll.result(agentproto.CollectorResult{ID: id, Revision: rev, OK: true, Snapshot: raw}); st != want {
			t.Errorf("%s: %d %s", what, st, b)
		}
	}
	bad("Proxmox", func(s *snmp.Snapshot) { s.Proxmox = &snmp.Proxmox{} }, 400)
	bad("Steuerzeichen", func(s *snmp.Snapshot) { s.System.Name = "a\u202eb" }, 400)
	bad("Zeit", func(s *snmp.Snapshot) { s.CollectedAt = s.CollectedAt.Add(-time.Hour); s.Counters.At = s.CollectedAt }, 400)
	bad("Zähler", func(s *snmp.Snapshot) { s.Counters.UptimeTicks++ }, 400)
	bad("frei > gesamt", func(s *snmp.Snapshot) { s.Memory.AvailableBytes = 1000 }, 400)
	bad("zu viele", func(s *snmp.Snapshot) {
		for i := 0; i <= snmp.MaxInterfaces; i++ {
			s.Interfaces = append(s.Interfaces, snmp.Interface{Index: 10 + i, Name: "x", Oper: "up"})
		}
	}, 400)
	if st, _ := coll.result(agentproto.CollectorResult{ID: id, Revision: rev + 1, OK: true, Snapshot: collectedSnapshot(t, time.Now(), 1, 1)}); st != 409 {
		t.Errorf("falsche Revision: %d", st)
	}
	if st, _ := coll.result(agentproto.CollectorResult{ID: "x", Revision: rev}); st != 400 {
		t.Errorf("ID: %d", st)
	}
	if st, _ := coll.result(agentproto.CollectorResult{ID: id, Revision: rev, OK: false, Snapshot: collectedSnapshot(t, time.Now(), 1, 1)}); st != 400 {
		t.Errorf("Messwerte bei Fehler: %d", st)
	}
	// Fehler: gespeichert, bereinigt
	if st, b := coll.result(agentproto.CollectorResult{ID: id, Revision: rev, Error: "keine Antwort\nvom Gerät"}); st != 204 {
		t.Fatalf("Fehler melden: %d %s", st, b)
	}
	var lastErr *string
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || *lastErr != "keine Antwort vom Gerät" {
		t.Errorf("Fehler: %v", lastErr)
	}

	// „Jetzt abfragen“ erscheint als fällig, bis der Sammler abgefragt hat.
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET last_try = now() - interval '1 minute' WHERE id = $1`, id)
	expectStatus(t, "jetzt", as(t, "v_fw").do("POST", "/api/v1/snmp/"+id+"/jetzt", nil), 202)
	if _, l, _ := coll.devices(list.State); len(l.Due) != 1 || l.Due[0] != id {
		t.Errorf("fällig: %+v", l.Due)
	}
	coll.result(agentproto.CollectorResult{ID: id, Revision: rev, Error: "x"})
	if _, l, _ := coll.devices(list.State); len(l.Due) != 0 {
		t.Errorf("nach Abfrage noch fällig: %+v", l.Due)
	}

	// Meldet der Agent andere Netze, gibt es für Adressen außerhalb keine
	// Zugangsdaten, und der Fehler steht an der Quelle.
	coll.reportNets("fw-port", "10.41.0.0/16")
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET last_try = now() - interval '2 minutes' WHERE id = $1`, id)
	_, l, body := coll.devices(list.State)
	if l.Unchanged || len(l.Devices) != 1 || l.Devices[0].ID != id3 || strings.Contains(body, testCommunity) {
		t.Errorf("andere Netze: %s", body)
	}
	owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
	if lastErr == nil || !strings.Contains(*lastErr, "10.41.0.0/16") {
		t.Errorf("Fehler außerhalb der Netze: %v", derefStr(lastErr))
	}
	// Ohne Freigabe: keine Liste, kein Abruf vermerkt
	owner.Exec(ctx, `UPDATE openwacht.agents SET collector_seen_at = NULL WHERE id = $1`, coll.id)
	coll.reportNets("fw-port")
	if _, l, _ := coll.devices(""); len(l.Devices) != 0 {
		t.Error("Liste nach Rücknahme der Freigabe")
	}
	owner.QueryRow(ctx, `SELECT collector_seen_at FROM openwacht.agents WHERE id = $1`, coll.id).Scan(&seen)
	if seen != nil {
		t.Error("Abruf ohne Freigabe vermerkt")
	}
	// Gesperrt: abgewiesen
	coll.reportNets("fw-port", "10.40.0.0/16")
	expectStatus(t, "sperren", as(t, "v_fw").do("POST", "/api/v1/agents/"+coll.id+"/sperren", nil), 204)
	if st, _, _ := coll.devices(""); st != 401 {
		t.Errorf("gesperrt Liste: %d", st)
	}
	if st, _ := coll.result(ok); st != 401 {
		t.Errorf("gesperrt Ergebnis: %d", st)
	}
	// Ungültige Netze in der Meldung werden abgelehnt.
	status, _, _ = postJSON(other.client(), agentSrv.URL+agentproto.PathReport, func() agentproto.Snapshot {
		s := validSnapshot("fw-port-2")
		s.Collector = &agentproto.Collector{Nets: []string{"0.0.0.0/0"}}
		return s
	}())
	if status != 400 {
		t.Errorf("Netz /0: %d", status)
	}
}

// TestSammlerAusfall: Fällt der Sammler aus, gibt es einen Alarm am Sammler,
// die Geräte werden grau und alarmieren nicht (Entscheidung, 20.11.2026).
func TestSammlerAusfall(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(f.URL)

	coll := collectorAgent(t, "v_oa", "Organisation", "oa-ausfall", "10.50.0.0/16")
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic) VALUES ($1, $2, 'S', $3, 'sammler')`,
		chID, ids["Organisation"], server); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_state_agents WHERE channel_id = $1`, chID)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_state_snmp WHERE channel_id = $1`, chID)
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, chID)
	})
	r := newDevice(t, "v_oa", "Organisation", "SX Switch", "")
	r = as(t, "v_oa").do("PUT", "/api/v1/geraete/"+r.body["id"].(string)+"/snmp", map[string]any{"version": "2c", "adresse": "10.50.0.1",
		"community": testCommunity, "sammler": coll.id})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	_, list, _ := coll.devices("")
	if st, b := coll.result(agentproto.CollectorResult{ID: id, Revision: list.Devices[0].Revision, OK: true,
		Snapshot: collectedSnapshot(t, time.Now(), 100, 1)}); st != 204 {
		t.Fatalf("Ergebnis: %d %s", st, b)
	}
	round := func() []ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatal(err)
		}
		return f.take()["sammler"]
	}
	sensors := func() map[string]map[string]any {
		t.Helper()
		out := map[string]map[string]any{}
		resp := as(t, "v_oa").do("GET", "/api/v1/sensoren", nil)
		expectStatus(t, "Sensoren", resp, 200)
		for _, x := range resp.body["sensoren"].([]any) {
			e := x.(map[string]any)
			if e["quelle_id"] == id || e["quelle_id"] == coll.id {
				out[e["art"].(string)+":"+e["gegenstand"].(string)] = e
			}
		}
		return out
	}
	if m := round(); len(m) != 0 {
		t.Fatalf("Alarm im Normalbetrieb: %+v", m)
	}
	if sn := sensors(); sn["host:sammler"]["status"] != "ok" || sn["snmp:stumm"]["status"] != "ok" {
		t.Errorf("Sensoren im Normalbetrieb: %+v", sn)
	}

	// Sammler holt nichts mehr ab, Agent meldet sich aber: ein Alarm am Sammler.
	owner.Exec(ctx, `UPDATE openwacht.agents SET collector_seen_at = now() - interval '10 minutes' WHERE id = $1`, coll.id)
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET last_ok = now() - interval '10 minutes', changed_at = now() - interval '1 hour' WHERE id = $1`, id)
	owner.Exec(ctx, `UPDATE openwacht.agents SET collector_since = now() - interval '1 hour' WHERE id = $1`, coll.id)
	m := round()
	if len(m) != 1 || !strings.Contains(m[0].Message, "oa-ausfall · Sammler") || !strings.Contains(m[0].Message, "holt seit") ||
		!strings.Contains(m[0].Message, "1 Gerät ohne Abfrage") || strings.Contains(m[0].Message, "SX Switch") {
		t.Fatalf("Alarm bei Ausfall: %+v", m)
	}
	sn := sensors()
	if sn["host:sammler"]["status"] != "crit" || sn["snmp:stumm"]["status"] != alarm.Unknown ||
		!strings.Contains(sn["snmp:stumm"]["meldung"].(string), "Sammler oa-ausfall") || sn["snmp:speicher"]["status"] != alarm.Unknown {
		t.Errorf("Sensoren bei Ausfall: %+v", sn)
	}
	// Lokal ausgeschaltet: eigener Text
	coll.reportNets("oa-ausfall")
	if sn := sensors(); !strings.Contains(sn["host:sammler"]["meldung"].(string), "lokal ausgeschaltet") {
		t.Errorf("lokal aus: %+v", sn["host:sammler"])
	}
	// Agent ganz stumm: der Stumm-Alarm nennt die Geräte.
	coll.reportNets("oa-ausfall", "10.50.0.0/16")
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_seen = now() - interval '10 minutes' WHERE id = $1`, coll.id)
	m = round()
	if len(m) != 1 || !strings.Contains(m[0].Message, "als Sammler fallen 1 Gerät aus") {
		t.Errorf("stummer Sammler: %+v", m)
	}

	// Zurück: Der Abruf beginnt neu, die Geräte alarmieren nicht sofort,
	// obwohl die letzte erfolgreiche Abfrage alt ist.
	coll.reportNets("oa-ausfall", "10.50.0.0/16")
	coll.devices("")
	m = round()
	for _, x := range m {
		if strings.Contains(x.Message, "SX Switch") {
			t.Errorf("Gerät alarmiert nach Rückkehr: %+v", x)
		}
	}
	var nState int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alert_state_snmp WHERE snmp_id = $1`, id).Scan(&nState)
	if nState != 0 {
		t.Errorf("Alarmzustand am Gerät nach Rückkehr: %d", nState)
	}
	if sn := sensors(); sn["host:sammler"]["status"] != "ok" || sn["snmp:stumm"]["status"] == alarm.Crit {
		t.Errorf("nach Rückkehr: %+v %+v", sn["host:sammler"], sn["snmp:stumm"])
	}
	// Antwortet das Gerät über den Sammler nicht, alarmiert es wie sonst.
	owner.Exec(ctx, `UPDATE openwacht.agents SET collector_since = now() - interval '1 hour' WHERE id = $1`, coll.id)
	m = round()
	found := false
	for _, x := range m {
		found = found || strings.Contains(x.Message, "SX Switch") && strings.Contains(x.Message, "antwortet nicht")
	}
	if !found {
		t.Errorf("Gerät antwortet nicht: %+v", m)
	}
	// Gesperrter Sammler: Die Geräte alarmieren selbst, mit Hinweis.
	expectStatus(t, "sperren", as(t, "v_oa").do("POST", "/api/v1/agents/"+coll.id+"/sperren", nil), 204)
	owner.Exec(ctx, `UPDATE openwacht.agents SET collector_seen_at = now() - interval '1 hour' WHERE id = $1`, coll.id)
	if sn := sensors(); sn["snmp:stumm"]["status"] != alarm.Crit || !strings.Contains(sn["snmp:stumm"]["meldung"].(string), "gesperrt") {
		t.Errorf("gesperrter Sammler: %+v", sn["snmp:stumm"])
	}
}

// TestSammlerEndeZuEnde: echter Agent-Code (Registrierung, Meldung,
// Geräteliste, Abfrage, Ergebnis) gegen die Zentrale und ein SNMP-Gerät.
func TestSammlerEndeZuEnde(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	srv := agentServer(t)
	ctx := context.Background()
	device := snmptest.New(t, testCommunity,
		snmptest.Str("1.3.6.1.2.1.2.2.1.2.1", "Port 1"), snmptest.Num("1.3.6.1.2.1.2.2.1.7.1", 1), snmptest.Num("1.3.6.1.2.1.2.2.1.8.1", 1),
		gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint(1000)})

	dir := t.TempDir()
	tok, r := newAgentToken(t, "v_fw", "Fertigung", 1)
	expectStatus(t, "Token", r, 201)
	vServer.agent.limiter = newIPLimiter(vServer.cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
	agentID, err := agent.Register(ctx, dir, srv.URL, tok, "fw-e2e", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE agent_id = $1`, agentID)
		owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET collector_id = NULL WHERE collector_id = $1`, agentID)
	})
	if _, err := agent.WriteCollectorConfig(dir, []string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sammler.json")); !strings.Contains(string(b), "127.0.0.1/32") {
		t.Fatalf("Freigabe: %s", b)
	}
	runner, err := agent.NewRunner(dir, func() (agentproto.Snapshot, error) { return validSnapshot("fw-e2e"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runner.Report(ctx); err != nil {
		t.Fatal(err)
	}
	r = newDevice(t, "v_fw", "Fertigung", "E2E Switch", "")
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+r.body["id"].(string)+"/snmp", map[string]any{"version": "2c",
		"adresse": "127.0.0.1", "port": int(device.Port()), "community": testCommunity, "sammler": agentID})
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)

	vServer.collectorListLimit = perKeyLimit{every: time.Nanosecond}
	vServer.collectorResultLimit = perKeyLimit{every: time.Nanosecond}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { runner.Run(runCtx); close(done) }()
	var lastOK *time.Time
	var raw []byte
	for runCtx.Err() == nil {
		owner.QueryRow(ctx, `SELECT last_ok, snapshot FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastOK, &raw)
		if lastOK != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done
	if lastOK == nil {
		var lastErr *string
		owner.QueryRow(ctx, `SELECT last_error FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr)
		t.Fatalf("keine Abfrage durch den Sammler, Fehler %v", lastErr)
	}
	var snap snmp.Snapshot
	json.Unmarshal(raw, &snap)
	if snap.System.Descr != "Testgerät" || len(snap.Interfaces) != 1 || snap.Interfaces[0].Name != "Port 1" {
		t.Errorf("Messwerte: %+v", snap)
	}
	if e, _ := snmpEntry(t, "v_fw", id); e["fehler"] != nil {
		t.Errorf("Fehler: %+v", e["fehler"])
	}
	// Die Zugangsdaten landen nicht auf der Platte.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(b), testCommunity) {
			t.Errorf("Community in %s", e.Name())
		}
	}
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
