// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

func snapAt(at time.Time, extra ...snmp.ExtraValue) *snmp.Snapshot {
	return &snmp.Snapshot{CollectedAt: at, Counters: &snmp.CounterInfo{At: at}, Extra: extra}
}

func TestEvalOID(t *testing.T) {
	now := time.Now()
	f := func(v float64) *float64 { return &v }
	u := func(v uint64) *uint64 { return &v }
	spec := func(raw string) checks.Spec {
		s, err := checks.Parse("snmp_oid", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	const o = "1.3.6.1.4.1.99.1.0"
	num := snapAt(now, snmp.ExtraValue{OID: o, Number: f(47)})
	txt := snapAt(now, snmp.ExtraValue{OID: o, TextHash: snmp.TextHash("Normal")})
	for _, tc := range []struct {
		name       string
		spec       string
		cur, prev  *snmp.Snapshot
		rebooted   bool
		record     bool
		status, in string
	}{
		{"nicht gelesen", `{"oid":"1.3.6.1.4.1.99.2.0"}`, num, nil, false, false, "", ""},
		{"fehlt", `{"oid":"` + o + `"}`, snapAt(now, snmp.ExtraValue{OID: o, Missing: true}), nil, false, true, checks.Unknown, "fehlt"},
		{"vorhanden", `{"oid":"` + o + `"}`, num, nil, false, true, checks.OK, "vorhanden"},
		{"Warnung", `{"oid":"` + o + `","warnung_ueber":40,"kritisch_ueber":50}`, num, nil, false, true, checks.Warn, "über 40"},
		{"kritisch", `{"oid":"` + o + `","warnung_ueber":30,"kritisch_ueber":40}`, num, nil, false, true, checks.Crit, "über 40"},
		{"unter", `{"oid":"` + o + `","warnung_unter":50}`, num, nil, false, true, checks.Warn, "unter 50"},
		{"Text gleich", `{"oid":"` + o + `","gleich":"Normal"}`, txt, nil, false, true, checks.OK, "wie erwartet"},
		{"Text anders", `{"oid":"` + o + `","gleich":"Fehler"}`, txt, nil, false, true, checks.Crit, "weicht"},
		{"Zahl gleich", `{"oid":"` + o + `","gleich":"47"}`, num, nil, false, true, checks.OK, "wie erwartet"},
		{"Text mit Schwelle", `{"oid":"` + o + `","warnung_ueber":1}`, txt, nil, false, true, checks.Unknown, "keine Zahl"},
		{"Rate ohne vorigen Wert", `{"oid":"` + o + `","rate":true}`, num, nil, false, false, "", ""},
		{"Rate Neustart", `{"oid":"` + o + `","rate":true}`,
			snapAt(now, snmp.ExtraValue{OID: o, Counter: u(100), Bits: 32}), snapAt(now.Add(-time.Minute), snmp.ExtraValue{OID: o, Counter: u(50), Bits: 32}),
			true, false, "", ""},
		{"Rate", `{"oid":"` + o + `","rate":true,"warnung_ueber":5}`,
			snapAt(now, snmp.ExtraValue{OID: o, Counter: u(700), Bits: 32}), snapAt(now.Add(-time.Minute), snmp.ExtraValue{OID: o, Counter: u(100), Bits: 32}),
			false, true, checks.Warn, "über 5"},
		{"Rate Überlauf 32", `{"oid":"` + o + `","rate":true}`,
			snapAt(now, snmp.ExtraValue{OID: o, Counter: u(10), Bits: 32}), snapAt(now.Add(-10*time.Second), snmp.ExtraValue{OID: o, Counter: u(1<<32 - 10), Bits: 32}),
			false, true, checks.OK, "vorhanden"},
	} {
		res, rec := evalOID(spec(tc.spec), tc.cur, tc.prev, tc.rebooted)
		if rec != tc.record || rec && (res.Status != tc.status || !strings.Contains(res.Message, tc.in)) {
			t.Errorf("%s: %v %+v", tc.name, rec, res)
		}
		if tc.name == "Rate" && res.Metric != "10/s" {
			t.Errorf("Rate Messwert %q", res.Metric)
		}
		if tc.name == "Rate Überlauf 32" && res.Metric != "2/s" {
			t.Errorf("Überlauf Messwert %q", res.Metric)
		}
	}
}

// TestSNMPOIDSammler: OID-Sensor an einem Gerät, das ein Sammler abfragt.
func TestSNMPOIDSammler(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	ctx := context.Background()
	coll := collectorAgent(t, "v_fw", "Fertigung", "oid-sammler", "10.20.0.0/16")
	r := newDevice(t, "v_fw", "Fertigung", "OID Switch", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	bare := newDevice(t, "v_fw", "Fertigung", "OID ohne SNMP", "").body["id"].(string)
	cleanupChecks(t, dev, bare)
	sensor := func(device, name, target string) response {
		return as(t, "v_fw").do("POST", "/api/v1/geraete/"+device+"/checks", map[string]any{"name": name, "typ": "snmp_oid",
			"ziel": json.RawMessage(target), "intervall_sekunden": 60})
	}
	expectStatus(t, "ohne SNMP", sensor(bare, "OID ohne", `{"oid":"1.3.6.1.4.1.99.1.0"}`), 409)
	// Zweite Schicht: auch die Datenbank lehnt ab.
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
			VALUES ($1, 'OID db', 'snmp_oid', '{"oid":"1.3.6.1"}', 60)`, bare)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "SNMP-Abfrage") {
		t.Errorf("DB ohne SNMP: %v", err)
	}
	// Ein anderes Gerät desselben Mandanten mit eigenem OID-Sensor
	other := newDevice(t, "v_fw", "Fertigung", "OID Zwei", "").body["id"].(string)
	cleanupChecks(t, other)
	expectStatus(t, "SNMP zwei", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+other+"/snmp", snmpBody("10.20.5.6", map[string]any{"sammler": coll.id})), 201)
	expectStatus(t, "Sensor zwei", sensor(other, "OID Fremd", `{"oid":"1.3.6.1.4.1.99.7.0"}`), 201)
	b := snmpBody("10.20.5.5", map[string]any{"sammler": coll.id})
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", b)
	expectStatus(t, "SNMP", r, 201)
	src := r.body["id"].(string)
	r = sensor(dev, "OID Temperatur", `{"oid":"1.3.6.1.4.1.99.1.0","warnung_ueber":40}`)
	expectStatus(t, "Sensor", r, 201)
	temp := r.body["id"].(string)
	r = sensor(dev, "OID Status", `{"oid":"1.3.6.1.4.1.99.2.0","gleich":"Normal"}`)
	expectStatus(t, "Sensor 2", r, 201)
	stat := r.body["id"].(string)

	// Der Planer der Checks führt OID-Sensoren nicht aus.
	var claimed int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks_claim(1000) WHERE id = ANY($1::uuid[])`, []string{temp, stat}).Scan(&claimed)
	if claimed != 0 {
		t.Errorf("checks_claim: %d", claimed)
	}
	// Der Sammler bekommt die OIDs mit der Geräteliste.
	_, list, _ := coll.devices("")
	var dev0 *agentproto.CollectorDevice
	for i := range list.Devices {
		if list.Devices[i].ID == src {
			dev0 = &list.Devices[i]
		}
	}
	if dev0 == nil || strings.Join(dev0.Extra, ",") != "1.3.6.1.4.1.99.1.0,1.3.6.1.4.1.99.2.0" {
		t.Fatalf("Geräteliste: %+v", dev0)
	}
	// Ergebnis mit eigenen Werten: Sensoren werden bewertet.
	now := time.Now()
	var s snmp.Snapshot
	json.Unmarshal(collectedSnapshot(t, now, 100000, 1000), &s)
	n := 47.0
	s.Extra = []snmp.ExtraValue{{OID: "1.3.6.1.4.1.99.1.0", Number: &n}, {OID: "1.3.6.1.4.1.99.2.0", TextHash: snmp.TextHash("Normal")}}
	raw, _ := json.Marshal(s)
	if st, b := coll.result(agentproto.CollectorResult{ID: src, Revision: dev0.Revision, OK: true, Snapshot: raw}); st != 204 {
		t.Fatalf("Ergebnis: %d %s", st, b)
	}
	if st, m, metric, _ := checkState(t, temp); st == nil || *st != "warn" || *metric != "47" {
		t.Errorf("Temperatur: %v %v %v", st, m, metric)
	}
	if st, _, _, _ := checkState(t, stat); st == nil || *st != "ok" {
		t.Errorf("Status: %v", st)
	}
	// Ungültige eigene Werte vom Sammler: abgelehnt
	s.Extra = []snmp.ExtraValue{{OID: "1.3.6.1.4.1.99.2.0", TextHash: "Normal im Klartext"}}
	raw, _ = json.Marshal(s)
	if st, _ := coll.result(agentproto.CollectorResult{ID: src, Revision: dev0.Revision, OK: true, Snapshot: raw}); st != 400 {
		t.Errorf("Klartext angenommen: %d", st)
	}
	// Die Liste der Quelle ändert ihren Stand, wenn ein Sensor dazukommt.
	_, again, _ := coll.devices(list.State)
	if !again.Unchanged {
		t.Error("Stand ohne Änderung neu")
	}
	sensor(dev, "OID Drei", `{"oid":"1.3.6.1.4.1.99.3.0"}`)
	if _, again, _ = coll.devices(list.State); again.Unchanged {
		t.Error("neuer Sensor ändert den Stand nicht")
	}
}

// TestSNMPOIDZentrale: OIDs laufen mit der Abfrage der Zentrale, Rate über
// zwei Abfragen.
func TestSNMPOIDZentrale(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	cfg := vServer.cfg
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.snmp.Timeout, s.snmp.Retries = 300*time.Millisecond, -1
	agent := snmptest.New(t, testCommunity,
		snmptest.Num("1.3.6.1.4.1.99.1.0", 47),
		gosnmp.SnmpPDU{Name: "1.3.6.1.4.1.99.4.0", Type: gosnmp.Counter32, Value: uint(1000)},
		snmptest.Num("1.3.6.1.4.1.99.6.1", 7), snmptest.Num("1.3.6.1.4.1.99.6.2", 1), snmptest.Num("1.3.6.1.4.1.99.6.3", 7))
	var tenant, dev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'OID Z') RETURNING id::text`, ids["IT"]).Scan(&tenant)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'oid-z') RETURNING id::text`, tenant).Scan(&dev)
	id, _ := newUUID()
	enc, _ := s.sealSNMP(id, tenant, "127.0.0.1", int(agent.Port()), snmpSecret{Community: testCommunity})
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, port, secret_enc)
		VALUES ($1, $2, '2c', '127.0.0.1', $3, $4)`, id, dev, int(agent.Port()), enc); err != nil {
		t.Fatal(err)
	}
	var temp, rate string
	owner.QueryRow(ctx, `INSERT INTO openwacht.checks (tenant_id, device_id, name, kind, target, interval_s)
		VALUES ($1, $2, 'oid temp', 'snmp_oid', '{"oid":"1.3.6.1.4.1.99.1.0","kritisch_ueber":45}', 60) RETURNING id::text`, tenant, dev).Scan(&temp)
	owner.QueryRow(ctx, `INSERT INTO openwacht.checks (tenant_id, device_id, name, kind, target, interval_s)
		VALUES ($1, $2, 'oid rate', 'snmp_oid', '{"oid":"1.3.6.1.4.1.99.4.0","rate":true}', 60) RETURNING id::text`, tenant, dev).Scan(&rate)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE tenant_id = $1`, tenant)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, tenant)
	})
	var down string
	owner.QueryRow(ctx, `INSERT INTO openwacht.checks (tenant_id, device_id, name, kind, target, interval_s)
		VALUES ($1, $2, 'spalte down', 'snmp_oid', '{"oid":"1.3.6.1.4.1.99.6","zusammenfassung":"anzahl_gleich","vergleichswert":1,"kritisch_ueber":0}', 60)
		RETURNING id::text`, tenant, dev).Scan(&down)
	if temp == "" || rate == "" || down == "" {
		t.Fatal("Sensoren nicht angelegt")
	}
	poll := func() {
		t.Helper()
		owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, id)
		due, err := s.claimSNMP(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range due {
			if c.id == id {
				s.pollSNMP(ctx, c)
			} else {
				owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
			}
		}
	}
	poll()
	if st, _, m, _ := checkState(t, temp); st == nil || *st != "crit" || *m != "47" {
		t.Errorf("Temperatur: %v %v", st, m)
	}
	if st, _, _, _ := checkState(t, rate); st != nil {
		t.Errorf("Rate nach einer Abfrage: %v", *st)
	}
	if st, _, m, _ := checkState(t, down); st == nil || *st != "crit" || *m != "1" {
		t.Errorf("Spalte: %v %v", st, m)
	}
	agent.Set(gosnmp.SnmpPDU{Name: "1.3.6.1.4.1.99.4.0", Type: gosnmp.Counter32, Value: uint(3000)})
	time.Sleep(1100 * time.Millisecond)
	poll()
	if st, _, m, _ := checkState(t, rate); st == nil || *st != "ok" || !strings.HasSuffix(*m, "/s") {
		t.Errorf("Rate: %v %v", st, m)
	}
	// Im gespeicherten Snapshot stehen die eigenen Werte.
	var raw []byte
	owner.QueryRow(ctx, `SELECT snapshot FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&raw)
	if !strings.Contains(string(raw), `"eigene"`) || !strings.Contains(string(raw), `"spalten"`) {
		t.Errorf("Snapshot ohne eigene Werte: %s", raw)
	}
}

func TestEvalSpalte(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	spec := func(raw string) checks.Spec {
		s, err := checks.Parse("snmp_oid", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	const o = "1.3.6.1.4.1.5951.4.1.1.56.1.1.5"
	snap := func(c ...snmp.ColumnValue) *snmp.Snapshot {
		s := snapAt(time.Now())
		s.Columns = c
		return s
	}
	days := snap(snmp.ColumnValue{OID: o, Rows: 3, Numbers: 3, Min: f(12), Max: f(3650), Sum: f(3700),
		Values: map[string]int{"12": 1, "38": 1, "3650": 1}})
	state := snap(snmp.ColumnValue{OID: o, Rows: 4, Numbers: 4, Min: f(1), Max: f(7), Sum: f(19),
		Values: map[string]int{"7": 2, "1": 1, "4": 1}})
	empty := snap(snmp.ColumnValue{OID: o})
	text := snap(snmp.ColumnValue{OID: o, Rows: 2})
	cut := snap(snmp.ColumnValue{OID: o, Rows: snmp.MaxColumnRows, Numbers: snmp.MaxColumnRows, Min: f(1), Max: f(900), Sum: f(5000),
		ValuesCut: true, Truncated: true})
	scalarOnly := snapAt(time.Now(), snmp.ExtraValue{OID: o, Number: f(1)})
	for _, tc := range []struct {
		name, spec       string
		cur              *snmp.Snapshot
		record           bool
		status, in, metr string
	}{
		{"nicht gelesen", `{"oid":"` + o + `","zusammenfassung":"minimum"}`, scalarOnly, false, "", "", ""},
		{"Minimum kritisch", `{"oid":"` + o + `","zusammenfassung":"minimum","warnung_unter":30,"kritisch_unter":14}`, days, true, checks.Crit, "unter 14", "12"},
		{"Minimum Warnung", `{"oid":"` + o + `","zusammenfassung":"minimum","warnung_unter":30,"kritisch_unter":10}`, days, true, checks.Warn, "unter 30", "12"},
		{"Maximum", `{"oid":"` + o + `","zusammenfassung":"maximum","warnung_ueber":4000}`, days, true, checks.OK, "im Rahmen", "3650"},
		{"Summe", `{"oid":"` + o + `","zusammenfassung":"summe"}`, days, true, checks.OK, "vorhanden", "3700"},
		{"Anzahl", `{"oid":"` + o + `","zusammenfassung":"anzahl","kritisch_unter":1}`, days, true, checks.OK, "im Rahmen", "3"},
		{"down gezählt", `{"oid":"` + o + `","zusammenfassung":"anzahl_gleich","vergleichswert":1,"kritisch_ueber":0}`, state, true, checks.Crit, "über 0", "1"},
		{"nicht up", `{"oid":"` + o + `","zusammenfassung":"anzahl_ungleich","vergleichswert":7,"warnung_ueber":0}`, state, true, checks.Warn, "über 0", "2"},
		{"Wert fehlt", `{"oid":"` + o + `","zusammenfassung":"anzahl_gleich","vergleichswert":5,"kritisch_ueber":0}`, state, true, checks.OK, "im Rahmen", "0"},
		{"leer Anzahl", `{"oid":"` + o + `","zusammenfassung":"anzahl_gleich","vergleichswert":1,"kritisch_ueber":0}`, empty, true, checks.OK, "im Rahmen", "0"},
		{"leer Minimum", `{"oid":"` + o + `","zusammenfassung":"minimum","kritisch_unter":14}`, empty, true, checks.Unknown, "ohne Zeilen", ""},
		{"Text", `{"oid":"` + o + `","zusammenfassung":"maximum","kritisch_ueber":1}`, text, true, checks.Unknown, "keine Zahlen", ""},
		{"Text zählen", `{"oid":"` + o + `","zusammenfassung":"anzahl_ungleich","vergleichswert":7,"kritisch_ueber":0}`, text, true, checks.Crit, "über 0", "2"},
		{"zu viele Werte", `{"oid":"` + o + `","zusammenfassung":"anzahl_gleich","vergleichswert":1,"kritisch_ueber":0}`, cut, true, checks.Unknown, "zu viele", ""},
		{"gekürzt", `{"oid":"` + o + `","zusammenfassung":"maximum","warnung_ueber":100}`, cut, true, checks.Warn, "nur die ersten 2000", "900"},
	} {
		res, rec := evalOID(spec(tc.spec), tc.cur, nil, false)
		if rec != tc.record || rec && (res.Status != tc.status || !strings.Contains(res.Message, tc.in) || res.Metric != tc.metr) {
			t.Errorf("%s: %v %+v", tc.name, rec, res)
		}
	}
	// Eine OID als Spalte und als einzelner Wert: getrennte Listen
	list := []oidCheck{{spec: spec(`{"oid":"` + o + `","zusammenfassung":"minimum"}`)}, {spec: spec(`{"oid":"` + o + `"}`)},
		{spec: spec(`{"oid":"` + o + `","zusammenfassung":"maximum"}`)}, {spec: spec(`{"oid":"1.3.6.1.2.1.1.3.0"}`)}}
	if c, e := extraColumns(list), extraOIDs(list); strings.Join(c, ",") != o || strings.Join(e, ",") != o+",1.3.6.1.2.1.1.3.0" {
		t.Errorf("Listen: %v %v", c, e)
	}
}

// TestSNMPSpalteSammler: Spalten-Sensor über einen Sammler, mit Stand der
// Geräteliste und Ablehnung unplausibler Kennzahlen.
func TestSNMPSpalteSammler(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	coll := collectorAgent(t, "v_fw", "Fertigung", "spalten-sammler", "10.20.0.0/16")
	r := newDevice(t, "v_fw", "Fertigung", "NetScaler Test", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	cleanupChecks(t, dev)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("10.20.5.9", map[string]any{"sammler": coll.id}))
	expectStatus(t, "SNMP", r, 201)
	src := r.body["id"].(string)
	const days = "1.3.6.1.4.1.5951.4.1.1.56.1.1.5"
	r = as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{"name": "Zertifikate", "typ": "snmp_oid",
		"ziel": json.RawMessage(`{"oid":"` + days + `","zusammenfassung":"minimum","warnung_unter":30,"kritisch_unter":14}`), "intervall_sekunden": 300})
	expectStatus(t, "Sensor", r, 201)
	cert := r.body["id"].(string)
	_, list, _ := coll.devices("")
	var dev0 *agentproto.CollectorDevice
	for i := range list.Devices {
		if list.Devices[i].ID == src {
			dev0 = &list.Devices[i]
		}
	}
	if dev0 == nil || strings.Join(dev0.Columns, ",") != days || len(dev0.Extra) != 0 {
		t.Fatalf("Geräteliste: %+v", dev0)
	}
	now := time.Now()
	var s snmp.Snapshot
	json.Unmarshal(collectedSnapshot(t, now, 100000, 1000), &s)
	lo, hi, sum := 20.0, 400.0, 420.0
	s.Columns = []snmp.ColumnValue{{OID: days, Rows: 2, Numbers: 2, Min: &lo, Max: &hi, Sum: &sum, Values: map[string]int{"20": 1, "400": 1}}}
	raw, _ := json.Marshal(s)
	if st, b := coll.result(agentproto.CollectorResult{ID: src, Revision: dev0.Revision, OK: true, Snapshot: raw}); st != 204 {
		t.Fatalf("Ergebnis: %d %s", st, b)
	}
	if st, m, metric, _ := checkState(t, cert); st == nil || *st != "warn" || *metric != "20" {
		t.Errorf("Zertifikate: %v %v %v", st, m, metric)
	}
	// Unplausible Kennzahlen: abgelehnt
	s.Columns[0].Min, s.Columns[0].Max = &hi, &lo
	raw, _ = json.Marshal(s)
	if st, _ := coll.result(agentproto.CollectorResult{ID: src, Revision: dev0.Revision, OK: true, Snapshot: raw}); st != 400 {
		t.Errorf("unplausibel angenommen: %d", st)
	}
	// Ein weiterer Spalten-Sensor ändert den Stand der Liste.
	_, again, _ := coll.devices(list.State)
	if !again.Unchanged {
		t.Error("Stand ohne Änderung neu")
	}
	expectStatus(t, "zweite Spalte", as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/checks", map[string]any{"name": "VS down", "typ": "snmp_oid",
		"ziel": json.RawMessage(`{"oid":"1.3.6.1.4.1.5951.4.1.3.1.1.5","zusammenfassung":"anzahl_gleich","vergleichswert":1}`), "intervall_sekunden": 300}), 201)
	if _, again, _ = coll.devices(list.State); again.Unchanged {
		t.Error("neue Spalte ändert den Stand nicht")
	}
	// Mandantentrennung: Geschwister sieht und ändert den Sensor nicht,
	// der Elternmandant sieht ihn.
	if r := as(t, "v_oa").do("GET", "/api/v1/checks", nil); strings.Contains(r.raw, cert) {
		t.Error("Geschwister sieht den Spalten-Sensor")
	}
	if r := as(t, "v_it").do("GET", "/api/v1/checks", nil); !strings.Contains(r.raw, cert) {
		t.Error("Elternmandant sieht den Spalten-Sensor nicht")
	}
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/checks/"+cert, map[string]any{"name": "x", "typ": "snmp_oid",
		"ziel": json.RawMessage(`{"oid":"` + days + `","zusammenfassung":"anzahl"}`), "intervall_sekunden": 300}), 404)
}

// TestEvalOIDZahlAusText (1.0.8): Zahl aus Text, Faktor und Einheit.
func TestEvalOIDZahlAusText(t *testing.T) {
	now := time.Now()
	f := func(v float64) *float64 { return &v }
	const o = "1.3.6.1.4.1.2356.14.1.1.1.24.0"
	h := snmp.TextHash("100ms:52%, 1s:57%, 10s:50%")
	cpu := snapAt(now, snmp.ExtraValue{OID: o, TextHash: h, AusText: []snmp.TextWert{{N: 6, Zahl: f(50)}, {Nach: "1s:", Zahl: f(57)}, {N: 1, Zahl: f(100)},
		{N: 9}}})
	for _, tc := range []struct {
		name, spec string
		cur        *snmp.Snapshot
		status     string
		in, metric string
	}{
		{"n-te", `{"oid":"` + o + `","zahl_aus_text":"nte","zahl_nr":6,"einheit":"%","warnung_ueber":80}`, cpu, checks.OK, "im Rahmen", "50 %"},
		{"nach Text", `{"oid":"` + o + `","zahl_aus_text":"nach","zahl_nach":"1s:","warnung_ueber":55}`, cpu, checks.Warn, "über 55", "57"},
		{"erste", `{"oid":"` + o + `","zahl_aus_text":"erste"}`, cpu, checks.OK, "vorhanden", "100"},
		{"keine Zahl", `{"oid":"` + o + `","zahl_aus_text":"nte","zahl_nr":9}`, cpu, checks.Unknown, "keine Zahl", ""},
		{"nicht gelesen", `{"oid":"` + o + `","zahl_aus_text":"nte","zahl_nr":3}`, cpu, checks.Unknown, "noch nicht gelesen", ""},
		{"Gerät liefert Zahl", `{"oid":"` + o + `","zahl_aus_text":"erste","einheit":"°C"}`, snapAt(now, snmp.ExtraValue{OID: o, Number: f(42)}),
			checks.OK, "vorhanden", "42 °C"},
		{"Zahl als Text „72“", `{"oid":"` + o + `","zahl_aus_text":"erste","kritisch_ueber":70}`,
			snapAt(now, snmp.ExtraValue{OID: o, Number: f(72), TextHash: snmp.TextHash("72"), AusText: []snmp.TextWert{{N: 1, Zahl: f(72)}}}),
			checks.Crit, "über 70", "72"},
		{"Faktor und Einheit", `{"oid":"` + o + `","faktor":0.1,"einheit":"W","warnung_ueber":600}`, snapAt(now, snmp.ExtraValue{OID: o, Number: f(810)}),
			checks.OK, "im Rahmen", "81 W"},
		{"Faktor, Schwelle auf umgerechnet", `{"oid":"` + o + `","faktor":0.1,"warnung_ueber":80}`, snapAt(now, snmp.ExtraValue{OID: o, Number: f(810)}),
			checks.Warn, "über 80", "81"},
	} {
		sp, err := checks.Parse("snmp_oid", []byte(tc.spec))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		res, record := evalOID(sp, tc.cur, nil, false)
		if !record || res.Status != tc.status || !strings.Contains(res.Message, tc.in) || res.Metric != tc.metric {
			t.Errorf("%s: record=%v %+v", tc.name, record, res)
		}
	}
	// Aufträge aus den Sensoren: ohne Doppel, „erste“ ist die 1. Zahl
	var list []oidCheck
	for _, raw := range []string{
		`{"oid":"` + o + `","zahl_aus_text":"erste"}`, `{"oid":"` + o + `","zahl_aus_text":"nte","zahl_nr":1}`,
		`{"oid":"` + o + `","zahl_aus_text":"nach","zahl_nach":"10s:"}`, `{"oid":"` + o + `"}`,
	} {
		sp, err := checks.Parse("snmp_oid", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, oidCheck{spec: sp})
	}
	got := extraText(list)
	if len(got) != 2 || got[0] != (snmp.TextZahl{OID: o, N: 1}) || got[1] != (snmp.TextZahl{OID: o, Nach: "10s:"}) {
		t.Errorf("Aufträge: %+v", got)
	}
	if oids := extraOIDs(list); len(oids) != 1 {
		t.Errorf("OIDs: %v", oids)
	}
}

// TestEinheitenUeberall: Web und Desktop-App bieten dieselben Einheiten an wie checks.Units.
func TestEinheitenUeberall(t *testing.T) {
	want := `"` + strings.Join(checks.Units, `", "`) + `"`
	for _, datei := range []string{"../../web/src/Checks.tsx", "../desktop/felder.go"} {
		b, err := os.ReadFile(datei)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s: Einheiten weichen von checks.Units ab (%s)", datei, want)
		}
	}
}
