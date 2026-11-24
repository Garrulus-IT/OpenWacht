// SPDX-License-Identifier: AGPL-3.0-only

//go:build lasttest

// Lasttest (Etappe 35). Läuft nicht in der normalen Testsuite und nicht in
// der CI, sondern nur mit dem Build-Tag „lasttest“ gegen eine laufende
// Zentrale (echtes Binary). Ablauf und Messwerte: Handbuch Kapitel 16.
//
//	LT_UI=http://127.0.0.1:8443 LT_AGENT=https://127.0.0.1:8444 \
//	LT_EMAIL=… LT_PASS=… LT_DAUER=30m LT_SIMAGENT=/tmp/bin/simagent \
//	go test -tags lasttest -run TestLast -timeout 4h -v ./tools/lasttest
//
// Aufbau: 20 Mandanten (Hauptmandant plus 19 Untermandanten in zwei
// Ebenen), je 25 Agents (500, simuliert mit tools/simagent, Takt 60 s) und
// je 100 SNMP-Geräte (2000, Attrappen auf 127.1.x.y:161, Abfrage 60 s).
// Gemessen werden Antwortzeiten der Oberfläche (p50/p95), Zeilen je Minute,
// CPU-Zeit von Zentrale und PostgreSQL. Das Hochrechnen auf 24 Stunden
// (Partitionen, Verdichtung) macht tag.sql in diesem Ordner.
package lasttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

const (
	tenants          = 20
	agentsPerTenant  = 25
	devicesPerTenant = 100
	community        = "lasttest-community"
)

type client struct {
	t       *testing.T
	base    string
	csrf    string
	cookies map[string]string
	mu      sync.Mutex
}

func (c *client) do(method, path string, body any) (int, map[string]any, time.Duration) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", c.base)
	}
	c.mu.Lock()
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range c.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	c.mu.Unlock()
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	d := time.Since(start)
	c.mu.Lock()
	for _, ck := range resp.Cookies() {
		c.cookies[ck.Name] = ck.Value
	}
	c.mu.Unlock()
	var out map[string]any
	json.Unmarshal(raw, &out)
	if s, ok := out["csrf"].(string); ok {
		c.csrf = s
	}
	return resp.StatusCode, out, d
}

func (c *client) must(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	st, out, _ := c.do(method, path, body)
	if st != want {
		c.t.Fatalf("%s %s: %d %v", method, path, st, out)
	}
	return out
}

func env(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Skip(k + " fehlt (nur mit laufender Zentrale, siehe Kopf der Datei)")
	}
	return v
}

// fakeDevice: SNMP-Attrappe mit CPU, RAM, Platte und zwei Schnittstellen.
func fakeDevice(t *testing.T, addr string, i int) *snmptest.Agent {
	n := func(oid string, v int) gosnmp.SnmpPDU { return snmptest.Num(oid, v) }
	g := func(oid string, v uint) gosnmp.SnmpPDU { return snmptest.Gauge(oid, v) }
	oid := func(o string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: o, Type: gosnmp.ObjectIdentifier, Value: "." + o}
	}
	c64 := func(o string, v uint64) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: o, Type: gosnmp.Counter64, Value: v}
	}
	return snmptest.NewOn(t, addr, community,
		n("1.3.6.1.2.1.25.3.3.1.2.1", 10+i%60),
		oid("1.3.6.1.2.1.25.2.3.1.2.1"), snmptest.Str("1.3.6.1.2.1.25.2.3.1.3.1", "Physical memory"),
		n("1.3.6.1.2.1.25.2.3.1.4.1", 1024), n("1.3.6.1.2.1.25.2.3.1.5.1", 8<<20), n("1.3.6.1.2.1.25.2.3.1.6.1", (3+i%4)<<20),
		gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.25.2.3.1.2.31", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.2.1.25.2.1.4"},
		snmptest.Str("1.3.6.1.2.1.25.2.3.1.3.31", "/"), n("1.3.6.1.2.1.25.2.3.1.4.31", 4096),
		n("1.3.6.1.2.1.25.2.3.1.5.31", 50<<20), n("1.3.6.1.2.1.25.2.3.1.6.31", (10+i%30)<<20),
		snmptest.Str("1.3.6.1.2.1.2.2.1.2.1", "eth0"), snmptest.Str("1.3.6.1.2.1.2.2.1.2.2", "eth1"),
		n("1.3.6.1.2.1.2.2.1.3.1", 6), n("1.3.6.1.2.1.2.2.1.3.2", 6),
		n("1.3.6.1.2.1.2.2.1.7.1", 1), n("1.3.6.1.2.1.2.2.1.7.2", 1),
		n("1.3.6.1.2.1.2.2.1.8.1", 1), n("1.3.6.1.2.1.2.2.1.8.2", 1),
		g("1.3.6.1.2.1.2.2.1.5.1", 1000000000), g("1.3.6.1.2.1.2.2.1.5.2", 1000000000),
		snmptest.Str("1.3.6.1.2.1.31.1.1.1.1.1", "eth0"), snmptest.Str("1.3.6.1.2.1.31.1.1.1.1.2", "eth1"),
		c64("1.3.6.1.2.1.31.1.1.1.6.1", uint64(i)*1e6), c64("1.3.6.1.2.1.31.1.1.1.10.1", uint64(i)*2e6),
		c64("1.3.6.1.2.1.31.1.1.1.6.2", uint64(i)*3e6), c64("1.3.6.1.2.1.31.1.1.1.10.2", uint64(i)*4e6),
		g("1.3.6.1.2.1.31.1.1.1.15.1", 1000), g("1.3.6.1.2.1.31.1.1.1.15.2", 1000),
	)
}

func deviceAddr(tenant, dev int) string {
	k := tenant*devicesPerTenant + dev + 1
	return fmt.Sprintf("127.1.%d.%d", k/250, k%250+1)
}

// cpuTicks: CPU-Zeit (User+System, in Ticks) aller Prozesse mit name im Befehl.
func cpuTicks(name string) uint64 {
	dirs, _ := os.ReadDir("/proc")
	var sum uint64
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		cmd, _ := os.ReadFile("/proc/" + d.Name() + "/cmdline")
		if !bytes.Contains(cmd, []byte(name)) {
			continue
		}
		st, _ := os.ReadFile("/proc/" + d.Name() + "/stat")
		f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+1:]))
		if len(f) > 13 {
			u, _ := strconv.ParseUint(f[11], 10, 64)
			s, _ := strconv.ParseUint(f[12], 10, 64)
			sum += u + s
		}
	}
	return sum
}

func rssMB(name string) float64 {
	dirs, _ := os.ReadDir("/proc")
	var kb float64
	for _, d := range dirs {
		cmd, _ := os.ReadFile("/proc/" + d.Name() + "/cmdline")
		if !bytes.Contains(cmd, []byte(name)) {
			continue
		}
		st, _ := os.ReadFile("/proc/" + d.Name() + "/status")
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "VmRSS:") {
				v, _ := strconv.ParseFloat(strings.Fields(l)[1], 64)
				kb += v
			}
		}
	}
	return kb / 1024
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func TestLast(t *testing.T) {
	ui, agentURL := env(t, "LT_UI"), env(t, "LT_AGENT")
	email, pass, sim := env(t, "LT_EMAIL"), env(t, "LT_PASS"), env(t, "LT_SIMAGENT")
	dauer, err := time.ParseDuration(env(t, "LT_DAUER"))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, base: ui, cookies: map[string]string{}}
	c.must("POST", "/api/v1/sitzung", map[string]string{"email": email, "passwort": pass}, 200)
	root := c.must("GET", "/api/v1/mandanten", nil, 200)["mandanten"].([]any)[0].(map[string]any)["id"].(string)

	// 1. Mandanten: Hauptmandant, 4 Bereiche, je 3–4 Untermandanten darunter.
	ids := []string{root}
	var parents []string
	for i := 0; len(ids) < tenants; i++ {
		parent := root
		if i >= 4 {
			parent = parents[i%4]
		}
		out := c.must("POST", "/api/v1/mandanten", map[string]string{"uebergeordnet_id": parent, "name": fmt.Sprintf("Last %02d", i)}, 201)
		ids = append(ids, out["id"].(string))
		if i < 4 {
			parents = append(parents, out["id"].(string))
		}
	}
	c.must("POST", "/api/v1/mandanten/"+root+"/snmp-profile", map[string]any{"name": "last", "version": "2c", "community": community}, 201)

	// 2. SNMP-Geräte: Attrappen starten, je Mandant ein CSV-Import.
	start := time.Now()
	for ti, id := range ids {
		var csv strings.Builder
		csv.WriteString("name;adresse;gruppe;profil;vorlage\n")
		for d := range devicesPerTenant {
			addr := deviceAddr(ti, d)
			fakeDevice(t, addr+":161", ti*devicesPerTenant+d)
			fmt.Fprintf(&csv, "sw-%02d-%03d;%s;;last;\n", ti, d, addr)
		}
		st, out, _ := c.do("POST", "/api/v1/mandanten/"+id+"/geraete/import", map[string]any{"csv": csv.String()})
		if f, _ := out["fehlerhaft"].(float64); f > 0 || st >= 300 {
			t.Fatalf("Import Mandant %d: %v", ti, out)
		}
	}
	t.Logf("Aufbau: %d Mandanten, %d SNMP-Geräte in %s", len(ids), len(ids)*devicesPerTenant, time.Since(start).Round(time.Second))

	// 3. Agents: je Mandant ein Token für 25 Rechner und ein simagent.
	var procs []*exec.Cmd
	for ti, id := range ids {
		tok := c.must("POST", "/api/v1/mandanten/"+id+"/agent-tokens", map[string]any{"notiz": "Lasttest", "anzahl": agentsPerTenant}, 201)["token"].(string)
		var hosts []string
		for a := range agentsPerTenant {
			hosts = append(hosts, fmt.Sprintf("srv-%02d-%02d", ti, a))
		}
		cmd := exec.Command(sim, "-zentrale", agentURL, "-token", tok, "-hosts", strings.Join(hosts, ","), "-runden", "0", "-takt", "60s",
			"-quelle", fmt.Sprintf("127.2.0.%d", ti+1))
		cmd.Env = append(os.Environ(), "HTTPS_PROXY=", "https_proxy=", "NO_PROXY=*")
		cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		procs = append(procs, cmd)
	}
	t.Cleanup(func() {
		for _, p := range procs {
			p.Process.Kill()
			p.Wait()
		}
	})

	// 4. Messen: Oberfläche im Takt abfragen, CPU über die ganze Dauer.
	endpoints := []string{
		"/api/v1/dashboard/kennzahlen", "/api/v1/geraete", "/api/v1/agents", "/api/v1/snmp",
		"/api/v1/dashboard/verlauf?zeitraum=24h", "/api/v1/alarme",
	}
	times := map[string][]time.Duration{}
	warm := 5 * time.Minute
	if dauer < 2*warm {
		warm = dauer / 4
	}
	time.Sleep(warm)
	z0, p0, t0 := cpuTicks("openwacht-zentrale"), cpuTicks("postgres"), time.Now()
	for time.Since(t0) < dauer {
		for _, e := range endpoints {
			st, _, d := c.do("GET", e, nil)
			if st == 200 {
				times[e] = append(times[e], d)
			} else {
				times[e+" (Fehler "+strconv.Itoa(st)+")"] = append(times[e+" (Fehler "+strconv.Itoa(st)+")"], d)
			}
		}
		time.Sleep(20 * time.Second)
	}
	secs := time.Since(t0).Seconds()
	hz := 100.0
	t.Logf("Messdauer %s nach %s Anlauf", time.Since(t0).Round(time.Second), warm)
	t.Logf("CPU Zentrale: %.1f %% eines Kerns, PostgreSQL: %.1f %% eines Kerns",
		float64(cpuTicks("openwacht-zentrale")-z0)/hz/secs*100, float64(cpuTicks("postgres")-p0)/hz/secs*100)
	t.Logf("Arbeitsspeicher Zentrale: %.0f MB, PostgreSQL: %.0f MB", rssMB("openwacht-zentrale"), rssMB("postgres"))
	var keys []string
	for k := range times {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-45s n=%3d p50=%6s p95=%6s max=%6s", k, len(times[k]), pct(times[k], 0.5).Round(time.Millisecond),
			pct(times[k], 0.95).Round(time.Millisecond), pct(times[k], 1).Round(time.Millisecond))
	}
	if os.Getenv("LT_HALTEN") != "" {
		t.Log("LT_HALTEN: Last läuft weiter, bis die Datei " + os.Getenv("LT_HALTEN") + " verschwindet")
		for {
			if _, err := os.Stat(os.Getenv("LT_HALTEN")); err != nil {
				break
			}
			time.Sleep(10 * time.Second)
		}
	}
}

// TestLastAbfragen: Antwortzeiten der Graphen nach tag.sql (voller Verlauf).
func TestLastAbfragen(t *testing.T) {
	ui, email, pass := env(t, "LT_UI"), env(t, "LT_EMAIL"), env(t, "LT_PASS")
	c := &client{t: t, base: ui, cookies: map[string]string{}}
	c.must("POST", "/api/v1/sitzung", map[string]string{"email": email, "passwort": pass}, 200)
	agents := c.must("GET", "/api/v1/agents", nil, 200)["agents"].([]any)
	snmp := c.must("GET", "/api/v1/snmp", nil, 200)
	var snmpID string
	for _, k := range []string{"quellen", "snmp"} {
		if l, ok := snmp[k].([]any); ok && len(l) > 0 {
			snmpID = l[0].(map[string]any)["id"].(string)
		}
	}
	agentID := agents[0].(map[string]any)["id"].(string)
	var paths []string
	for _, z := range []string{"24h", "7t", "30t"} {
		paths = append(paths, "/api/v1/agents/"+agentID+"/verlauf?zeitraum="+z, "/api/v1/dashboard/verlauf?zeitraum="+z)
		if snmpID != "" {
			paths = append(paths, "/api/v1/snmp/"+snmpID+"/verlauf?zeitraum="+z)
		}
	}
	paths = append(paths, "/api/v1/dashboard/kennzahlen", "/api/v1/geraete", "/api/v1/agents", "/api/v1/snmp")
	for _, p := range paths {
		var d []time.Duration
		status := 0
		for range 10 {
			st, _, x := c.do("GET", p, nil)
			status = st
			d = append(d, x)
		}
		t.Logf("%-70s %d p50=%6s p95=%6s", p, status, pct(d, 0.5).Round(time.Millisecond), pct(d, 0.95).Round(time.Millisecond))
	}
}
