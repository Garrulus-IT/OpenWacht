// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/gosnmp/gosnmp"
)

// Gegenstelle für die Integrationstests: ein Net-SNMP-snmpd mit der
// Community aus OPENWACHT_TEST_SNMP_COMMUNITY (Standard „geheim-test“) unter
// OPENWACHT_TEST_SNMPD (z. B. 127.0.0.1:16161). Ohne die Variable werden die
// Tests übersprungen, mit OPENWACHT_REQUIRE_SNMPD=1 schlagen sie dann fehl.
func testTarget(t *testing.T) (string, uint16, string) {
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
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := os.Getenv("OPENWACHT_TEST_SNMP_COMMUNITY")
	if c == "" {
		c = "geheim-test"
	}
	return host, uint16(p), c
}

func loopbackClient() *Client {
	g := checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	return &Client{Guard: g, Timeout: 500 * time.Millisecond, Retries: -1, Budget: 20 * time.Second}
}

func TestPollGegenSnmpd(t *testing.T) {
	host, port, community := testTarget(t)
	c := loopbackClient()
	ctx := context.Background()
	for _, v := range []string{V1, V2c} {
		t.Run("v"+v, func(t *testing.T) {
			cfg := Config{Version: v, Host: host, Port: port, Community: community}
			sys, err := c.Probe(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if sys.Name == "" || sys.Descr == "" || sys.ObjectID == "" {
				t.Errorf("Systemdaten unvollständig: %+v", sys)
			}
			first, err := c.Poll(ctx, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Partial) > 0 {
				t.Errorf("teilweise gescheitert: %v", first.Partial)
			}
			if first.Memory == nil || first.Memory.TotalBytes == 0 || first.Memory.AvailableBytes > first.Memory.TotalBytes {
				t.Errorf("Speicher: %+v", first.Memory)
			}
			// Net-SNMP liefert CPU-Werte erst nach etwa einer Minute Laufzeit.
			cpuReady := first.System.UptimeS >= 90
			if cpuReady && (first.CPU == nil || first.CPU.Percent < 0 || first.CPU.Percent > 100) {
				t.Errorf("CPU: %+v", first.CPU)
			}
			var root bool
			for _, d := range first.Disks {
				root = root || d.Mount == "/"
			}
			if !root {
				t.Errorf("Platte / fehlt: %+v", first.Disks)
			}
			var lo *Interface
			for i := range first.Interfaces {
				if first.Interfaces[i].Name == "lo" {
					lo = &first.Interfaces[i]
				}
			}
			if lo == nil || lo.Oper != "up" {
				t.Fatalf("Schnittstelle lo fehlt oder nicht up: %+v", first.Interfaces)
			}
			if v == V1 && lo.HC || v == V2c && !lo.HC {
				t.Errorf("64-Bit-Zähler bei v%s: %v", v, lo.HC)
			}
			if first.Synology != nil || first.UPS != nil || len(first.Supplies) != 0 {
				t.Errorf("Herstellerteile ohne Herstellergerät: %+v %+v %+v", first.Synology, first.UPS, first.Supplies)
			}
			// Raten ab der zweiten Abfrage: Verkehr auf lo erzeugen wir selbst (die Abfragen).
			time.Sleep(1100 * time.Millisecond)
			second, err := c.Poll(ctx, cfg, first)
			if err != nil {
				t.Fatal(err)
			}
			// snmpd meldet für lo nur 10 Mbit/s. Laufen parallel andere Tests
			// über Loopback (in der CI die Datenbanktests), liegt der Verkehr
			// darüber, und die Plausibilitätsprüfung verwirft die Rate mit
			// Absicht. Dann gibt es auch keine Reihe if_ein:lo.
			loRate := true
			for _, it := range second.Interfaces {
				if it.Name != "lo" {
					continue
				}
				if it.InBps == nil && implausible(first, second, it) {
					loRate = false
					t.Logf("Rate für lo über der Schnittstellengeschwindigkeit (Verkehr anderer Tests), nicht geprüft")
					continue
				}
				// snmpd puffert Zähler einige Sekunden; die Rate kann 0 sein.
				if it.InBps == nil || *it.InBps < 0 || it.NewErrors == nil {
					t.Errorf("keine Rate für lo: %+v", it)
				}
			}
			names, values := Series(second)
			if len(names) != len(values) || len(names) == 0 {
				t.Fatalf("Reihen: %v %v", names, values)
			}
			joined := "," + strings.Join(names, ",") + ","
			for _, want := range []string{",cpu,", ",speicher,", ",platte:/,", ",if_ein:lo,"} {
				if want == ",cpu," && !cpuReady || want == ",if_ein:lo," && !loRate {
					continue
				}
				if !strings.Contains(joined, want) {
					t.Errorf("Reihe %s fehlt: %v", want, names)
				}
			}
		})
	}
}

// implausible: Läge die Rate der Schnittstelle über 110 % ihrer
// Geschwindigkeit (dann verwirft Poll sie absichtlich)?
func implausible(first, second *Snapshot, it Interface) bool {
	if it.SpeedBps == 0 || first.Counters == nil || second.Counters == nil {
		return false
	}
	for _, p := range first.Interfaces {
		if p.Index != it.Index {
			continue
		}
		dt := second.Counters.At.Sub(first.Counters.At).Seconds()
		bits := 32
		if it.HC {
			bits = 64
		}
		d, ok := delta(p.InOctets, it.InOctets, bits)
		return ok && dt > 0 && float64(d)*8/dt > float64(it.SpeedBps)*1.1
	}
	return false
}

func TestPollNegativ(t *testing.T) {
	host, port, community := testTarget(t)
	c := loopbackClient()
	ctx := context.Background()

	// Falsche Community: snmpd antwortet gar nicht (v1/v2c kennen keine Fehlermeldung dafür).
	start := time.Now()
	_, err := c.Probe(ctx, Config{Version: V2c, Host: host, Port: port, Community: community + "-falsch"})
	if !errors.Is(err, ErrNoResponse) {
		t.Errorf("falsche Community: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("falsche Community dauerte %s", time.Since(start))
	}

	// Nicht freigegeben: kein Paket verlässt die Zentrale.
	g := checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	blocked := &Client{Guard: g, Timeout: 500 * time.Millisecond}
	_, err = blocked.Probe(ctx, Config{Version: V2c, Host: host, Port: port, Community: community})
	var na *checks.NotAllowedError
	if !errors.As(err, &na) {
		t.Errorf("Freigabe umgangen: %v", err)
	}
	// Auch nicht über einen Namen, der auf eine gesperrte Adresse zeigt.
	_, err = blocked.Probe(ctx, Config{Version: V2c, Host: "localhost", Port: port, Community: community})
	if !errors.As(err, &na) {
		t.Errorf("Freigabe über Namen umgangen: %v", err)
	}

	// Ungültige Community und Version werden vor jedem Paket abgelehnt.
	for _, cfg := range []Config{
		{Version: V2c, Host: host, Port: port, Community: ""},
		{Version: V2c, Host: host, Port: port, Community: "mit\nzeilenumbruch"},
		{Version: "3", Host: host, Port: port, Community: community},
	} {
		start := time.Now()
		if _, err := c.Probe(ctx, cfg); err == nil || errors.Is(err, ErrNoResponse) || time.Since(start) > 100*time.Millisecond {
			t.Errorf("nicht vorab abgelehnt: %+v: %v nach %s", cfg, err, time.Since(start))
		}
	}

	// Kein SNMP auf dem Port: keine Antwort bzw. Port unerreichbar.
	if _, err := c.Probe(ctx, Config{Version: V2c, Host: host, Port: 9, Community: community}); err == nil {
		t.Error("Port 9 hat geantwortet")
	}
}

// Antworten von einer anderen Adresse als der abgefragten nimmt der
// verbundene Socket nicht an: Ein Fremder schickt eine passende Antwort an
// den Port der Zentrale, die Abfrage läuft trotzdem in die Zeitgrenze.
func TestFremdeAntwortVerworfen(t *testing.T) {
	// Gegenstelle, die nie antwortet, auf 127.0.0.2
	silent, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 nicht verfügbar:", err)
	}
	defer silent.Close()
	spoofer, err := net.ListenPacket("udp", "127.0.0.3:0")
	if err != nil {
		t.Skip("127.0.0.3 nicht verfügbar:", err)
	}
	defer spoofer.Close()
	go func() {
		buf := make([]byte, 2048)
		n, from, err := silent.ReadFrom(buf)
		if err != nil {
			return
		}
		// Antwort wie vom Gerät, aber von einer anderen Adresse: Anfrage
		// spiegeln und den PDU-Typ auf GetResponse (0xa2) setzen.
		resp := append([]byte(nil), buf[:n]...)
		for i := range resp {
			if resp[i] == 0xa0 {
				resp[i] = 0xa2
				break
			}
		}
		_, _ = spoofer.WriteTo(resp, from)
	}()
	c := loopbackClient()
	port := uint16(silent.LocalAddr().(*net.UDPAddr).Port)
	_, err = c.Probe(context.Background(), Config{Version: V2c, Host: "127.0.0.2", Port: port, Community: "x"})
	if !errors.Is(err, ErrNoResponse) {
		t.Errorf("fremde Antwort angenommen: %v", err)
	}
}

func TestCleanBytes(t *testing.T) {
	cases := map[string]string{
		"normal":                        "normal",
		"  mehr   Leer\traum ":          "mehr Leer raum",
		"Steuer\x1b[31mzeichen\x00\x00": "Steuer [31mzeichen",
		"\xe4\xf6\xfc":                  "äöü", // Latin-1
		"Bidi‮Täuschung":                "Bidi Täuschung",
		strings.Repeat("x", 500):        strings.Repeat("x", MaxText),
		"<script>alert(1)</script>":     "<script>alert(1)</script>", // Escaping macht die Oberfläche
	}
	for in, want := range cases {
		if got := cleanBytes([]byte(in), MaxText); got != want {
			t.Errorf("cleanBytes(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

func TestPseudoMount(t *testing.T) {
	for m, want := range map[string]bool{"/": false, "/volume1": false, "/boot/efi": false, "/run": true,
		"/run/credentials/systemd-journald.service": true, "/dev/shm": true, "/sys/fs/cgroup": true, "/runner": false} {
		if pseudoMount(m) != want {
			t.Errorf("pseudoMount(%q) != %v", m, want)
		}
	}
}

func TestValidCommunity(t *testing.T) {
	for _, ok := range []string{"public", "geheim-test", "a!b#c$%&'()*+,-./:;<=>?@[]^_`{|}~", strings.Repeat("x", 64)} {
		if !ValidCommunity(ok) {
			t.Errorf("abgelehnt: %q", ok)
		}
	}
	for _, bad := range []string{"", " lead", "trail ", "um\nbruch", "ümlaut", strings.Repeat("x", 65), "nul\x00"} {
		if ValidCommunity(bad) {
			t.Errorf("angenommen: %q", bad)
		}
	}
}

func TestRebooted(t *testing.T) {
	cases := []struct {
		old, cur uint32
		dt       float64
		want     bool
	}{
		{1000, 7000, 60, false},          // normal
		{500000, 300, 60, true},          // Neustart
		{4294960000, 2704, 60, false},    // Überlauf nach 497 Tagen, passt zur Zeit
		{4294960000, 90000000, 60, true}, // Überlauf passt nicht: Neustart
		{6000, 6000, 60, false},          // gleich (Gerät aktualisiert selten)
	}
	for _, c := range cases {
		if got := Rebooted(c.old, c.cur, c.dt); got != c.want {
			t.Errorf("Rebooted(%d, %d, %g) = %v", c.old, c.cur, c.dt, got)
		}
	}
}

func TestRates(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	mk := func(at time.Time, ticks uint32, in, out uint64, hc bool, speed uint64) *Snapshot {
		return &Snapshot{Counters: &CounterInfo{At: at, UptimeTicks: ticks},
			Interfaces: []Interface{{Index: 1, Name: "eth0", InOctets: in, OutOctets: out, HC: hc, SpeedBps: speed}}}
	}
	// 32-Bit-Überlauf: einmal übergelaufen, Rate stimmt.
	prev := mk(t0, 1000, 4294967000, 100, false, 1_000_000_000)
	cur := mk(t0.Add(60*time.Second), 7000, 1000, 1100, false, 1_000_000_000)
	rates(cur, prev)
	if r := cur.Interfaces[0].InBps; r == nil || int(*r) != (1000+4294967296-4294967000)*8/60 {
		t.Errorf("Überlauf: %v", r)
	}
	// 64 Bit kleiner: zurückgesetzt, keine Rate.
	prev = mk(t0, 1000, 5000, 100, true, 0)
	cur = mk(t0.Add(60*time.Second), 7000, 10, 200, true, 0)
	rates(cur, prev)
	if cur.Interfaces[0].InBps != nil || cur.Interfaces[0].OutBps == nil {
		t.Errorf("Zurücksetzen: %+v", cur.Interfaces[0])
	}
	// Neustart: keine Raten.
	prev = mk(t0, 500000, 1, 1, true, 0)
	cur = mk(t0.Add(60*time.Second), 100, 100, 100, true, 0)
	rates(cur, prev)
	if cur.Interfaces[0].InBps != nil {
		t.Error("Rate trotz Neustart")
	}
	// Unplausibel schnell (über ifSpeed): keine Rate.
	prev = mk(t0, 1000, 0, 0, true, 10_000_000)
	cur = mk(t0.Add(10*time.Second), 2000, 1<<40, 0, true, 10_000_000)
	rates(cur, prev)
	if cur.Interfaces[0].InBps != nil {
		t.Error("unplausible Rate angenommen")
	}
}

func TestImplausibleRate(t *testing.T) {
	now := time.Now()
	mk := func(at time.Time, octets uint64) *Snapshot {
		s := &Snapshot{Interfaces: []Interface{{Index: 1, Name: "lo", SpeedBps: 10_000_000, InOctets: octets}}}
		s.Counters = &CounterInfo{At: at}
		return s
	}
	a := mk(now, 1000)
	if !implausible(a, mk(now.Add(time.Second), 1000+5_000_000), mk(now, 1000+5_000_000).Interfaces[0]) {
		t.Error("40 Mbit/s auf 10 Mbit/s gilt nicht als unplausibel")
	}
	if implausible(a, mk(now.Add(time.Second), 1000+100_000), mk(now, 1000+100_000).Interfaces[0]) {
		t.Error("0,8 Mbit/s gilt als unplausibel")
	}
}

// Ein Gerät meldet in der Counter32-Spalte Counter64 oder eine zu große
// Zahl: Der Wert zählt als fehlend, die Abfrage bleibt gültig.
func TestCounter32Unplausibel(t *testing.T) {
	for _, tc := range []struct {
		pdu  gosnmp.SnmpPDU
		want uint64
	}{
		{gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(4294967295)}, 4294967295},
		{gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1) << 40}, 0},
		{gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: int(1) << 33}, 0},
		{gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("x")}, 0},
	} {
		if got := counter32(value{pdu: tc.pdu}); got != tc.want {
			t.Errorf("%v %v: %d, erwartet %d", tc.pdu.Type, tc.pdu.Value, got, tc.want)
		}
	}
}
