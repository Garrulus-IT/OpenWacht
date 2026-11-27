// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParse18b(t *testing.T) {
	for kind, raw := range map[string]string{
		"tcp_banner": `{"host":"127.0.0.1","port":25,"enthaelt":"220"}`,
		"ntp":        `{"host":"ntp.example.org"}`,
		"snmp_oid":   `{"oid":".1.3.6.1.4.1.6574.1.2.0","warnung_ueber":60}`,
		"docker":     `{"name":"webapp_webserver_1"}`,
		"hyperv":     `{"name":"Büro-PC (alt) #2"}`,
	} {
		s, err := Parse(kind, []byte(raw))
		if err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		if kind == "ntp" && (s.Port != 123 || s.OffsetWarnMS != 100 || s.OffsetCritMS != 1000) {
			t.Errorf("ntp Standard: %+v", s)
		}
		if kind == "snmp_oid" && s.OID != "1.3.6.1.4.1.6574.1.2.0" {
			t.Errorf("OID nicht bereinigt: %q", s.OID)
		}
	}
	for _, tc := range []struct{ kind, raw, want string }{
		{"tcp_banner", `{"host":"x"}`, "Port"},
		{"tcp_banner", `{"host":"x","port":25,"ca_pem":"x"}`, "nur mit TLS"},
		{"ntp", `{"host":"x","abweichung_warnung_ms":500,"abweichung_kritisch_ms":100}`, "Warnung kleiner"},
		{"snmp_oid", `{"oid":"1.3.6.1.x"}`, "OID"},
		{"snmp_oid", `{"oid":"7.1"}`, "OID"},
		{"snmp_oid", `{"oid":"1.3.06.1"}`, "OID"},
		{"snmp_oid", `{"oid":"1.3.6","rate":true,"gleich":"x"}`, "Rate"},
		{"snmp_oid", `{"oid":"1.3.6","host":"x"}`, "passt nicht"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"mittel"}`, "Zusammenfassung der Spalte"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"minimum","rate":true}`, "Spalte"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"minimum","gleich":"1"}`, "Spalte"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"anzahl_gleich"}`, "Vergleichswert"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"minimum","vergleichswert":1}`, "Vergleichswert"},
		{"snmp_oid", `{"oid":"1.3.6","vergleichswert":1}`, "Vergleichswert"},
		{"snmp_oid", `{"oid":"1.3.6","zusammenfassung":"anzahl_gleich","vergleichswert":4294967296}`, "32-Bit"},
		{"leistungsindikator", `{"objekt":"A","indikator":"B","vergleichswert":1}`, "passt nicht"},
		{"docker", `{"name":"/etc"}`, "Container"},
		{"docker", `{"name":"a b"}`, "Container"},
		{"hyperv", `{"name":"-x"}`, "VM"},
		{"hyperv", `{"name":"a\nb"}`, "VM"},
		{"hyperv", `{"name":"a;b"}`, "VM"},
		{"hyperv", `{"name":"$(x)"}`, "VM"},
		{"hyperv", `{"name":""}`, "VM"},
		{"hyperv", `{"name":"dc01","pfad":"/x"}`, "passt nicht"},
	} {
		if _, err := Parse(tc.kind, []byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: %v", tc.kind, tc.raw, err)
		}
	}
	sp, err := Parse("snmp_oid", []byte(`{"oid":"1.3.6.1","zusammenfassung":" Anzahl_Gleich ","vergleichswert":1,"kritisch_ueber":0}`))
	if err != nil || sp.Aggregate != "anzahl_gleich" || *sp.Compare != 1 || DefaultName("snmp_oid", sp) != "Spalte 1.3.6.1 anzahl_gleich" {
		t.Errorf("Spalte: %v %+v", err, sp)
	}
	if !IsAgentKind("docker") || !IsAgentKind("hyperv") || IsAgentKind("snmp_oid") || !IsSNMPKind("snmp_oid") {
		t.Error("Einteilung der Arten")
	}
}

func bannerServer(t *testing.T, greeting string, tlsCfg *tls.Config) int {
	t.Helper()
	var l net.Listener
	var err error
	if tlsCfg != nil {
		l, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		l, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if greeting != "" {
					c.Write([]byte(greeting))
				}
				time.Sleep(1500 * time.Millisecond)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestBanner(t *testing.T) {
	r := runner()
	smtp := bannerServer(t, "220 mail.example ESMTP Postfix geheim\r\n250 more\r\n", nil)
	b := func(rest string, port int) string { return fmt.Sprintf(`{"host":"127.0.0.1","port":%d%s}`, port, rest) }
	expect(t, "Banner", run(t, r, "tcp_banner", b(`,"enthaelt":"220"`, smtp)), OK, "Banner erhalten")
	got := run(t, r, "tcp_banner", b(`,"enthaelt":"IMAP"`, smtp))
	expect(t, "falscher Text", got, Crit, "ohne erwarteten Text")
	if strings.Contains(got.Message+got.Metric, "Postfix") {
		t.Errorf("Banner in der Meldung: %+v", got)
	}
	still := bannerServer(t, "", nil)
	expect(t, "stumm", run(t, r, "tcp_banner", b(`,"timeout_s":1`, still)), Crit, "kein Banner")
	expect(t, "zu", run(t, r, "tcp_banner", b("", freePort(t))), Crit, "Verbindung abgelehnt")
	expect(t, "gesperrt", run(t, &Runner{Guard: NewGuard(nil)}, "tcp_banner", b("", smtp)), Unknown, "nicht freigegeben")

	// direktes TLS mit eigener CA
	p := newPKI(t)
	now := time.Now()
	leaf, key := newCert(t, &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, p.inter, p.interKey)
	imaps := bannerServer(t, "* OK IMAP4rev1 ready\r\n", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, p.inter.Raw}, PrivateKey: key}}})
	expect(t, "TLS", run(t, r, "tcp_banner", b(`,"tls":true,"enthaelt":"OK","ca_pem":"`+p.rootPEM+`"`, imaps)), OK, "Banner erhalten")
	expect(t, "TLS ohne CA", run(t, r, "tcp_banner", b(`,"tls":true`, imaps)), Crit, "TLS")
}

// fakeNTP antwortet mit einer Uhr, die um skew falsch geht.
func fakeNTP(t *testing.T, skew time.Duration, stratum byte, li byte, echoOrigin bool) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 128)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			resp := make([]byte, 48)
			resp[0] = li<<6 | 4<<3 | 4
			resp[1] = stratum
			if echoOrigin {
				copy(resp[24:32], buf[40:48])
			}
			now := toNTP(time.Now().Add(skew))
			binary.BigEndian.PutUint64(resp[32:], now)
			binary.BigEndian.PutUint64(resp[40:], now)
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestNTP(t *testing.T) {
	r := runner()
	n := func(port int, rest string) string { return fmt.Sprintf(`{"host":"127.0.0.1","port":%d%s}`, port, rest) }
	expect(t, "gut", run(t, r, "ntp", n(fakeNTP(t, 0, 2, 0, true), "")), OK, "Zeit stimmt")
	expect(t, "Warnung", run(t, r, "ntp", n(fakeNTP(t, 300*time.Millisecond, 2, 0, true), "")), Warn, "über 100 ms")
	got := run(t, r, "ntp", n(fakeNTP(t, -3*time.Second, 2, 0, true), ""))
	expect(t, "kritisch", got, Crit, "über 1000 ms")
	if !strings.HasPrefix(got.Metric, "−") || !strings.Contains(got.Metric, "Stratum 2") {
		t.Errorf("Messwert %q", got.Metric)
	}
	expect(t, "Stratum 16", run(t, r, "ntp", n(fakeNTP(t, 0, 16, 3, true), "")), Warn, "nicht synchron")
	expect(t, "KoD", run(t, r, "ntp", n(fakeNTP(t, 0, 0, 3, true), "")), Crit, "Kiss")
	// Antwort ohne unseren Zeitstempel wird verworfen: Zeitüberschreitung
	expect(t, "fremd", run(t, r, "ntp", n(fakeNTP(t, 0, 2, 0, false), `,"timeout_s":1`)), Crit, "Zeitüberschreitung")
	expect(t, "gesperrt", run(t, &Runner{Guard: NewGuard(nil)}, "ntp", n(123, "")), Unknown, "nicht freigegeben")
	if tt := fromNTP(toNTP(time.Unix(1700000000, 500000000))); tt.Sub(time.Unix(1700000000, 500000000)).Abs() > time.Microsecond {
		t.Errorf("NTP-Zeit: %v", tt)
	}
}

// TestNumberFromText (1.0.8): Zahl aus einem Text des Geräts, Beispiele vom
// LANCOM GS-3628XUP.
func TestNumberFromText(t *testing.T) {
	cpu := "100ms:52%, 1s:57%, 10s:50%"
	for _, c := range []struct {
		text  string
		n     int
		after string
		want  float64
		ok    bool
	}{
		{"72", 1, "", 72, true},
		{"1500RPM", 1, "", 1500, true},
		{"994 M", 1, "", 994, true},
		{cpu, 1, "", 100, true},
		{cpu, 2, "", 52, true},
		{cpu, 6, "", 50, true},
		{cpu, 7, "", 0, false},
		{cpu, 0, "10s:", 50, true},
		{cpu, 0, "1s:", 57, true},
		{cpu, 0, "5min:", 0, false},
		{"Temp: 41,5 °C", 1, "", 41.5, true},
		{"Temp: 41.5 °C", 1, "", 41.5, true},
		{"-5 dBm", 1, "", -5, true},
		{"rx -12.3", 1, "", -12.3, true},
		{"port1-5", 2, "", 5, true},
		{"a-5", 1, "", 5, true},
		{"1.2.3", 2, "", 3, true},
		{"1,", 1, "", 1, true},
		{"v4.30.0503SU11", 1, "", 4.30, true},
		{"none", 1, "", 0, false},
		{"", 1, "", 0, false},
		{"5", 0, "", 0, false},
		{"Lüfter 2: 1500", 0, "Lüfter 2: ", 1500, true},
		{strings.Repeat("9", 500), 1, "", 0, false},
	} {
		got, ok := NumberFromText(c.text, c.n, c.after)
		if ok != c.ok || got != c.want {
			t.Errorf("NumberFromText(%q, %d, %q) = %v, %v", c.text, c.n, c.after, got, ok)
		}
	}
}

func TestSNMPOIDZahlAusText(t *testing.T) {
	gut := []string{
		`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.17.0","zahl_aus_text":"erste","einheit":"RPM","warnung_unter":500}`,
		`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.24.0","zahl_aus_text":"nte","zahl_nr":6,"einheit":"%","warnung_ueber":80}`,
		`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.24.0","zahl_aus_text":"nach","zahl_nach":"10s:","einheit":"%"}`,
		`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.204.0","faktor":0.1,"einheit":"W"}`,
		`{"oid":"1.3.6.1.2.1.2.2.1.14","zusammenfassung":"summe","faktor":2}`,
	}
	for _, g := range gut {
		if _, err := Parse("snmp_oid", []byte(g)); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	schlecht := []string{
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"regex"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"erste","zahl_nr":2}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"nte"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"nte","zahl_nr":17}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"nach"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"nach","zahl_nach":"` + strings.Repeat("x", 41) + `"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"nach","zahl_nach":"a\u0007"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_nr":2}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_nach":"x"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"erste","gleich":"5"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","zahl_aus_text":"erste","rate":true}`,
		`{"oid":"1.3.6.1.2.1.2.2.1.14","zusammenfassung":"summe","zahl_aus_text":"erste"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","einheit":"Furlong"}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","faktor":1e12}`,
		`{"oid":"1.3.6.1.2.1.1.1.0","faktor":1e-12}`,
		`{"host":"a.example","zahl_aus_text":"erste"}`,
	}
	for _, s := range schlecht {
		if _, err := Parse("snmp_oid", []byte(s)); err == nil {
			t.Errorf("angenommen: %s", s)
		}
	}
	if _, err := Parse("ping", []byte(`{"host":"a.example","faktor":2}`)); err == nil {
		t.Error("Faktor am Ping angenommen")
	}
	// Faktor 1 ist kein Faktor.
	sp, err := Parse("snmp_oid", []byte(`{"oid":"1.3.6.1.2.1.1.1.0","faktor":1}`))
	if err != nil || sp.Factor != 0 {
		t.Errorf("Faktor 1: %v %v", sp.Factor, err)
	}
}
