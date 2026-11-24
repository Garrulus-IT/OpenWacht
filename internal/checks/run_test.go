// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var loopback = NewGuard(prefixes("127.0.0.1/32"))

// Ein Proxy, der nicht antwortet: Würde ein Check ihn benutzen, schlüge er fehl.
// Go liest die Variablen nur einmal je Prozess, deshalb vor allen Tests.
func TestMain(m *testing.M) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		os.Setenv(v, "http://127.0.0.1:1")
	}
	for _, v := range []string{"NO_PROXY", "no_proxy"} {
		os.Unsetenv(v)
	}
	os.Exit(m.Run())
}

func runner() *Runner { return &Runner{Guard: loopback} }

func run(t *testing.T, r *Runner, kind, raw string) Result {
	t.Helper()
	s, err := Parse(kind, []byte(raw))
	if err != nil {
		t.Fatalf("Parse %s: %v", raw, err)
	}
	return r.Run(context.Background(), kind, s)
}

func expect(t *testing.T, what string, got Result, status, contains string) {
	t.Helper()
	if got.Status != status || !strings.Contains(got.Message, contains) {
		t.Errorf("%s: %s %q, erwartet %s mit %q", what, got.Status, got.Message, status, contains)
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	r := run(t, runner(), "tcp", fmt.Sprintf(`{"host":"127.0.0.1","port":%d}`, port))
	expect(t, "offen", r, OK, fmt.Sprintf("Port %d offen", port))
	if !strings.HasSuffix(r.Metric, " ms") {
		t.Errorf("Messwert %q", r.Metric)
	}
	expect(t, "geschlossen", run(t, runner(), "tcp", fmt.Sprintf(`{"host":"127.0.0.1","port":%d}`, freePort(t))),
		Crit, "Verbindung abgelehnt")
	// Breite Freigabe öffnet Loopback nicht.
	wide := &Runner{Guard: NewGuard(prefixes("0.0.0.0/0"))}
	expect(t, "nicht freigegeben", run(t, wide, "tcp", fmt.Sprintf(`{"host":"127.0.0.1","port":%d}`, port)),
		Unknown, "nicht freigegeben")
}

func TestHTTP(t *testing.T) {
	var redirectFollowed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"healthy":true}`) })
	mux.HandleFunc("/umleitung", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ziel", http.StatusFound) })
	mux.HandleFunc("/ziel", func(w http.ResponseWriter, r *http.Request) { redirectFollowed.Store(true) })
	mux.HandleFunc("/fehler", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "kaputt", 500) })
	mux.HandleFunc("/langsam", func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u := srv.URL

	expect(t, "200", run(t, runner(), "http", `{"url":"`+u+`/ok"}`), OK, "HTTP 200")
	expect(t, "Text da", run(t, runner(), "http", `{"url":"`+u+`/ok","enthaelt":"\"healthy\":true"}`), OK, "HTTP 200")
	expect(t, "Text fehlt", run(t, runner(), "http", `{"url":"`+u+`/ok","enthaelt":"krank"}`), Crit, "erwarteter Text fehlt")
	expect(t, "302 gilt als OK", run(t, runner(), "http", `{"url":"`+u+`/umleitung"}`), OK, "HTTP 302")
	if redirectFollowed.Load() {
		t.Error("Weiterleitung gefolgt")
	}
	expect(t, "500", run(t, runner(), "http", `{"url":"`+u+`/fehler"}`), Crit, "HTTP 500 (unerwartet)")
	expect(t, "500 erwartet", run(t, runner(), "http", `{"url":"`+u+`/fehler","erwarte_status":[500]}`), OK, "HTTP 500")
	expect(t, "302 nicht erwartet", run(t, runner(), "http", `{"url":"`+u+`/umleitung","erwarte_status":[200]}`), Crit, "302")
	expect(t, "Zeitüberschreitung", run(t, runner(), "http", `{"url":"`+u+`/langsam","timeout_s":1}`), Crit, "Zeitüberschreitung nach 1 s")
	// Ein Proxy aus der Umgebung (TestMain setzt einen, der nicht antwortet)
	// wird nicht benutzt. Mit Namen statt IP, denn Go schickt Anfragen an
	// Loopback-Adressen ohnehin nie über einen Proxy.
	named := NewGuard(prefixes("127.0.0.1/32"))
	named.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	port := u[strings.LastIndex(u, ":")+1:]
	expect(t, "ohne Proxy", run(t, &Runner{Guard: named}, "http", `{"url":"http://dienst.test:`+port+`/ok"}`), OK, "HTTP 200")
	expect(t, "Name statt IP", run(t, runner(), "http", `{"url":"http://gibt-es-nicht.invalid/"}`), Crit, "nicht auflösbar")

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	expect(t, "selbstsigniert", run(t, runner(), "http", `{"url":"`+ts.URL+`/ok"}`), Crit, "TLS: selbstsigniertes Zertifikat")
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	caJSON := strings.ReplaceAll(ca, "\n", `\n`)
	expect(t, "eigene CA", run(t, runner(), "http", `{"url":"`+ts.URL+`/ok","ca_pem":"`+caJSON+`"}`), OK, "HTTP 200")
}

// --- TLS mit eigener Kette ------------------------------------------------------

type pki struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	rootPEM           string
}

func newCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func newPKI(t *testing.T) *pki {
	now := time.Now()
	p := &pki{}
	p.root, p.rootKey = newCert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	p.inter, p.interKey = newCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Zwischen-CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, p.root, p.rootKey)
	p.rootPEM = strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.root.Raw})), "\n", `\n`)
	return p
}

// server liefert ein Zertifikat für name mit der gegebenen Restlaufzeit,
// mit oder ohne Zwischenzertifikat in der Kette.
func (p *pki) server(t *testing.T, name string, left time.Duration, withInter bool) int {
	t.Helper()
	now := time.Now()
	leaf, key := newCert(t, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(left),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, p.inter, p.interKey)
	chain := [][]byte{leaf.Raw}
	if withInter {
		chain = append(chain, p.inter.Raw)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
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
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestTLS(t *testing.T) {
	p := newPKI(t)
	day := 24 * time.Hour
	check := func(name string, port int, extra string) Result {
		return run(t, runner(), "tls", fmt.Sprintf(`{"host":"%s","verbinde":"127.0.0.1","port":%d,"ca_pem":"%s"%s}`,
			name, port, p.rootPEM, extra))
	}
	expect(t, "gültig", check("dms.test", p.server(t, "dms.test", 100*day, true), ""), OK, "Aussteller Test Zwischen-CA")
	expect(t, "Restlaufzeit", check("dms.test", p.server(t, "dms.test", 100*day, true), ""), OK, "noch 99 Tage")
	expect(t, "Warnung", check("dms.test", p.server(t, "dms.test", 10*day, true), ""), Warn, "läuft in 9 Tage")
	expect(t, "kritisch", check("dms.test", p.server(t, "dms.test", 3*day, true), ""), Crit, "läuft in 2 Tage")
	expect(t, "eigene Schwellen", check("dms.test", p.server(t, "dms.test", 3*day, true), `,"warnung_tage":2,"kritisch_tage":1`), OK, "gültig bis")
	expect(t, "weniger als ein Tag", check("dms.test", p.server(t, "dms.test", 10*time.Hour, true), ""), Crit, "weniger als 1 Tag")
	expect(t, "abgelaufen", check("dms.test", p.server(t, "dms.test", -day, true), ""), Crit, "abgelaufen am")
	// Lehre aus dem StoreFront-Zertifikatstausch: fehlende Zwischen-CA ausdrücklich melden, Ablauf trotzdem nennen.
	r := check("dms.test", p.server(t, "dms.test", 100*day, false), "")
	expect(t, "ohne Zwischenzertifikat", r, Crit, "fehlt das Zwischenzertifikat?")
	expect(t, "ohne Zwischenzertifikat: Ablauf", r, Crit, "gültig bis")
	expect(t, "falscher Name", check("anderer.test", p.server(t, "dms.test", 100*day, true), ""), Crit, "Name passt nicht")
	expect(t, "unbekannte CA", run(t, runner(), "tls", fmt.Sprintf(`{"host":"dms.test","verbinde":"127.0.0.1","port":%d}`,
		p.server(t, "dms.test", 100*day, true))), Crit, "unbekannte CA")
	expect(t, "Port zu", check("dms.test", freePort(t), ""), Crit, "Verbindung abgelehnt")

	// Kein TLS am anderen Ende
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	expect(t, "kein TLS", check("dms.test", l.Addr().(*net.TCPAddr).Port, ""), Crit, "TLS-Handshake fehlgeschlagen")
}

func TestPing(t *testing.T) {
	r := run(t, runner(), "ping", `{"host":"127.0.0.1","timeout_s":1}`)
	if r.Status == Unknown && strings.Contains(r.Message, "ping_group_range") {
		t.Skip("Ping ohne Root ist auf diesem System gesperrt (net.ipv4.ping_group_range)")
	}
	expect(t, "Ping Loopback", r, OK, "erreichbar")
	if !strings.HasSuffix(r.Metric, " ms") {
		t.Errorf("Messwert %q", r.Metric)
	}
	quiet := &Runner{Guard: NewGuard(prefixes("192.0.2.0/24"))}
	expect(t, "nicht freigegeben", run(t, quiet, "ping", `{"host":"127.0.0.1","timeout_s":1}`), Unknown, "nicht freigegeben")
}
