// SPDX-License-Identifier: AGPL-3.0-only

// Package brevistest ist eine Attrappe eines brevis.one-SMS-Gateways für
// Tests (HTTP API nach docs.brevis.one, „HTTP API“, Stand 23.11.2026):
// POST oder GET auf /api.php mit username, password, to, text und optional
// mode, ring, flash. Fehler wie in der Doku als HTTP-Status mit Text:
//
//	400 „Error: Parameter miss.“            Pflichtangabe fehlt
//	400 „Error. See Gateway logs …“          unbekannte Gruppe, ungültige Nummer
//	401 „401 Unauthorized - …“               Benutzer oder Passwort falsch
//	403 „403 Forbidden - …“                  Benutzer ohne Recht auf die API
//	408 „FAILED - Timeout …“                 Zeitüberschreitung im Mobilfunk
//
// Zusätzlich: Weiterleitung, übergroße Antwort, langsame Antwort. Jede
// Attrappe hat ein eigenes, selbstsigniertes Zertifikat wie ein Gateway ab
// Werk. Zugangsdaten und Nummern sind feste Testwerte.
package brevistest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Feste Testwerte.
const (
	User     = "openwacht-api"
	Password = "test-passwort-123"
)

// Request: eine angenommene Anfrage.
type Request struct {
	Method      string
	ContentType string
	RawQuery    string // muss bei POST leer sein (Passwort nie in der URL)
	User        string
	Mode        string
	To          string
	Text        string
	Ring        bool
	Flash       bool
}

// Fake: Zustand der Attrappe.
type Fake struct {
	mu       sync.Mutex
	user     string
	pass     string
	noRight  bool
	groups   map[string]bool
	timeout  bool
	redirect bool
	huge     bool
	status   int // feste Antwort (0 = normal)
	body     string
	delay    time.Duration
	failNext int // die nächsten n Anfragen mit 408
	noRing   bool
	requests []Request
	// OnRequest: wird je Anfrage aufgerufen (tools/brevisattrappe protokolliert damit).
	OnRequest func(Request, int)
}

// NewFake: Gateway mit Benutzer User/Password und den Gruppen „1“ und
// „Bereitschaft“.
func NewFake() *Fake {
	return &Fake{user: User, pass: Password, groups: map[string]bool{"1": true, "Bereitschaft": true}}
}

// NoRight: Der Benutzer hat nicht das Recht „Zugriff auf die HTTP API“ (403).
func (f *Fake) NoRight(on bool) { f.mu.Lock(); f.noRight = on; f.mu.Unlock() }

// Timeout: Das Gateway meldet 408.
func (f *Fake) Timeout(on bool) { f.mu.Lock(); f.timeout = on; f.mu.Unlock() }

// FailNext: die nächsten n Anfragen mit 408.
func (f *Fake) FailNext(n int) { f.mu.Lock(); f.failNext = n; f.mu.Unlock() }

// NoRing: Anrufe (ring=true) scheitern mit 400, SMS gehen (SIM nur für SMS).
func (f *Fake) NoRing(on bool) { f.mu.Lock(); f.noRing = on; f.mu.Unlock() }

// Redirect: Antwort 302 nach /login.
func (f *Fake) Redirect(on bool) { f.mu.Lock(); f.redirect = on; f.mu.Unlock() }

// Huge: Antwort 200 mit 8 MiB Inhalt.
func (f *Fake) Huge(on bool) { f.mu.Lock(); f.huge = on; f.mu.Unlock() }

// Respond: feste Antwort (status 0 = wieder normal).
func (f *Fake) Respond(status int, body string) {
	f.mu.Lock()
	f.status, f.body = status, body
	f.mu.Unlock()
}

// Delay: Antwort erst nach d.
func (f *Fake) Delay(d time.Duration) { f.mu.Lock(); f.delay = d; f.mu.Unlock() }

// AddGroup legt eine Gruppe an.
func (f *Fake) AddGroup(g string) { f.mu.Lock(); f.groups[g] = true; f.mu.Unlock() }

// Requests: alle angenommenen Anfragen (auch abgelehnte).
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Sent: erfolgreich angenommene SMS (ohne Anrufe).
func (f *Fake) Sent() []Request {
	var out []Request
	for _, r := range f.Requests() {
		if r.Method == "ok" {
			out = append(out, r)
		}
	}
	return out
}

// Reset leert die Liste der Anfragen.
func (f *Fake) Reset() { f.mu.Lock(); f.requests = nil; f.mu.Unlock() }

var numberPattern = regexp.MustCompile(`^(00|\+)?[0-9]{6,16}$`)

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api.php" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Error: Parameter miss."))
		return
	}
	req := Request{Method: r.Method, ContentType: r.Header.Get("Content-Type"), RawQuery: r.URL.RawQuery,
		User: r.Form.Get("username"), Mode: r.Form.Get("mode"), To: r.Form.Get("to"), Text: r.Form.Get("text"),
		Ring: r.Form.Get("ring") == "true", Flash: r.Form.Get("flash") == "true"}
	f.mu.Lock()
	delay := f.delay
	status, body := f.status, f.body
	answer := func(code int, text string) {
		if code == http.StatusOK {
			req.Method = "ok"
		}
		f.requests = append(f.requests, req)
		hook := f.OnRequest
		f.mu.Unlock()
		if hook != nil {
			hook(req, code)
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				// Verbindung abbrechen statt still mit 200 zu antworten:
				// sonst kann ein Client, der gerade aufgibt, Erfolg lesen.
				panic(http.ErrAbortHandler)
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(text))
	}
	switch {
	case f.redirect:
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	case f.huge:
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 64<<10))
		for i := 0; i < 128; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		return
	case status != 0:
		answer(status, body)
	case req.User == "" || r.Form.Get("password") == "" || req.To == "" || req.Text == "":
		answer(http.StatusBadRequest, "Error: Parameter miss.")
	case req.User != f.user || r.Form.Get("password") != f.pass:
		answer(http.StatusUnauthorized, "401 Unauthorized - Username or Password wrong.")
	case f.noRight:
		answer(http.StatusForbidden, "403 Forbidden - Your User has no right to send SMS over API.")
	case f.timeout || f.failNext > 0:
		if f.failNext > 0 {
			f.failNext--
		}
		answer(http.StatusRequestTimeout, "FAILED - Timeout or see Gateway logs for more information.")
	case req.Ring && f.noRing:
		answer(http.StatusBadRequest, "Error. See Gateway logs for more information.")
	case req.Mode == "group" && !f.groups[req.To]:
		answer(http.StatusBadRequest, "Error. See Gateway logs for more information.")
	case (req.Mode == "" || req.Mode == "number") && !numberPattern.MatchString(req.To):
		answer(http.StatusBadRequest, "Error. See Gateway logs for more information.")
	default:
		// Erfolg: Die Doku beschreibt den Inhalt nicht; „OK“ als Platzhalter.
		answer(http.StatusOK, "OK")
	}
}

// Server: laufende Attrappe.
type Server struct {
	*httptest.Server
	// Gateway: https://127.0.0.1:<port>
	Gateway string
	// Pin: SHA-256 des Zertifikats (hex, klein)
	Pin string
}

// Start startet die Attrappe mit TLS und eigenem, selbstsigniertem Zertifikat.
func Start(t *testing.T, f *Fake) *Server {
	t.Helper()
	cert, pin, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return &Server{Server: srv, Gateway: "https://127.0.0.1:" + port, Pin: pin}
}

// Serve startet die Attrappe außerhalb von Tests (Bilder-Skript,
// tools/brevisattrappe) auf addr und liefert den Fingerabdruck.
func Serve(addr string, f *Fake) (*http.Server, string, error) {
	cert, pin, err := selfSigned()
	if err != nil {
		return nil, "", err
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return srv, pin, nil
}

// Port der Attrappe.
func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	n, _ := strconv.Atoi(p)
	return n
}

func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "sms-gateway-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"sms-gateway.invalid"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}
