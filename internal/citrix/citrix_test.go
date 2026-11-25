// SPDX-License-Identifier: AGPL-3.0-only

package citrix

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/citrix/citrixtest"
)

type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

type denyDialer struct{}

func (denyDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("nicht freigegeben")
}

func cfgFor(s *citrixtest.Server) Config {
	return Config{Host: s.Host, Port: s.Port, User: citrixtest.User, Password: citrixtest.Password, Pin: s.Pin}
}

func TestPoll(t *testing.T) {
	s := citrixtest.Start(t)
	c := &Client{Guard: plainDialer{}}
	snap, err := c.Poll(context.Background(), cfgFor(s))
	if err != nil {
		t.Fatal(err)
	}
	x := snap.Citrix
	if x.Machines != 3 || x.Registered != 1 || x.Maintenance != 1 || x.Unregistered != 1 ||
		len(x.UnregisteredNames) != 1 || x.UnregisteredNames[0] != `BEISPIEL\VDA-02` {
		t.Errorf("Maschinen: %+v", x)
	}
	if x.FailureTotal != 3 || len(x.Failures) != 2 || x.Failures[0].Code != 3 || x.Failures[0].Count != 2 {
		t.Errorf("Fehlschläge: %+v", x.Failures)
	}
	// Nur GET, nur die zwei Entitäten, mit Filter und Auswahl der Felder.
	for _, m := range s.Methods {
		if m != "GET" {
			t.Errorf("Methode %s", m)
		}
	}
	all, _ := url.QueryUnescape(strings.Join(s.Requests, "\n"))
	if !strings.Contains(all, "$select=Name,DnsName,CurrentRegistrationState,IsInMaintenanceMode") ||
		!strings.Contains(all, "$filter=LifecycleState eq 0") || !strings.Contains(all, "$select=ConnectionFailureEnumValue") {
		t.Errorf("Anfragen:\n%s", all)
	}
	// Datensparsam: keine Benutzer, Sitzungen oder Clients angefragt.
	for _, w := range []string{"User", "Session", "expand", "Client"} {
		if strings.Contains(all, w) {
			t.Errorf("fragt %s an", w)
		}
	}
}

func TestPollFehler(t *testing.T) {
	ctx := context.Background()
	c := &Client{Guard: plainDialer{}}

	s := citrixtest.Start(t)
	cfg := cfgFor(s)
	cfg.Password = "falsch-falsch-falsch"
	if _, err := c.Poll(ctx, cfg); !errors.Is(err, ErrLogin) {
		t.Errorf("falsches Passwort: %v", err)
	}
	cfg = cfgFor(s)
	cfg.Pin = strings.Repeat("0", 64)
	var pe *PinError
	if _, err := c.Poll(ctx, cfg); !errors.As(err, &pe) || pe.Got != s.Pin {
		t.Errorf("falscher Fingerabdruck: %v", err)
	}
	if len(s.Requests) != 0 {
		t.Errorf("Anfrage trotz Fehler: %v", s.Requests)
	}
	if _, err := (&Client{Guard: denyDialer{}}).Poll(ctx, cfgFor(s)); err == nil || !strings.Contains(err.Error(), "nicht freigegeben") {
		t.Errorf("Guard: %v", err)
	}

	for name, set := range map[string]func(*citrixtest.Server){
		"Forbidden":   func(s *citrixtest.Server) { s.Forbidden = true },
		"NoNTLM":      func(s *citrixtest.Server) { s.NoNTLM = true },
		"Huge":        func(s *citrixtest.Server) { s.Huge = true },
		"ForeignNext": func(s *citrixtest.Server) { s.Pages, s.ForeignNext = true, true },
	} {
		s := citrixtest.Start(t)
		set(s)
		_, err := c.Poll(ctx, cfgFor(s))
		want := map[string]error{"Forbidden": ErrNoRole, "NoNTLM": ErrNoNTLM, "Huge": ErrTooMuch}[name]
		switch {
		case err == nil:
			t.Errorf("%s: kein Fehler", name)
		case want != nil && !errors.Is(err, want):
			t.Errorf("%s: %v", name, err)
		case name == "ForeignNext" && !strings.Contains(err.Error(), "andere Adresse"):
			t.Errorf("%s: %v", name, err)
		}
	}

	// Mehrere Seiten auf derselben Adresse: gelesen.
	s = citrixtest.Start(t)
	s.Pages = true
	snap, err := c.Poll(ctx, cfgFor(s))
	if err != nil || snap.Citrix.Machines != 3 {
		t.Errorf("Seiten: %v", err)
	}
	// Fehlschläge nicht lesbar: Abfrage gilt, als teilweise markiert.
	s = citrixtest.Start(t)
	s.FailuresBroken = true
	snap, err = c.Poll(ctx, cfgFor(s))
	if err != nil || len(snap.Partial) != 1 || snap.Citrix.FailureTotal != 0 {
		t.Errorf("Fehlschläge kaputt: %v %+v", err, snap)
	}
}

func TestFingerprint(t *testing.T) {
	s := citrixtest.Start(t)
	fp, err := (&Client{Guard: plainDialer{}}).Fingerprint(context.Background(), s.Host, s.Port)
	if err != nil || fp != s.Pin {
		t.Fatalf("%v %s", err, fp)
	}
	if len(s.Requests)+len(s.Methods) != 0 {
		t.Error("Fingerabdruck hat eine Anfrage gesendet")
	}
}

func TestBuildNamen(t *testing.T) {
	var raw Raw
	for i := 0; i < 80; i++ {
		raw.Machines = append(raw.Machines, Machine{Name: "B\\VDA-" + string(rune('A'+i%26)) + strings.Repeat("x", i), Registration: 0})
	}
	raw.Machines = append(raw.Machines, Machine{Name: "B\\\x07böse\u0000", Registration: 2}, Machine{DNSName: "nur-dns.beispiel.example"})
	x := Build(raw, "")
	if x.Unregistered != 82 || len(x.UnregisteredNames) != 50 {
		t.Errorf("%d %d", x.Unregistered, len(x.UnregisteredNames))
	}
	for _, n := range x.UnregisteredNames {
		if strings.ContainsAny(n, "\x00\x07") || len([]rune(n)) > 120 {
			t.Errorf("Name %q", n)
		}
	}
}

func TestValidUser(t *testing.T) {
	for _, u := range []string{`BEISPIEL\svc-ow`, "svc.ow@beispiel.example"} {
		if !ValidUser(u) {
			t.Errorf("%q abgelehnt", u)
		}
	}
	for _, u := range []string{"", "svc", `a\b\c`, "a@b@c", "x\x00@y", `B\` + strings.Repeat("x", 200)} {
		if ValidUser(u) {
			t.Errorf("%q angenommen", u)
		}
	}
}
