// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestGuardAllowed(t *testing.T) {
	g := NewGuard(prefixes("172.16.0.0/12", "10.0.0.0/8", "0.0.0.0/0", "::/0", "127.0.0.1/32"))
	cases := map[string]bool{
		"192.168.1.10":       true,
		"8.8.8.8":            true,  // über 0.0.0.0/0
		"2001:db8::1":        true,  // über ::/0
		"127.0.0.1":          true,  // ausdrücklich freigegeben
		"127.0.0.2":          false, // nicht über 0.0.0.0/0
		"::ffff:127.0.0.2":   false, // IPv4 in IPv6 verpackt
		"::ffff:192.168.1.1": true,
		"169.254.169.254":    false, // Cloud-Metadaten, nicht über 0.0.0.0/0
		"::1":                false, // nicht über ::/0
		"fe80::1":            false,
		"0.0.0.0":            false,
		"0.1.2.3":            false,
		"224.0.0.1":          false,
		"255.255.255.255":    false,
		"ff02::1":            false,
		"::":                 false,
	}
	for ip, want := range cases {
		if got := g.Allowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Allowed(%s) = %v, erwartet %v", ip, got, want)
		}
	}
	if NewGuard(nil).Allowed(netip.MustParseAddr("192.168.1.1")) {
		t.Error("ohne Freigabe erlaubt")
	}
	// Freigabe des ganzen Loopback-Bereichs gilt, weil sie darin liegt.
	if !NewGuard(prefixes("127.0.0.0/8")).Allowed(netip.MustParseAddr("127.0.0.53")) {
		t.Error("127.0.0.0/8 gibt 127.0.0.53 nicht frei")
	}
	// Eine Freigabe, die über den Bereich hinausgeht, gibt ihn nicht frei.
	if NewGuard(prefixes("127.0.0.0/7")).Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("127.0.0.0/7 gibt Loopback frei")
	}
}

func TestGuardResolve(t *testing.T) {
	g := NewGuard(prefixes("172.16.0.0/12"))
	g.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "nas.lan":
			return []netip.Addr{netip.MustParseAddr("172.16.1.10")}, nil
		case "gemischt.lan":
			return []netip.Addr{netip.MustParseAddr("172.16.1.10"), netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, errors.New("unbekannt")
	}
	ctx := context.Background()
	if a, err := g.Resolve(ctx, "nas.lan"); err != nil || len(a) != 1 {
		t.Fatalf("nas.lan: %v %v", a, err)
	}
	// Ein einziger gesperrter Eintrag sperrt den ganzen Namen.
	if _, err := g.Resolve(ctx, "gemischt.lan"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("gemischt.lan: %v", err)
	}
	if _, err := g.Resolve(ctx, "[::ffff:127.0.0.1]"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("verpacktes Loopback: %v", err)
	}
}

// Die letzte Schicht: Auch wenn ein Name zwischen Auflösen und Verbinden
// auf eine andere Adresse zeigt (DNS-Rebinding), prüft control die echte.
func TestGuardControl(t *testing.T) {
	g := NewGuard(prefixes("0.0.0.0/0"))
	if err := g.control("tcp", "127.0.0.1:5432", nil); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("control lässt Loopback durch: %v", err)
	}
	if err := g.control("tcp", "[::ffff:169.254.169.254]:80", nil); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("control lässt Metadaten durch: %v", err)
	}
	if err := g.control("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("control sperrt freigegebene Adresse: %v", err)
	}
	if _, err := g.DialContext(context.Background(), "udp", "192.168.1.1:53"); err == nil {
		t.Error("UDP erlaubt")
	}
}

func TestGuardRestrictUndSetNetworks(t *testing.T) {
	g := NewGuard([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")})
	fw := g.Restrict([][]netip.Prefix{{netip.MustParsePrefix("10.20.0.0/16")}})
	lz := fw.Restrict([][]netip.Prefix{{netip.MustParsePrefix("10.20.5.0/24"), netip.MustParsePrefix("10.99.0.0/16")}})
	none := g.Restrict([][]netip.Prefix{{}})
	if g.Restrict(nil) != g {
		t.Error("ohne Ketten nicht derselbe Guard")
	}
	for _, c := range []struct {
		g    *Guard
		addr string
		want bool
	}{
		{g, "10.30.0.1", true},
		{fw, "10.20.1.1", true},
		{fw, "10.30.0.1", false}, // außerhalb des Mandanten
		{fw, "127.0.0.1", false}, // global frei, im Mandanten nicht
		{lz, "10.20.5.9", true},
		{lz, "10.20.6.1", false}, // im Elternmandanten, nicht im eigenen
		{lz, "10.99.0.1", false}, // im eigenen, nicht im Elternmandanten (nur enger)
		{none, "10.1.1.1", false},
		{fw, "::ffff:10.20.1.1", true},
	} {
		if got := c.g.Allowed(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("%s: %v, erwartet %v", c.addr, got, c.want)
		}
	}
	// Ein Mandant kann nichts freigeben, was global gesperrt ist.
	wide := g.Restrict([][]netip.Prefix{{netip.MustParsePrefix("0.0.0.0/0")}})
	if wide.Allowed(netip.MustParseAddr("192.168.1.1")) || wide.Allowed(netip.MustParseAddr("127.0.0.2")) {
		t.Error("Mandant erweitert die globale Freigabe")
	}
	// Neue globale Netze gelten sofort auch für eingeschränkte Guards.
	g.SetNetworks([]netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")})
	if fw.Allowed(netip.MustParseAddr("10.20.2.1")) || !fw.Allowed(netip.MustParseAddr("10.20.1.5")) {
		t.Error("SetNetworks wirkt nicht auf den eingeschränkten Guard")
	}
	if got := fw.Networks(); len(got) != 1 || got[0].String() != "10.20.1.0/24" {
		t.Errorf("Networks: %v", got)
	}
	if _, err := fw.Resolve(context.Background(), "10.20.2.1"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Resolve: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("SetNetworks auf eingeschränktem Guard ohne Panik")
		}
	}()
	fw.SetNetworks(nil)
}
