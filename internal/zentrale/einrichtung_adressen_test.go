// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Gehärteter Dienst ohne Netlink: Die eigenen Adressen lassen sich nicht
// abfragen. Der Assistent muss trotzdem Listen bekommen, nie „null“
// (0.47.0: „Cannot read properties of null (reading 'join')“).
func TestVorschlaegeOhneAdressen(t *testing.T) {
	alt := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = alt })
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, errors.New("Cannot open netlink socket: Address family not supported by protocol")
	}

	if p := hostPrefixes(); p == nil || len(p) != 0 {
		t.Fatalf("hostPrefixes() = %#v, erwartet leere Liste", p)
	}
	r := httptest.NewRequest("GET", "/api/v1/einrichtung", nil)
	r.Host = "openwacht.example:443"
	b, err := json.Marshal((&Setup{}).proposals(r))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["netze"]) != "[]" {
		t.Errorf("netze = %s, erwartet []", got["netze"])
	}
	var adressen []string
	if err := json.Unmarshal(got["adressen"], &adressen); err != nil || len(adressen) == 0 || adressen[0] != "openwacht.example" {
		t.Errorf("adressen = %s, erwartet zuerst openwacht.example", got["adressen"])
	}
}

// Mit lesbaren Adressen: Netz und Adresse werden vorgeschlagen.
func TestVorschlaegeMitAdressen(t *testing.T) {
	alt := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = alt })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("10.20.0.5"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	r := httptest.NewRequest("GET", "/api/v1/einrichtung", nil)
	r.Host = "openwacht.example"
	p := (&Setup{}).proposals(r)
	if n := p["netze"].([]string); len(n) != 1 || n[0] != "10.20.0.0/24" {
		t.Errorf("netze = %v, erwartet [10.20.0.0/24]", n)
	}
	if a := p["adressen"].([]string); !strings.Contains(strings.Join(a, " "), "10.20.0.5") {
		t.Errorf("adressen = %v, erwartet 10.20.0.5", a)
	}
}

// Der Dienst muss Netlink erlauben, sonst sieht die Zentrale ihre Adressen nicht.
func TestZentraleUnitErlaubtNetlink(t *testing.T) {
	b, err := os.ReadFile("../../deploy/linux/openwacht-zentrale.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "RestrictAddressFamilies=") {
			if !strings.Contains(l, "AF_NETLINK") {
				t.Fatalf("%s: AF_NETLINK fehlt", l)
			}
			return
		}
	}
	t.Fatal("RestrictAddressFamilies fehlt in openwacht-zentrale.service")
}

// Öffentliche IPv6-Adressen wechseln mit dem Präfix des Providers und gehören
// weder ins Zertifikat noch in die vorgeschlagene Netzfreigabe; ULA schon.
func TestVorschlaegeOhneOeffentlicheIPv6(t *testing.T) {
	alt := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = alt })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.20.0.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8:1:2::5"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fd12:3456:789a::5"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	var got []string
	for _, p := range hostPrefixes() {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "10.20.0.5/24 fd12:3456:789a::5/64" {
		t.Fatalf("hostPrefixes() = %v, erwartet IPv4 und ULA ohne 2001:db8::/32", got)
	}
	for _, n := range HostNames() {
		if strings.HasPrefix(n, "2001:") {
			t.Fatalf("HostNames() enthält öffentliche IPv6-Adresse %s", n)
		}
	}
}
