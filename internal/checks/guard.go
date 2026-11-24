// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
)

// ErrNotAllowed: Das Ziel liegt außerhalb der freigegebenen Netze.
var ErrNotAllowed = errors.New("Ziel ist für Sensoren der Zentrale nicht freigegeben")

// NotAllowedError nennt die gesperrte Adresse.
type NotAllowedError struct{ Addr netip.Addr }

func (e *NotAllowedError) Error() string {
	return fmt.Sprintf("Adresse %s ist für Sensoren der Zentrale nicht freigegeben", e.Addr)
}
func (e *NotAllowedError) Unwrap() error { return ErrNotAllowed }

// Bereiche, die nur ein ausdrücklich darin liegender Eintrag freigibt: Über
// sie erreicht man die Zentrale selbst (Datenbank, Oberfläche) oder
// Metadaten-Dienste von Clouds (169.254.169.254). „0.0.0.0/0“ reicht dafür nicht.
var specialRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
}

// Nie erlaubt, egal was freigegeben ist.
var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // „dieses Netz“, unter Linux die Maschine selbst
	netip.MustParsePrefix("224.0.0.0/4"),        // Multicast
	netip.MustParsePrefix("255.255.255.255/32"), // Broadcast
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("ff00::/8"),
}

// Guard entscheidet, welche Adressen Checks erreichen dürfen, und stellt
// die einzigen Verbindungen her, die Checks benutzen. Der Betreiber legt die
// Netze fest (Startoption -check-netze bzw. Seite Einstellungen), nicht die
// Mandanten: Checks laufen von der Zentrale aus und könnten sonst deren Netz
// abtasten. Die Netze lassen sich zur Laufzeit ersetzen (SetNetworks); ein
// eingeschränkter Guard (Restrict) für einen Mandanten folgt dem sofort.
type Guard struct {
	mu      sync.RWMutex
	allowed []netip.Prefix
	// Nur bei eingeschränkten Guards: Die Adresse muss der Elternguard
	// erlauben und zusätzlich in jeder Liste von within liegen.
	parent *Guard
	within [][]netip.Prefix
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// NewGuard: allowed leer = kein Check darf irgendwohin.
func NewGuard(allowed []netip.Prefix) *Guard {
	g := &Guard{}
	g.SetNetworks(allowed)
	g.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	return g
}

// SetNetworks ersetzt die freigegebenen Netze (nicht bei eingeschränkten Guards).
func (g *Guard) SetNetworks(allowed []netip.Prefix) {
	if g.parent != nil {
		panic("checks: SetNetworks auf eingeschränktem Guard")
	}
	var list []netip.Prefix
	for _, p := range allowed {
		list = append(list, p.Masked())
	}
	g.mu.Lock()
	g.allowed = list
	g.mu.Unlock()
}

// Restrict liefert einen Guard, der zusätzlich nur Adressen erlaubt, die in
// jeder der Listen liegen (Netze je Mandant entlang des Mandantenbaums). Eine
// leere Liste in chains sperrt alles. Ohne chains ist es g selbst.
func (g *Guard) Restrict(chains [][]netip.Prefix) *Guard {
	if len(chains) == 0 {
		return g
	}
	root := g
	for root.parent != nil {
		chains = append(append([][]netip.Prefix(nil), root.within...), chains...)
		root = root.parent
	}
	r := &Guard{parent: root}
	for _, c := range chains {
		list := make([]netip.Prefix, 0, len(c))
		for _, p := range c {
			list = append(list, p.Masked())
		}
		r.within = append(r.within, list)
	}
	return r
}

func (g *Guard) resolver() func(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.parent != nil {
		return g.parent.resolver()
	}
	return g.lookup
}

// Networks liefert die freigegebenen Netze der Installation.
func (g *Guard) Networks() []netip.Prefix {
	if g.parent != nil {
		return g.parent.Networks()
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]netip.Prefix(nil), g.allowed...)
}

// Restricted meldet, ob zusätzlich Netze eines Mandanten gelten.
func (g *Guard) Restricted() bool { return g.parent != nil }

func within(p, outer netip.Prefix) bool {
	return p.Bits() >= outer.Bits() && outer.Contains(p.Addr())
}

// Allowed prüft eine einzelne Adresse.
func (g *Guard) Allowed(ip netip.Addr) bool {
	if g.parent != nil {
		if !g.parent.Allowed(ip) {
			return false
		}
		ip = ip.Unmap().WithZone("")
		for _, list := range g.within {
			in := false
			for _, p := range list {
				if p.Contains(ip) {
					in = true
					break
				}
			}
			if !in {
				return false
			}
		}
		return true
	}
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false
	}
	for _, b := range blockedRanges {
		if b.Contains(ip) {
			return false
		}
	}
	var special *netip.Prefix
	for i, s := range specialRanges {
		if s.Contains(ip) {
			special = &specialRanges[i]
		}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, p := range g.allowed {
		if !p.Contains(ip) {
			continue
		}
		if special == nil || within(p, *special) {
			return true
		}
	}
	return false
}

// Resolve löst einen Namen auf und lehnt ab, wenn auch nur eine Adresse
// nicht freigegeben ist.
func (g *Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !g.Allowed(ip) {
			return nil, &NotAllowedError{ip}
		}
		return []netip.Addr{ip}, nil
	}
	addrs, err := g.resolver()(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "keine Adresse", Name: host, IsNotFound: true}
	}
	for i, a := range addrs {
		a = a.Unmap().WithZone("")
		if !g.Allowed(a) {
			return nil, &NotAllowedError{a}
		}
		addrs[i] = a
	}
	return addrs, nil
}

// control prüft unmittelbar vor dem connect() die tatsächliche Zieladresse.
// Damit hilft auch DNS-Rebinding nicht, und kein Codepfad kann den Guard umgehen.
func (g *Guard) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unerwartete Adresse %q", address)
	}
	if !g.Allowed(ap.Addr()) {
		return &NotAllowedError{ap.Addr().Unmap()}
	}
	return nil
}

// Control ist die Prüfung unmittelbar vor connect() für Verbindungen, die
// nicht über DialContext laufen (SNMP über UDP). Sie lässt nur freigegebene
// Adressen durch, egal welchen Namen der Aufrufer aufgelöst hat.
func (g *Guard) Control(network, address string, c syscall.RawConn) error {
	return g.control(network, address, c)
}

// DialContext verbindet sich per TCP mit host:port, nur zu freigegebenen Adressen.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("Netzwerk %q nicht unterstützt", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := g.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Control: g.control}
	var first error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		if first == nil {
			first = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, first
}
