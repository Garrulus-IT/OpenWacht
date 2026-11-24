// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// fakeConn spielt vorbereitete Antworten ab. Die Antwort auf die eigene
// Anfrage baut sie aus dem, was echo gesendet hat.
type fakeConn struct {
	net.PacketConn
	sent    []byte
	replies []func(req []byte) ([]byte, netip.Addr)
}

func (f *fakeConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.sent = append([]byte(nil), b...)
	return len(b), nil
}
func (f *fakeConn) SetDeadline(time.Time) error { return nil }
func (f *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(f.replies) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	msg, from := f.replies[0](f.sent)
	f.replies = f.replies[1:]
	return copy(b, msg), &net.UDPAddr{IP: from.AsSlice()}, nil
}

func reply(mod func(m []byte)) func([]byte) []byte {
	return func(req []byte) []byte {
		m := append([]byte(nil), req...)
		m[0] = 0 // Echo Reply
		if mod != nil {
			mod(m)
		}
		return m
	}
}

func TestEchoZuordnung(t *testing.T) {
	target := netip.MustParseAddr("192.168.1.10")
	other := netip.MustParseAddr("192.168.1.11")
	from := func(a netip.Addr, f func([]byte) []byte) func([]byte) ([]byte, netip.Addr) {
		return func(req []byte) ([]byte, netip.Addr) { return f(req), a }
	}
	wrong := []func([]byte) ([]byte, netip.Addr){
		from(other, reply(nil)), // anderer Absender
		from(target, reply(func(m []byte) { binary.BigEndian.PutUint16(m[6:], 99) })), // andere Folgenummer
		from(target, reply(func(m []byte) { m[10] ^= 0xff })),                         // andere Zufallsdaten
		from(target, reply(func(m []byte) { m[0] = 8 })),                              // keine Antwort, sondern Anfrage
		from(target, func(req []byte) []byte { return req[:6] }),                      // zu kurz
	}
	c := &fakeConn{replies: wrong}
	if _, err := echo(c, target, 1, time.Second); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("falsche Antworten angenommen: %v", err)
	}
	if c.sent[0] != 8 || checksum(c.sent) != 0 {
		t.Errorf("Anfrage: Typ %d, Prüfsumme falsch", c.sent[0])
	}
	c = &fakeConn{replies: append(wrong, from(target, reply(nil)))}
	if _, err := echo(c, target, 7, time.Second); err != nil {
		t.Errorf("passende Antwort nach falschen nicht erkannt: %v", err)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	c = &fakeConn{replies: []func([]byte) ([]byte, netip.Addr){from(v6, reply(func(m []byte) { m[0] = 129 }))}}
	if _, err := echo(c, v6, 1, time.Second); err != nil || c.sent[0] != 128 {
		t.Errorf("IPv6: %v, Typ %d", err, c.sent[0])
	}
}
