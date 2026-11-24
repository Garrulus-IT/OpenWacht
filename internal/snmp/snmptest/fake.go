// SPDX-License-Identifier: AGPL-3.0-only

// Package snmptest stellt eine kleine SNMP-Gegenstelle für Tests bereit:
// Sie beantwortet GET, GETNEXT und GETBULK (v1 und v2c) aus einer festen
// Tabelle. Nur für Tests.
package snmptest

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Alle Gegenstellen dekodieren mit gosnmp.Default. Das setzt beim ersten
// Aufruf Context; vorher gesetzt, liest gosnmp nur noch, und mehrere
// Gegenstellen in einem Test laufen ohne Datenrennen.
func init() {
	if gosnmp.Default.Context == nil {
		gosnmp.Default.Context = context.Background()
	}
}

// Systemdaten, die jede Gegenstelle liefert.
const (
	sysDescr    = "1.3.6.1.2.1.1.1.0"
	sysObjectID = "1.3.6.1.2.1.1.2.0"
	sysUpTime   = "1.3.6.1.2.1.1.3.0"
	sysName     = "1.3.6.1.2.1.1.5.0"
)

// oidAfter: a kommt in der OID-Ordnung nach b.
func oidAfter(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, err1 := strconv.ParseUint(as[i], 10, 64)
		y, err2 := strconv.ParseUint(bs[i], 10, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		if x != y {
			return x > y
		}
	}
	return len(as) > len(bs)
}

// Agent beantwortet GET, GETNEXT und GETBULK aus einer Tabelle (v1 und
// v2c). So lassen sich Herstellerteile und kaputte Geräte testen, ohne
// echtes Gerät. Die Gegenstelle läuft auf 127.0.0.1.
type Agent struct {
	mu        sync.Mutex
	conn      net.PacketConn
	community string
	values    map[string]gosnmp.SnmpPDU
	sorted    []string
	// Fehlerbild: GETNEXT/GETBULK liefern immer dieselbe OID (Schleife)
	loop string
}

// New startet eine Gegenstelle mit den Systemdaten und pdus.
func New(t *testing.T, community string, pdus ...gosnmp.SnmpPDU) *Agent {
	return NewLoop(t, community, "", pdus...)
}

// NewLoop: wie New, aber GETNEXT/GETBULK liefern immer loop (kaputtes Gerät).
func NewLoop(t *testing.T, community, loop string, pdus ...gosnmp.SnmpPDU) *Agent {
	return start(t, "127.0.0.1:0", community, loop, pdus...)
}

// NewOn: wie New, auf einer festen Adresse.
func NewOn(t *testing.T, addr, community string, pdus ...gosnmp.SnmpPDU) *Agent {
	return start(t, addr, community, "", pdus...)
}

// Set ändert einen vorhandenen Wert (z. B. Zähler).
func (f *Agent) Set(p gosnmp.SnmpPDU) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.values[p.Name]; ok {
		f.values[p.Name] = p
	}
}

func start(t *testing.T, addr, community, loop string, pdus ...gosnmp.SnmpPDU) *Agent {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	f := &Agent{conn: conn, community: community, values: map[string]gosnmp.SnmpPDU{}, loop: loop}
	base := []gosnmp.SnmpPDU{
		{Name: sysDescr, Type: gosnmp.OctetString, Value: []byte("Testgerät")},
		{Name: sysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.99999"},
		{Name: sysUpTime, Type: gosnmp.TimeTicks, Value: uint32(123456)},
		{Name: sysName, Type: gosnmp.OctetString, Value: []byte("fake")},
	}
	for _, p := range append(base, pdus...) {
		f.values[p.Name] = p
	}
	for k := range f.values {
		f.sorted = append(f.sorted, k)
	}
	sort.Slice(f.sorted, func(i, j int) bool { return oidAfter(f.sorted[j], f.sorted[i]) })
	go f.serve()
	t.Cleanup(func() { conn.Close() })
	return f
}

// Port der Gegenstelle.
func (f *Agent) Port() uint16 { return uint16(f.conn.LocalAddr().(*net.UDPAddr).Port) }

func (f *Agent) next(oid string) (gosnmp.SnmpPDU, bool) {
	oid = strings.TrimPrefix(oid, ".")
	for _, k := range f.sorted {
		if oidAfter(k, oid) {
			return f.values[k], true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

func (f *Agent) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.answer(buf[:n], from)
		f.mu.Unlock()
	}
}

func (f *Agent) answer(msg []byte, from net.Addr) {
	{
		req, err := gosnmp.Default.SnmpDecodePacket(msg)
		if err != nil || req.Community != f.community {
			return // falsche Community: keine Antwort, wie snmpd
		}
		resp := &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse,
			RequestID: req.RequestID}
		endOfMib := func(name string) gosnmp.SnmpPDU {
			if req.Version == gosnmp.Version1 {
				resp.Error, resp.ErrorIndex = gosnmp.NoSuchName, 1
				return gosnmp.SnmpPDU{Name: name, Type: gosnmp.Null}
			}
			return gosnmp.SnmpPDU{Name: name, Type: gosnmp.EndOfMibView}
		}
		for _, v := range req.Variables {
			name := strings.TrimPrefix(v.Name, ".")
			switch req.PDUType {
			case gosnmp.GetRequest:
				if p, ok := f.values[name]; ok {
					resp.Variables = append(resp.Variables, p)
				} else if req.Version == gosnmp.Version1 {
					resp.Error, resp.ErrorIndex = gosnmp.NoSuchName, 1
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: name, Type: gosnmp.Null})
				} else {
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchObject})
				}
			case gosnmp.GetNextRequest:
				if f.loop != "" {
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: f.loop, Type: gosnmp.Integer, Value: 1})
					continue
				}
				if p, ok := f.next(name); ok {
					resp.Variables = append(resp.Variables, p)
				} else {
					resp.Variables = append(resp.Variables, endOfMib(name))
				}
			case gosnmp.GetBulkRequest:
				cur := name
				for i := 0; i < int(req.MaxRepetitions); i++ {
					if f.loop != "" {
						resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: f.loop, Type: gosnmp.Integer, Value: 1})
						break
					}
					p, ok := f.next(cur)
					if !ok {
						resp.Variables = append(resp.Variables, endOfMib(cur))
						break
					}
					resp.Variables = append(resp.Variables, p)
					cur = p.Name
				}
			}
		}
		out, err := resp.MarshalMsg()
		if err == nil {
			_, _ = f.conn.WriteTo(out, from)
		}
	}
}

// Str, Num, Gauge: Werte für die Tabelle.
func Str(oid, s string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(s)}
}
func Num(oid string, n int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: n}
}
func Gauge(oid string, n uint) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Gauge32, Value: n}
}
