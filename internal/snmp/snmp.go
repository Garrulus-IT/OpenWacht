// SPDX-License-Identifier: AGPL-3.0-only

// Package snmp fragt Geräte ohne Agent per SNMP ab (v1, v2c und v3).
//
// SNMPv3 nur mit authPriv (Entscheidung, 20.11.2026): Authentifizierung mit SHA-1
// oder SHA-2, Verschlüsselung mit AES. MD5, DES, authNoPriv und noAuthNoPriv
// gibt es nicht; Geräte, die nur das können, bleiben bei v2c.
//
// Die Zentrale fragt nur lesend (GET, GETNEXT, GETBULK); SET gibt es nicht.
// Verbindungen laufen über den Guard der Checks: Erreichbar ist nur, was der
// Betreiber mit -check-netze freigegeben hat, geprüft unmittelbar vor dem
// connect(). Der UDP-Socket ist verbunden, der Kernel nimmt also nur Antworten
// von der abgefragten Adresse an.
//
// Alles, was ein Gerät liefert, ist nicht vertrauenswürdig: Texte werden auf
// gültiges UTF-8 ohne Steuerzeichen gekürzt, Tabellen auf eine Höchstzahl an
// Zeilen begrenzt, Zahlen auf plausible Bereiche geprüft.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// Versionen.
const (
	V1  = "1"
	V2c = "2c"
	V3  = "3"
)

// Grenzen für Gerätedaten.
const (
	MaxInterfaces = 512
	MaxStorage    = 128
	MaxCPUs       = 256
	MaxDisks      = 64
	MaxRaids      = 32
	MaxSupplies   = 32
	MaxText       = 200
	// MaxCommunity: RFC 3414 erlaubt beliebig lange Communities, Geräte
	// nehmen meist höchstens 32 Zeichen.
	MaxCommunity = 64
)

// Config beschreibt, wie ein Gerät abgefragt wird.
type Config struct {
	Version   string
	Host      string // Hostname oder IP-Adresse
	Port      uint16
	Community string  // v1, v2c
	V3        *V3Auth // v3
	// Extra: eigene OIDs für Sensoren (Etappe 18b), geprüft mit CheckExtraOIDs
	Extra []string
	// ExtraText (1.0.8): aus dem Text dieser eigenen OIDs je eine Zahl lesen,
	// geprüft mit CheckExtraText
	ExtraText []TextZahl
	// ExtraShow (1.0.10): von diesen eigenen OIDs den Text selbst melden,
	// geprüft mit CheckExtraShow
	ExtraShow []string
	// Columns: eigene Tabellenspalten (0.47.0), geprüft mit CheckColumns
	Columns []string
}

// ValidCommunity: druckbares ASCII ohne Leerzeichen am Rand, 1 bis 64 Zeichen.
func ValidCommunity(s string) bool {
	if s == "" || len(s) > MaxCommunity || strings.TrimSpace(s) != s {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Resolver löst Namen auf und lehnt nicht freigegebene Adressen ab; Control
// prüft die tatsächliche Zieladresse vor dem connect() (checks.Guard).
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
	Control(network, address string, c syscall.RawConn) error
}

// Client fragt Geräte ab.
type Client struct {
	Guard   Resolver
	Timeout time.Duration // je Anfrage, Standard 3 s
	Retries int           // Standard 1
	// Budget für eine ganze Abfrage, Standard 30 s
	Budget time.Duration
	// Now für Tests
	Now func() time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Fehler, die die Oberfläche verständlich anzeigen soll.
var (
	ErrNoResponse = errors.New("keine Antwort (Adresse, Port und Freigabe für die Zentrale prüfen, dazu die Zugangsdaten: bei v1/v2c die Community, bei v3 Benutzer, Verfahren und Passwörter – manche Geräte antworten auf falsche Zugangsdaten gar nicht)")
	ErrTooMuch    = errors.New("das Gerät liefert mehr Daten als erlaubt")
)

// session ist eine geöffnete Verbindung zu einem Gerät.
type session struct {
	g       *gosnmp.GoSNMP
	version string
	// Anzahl Anfragen, Schutz gegen Geräte, die endlos antworten
	requests int
}

const maxRequests = 2000

func (c *Client) open(ctx context.Context, cfg Config) (*session, error) {
	switch cfg.Version {
	case V1, V2c:
		if !ValidCommunity(cfg.Community) {
			return nil, errors.New("Community ungültig")
		}
	case V3:
		if err := cfg.V3.Validate(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("SNMP-Version %q wird nicht unterstützt", cfg.Version)
	}
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	addrs, err := c.Guard.Resolve(ctx, cfg.Host)
	if err != nil {
		return nil, err
	}
	ip := addrs[0]
	for _, a := range addrs { // IPv4 bevorzugen, wie beim Ping
		if a.Is4() {
			ip = a
			break
		}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	retries := c.Retries
	if retries < 0 {
		retries = 0
	} else if retries == 0 {
		retries = 1
	}
	v := gosnmp.Version2c
	if cfg.Version == V1 {
		v = gosnmp.Version1
	}
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      cfg.Port,
		Transport: "udp",
		Community: cfg.Community,
		Version:   v,
		Context:   ctx,
		Timeout:   timeout,
		Retries:   retries,
		// Klein halten: Antworten bleiben unter typischen MTUs, und ein
		// Gerät kann pro Anfrage nicht beliebig viel schicken.
		MaxOids:        16,
		MaxRepetitions: 20,
		Control:        c.Guard.Control,
	}
	if cfg.Version == V3 {
		g.Version, g.Community = gosnmp.Version3, ""
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = cfg.V3.usm()
	}
	if err := g.Connect(); err != nil {
		return nil, describe(err)
	}
	return &session{g: g, version: cfg.Version}, nil
}

func (s *session) close() { _ = s.g.Close() }

// describe macht aus Netzwerkfehlern verständliche Meldungen. Die Community
// steht in keinem Fehler (gosnmp nennt sie nicht, und wir hängen sie nicht an).
func describe(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout(),
		strings.Contains(msg, "request timeout"):
		return ErrNoResponse
	case strings.Contains(msg, "connection refused"):
		return errors.New("Port nicht erreichbar (ICMP: Port unerreichbar)")
	case strings.Contains(msg, "not authentic"):
		// Der Report des Geräts (unbekannter Benutzer, falsche Prüfsumme) ist
		// selbst nicht authentifiziert; gosnmp verwirft ihn zu Recht.
		return errors.New("SNMPv3: Anmeldung abgelehnt (Benutzer, Passwort und Verfahren prüfen)")
	case errors.Is(err, gosnmp.ErrUnknownUsername):
		return errors.New("SNMPv3: Benutzer am Gerät unbekannt")
	case errors.Is(err, gosnmp.ErrWrongDigest):
		return errors.New("SNMPv3: Authentifizierung abgelehnt (Passwort oder Verfahren falsch)")
	case errors.Is(err, gosnmp.ErrDecryption):
		return errors.New("SNMPv3: Entschlüsselung gescheitert (Verschlüsselungs-Passwort oder Verfahren falsch)")
	case errors.Is(err, gosnmp.ErrUnknownSecurityLevel):
		return errors.New("SNMPv3: Das Gerät erlaubt für diesen Benutzer kein authPriv")
	case errors.Is(err, gosnmp.ErrNotInTimeWindow):
		return errors.New("SNMPv3: Zeitfenster des Geräts nicht synchron")
	case errors.Is(err, gosnmp.ErrUnknownEngineID):
		return errors.New("SNMPv3: Engine-ID des Geräts nicht ermittelbar")
	}
	return errors.New(clean(msg, 150))
}

func (s *session) count() error {
	s.requests++
	if s.requests > maxRequests {
		return ErrTooMuch
	}
	return nil
}

// --- Werte ------------------------------------------------------------------------

// value ist ein gelesener Wert, bereits auf erwartete Typen geprüft.
type value struct {
	pdu gosnmp.SnmpPDU
}

func (v value) missing() bool {
	switch v.pdu.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return true
	}
	return false
}

// text: OctetString als bereinigter Text (ungültiges UTF-8 wird als Latin-1
// gelesen, Steuerzeichen werden Leerzeichen).
func (v value) text() (string, bool) {
	b, ok := v.pdu.Value.([]byte)
	if v.pdu.Type != gosnmp.OctetString || !ok {
		return "", false
	}
	return cleanBytes(b, MaxText), true
}

// uint: Integer, Counter32, Gauge32, TimeTicks, Counter64, Uinteger32 als
// nicht negative Zahl.
func (v value) uint() (uint64, bool) {
	switch v.pdu.Type {
	case gosnmp.Integer:
		if n, ok := v.pdu.Value.(int); ok && n >= 0 {
			return uint64(n), true
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Uinteger32:
		if n, ok := v.pdu.Value.(uint); ok {
			return uint64(n), true
		}
	case gosnmp.TimeTicks:
		if n, ok := v.pdu.Value.(uint32); ok {
			return uint64(n), true
		}
	case gosnmp.Counter64:
		if n, ok := v.pdu.Value.(uint64); ok {
			return n, true
		}
	}
	return 0, false
}

// int: Integer (vorzeichenbehaftet).
func (v value) int() (int64, bool) {
	if v.pdu.Type == gosnmp.Integer {
		if n, ok := v.pdu.Value.(int); ok {
			return int64(n), true
		}
	}
	if u, ok := v.uint(); ok && u <= math.MaxInt64 {
		return int64(u), true
	}
	return 0, false
}

// status: Zustandswerte (INTEGER, 32 Bit). Größere Zahlen sind kein Zustand;
// dieselbe Grenze prüft ValidateCollected für Sammler.
func (v value) status() (int64, bool) {
	if n, ok := v.int(); ok && n >= math.MinInt32 && n <= math.MaxInt32 {
		return n, true
	}
	return 0, false
}

// float: Zahlen und Opaque-Float (Synology-USV), endlich.
func (v value) float() (float64, bool) {
	switch v.pdu.Type {
	case gosnmp.OpaqueFloat:
		if f, ok := v.pdu.Value.(float32); ok && !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) {
			return float64(f), true
		}
	case gosnmp.OpaqueDouble:
		if f, ok := v.pdu.Value.(float64); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case gosnmp.OctetString:
		// Manche Geräte liefern Zahlen als Text.
		if t, ok := v.text(); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f, true
			}
		}
	}
	if n, ok := v.int(); ok {
		return float64(n), true
	}
	return 0, false
}

func (v value) oid() (string, bool) {
	if v.pdu.Type != gosnmp.ObjectIdentifier {
		return "", false
	}
	s, ok := v.pdu.Value.(string)
	if !ok || len(s) > 256 {
		return "", false
	}
	return strings.TrimPrefix(s, "."), true
}

// --- Abfragen -----------------------------------------------------------------------

// get liest einzelne OIDs. Fehlt eine, ist ihr Wert „missing“. Unter v1
// scheitert eine ganze Anfrage an einer fehlenden OID (noSuchName), deshalb
// wird dort einzeln nachgefragt.
func (s *session) get(oids ...string) (map[string]value, error) {
	out := map[string]value{}
	for start := 0; start < len(oids); start += s.g.MaxOids {
		part := oids[start:min(start+s.g.MaxOids, len(oids))]
		if err := s.count(); err != nil {
			return nil, err
		}
		pkt, err := s.g.Get(part)
		if err != nil {
			return nil, describe(err)
		}
		if pkt.Error == gosnmp.NoSuchName && len(part) > 1 {
			for _, o := range part {
				one, err := s.get(o)
				if err != nil {
					return nil, err
				}
				for k, v := range one {
					out[k] = v
				}
			}
			continue
		}
		if pkt.Error != gosnmp.NoError && pkt.Error != gosnmp.NoSuchName {
			return nil, fmt.Errorf("Gerät meldet Fehler %s", pkt.Error)
		}
		for _, p := range pkt.Variables {
			name := strings.TrimPrefix(p.Name, ".")
			if pkt.Error == gosnmp.NoSuchName {
				p.Type = gosnmp.NoSuchObject
			}
			out[name] = value{p}
		}
	}
	return out, nil
}

// row ist eine Zeile einer Tabellenspalte: Index (OID-Rest) und Wert.
type row struct {
	index string
	v     value
}

// walk liest eine Spalte bzw. einen Teilbaum, höchstens limit Einträge. Die
// OIDs müssen streng steigen; ein Gerät, das sich wiederholt, wird beendet.
func (s *session) walk(root string, limit int) ([]row, error) {
	prefix := root + "."
	var out []row
	cur := root
	for {
		if err := s.count(); err != nil {
			return nil, err
		}
		var pkt *gosnmp.SnmpPacket
		var err error
		if s.version == V1 {
			pkt, err = s.g.GetNext([]string{cur})
		} else {
			pkt, err = s.g.GetBulk([]string{cur}, 0, s.g.MaxRepetitions)
		}
		if err != nil {
			return nil, describe(err)
		}
		if pkt.Error == gosnmp.NoSuchName { // v1: Ende der MIB
			return out, nil
		}
		if pkt.Error != gosnmp.NoError {
			return nil, fmt.Errorf("Gerät meldet Fehler %s", pkt.Error)
		}
		if len(pkt.Variables) == 0 {
			return out, nil
		}
		for _, p := range pkt.Variables {
			name := strings.TrimPrefix(p.Name, ".")
			if p.Type == gosnmp.EndOfMibView || !strings.HasPrefix(name, prefix) {
				return out, nil
			}
			if !oidAfter(name, cur) {
				return nil, errors.New("das Gerät liefert Tabellen in falscher Reihenfolge")
			}
			if len(out) >= limit {
				return out, ErrTooMuch
			}
			out = append(out, row{index: strings.TrimPrefix(name, prefix), v: value{p}})
			cur = name
		}
	}
}

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

// column liest eine Tabellenspalte als Map Index → Wert. Zu viele Zeilen sind
// kein Fehler: Es bleibt bei den ersten limit.
func (s *session) column(oid string, limit int) (map[string]value, []string, error) {
	rows, err := s.walk(oid, limit)
	if err != nil && !errors.Is(err, ErrTooMuch) {
		return nil, nil, err
	}
	m := make(map[string]value, len(rows))
	order := make([]string, 0, len(rows))
	for _, r := range rows {
		if _, dup := m[r.index]; !dup {
			order = append(order, r.index)
		}
		m[r.index] = r.v
	}
	return m, order, nil
}

// --- Texte ---------------------------------------------------------------------------

func clean(s string, n int) string { return cleanBytes([]byte(s), n) }

// cleanBytes: gültiges UTF-8 ohne Steuerzeichen, Leerraum zusammengefasst,
// höchstens n Zeichen. Ungültiges UTF-8 wird als Latin-1 gelesen (ältere
// Geräte), Nullbytes am Ende (C-Strings) fallen weg.
func cleanBytes(b []byte, n int) string {
	if len(b) > 4*n+16 {
		b = b[:4*n+16]
	}
	var s string
	if utf8.Valid(b) {
		s = string(b)
	} else {
		r := make([]rune, len(b))
		for i, c := range b {
			r[i] = rune(c)
		}
		s = string(r)
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return s
}

// CleanText bereinigt Text von Geräten wie cleanBytes (für Traps).
func CleanText(b []byte, n int) string { return cleanBytes(b, n) }
