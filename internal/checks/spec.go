// SPDX-License-Identifier: AGPL-3.0-only

// Package checks führt aktive Checks aus (Ping, TCP, HTTP, TLS-Zertifikat,
// seit Etappe 18 auch DNS und HTTP-JSON-Wert) und beschreibt die Sensoren,
// die ein Agent misst (Dienst, Prozess, Datei). Übernommen aus dem
// Python-Prototyp v0.1.0: dieselben Meldungen, dieselbe Bewertung, aber jede
// Verbindung läuft über den Guard.
package checks

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Kinds: die erlaubten Check-Typen. Die Arten ab „dienst“ misst der Agent.
var Kinds = []string{"ping", "tcp", "http", "tls", "dns", "http_json", "tcp_banner", "ntp", "snmp_oid",
	"dienst", "prozess", "datei", "docker", "hyperv", "leistungsindikator", "autodienste"}

// AgentKinds misst der Agent auf seinem Rechner, nicht die Zentrale.
var AgentKinds = []string{"dienst", "prozess", "datei", "docker", "hyperv", "leistungsindikator", "autodienste"}

// IsSNMPKind: Wert wird mit der SNMP-Abfrage des Geräts gelesen (Zentrale
// oder Sammler), nicht vom Planer der Checks.
func IsSNMPKind(kind string) bool { return kind == "snmp_oid" }

// IsAgentKind: Art läuft auf dem Agent (gleiche Liste wie openwacht.is_agent_kind).
func IsAgentKind(kind string) bool { return slices.Contains(AgentKinds, kind) }

// Spec beschreibt das Ziel eines Checks. Gespeichert wird es als JSON;
// welche Felder erlaubt sind, hängt vom Typ ab.
type Spec struct {
	Host         string  `json:"host,omitempty"`
	Port         int     `json:"port,omitempty"`
	URL          string  `json:"url,omitempty"`
	ExpectStatus []int   `json:"erwarte_status,omitempty"`
	Contains     string  `json:"enthaelt,omitempty"`
	Connect      string  `json:"verbinde,omitempty"` // TLS: direkt an diese Adresse, Name per SNI
	WarnDays     float64 `json:"warnung_tage,omitempty"`
	CritDays     float64 `json:"kritisch_tage,omitempty"`
	TimeoutSec   int     `json:"timeout_s,omitempty"`
	CAPEM        string  `json:"ca_pem,omitempty"` // eigene Root-CA (öffentliches Zertifikat, kein Geheimnis)

	// Ping (Etappe 18): Pakete und Schwellen; 0 = Schwelle aus
	Count    int     `json:"anzahl,omitempty"`
	LossWarn float64 `json:"verlust_warnung,omitempty"` // Prozent
	LossCrit float64 `json:"verlust_kritisch,omitempty"`
	RTTWarn  float64 `json:"antwort_warnung_ms,omitempty"`
	RTTCrit  float64 `json:"antwort_kritisch_ms,omitempty"`

	// DNS: Name (dienst/prozess: Name des Dienstes bzw. Prozesses)
	Name   string   `json:"name,omitempty"`
	Server string   `json:"server,omitempty"`  // IP des DNS-Servers; leer = Resolver der Zentrale
	Record string   `json:"eintrag,omitempty"` // A, AAAA; leer = beide
	Expect []string `json:"erwartet,omitempty"`

	// HTTP-JSON: Wert an einem Pfad; Schwellen als Zeiger, weil 0 ein Wert ist
	JSONPath  string   `json:"json_pfad,omitempty"`
	WarnAbove *float64 `json:"warnung_ueber,omitempty"`
	CritAbove *float64 `json:"kritisch_ueber,omitempty"`
	WarnBelow *float64 `json:"warnung_unter,omitempty"`
	CritBelow *float64 `json:"kritisch_unter,omitempty"`
	Equals    *string  `json:"gleich,omitempty"`

	// Prozess: Anzahl laufender Prozesse mit diesem Namen
	Min int `json:"mindestens,omitempty"`
	Max int `json:"hoechstens,omitempty"`

	// Datei: Alter der Datei bzw. des jüngsten Eintrags im Ordner
	Path      string  `json:"pfad,omitempty"`
	Folder    bool    `json:"ordner,omitempty"`
	WarnHours float64 `json:"warnung_stunden,omitempty"`
	CritHours float64 `json:"kritisch_stunden,omitempty"`
	MinBytes  int64   `json:"mindestgroesse,omitempty"`

	// Etappe 18b: TCP-Banner mit direktem TLS; NTP-Schwellen; SNMP-OID
	TLS          bool    `json:"tls,omitempty"`
	OffsetWarnMS float64 `json:"abweichung_warnung_ms,omitempty"`
	OffsetCritMS float64 `json:"abweichung_kritisch_ms,omitempty"`
	OID          string  `json:"oid,omitempty"`
	Rate         bool    `json:"rate,omitempty"`

	// 0.44.0: Windows-Leistungsindikator (\Objekt(Instanz)\Indikator). Instanz
	// „*“ fasst alle Instanzen zusammen (ohne Namen zu melden); Bezug teilt
	// durch einen zweiten Indikator desselben Objekts (Anteil in Prozent).
	Object    string `json:"objekt,omitempty"`
	Counter   string `json:"indikator,omitempty"`
	Instance  string `json:"instanz,omitempty"`
	Aggregate string `json:"zusammenfassung,omitempty"`
	Relative  string `json:"bezug,omitempty"`
	// SNMP-Spalte (0.47.0): Vergleichswert für anzahl_gleich/anzahl_ungleich
	Compare *int64 `json:"vergleichswert,omitempty"`
	// 1.0.8, SNMP-OID: Zahl aus einem Text des Geräts („1500RPM“ → 1500).
	// TextNumber: "" (aus), "erste", "nte" (TextIndex 1–16) oder "nach"
	// (erste Zahl hinter TextAfter). Gelesen wird beim Abfragen; gespeichert
	// wird nur die Zahl, nie der Text.
	TextNumber string `json:"zahl_aus_text,omitempty"`
	TextIndex  int    `json:"zahl_nr,omitempty"`
	TextAfter  string `json:"zahl_nach,omitempty"`
	// 1.0.8, SNMP-OID: Faktor (0 = 1) und Einheit für die Anzeige. Schwellen
	// gelten auf den umgerechneten Wert.
	Factor float64 `json:"faktor,omitempty"`
	Unit   string  `json:"einheit,omitempty"`

	// 1.0.5: automatisch startende Windows-Dienste; diese Dienste zählen
	// nicht (Dienst- oder Anzeigename, ein „*“ am Ende passt auf den Anfang).
	Exceptions []string `json:"ausnahmen,omitempty"`
}

const (
	maxContains = 200
	maxURL      = 2000
	maxCAPEM    = 16 << 10
	maxStatus   = 20
)

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidHost meldet, ob h ein Hostname oder eine IP-Adresse ohne Zone ist
// (ohne Protokoll und Port).
func ValidHost(h string) bool { return validHost(h) }

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return !strings.Contains(h, "%") // keine Zonen
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Parse prüft das Ziel für einen Typ, setzt Standardwerte und liefert die
// bereinigte Fassung. Unbekannte Felder und Felder, die nicht zum Typ
// passen, werden abgelehnt.
func Parse(kind string, raw []byte) (Spec, error) {
	var s Spec
	if len(raw) > 32<<10 {
		return s, errors.New("Ziel zu groß")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("Ziel ist kein gültiges JSON für einen Sensor: %v", err)
	}
	if dec.More() {
		return s, errors.New("Ziel enthält mehr als ein JSON-Objekt")
	}
	return s, s.normalize(kind)
}

// allowedFields je Typ (Namen wie im JSON).
var allowedFields = map[string][]string{
	"ping": {"host", "timeout_s", "anzahl", "verlust_warnung", "verlust_kritisch", "antwort_warnung_ms", "antwort_kritisch_ms"},
	"tcp":  {"host", "port", "timeout_s"},
	"http": {"url", "erwarte_status", "enthaelt", "timeout_s", "ca_pem"},
	"tls":  {"host", "port", "verbinde", "warnung_tage", "kritisch_tage", "timeout_s", "ca_pem"},
	"dns":  {"name", "server", "eintrag", "erwartet", "timeout_s"},
	"http_json": {"url", "erwarte_status", "json_pfad", "warnung_ueber", "kritisch_ueber", "warnung_unter", "kritisch_unter",
		"gleich", "timeout_s", "ca_pem"},
	"tcp_banner": {"host", "port", "tls", "enthaelt", "timeout_s", "ca_pem"},
	"ntp":        {"host", "port", "abweichung_warnung_ms", "abweichung_kritisch_ms", "timeout_s"},
	"snmp_oid": {"oid", "rate", "warnung_ueber", "kritisch_ueber", "warnung_unter", "kritisch_unter", "gleich",
		"zusammenfassung", "vergleichswert", "zahl_aus_text", "zahl_nr", "zahl_nach", "faktor", "einheit"},
	"dienst":  {"name"},
	"prozess": {"name", "mindestens", "hoechstens"},
	"datei":   {"pfad", "ordner", "warnung_stunden", "kritisch_stunden", "mindestgroesse"},
	"docker":  {"name"},
	"hyperv":  {"name"},
	"leistungsindikator": {"objekt", "indikator", "instanz", "zusammenfassung", "bezug",
		"warnung_ueber", "kritisch_ueber", "warnung_unter", "kritisch_unter"},
	"autodienste": {"ausnahmen"},
}

func (s *Spec) setFields() []string {
	var f []string
	add := func(set bool, name string) {
		if set {
			f = append(f, name)
		}
	}
	add(s.Host != "", "host")
	add(s.Port != 0, "port")
	add(s.URL != "", "url")
	add(len(s.ExpectStatus) > 0, "erwarte_status")
	add(s.Contains != "", "enthaelt")
	add(s.Connect != "", "verbinde")
	add(s.WarnDays != 0, "warnung_tage")
	add(s.CritDays != 0, "kritisch_tage")
	add(s.TimeoutSec != 0, "timeout_s")
	add(s.CAPEM != "", "ca_pem")
	add(s.Count != 0, "anzahl")
	add(s.LossWarn != 0, "verlust_warnung")
	add(s.LossCrit != 0, "verlust_kritisch")
	add(s.RTTWarn != 0, "antwort_warnung_ms")
	add(s.RTTCrit != 0, "antwort_kritisch_ms")
	add(s.Name != "", "name")
	add(s.Server != "", "server")
	add(s.Record != "", "eintrag")
	add(len(s.Expect) > 0, "erwartet")
	add(s.JSONPath != "", "json_pfad")
	add(s.WarnAbove != nil, "warnung_ueber")
	add(s.CritAbove != nil, "kritisch_ueber")
	add(s.WarnBelow != nil, "warnung_unter")
	add(s.CritBelow != nil, "kritisch_unter")
	add(s.Equals != nil, "gleich")
	add(s.Min != 0, "mindestens")
	add(s.Max != 0, "hoechstens")
	add(s.Path != "", "pfad")
	add(s.Folder, "ordner")
	add(s.WarnHours != 0, "warnung_stunden")
	add(s.CritHours != 0, "kritisch_stunden")
	add(s.MinBytes != 0, "mindestgroesse")
	add(s.TLS, "tls")
	add(s.OffsetWarnMS != 0, "abweichung_warnung_ms")
	add(s.OffsetCritMS != 0, "abweichung_kritisch_ms")
	add(s.OID != "", "oid")
	add(s.Rate, "rate")
	add(s.Object != "", "objekt")
	add(s.Counter != "", "indikator")
	add(s.Instance != "", "instanz")
	add(s.Aggregate != "", "zusammenfassung")
	add(s.Relative != "", "bezug")
	add(s.Compare != nil, "vergleichswert")
	add(s.TextNumber != "", "zahl_aus_text")
	add(s.TextIndex != 0, "zahl_nr")
	add(s.TextAfter != "", "zahl_nach")
	add(s.Factor != 0, "faktor")
	add(s.Unit != "", "einheit")
	add(len(s.Exceptions) > 0, "ausnahmen")
	return f
}

func (s *Spec) normalize(kind string) error {
	allowed, ok := allowedFields[kind]
	if !ok {
		return fmt.Errorf("unbekannter Typ %q (erlaubt: %s)", kind, strings.Join(Kinds, ", "))
	}
	for _, f := range s.setFields() {
		found := false
		for _, a := range allowed {
			found = found || a == f
		}
		if !found {
			return fmt.Errorf("Feld %q passt nicht zum Typ %s", f, kind)
		}
	}
	s.Host = strings.TrimSpace(s.Host)
	s.Connect = strings.TrimSpace(s.Connect)
	s.Name = strings.TrimSpace(s.Name)
	s.Server = strings.TrimSpace(s.Server)
	if IsAgentKind(kind) {
		// Der Agent misst lokal; ein Zeitlimit gibt es dort nicht.
		return s.normalizeAgent(kind)
	}
	if IsSNMPKind(kind) {
		// Läuft mit der SNMP-Abfrage des Geräts (deren Zeitgrenzen gelten).
		return s.normalizeOID()
	}
	defTimeout := map[string]int{"ping": 2, "tcp": 5, "http": 10, "tls": 10, "dns": 5, "http_json": 10, "tcp_banner": 10, "ntp": 5}[kind]
	if s.TimeoutSec == 0 {
		s.TimeoutSec = defTimeout
	}
	if s.TimeoutSec < 1 || s.TimeoutSec > 30 {
		return errors.New("Zeitlimit: 1 bis 30 Sekunden")
	}

	switch kind {
	case "ping", "tcp", "tls", "tcp_banner", "ntp":
		if !validHost(s.Host) {
			return errors.New("Host: Name oder IP-Adresse angeben (ohne Protokoll und Port)")
		}
	}
	switch kind {
	case "ping":
		if err := s.normalizePing(); err != nil {
			return err
		}
	case "dns":
		if err := s.normalizeDNS(); err != nil {
			return err
		}
	case "http_json":
		if err := checkURL(s.URL); err != nil {
			return err
		}
		if err := s.normalizeJSON(); err != nil {
			return err
		}
	case "tcp_banner":
		if s.Port < 1 || s.Port > 65535 {
			return errors.New("Port: 1 bis 65535")
		}
		if utf8.RuneCountInString(s.Contains) > maxContains || hasControl(s.Contains) {
			return fmt.Errorf("Erwarteter Text: höchstens %d Zeichen, keine Steuerzeichen", maxContains)
		}
		if s.CAPEM != "" && !s.TLS {
			return errors.New("Eigene CA nur mit TLS")
		}
	case "ntp":
		if err := s.normalizeNTP(); err != nil {
			return err
		}
	case "tcp":
		if s.Port < 1 || s.Port > 65535 {
			return errors.New("Port: 1 bis 65535")
		}
	case "tls":
		if s.Port == 0 {
			s.Port = 443
		}
		if s.Port < 1 || s.Port > 65535 {
			return errors.New("Port: 1 bis 65535")
		}
		if s.Connect != "" && !validHost(s.Connect) {
			return errors.New("Verbinden mit: Name oder IP-Adresse angeben")
		}
		if s.WarnDays == 0 {
			s.WarnDays = 21
		}
		if s.CritDays == 0 {
			s.CritDays = 7
		}
		if s.CritDays <= 0 || s.WarnDays > 365 || s.CritDays >= s.WarnDays {
			return errors.New("Warnung und kritisch: in Tagen, kritisch kleiner als Warnung, höchstens 365")
		}
	case "http":
		if err := checkURL(s.URL); err != nil {
			return err
		}
		if len(s.ExpectStatus) > maxStatus {
			return fmt.Errorf("Erwartete Status-Codes: höchstens %d", maxStatus)
		}
		for _, c := range s.ExpectStatus {
			if c < 100 || c > 599 {
				return errors.New("Erwartete Status-Codes: 100 bis 599")
			}
		}
		if utf8.RuneCountInString(s.Contains) > maxContains || hasControl(s.Contains) {
			return fmt.Errorf("Erwarteter Text: höchstens %d Zeichen, keine Steuerzeichen", maxContains)
		}
	}
	if s.CAPEM != "" {
		if _, err := s.roots(); err != nil {
			return err
		}
	}
	return nil
}

func checkURL(raw string) error {
	if raw == "" || len(raw) > maxURL || hasControl(raw) {
		return errors.New("URL fehlt oder ist zu lang")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("URL muss mit http:// oder https:// beginnen")
	}
	if u.User != nil {
		return errors.New("URL darf keine Zugangsdaten enthalten")
	}
	if !validHost(u.Hostname()) {
		return errors.New("URL enthält keinen gültigen Host")
	}
	return nil
}

// roots: Systemzertifikate plus eigene CA.
func (s *Spec) roots() (*x509.CertPool, error) {
	if s.CAPEM == "" {
		return nil, nil // Systemzertifikate
	}
	if len(s.CAPEM) > maxCAPEM {
		return nil, errors.New("Eigene CA: höchstens 16 KiB")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	rest, n := []byte(s.CAPEM), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, errors.New("Eigene CA: nur Zertifikate (BEGIN CERTIFICATE), keine Schlüssel")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("Eigene CA: Zertifikat nicht lesbar")
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("Eigene CA: PEM mit mindestens einem Zertifikat erwartet")
	}
	return pool, nil
}

// LiteralAddrs liefert die IP-Adressen, die direkt im Ziel stehen. Die
// Oberfläche kann so sofort sagen, dass ein Ziel nicht freigegeben ist;
// Namen werden erst beim Prüfen aufgelöst.
func (s *Spec) LiteralAddrs() []netip.Addr {
	var out []netip.Addr
	for _, h := range []string{s.Host, s.Connect, hostOfURL(s.URL), s.Server} {
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func hostOfURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
