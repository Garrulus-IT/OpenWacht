// SPDX-License-Identifier: AGPL-3.0-only

// Package agentproto beschreibt das Protokoll zwischen Agent und Zentrale:
// Registrierungs-Token, Anfragen und die Messwerte. Agent und Zentrale nutzen
// dieselben Typen; die Zentrale prüft alles, was ein Agent schickt, mit
// Validate, weil Agent-Daten nicht vertrauenswürdig sind.
package agentproto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Pfade auf dem Agent-Port der Zentrale.
const (
	PathRegister = "/agent/v1/registrieren"
	PathReport   = "/agent/v1/messwerte"
	PathRenew    = "/agent/v1/zertifikat"
	// Signierte Updates (Etappe 23): Signatur und Binary der freigegebenen Version
	PathUpdateSignature = "/agent/v1/update/signatur"
	PathUpdateBinary    = "/agent/v1/update/binary"
	// Sammler (Etappe 15): Geräteliste abholen, Ergebnis einer Abfrage senden
	PathCollectorDevices = "/agent/v1/sammler/geraete"
	PathCollectorResult  = "/agent/v1/sammler/ergebnis"
)

// --- Registrierungs-Token -------------------------------------------------------
//
// Format: owa1.<Geheimnis>.<CA-Fingerabdruck>  (Punkt als Trenner, weil er in
// Base64url nicht vorkommt; der Unterstrich schon)
// Das Geheimnis (32 Byte, Base64url) weist die Berechtigung nach, der
// Fingerabdruck sagt dem Agent, welcher CA er beim ersten Kontakt trauen darf.

const tokenPrefix = "owa1."

// NewToken erzeugt ein Token. Gespeichert wird nur der Hash des Geheimnisses.
func NewToken(caFingerprint string) (token string, secret []byte, err error) {
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(secret) + "." + caFingerprint, secret, nil
}

// TokenLen ist die Länge eines vollständigen Tokens: Präfix, 43 Zeichen
// Geheimnis, Punkt, 43 Zeichen CA-Fingerabdruck.
const TokenLen = len(tokenPrefix) + 43 + 1 + 43

// tokenHint: Die meisten kaputten Tokens sind beim Kopieren abgeschnitten
// oder haben Anführungszeichen bzw. Befehlsreste angehängt bekommen.
var tokenHint = fmt.Sprintf(" – das Token aus der Oberfläche neu kopieren: nur owa1.… bis zum letzten Zeichen, ohne Anführungszeichen (%d Zeichen)", TokenLen)

// fingerprintRE: SHA-256 als Base64url ohne Auffüllung (pki.Fingerprint).
var fingerprintRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ParseToken zerlegt ein Token in Geheimnis und CA-Fingerabdruck.
func ParseToken(token string) (secret []byte, caFingerprint string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), tokenPrefix)
	if !ok {
		return nil, "", errors.New("das Token hat nicht das erwartete Format (owa1.…)" + tokenHint)
	}
	s, fp, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, "", errors.New("das Token ist unvollständig" + tokenHint)
	}
	secret, err = base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(secret) != 32 {
		return nil, "", errors.New("das Token ist beschädigt" + tokenHint)
	}
	if b, err := base64.RawURLEncoding.DecodeString(fp); err != nil || len(b) != 32 {
		return nil, "", errors.New("der CA-Fingerabdruck im Token ist beschädigt" + tokenHint)
	}
	return secret, fp, nil
}

// --- Anfragen ----------------------------------------------------------------------

type RegisterRequest struct {
	Token    string `json:"token"`
	CSR      []byte `json:"csr"` // DER, in JSON als Base64
	Hostname string `json:"hostname"`
}

type RegisterResponse struct {
	AgentID     string `json:"agent_id"`
	Certificate string `json:"zertifikat"` // PEM
	CA          string `json:"ca"`         // PEM
}

type RenewRequest struct {
	CSR []byte `json:"csr"`
}

type RenewResponse struct {
	Certificate string `json:"zertifikat"`
	// CA: vertrauenswürdige Agent-CAs als PEM-Bündel, die ausstellende zuerst
	// (Etappe 32). Fehlt bei älteren Zentralen.
	CA string `json:"ca,omitempty"`
}

// ReportResponse: Die Zentrale antwortet nur mit Daten, nie mit Befehlen
// (Leitprinzip 1). Das Intervall ist ein Wunsch, den der Agent begrenzt.
type ReportResponse struct {
	IntervalSeconds int `json:"intervall_sekunden"`
	// Update: für diesen Agent freigegebene neuere Version (Etappe 23). Der
	// Agent installiert sie nur mit gültiger Offline-Signatur.
	Update *UpdateOffer `json:"update,omitempty"`
	// CA: neues Bündel der Agent-CAs (PEM, die ausstellende zuerst), nur wenn
	// der Agent ein anderes meldet (Agent-CA-Wechsel, Etappe 32). Daten,
	// kein Befehl: Der Agent übernimmt es nur, wenn es eine CA enthält, der er
	// schon vertraut.
	CA string `json:"ca,omitempty"`
}

// UpdateOffer nennt die freigegebene Version.
type UpdateOffer struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// --- Messwerte ----------------------------------------------------------------------

type Snapshot struct {
	CollectedAt  time.Time `json:"erfasst"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`     // z. B. "Debian GNU/Linux 13 (trixie)"
	Kernel       string    `json:"kernel"` // z. B. "6.12.48-1-amd64"
	Arch         string    `json:"arch"`   // GOARCH
	AgentVersion string    `json:"agent"`  // Version des Agents
	UptimeSec    uint64    `json:"laufzeit_s"`
	CPU          CPU       `json:"cpu"`
	Memory       Memory    `json:"speicher"`
	Disks        []Disk    `json:"platten"`
	// Collector: nur gesetzt, wenn der Sammler auf dem Rechner lokal
	// freigegeben ist (openwacht-agent sammler -netze …).
	Collector *Collector `json:"sammler,omitempty"`
	// Lokale Freigabe für Sensoren (Etappe 18); fehlt = keine
	Sensors *SensorRelease `json:"sensoren,omitempty"`
	// Platform: GOOS/GOARCH (ab 0.23, für Updates)
	Platform string `json:"plattform,omitempty"`
	// UpdateError: letzte gescheiterte Update-Installation (ab 0.23)
	UpdateError string `json:"update_fehler,omitempty"`
	// CAs: Fingerabdrücke der Agent-CAs in ca.pem, in Dateireihenfolge (Etappe 32).
	CAs []string `json:"cas,omitempty"`
	// CertCA: Fingerabdruck der CA, die das Client-Zertifikat ausgestellt hat.
	// Setzt die Zentrale aus der geprüften TLS-Kette; ein Wert des Agents wird überschrieben.
	CertCA string `json:"zert_ca,omitempty"`
}

// Collector: lokale Freigabe als Sammler. Die Netze legt der Betreiber des
// Rechners fest; der Agent fragt nur Adressen darin ab. Die Zentrale nutzt
// sie nur für Hinweise und gibt Zugangsdaten für Adressen außerhalb nicht heraus.
type Collector struct {
	Nets []string `json:"netze"`
}

type CPU struct {
	Cores   int     `json:"kerne"`
	Percent float64 `json:"auslastung_prozent"`
	Load1   float64 `json:"last1"`
	Load5   float64 `json:"last5"`
	Load15  float64 `json:"last15"`
	// NoLoad: Das System kennt keine Load Average (Windows); Last1 bis Last15 sind dann 0.
	NoLoad bool `json:"ohne_last,omitempty"`
}

type Memory struct {
	TotalBytes     uint64 `json:"gesamt"`
	AvailableBytes uint64 `json:"verfuegbar"`
	SwapTotalBytes uint64 `json:"swap_gesamt"`
	SwapFreeBytes  uint64 `json:"swap_frei"`
}

type Disk struct {
	Mount      string `json:"einhaengepunkt"`
	FSType     string `json:"dateisystem"`
	TotalBytes uint64 `json:"gesamt"`
	FreeBytes  uint64 `json:"frei"`
}

// Obergrenzen für Agent-Daten.
const (
	MaxReportBytes = 64 << 10
	MaxDisks       = 64
	// Sammler
	MaxCollectorNets    = 32
	MaxCollectorDevices = 500
	// MaxCollectorResultBytes: Messwerte (≤ 512 KiB gespeichert) plus Rahmen
	MaxCollectorResultBytes = 640 << 10
	MaxCollectorListBytes   = 4 << 10
)

func checkText(field, s string, max int) error {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return fmt.Errorf("%s: zu lang oder kein gültiges UTF-8", field)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s: enthält Steuerzeichen", field)
		}
	}
	return nil
}

func checkFloat(field string, v, min, max float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < min || v > max {
		return fmt.Errorf("%s: Wert außerhalb des gültigen Bereichs", field)
	}
	return nil
}

// ValidHostname: Buchstaben, Ziffern, Bindestrich, Punkt, Unterstrich.
func ValidHostname(h string) error {
	if h == "" || len(h) > 253 {
		return errors.New("hostname: leer oder zu lang")
	}
	for _, r := range h {
		if !(r == '-' || r == '.' || r == '_' || r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r))) {
			return errors.New("hostname: ungültige Zeichen")
		}
	}
	return nil
}

// Validate prüft einen Snapshot. now dient der Plausibilität des Zeitstempels.
func (s *Snapshot) Validate(now time.Time) error {
	if err := ValidHostname(s.Hostname); err != nil {
		return err
	}
	for _, f := range []struct {
		name, v string
		max     int
	}{{"os", s.OS, 100}, {"kernel", s.Kernel, 100}, {"arch", s.Arch, 20}, {"agent", s.AgentVersion, 40},
		{"plattform", s.Platform, 30}, {"update_fehler", s.UpdateError, 300}} {
		if err := checkText(f.name, f.v, f.max); err != nil {
			return err
		}
	}
	if len(s.CAs) > 3 {
		return errors.New("cas: höchstens 3")
	}
	for _, fp := range append(append([]string{}, s.CAs...), s.CertCA) {
		if fp != "" && !fingerprintRE.MatchString(fp) {
			return errors.New("cas: Fingerabdruck ungültig")
		}
	}
	if s.CollectedAt.IsZero() || s.CollectedAt.After(now.Add(10*time.Minute)) || s.CollectedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("erfasst: Zeitstempel unplausibel (Uhr des Agents prüfen)")
	}
	if s.CPU.Cores < 1 || s.CPU.Cores > 4096 {
		return errors.New("cpu.kerne: unplausibel")
	}
	if err := checkFloat("cpu.auslastung_prozent", s.CPU.Percent, 0, 100); err != nil {
		return err
	}
	for name, v := range map[string]float64{"cpu.last1": s.CPU.Load1, "cpu.last5": s.CPU.Load5, "cpu.last15": s.CPU.Load15} {
		if err := checkFloat(name, v, 0, 100000); err != nil {
			return err
		}
	}
	if s.CPU.NoLoad && (s.CPU.Load1 != 0 || s.CPU.Load5 != 0 || s.CPU.Load15 != 0) {
		return errors.New("cpu.ohne_last: dann müssen die Lastwerte 0 sein")
	}
	if s.Memory.AvailableBytes > s.Memory.TotalBytes || s.Memory.SwapFreeBytes > s.Memory.SwapTotalBytes {
		return errors.New("speicher: frei größer als gesamt")
	}
	if len(s.Disks) > MaxDisks {
		return fmt.Errorf("platten: höchstens %d", MaxDisks)
	}
	for i, d := range s.Disks {
		if err := checkText(fmt.Sprintf("platten[%d].einhaengepunkt", i), d.Mount, 256); err != nil {
			return err
		}
		if d.Mount == "" {
			return fmt.Errorf("platten[%d].einhaengepunkt: leer", i)
		}
		if err := checkText(fmt.Sprintf("platten[%d].dateisystem", i), d.FSType, 32); err != nil {
			return err
		}
		if d.FreeBytes > d.TotalBytes {
			return fmt.Errorf("platten[%d]: frei größer als gesamt", i)
		}
	}
	if s.Collector != nil {
		if _, err := ParseCollectorNets(s.Collector.Nets); err != nil {
			return err
		}
	}
	if s.Sensors != nil {
		if err := s.Sensors.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ParseCollectorNets prüft die Netze eines Sammlers: höchstens 32, jedes als
// Netz in kanonischer Form (10.20.0.0/16), kein /0.
func ParseCollectorNets(nets []string) ([]netip.Prefix, error) {
	if len(nets) == 0 {
		return nil, errors.New("sammler.netze: mindestens ein Netz angeben")
	}
	if len(nets) > MaxCollectorNets {
		return nil, fmt.Errorf("sammler.netze: höchstens %d", MaxCollectorNets)
	}
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		p, err := netip.ParsePrefix(n)
		if err != nil || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("sammler.netze: %q ist kein Netz (Form 10.20.0.0/16)", clip(n, 60))
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("sammler.netze: %s gibt alles frei, bitte das Netz der Geräte angeben", p)
		}
		if p.Masked() != p || p.Addr().Is4In6() {
			return nil, fmt.Errorf("sammler.netze: %s bitte als %s angeben", p, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// --- Sammler: Geräteliste und Ergebnisse --------------------------------------
//
// Der Agent holt die Liste bei jedem Meldezyklus ab. Hat sich nichts geändert
// (gleicher Stand), schickt die Zentrale keine Zugangsdaten mit.

type CollectorDevicesRequest struct {
	State string `json:"stand"` // Stand der zuletzt erhaltenen Liste, leer beim Start
}

type CollectorDevicesResponse struct {
	State     string            `json:"stand"`
	Unchanged bool              `json:"unveraendert"`
	Devices   []CollectorDevice `json:"geraete"` // nur wenn geändert
	Due       []string          `json:"faellig"` // IDs, die jetzt abgefragt werden sollen
}

// CollectorDevice: ein Gerät, das der Sammler abfragt (nur lesend: GET,
// GETNEXT, GETBULK). Die Zugangsdaten sind Daten, kein Code.
type CollectorDevice struct {
	ID              string       `json:"id"`
	Revision        int          `json:"revision"`
	Version         string       `json:"version"` // 1, 2c, 3
	Host            string       `json:"adresse"`
	Port            int          `json:"port"`
	IntervalSeconds int          `json:"intervall_sekunden"`
	Community       string       `json:"community,omitempty"`
	V3              *CollectorV3 `json:"v3,omitempty"`
	// Eigene OIDs für Sensoren (Etappe 18b), nur lesend abgefragt
	Extra []string `json:"eigene_oids,omitempty"`
	// Eigene Tabellenspalten (0.47.0): nur lesend, gemeldet werden Kennzahlen
	Columns []string `json:"eigene_spalten,omitempty"`
}

type CollectorV3 struct {
	User     string `json:"benutzer"`
	Auth     string `json:"auth"`
	AuthPass string `json:"auth_passwort"`
	Priv     string `json:"priv"`
	PrivPass string `json:"priv_passwort"`
}

// CollectorResult: Ergebnis einer Abfrage. Messwerte wie die Zentrale sie
// speichert (snmp.Snapshot), ohne Raten; die rechnet die Zentrale selbst.
type CollectorResult struct {
	ID       string          `json:"id"`
	Revision int             `json:"revision"`
	OK       bool            `json:"ok"`
	Error    string          `json:"fehler,omitempty"`
	Snapshot json.RawMessage `json:"messwerte,omitempty"`
}
