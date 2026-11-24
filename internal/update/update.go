// SPDX-License-Identifier: AGPL-3.0-only

// Package update prüft signierte Agent-Updates (Etappe 23, Leitprinzip 4).
//
// Ein Update besteht aus dem Agent-Binary und einer Signaturdatei. Die
// Signatur (Ed25519) deckt Version, Betriebssystem, Architektur, Größe und
// SHA-256 des Binarys ab. Signiert wird nur offline mit tools/signieren; die
// öffentlichen Schlüssel stehen in schluessel.pub und werden in Zentrale und
// Agent eingebettet. Ohne eingetragenen Schlüssel sind Updates aus.
//
// Seit Etappe 32 (Befund M5) stehen dort bis zu drei Schlüssel mit Zustand
// (aktiv, reserve, auslaufend, widerrufen). Eine Signatur kann zusätzlich
// Schlüssel als widerrufen markieren; Zentrale und Installationsdienst merken
// sich das und nehmen danach nichts mehr an, was mit ihnen signiert ist.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed schluessel.pub
var embeddedKey string

// MaxSize: größtes erlaubtes Agent-Binary.
const MaxSize = 64 << 20

// Manifest beschreibt ein Update.
type Manifest struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"groesse"`
}

// Signed ist der Inhalt der Signaturdatei (.sig).
type Signed struct {
	Manifest
	// Revoked: Kennungen von Schlüsseln, die dieses Update für widerrufen
	// erklärt (sortiert, ohne Doppel, nie der eigene). Mit signiert.
	Revoked   []string `json:"widerrufen,omitempty"`
	KeyID     string   `json:"schluessel"` // erste 8 Byte von SHA-256(public key), hex
	Signature string   `json:"signatur"`   // base64
}

// Zustände eines Schlüssels in schluessel.pub.
const (
	StateActive   = "aktiv"      // signiert neue Updates
	StateSpare    = "reserve"    // offline bereit, falls der aktive verloren geht
	StateRetiring = "auslaufend" // wird ersetzt, Signaturen gelten noch
	StateRevoked  = "widerrufen" // gilt nicht mehr
	// MaxKeys: höchstens so viele Schlüssel in schluessel.pub.
	MaxKeys = 3
	// MaxRevoked: höchstens so viele Widerrufe in einer Signatur.
	MaxRevoked = 8
)

var (
	ErrNoKey     = errors.New("kein Update-Schlüssel eingetragen: Agent-Updates sind aus")
	ErrSignature = errors.New("Signatur ungültig")
	ErrRevoked   = errors.New("Schlüssel widerrufen")
	versionRe    = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$`)
	keyIDRe      = regexp.MustCompile(`^[0-9a-f]{16}$`)
	osArch       = map[string]bool{"linux/amd64": true, "linux/arm64": true, "windows/amd64": true}
)

// Key: ein öffentlicher Schlüssel mit Zustand.
type Key struct {
	Pub   ed25519.PublicKey
	ID    string
	State string
}

// Keyring: die Schlüssel aus schluessel.pub plus bekannte Widerrufe.
type Keyring struct {
	Keys    []Key
	revoked map[string]bool
}

// Keys liefert die eingebetteten Schlüssel (oder ErrNoKey).
func Keys() (*Keyring, error) { return ParseKeyring(embeddedKey) }

// ParseKeyring liest Zeilen „ed25519:<base64> [zustand]“ (ohne Zustand:
// aktiv; Kommentarzeilen mit #). Höchstens drei Schlüssel, höchstens einer
// aktiv, keiner doppelt. Ohne gültigen Schlüssel: ErrNoKey.
func ParseKeyring(s string) (*Keyring, error) {
	k := &Keyring{revoked: map[string]bool{}}
	active := 0
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 2 {
			return nil, errors.New("Schlüssel: erwartet ed25519:<base64> [aktiv|reserve|auslaufend|widerrufen]")
		}
		b64, ok := strings.CutPrefix(f[0], "ed25519:")
		if !ok {
			return nil, errors.New("Schlüssel: erwartet ed25519:<base64>")
		}
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("Schlüssel unlesbar")
		}
		state := StateActive
		if len(f) == 2 {
			state = f[1]
		}
		switch state {
		case StateActive:
			active++
		case StateSpare, StateRetiring:
		case StateRevoked:
			k.revoked[KeyID(b)] = true
		default:
			return nil, fmt.Errorf("Schlüssel: unbekannter Zustand %q", state)
		}
		key := Key{Pub: ed25519.PublicKey(b), ID: KeyID(b), State: state}
		for _, o := range k.Keys {
			if o.ID == key.ID {
				return nil, errors.New("Schlüssel doppelt eingetragen")
			}
		}
		k.Keys = append(k.Keys, key)
	}
	if len(k.Keys) > MaxKeys {
		return nil, fmt.Errorf("höchstens %d Update-Schlüssel", MaxKeys)
	}
	if active > 1 {
		return nil, errors.New("höchstens ein aktiver Update-Schlüssel")
	}
	if len(k.Keys) == len(k.revoked) {
		return nil, ErrNoKey
	}
	return k, nil
}

// SingleKey: Schlüsselbund mit einem aktiven Schlüssel (Tests, Werkzeuge).
func SingleKey(pub ed25519.PublicKey) *Keyring {
	return &Keyring{Keys: []Key{{Pub: pub, ID: KeyID(pub), State: StateActive}}, revoked: map[string]bool{}}
}

// Revoke vermerkt Widerrufe (z. B. aus der Datenbank oder einer Datei).
func (k *Keyring) Revoke(ids ...string) {
	for _, id := range ids {
		if keyIDRe.MatchString(id) {
			k.revoked[id] = true
		}
	}
}

func (k *Keyring) lookup(id string) (Key, bool) {
	for _, key := range k.Keys {
		if key.ID == id {
			return key, true
		}
	}
	return Key{}, false
}

// IsRevoked: Ist der Schlüssel widerrufen?
func (k *Keyring) IsRevoked(id string) bool { return k.revoked[id] }

// Revoked: alle bekannten Widerrufe, sortiert.
func (k *Keyring) Revoked() []string {
	out := make([]string, 0, len(k.revoked))
	for id := range k.revoked {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Active: Kennung des aktiven, nicht widerrufenen Schlüssels ("" = keiner).
func (k *Keyring) Active() string {
	for _, key := range k.Keys {
		if key.State == StateActive && !k.revoked[key.ID] {
			return key.ID
		}
	}
	return ""
}

// Usable: Gibt es mindestens einen nicht widerrufenen Schlüssel?
func (k *Keyring) Usable() bool {
	if k == nil {
		return false
	}
	for _, key := range k.Keys {
		if !k.revoked[key.ID] {
			return true
		}
	}
	return false
}

// ParseRevoked liest eine Datei mit Widerrufen (eine Kennung je Zeile).
func ParseRevoked(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); keyIDRe.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// KeyID kennzeichnet einen Schlüssel.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// message: die signierten Bytes (eindeutig, ohne JSON-Mehrdeutigkeiten).
// Ohne Widerruf wie bisher (v1), damit ältere Agents dieselbe Datei prüfen können.
func (m Manifest) message(revoked []string) []byte {
	if len(revoked) == 0 {
		return []byte(fmt.Sprintf("openwacht-agent-update v1\n%s\n%s\n%s\n%s\n%d\n", m.Version, m.OS, m.Arch, m.SHA256, m.Size))
	}
	return []byte(fmt.Sprintf("openwacht-agent-update v2\n%s\n%s\n%s\n%s\n%d\nwiderrufen %s\n",
		m.Version, m.OS, m.Arch, m.SHA256, m.Size, strings.Join(revoked, ",")))
}

// checkRevoked: sortiert, ohne Doppel, gültige Kennungen, nicht der eigene Schlüssel.
func checkRevoked(revoked []string, own string) error {
	if len(revoked) > MaxRevoked {
		return errors.New("zu viele Widerrufe")
	}
	for i, id := range revoked {
		if !keyIDRe.MatchString(id) {
			return errors.New("Widerruf: Kennung ungültig")
		}
		if i > 0 && revoked[i-1] >= id {
			return errors.New("Widerruf: Kennungen sortiert und ohne Doppel angeben")
		}
		if id == own {
			return errors.New("Widerruf: ein Schlüssel kann sich nicht selbst widerrufen")
		}
	}
	return nil
}

// Check prüft die Form des Manifests.
func (m Manifest) Check() error {
	if !versionRe.MatchString(m.Version) {
		return errors.New("Version: erwartet x.y.z")
	}
	if !osArch[m.OS+"/"+m.Arch] {
		return fmt.Errorf("Plattform %s/%s nicht unterstützt", m.OS, m.Arch)
	}
	if b, err := hex.DecodeString(m.SHA256); err != nil || len(b) != 32 || m.SHA256 != strings.ToLower(m.SHA256) {
		return errors.New("SHA-256 ungültig")
	}
	if m.Size <= 0 || m.Size > MaxSize {
		return errors.New("Größe ungültig")
	}
	return nil
}

// Sign signiert (nur tools/signieren und Tests). revoke: Schlüssel, die
// dieses Update für widerrufen erklärt (wird sortiert).
func Sign(priv ed25519.PrivateKey, m Manifest, revoke ...string) (Signed, error) {
	if err := m.Check(); err != nil {
		return Signed{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	var rev []string
	if len(revoke) > 0 {
		rev = append(rev, revoke...)
		sort.Strings(rev)
	}
	if err := checkRevoked(rev, KeyID(pub)); err != nil {
		return Signed{}, err
	}
	return Signed{Manifest: m, Revoked: rev, KeyID: KeyID(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.message(rev)))}, nil
}

// ManifestFor beschreibt ein Binary.
func ManifestFor(version, goos, arch string, bin []byte) Manifest {
	h := sha256.Sum256(bin)
	return Manifest{Version: version, OS: goos, Arch: arch, SHA256: hex.EncodeToString(h[:]), Size: int64(len(bin))}
}

// ParseSigned liest eine Signaturdatei.
func ParseSigned(b []byte) (Signed, error) {
	var s Signed
	if len(b) > 4096 {
		return s, errors.New("Signaturdatei zu groß")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("Signaturdatei unlesbar: %w", err)
	}
	if err := s.Check(); err != nil {
		return s, err
	}
	return s, checkRevoked(s.Revoked, s.KeyID)
}

// VerifySigned prüft Signatur und Manifest (ohne Binary).
func (k *Keyring) VerifySigned(s Signed) error {
	if !k.Usable() {
		return ErrNoKey
	}
	if err := s.Check(); err != nil {
		return err
	}
	if err := checkRevoked(s.Revoked, s.KeyID); err != nil {
		return err
	}
	signer, ok := k.lookup(s.KeyID)
	if !ok {
		return fmt.Errorf("%w: unbekannter Schlüssel (%s)", ErrSignature, s.KeyID)
	}
	pub := signer.Pub
	if k.revoked[s.KeyID] {
		return fmt.Errorf("%w (%s)", ErrRevoked, s.KeyID)
	}
	// Wer wen widerrufen darf: Die Reserve ist der Notfallschlüssel und darf
	// jeden widerrufen; der aktive nur einen auslaufenden. So kann, wer nur
	// den aktiven Schlüssel erbeutet hat, die Reserve nicht aussperren.
	for _, id := range s.Revoked {
		target, known := k.lookup(id)
		if !known || signer.State == StateSpare || (signer.State == StateActive && target.State == StateRetiring) {
			continue
		}
		return fmt.Errorf("%w: Schlüssel %s (%s) darf %s (%s) nicht widerrufen", ErrSignature, signer.ID, signer.State, id, target.State)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, s.message(s.Revoked), sig) {
		return ErrSignature
	}
	return nil
}

// Verify prüft Signatur, Manifest und Binary.
func (k *Keyring) Verify(s Signed, bin []byte) error {
	if err := k.VerifySigned(s); err != nil {
		return err
	}
	return checkBinary(s, bin)
}

// VerifySigned mit genau einem Schlüssel.
func VerifySigned(pub ed25519.PublicKey, s Signed) error { return SingleKey(pub).VerifySigned(s) }

// Verify mit genau einem Schlüssel.
func Verify(pub ed25519.PublicKey, s Signed, bin []byte) error { return SingleKey(pub).Verify(s, bin) }

func checkBinary(s Signed, bin []byte) error {
	h := sha256.Sum256(bin)
	if int64(len(bin)) != s.Size || hex.EncodeToString(h[:]) != s.SHA256 {
		return errors.New("Binary passt nicht zur Signatur")
	}
	return nil
}

// Newer: ist v neuer als cur? Unbekannte Versionen (z. B. "dev") gelten als 0.0.0.
func Newer(v, cur string) bool {
	a, b := parse(v), parse(cur)
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func parse(v string) []int {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range 3 {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}
