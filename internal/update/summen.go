// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Signatur der Prüfsummen eines Releases (Etappe 32, Befund M7). Signiert
// wird SHA256SUMS mit denselben Offline-Schlüsseln wie die Agent-Updates,
// aber mit eigenem Kontext: Eine Update-Signatur gilt nie als
// Prüfsummen-Signatur und umgekehrt.
//
// Datei <SHA256SUMS>.sig (Text, damit installieren.sh sie mit sed lesen kann):
//
//	openwacht-sha256sums v1
//	schluessel <kennung>
//	signatur <base64>
//
// Die signierten Bytes sind „openwacht-sha256sums v1\n“ gefolgt vom
// unveränderten Inhalt von SHA256SUMS; so lässt sich die Signatur auch ohne
// OpenWacht mit „openssl pkeyutl -verify -rawin“ prüfen.

// SumsContext steht vor dem Inhalt von SHA256SUMS.
const SumsContext = "openwacht-sha256sums v1\n"

// MaxSums: größte Prüfsummendatei.
const MaxSums = 1 << 20

// SumsSig: gelesene Signaturdatei.
type SumsSig struct {
	KeyID     string
	Signature []byte
}

func sumsMessage(content []byte) []byte {
	return append([]byte(SumsContext), content...)
}

// SignSums signiert den Inhalt von SHA256SUMS (nur tools/signieren und Tests).
func SignSums(priv ed25519.PrivateKey, content []byte) ([]byte, error) {
	if len(content) == 0 || len(content) > MaxSums {
		return nil, errors.New("SHA256SUMS leer oder zu groß")
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, sumsMessage(content))
	return []byte(fmt.Sprintf("openwacht-sha256sums v1\nschluessel %s\nsignatur %s\n", KeyID(pub), base64.StdEncoding.EncodeToString(sig))), nil
}

// ParseSumsSig liest eine Signaturdatei streng (genau drei Zeilen).
func ParseSumsSig(b []byte) (SumsSig, error) {
	var s SumsSig
	if len(b) > 512 {
		return s, errors.New("Signaturdatei zu groß")
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 3 || lines[0] != strings.TrimSuffix(SumsContext, "\n") {
		return s, errors.New("Signaturdatei: erwartet openwacht-sha256sums v1")
	}
	id, ok := strings.CutPrefix(lines[1], "schluessel ")
	if !ok || !keyIDRe.MatchString(id) {
		return s, errors.New("Signaturdatei: Kennung des Schlüssels fehlt")
	}
	b64, ok := strings.CutPrefix(lines[2], "signatur ")
	sig, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil || len(sig) != ed25519.SignatureSize {
		return s, errors.New("Signaturdatei: Signatur unlesbar")
	}
	return SumsSig{KeyID: id, Signature: sig}, nil
}

// VerifySums prüft die Signatur von SHA256SUMS gegen den Schlüsselbund.
func (k *Keyring) VerifySums(content []byte, s SumsSig) error {
	if !k.Usable() {
		return ErrNoKey
	}
	if len(content) == 0 || len(content) > MaxSums {
		return errors.New("SHA256SUMS leer oder zu groß")
	}
	key, ok := k.lookup(s.KeyID)
	if !ok {
		return fmt.Errorf("%w: unbekannter Schlüssel (%s)", ErrSignature, s.KeyID)
	}
	if k.revoked[s.KeyID] {
		return fmt.Errorf("%w (%s)", ErrRevoked, s.KeyID)
	}
	if !ed25519.Verify(key.Pub, sumsMessage(content), s.Signature) {
		return ErrSignature
	}
	return nil
}

// Pin lässt nur den Schlüssel mit der Kennung id im Bund (Prüfung mit einem
// Fingerabdruck aus einer zweiten Quelle). Fehler, wenn es ihn nicht gibt.
func (k *Keyring) Pin(id string) (*Keyring, error) {
	key, ok := k.lookup(id)
	if !ok || k.revoked[id] {
		return nil, fmt.Errorf("kein gültiger Schlüssel mit der Kennung %s", id)
	}
	return &Keyring{Keys: []Key{key}, revoked: map[string]bool{}}, nil
}
