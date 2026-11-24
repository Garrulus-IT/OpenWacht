// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Verteilung des Agents durch die Zentrale (Etappe 34). Die Zentrale liefert
// nur Pakete, die mit den Offline-Schlüsseln signiert sind; geprüft wird auf
// dem Zielrechner, bevor etwas installiert wird:
//   - Linux: Ed25519-Signatur mit openssl gegen die Schlüssel, die im
//     Befehl selbst stehen (DownloadText, PublicKeyPEM).
//   - Windows: Authenticode-Signatur mit Get-AuthenticodeSignature gegen
//     die Fingerabdrücke aus authenticode.txt (PowerShell kann kein Ed25519).
// Den Befehl zeigt zwar die Zentrale an; wer ihr nicht traut, vergleicht die
// Kennungen mit denen im Handbuch (zweite Quelle, wie bei installieren.sh).

//go:embed authenticode.txt
var embeddedThumbprints string

// MaxThumbprints: höchstens so viele Authenticode-Zertifikate.
const MaxThumbprints = 3

var thumbRe = regexp.MustCompile(`^[0-9A-F]{40}$`)

// ParseThumbprints liest Fingerabdrücke (Großbuchstaben, ohne Trenner;
// Kommentare mit #). Leer = keine.
func ParseThumbprints(s string) ([]string, error) {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		l = strings.ToUpper(strings.ReplaceAll(l, " ", ""))
		if !thumbRe.MatchString(l) {
			return nil, fmt.Errorf("Authenticode-Fingerabdruck %q: erwartet 40 Hex-Zeichen", l)
		}
		for _, o := range out {
			if o == l {
				return nil, errors.New("Authenticode-Fingerabdruck doppelt")
			}
		}
		out = append(out, l)
	}
	if len(out) > MaxThumbprints {
		return nil, fmt.Errorf("höchstens %d Authenticode-Fingerabdrücke", MaxThumbprints)
	}
	return out, nil
}

// Thumbprints: eingebettete Fingerabdrücke (leer = Windows-Download aus).
func Thumbprints() ([]string, error) { return ParseThumbprints(embeddedThumbprints) }

// PublicKeyPEM: öffentlicher Schlüssel als PEM (SubjectPublicKeyInfo), so
// wie openssl ihn für -pubin erwartet.
func PublicKeyPEM(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// DownloadHeader: erste Zeile der Signaturdatei für den Download.
const DownloadHeader = "openwacht-agent-download v1"

// DownloadText: Signatur eines Pakets als Textzeilen, damit ein
// Shell-Skript sie ohne JSON-Werkzeug lesen und mit openssl prüfen kann.
// Signiert sind dieselben Bytes wie beim Update (Manifest.message).
func DownloadText(s Signed) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nversion %s\nos %s\narch %s\nsha256 %s\ngroesse %d\nschluessel %s\nsignatur %s\n",
		DownloadHeader, s.Version, s.OS, s.Arch, s.SHA256, s.Size, s.KeyID, s.Signature)
	if len(s.Revoked) > 0 {
		fmt.Fprintf(&b, "widerrufen %s\n", strings.Join(s.Revoked, ","))
	}
	return b.String()
}

// SignedMessage: die signierten Bytes (für Tests des Skripts).
func SignedMessage(s Signed) []byte { return s.message(s.Revoked) }
