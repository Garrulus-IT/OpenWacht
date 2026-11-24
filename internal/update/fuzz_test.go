// SPDX-License-Identifier: AGPL-3.0-only

package update

// Fuzz-Ziel für Signaturdateien von Agent-Updates (Befund M3). Die Datei
// kommt über die Zentrale, die übernommen sein kann. Ohne den passenden
// Schlüssel darf keine Eingabe als gültig gelten.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func FuzzParseSigned(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil) // Testschlüssel, nur im Speicher
	m := ManifestFor("0.32.0", "linux", "amd64", []byte("agent"))
	s, err := Sign(priv, m)
	if err != nil {
		f.Fatal(err)
	}
	b, _ := json.Marshal(s)
	f.Add(b)
	f.Add([]byte(`{"version":"1","schluessel":"","signatur":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSigned(b)
		if err != nil {
			return
		}
		if VerifySigned(pub, s) == nil {
			// nur das unveränderte Original darf passen
			if s.Manifest != m {
				t.Fatalf("fremdes Manifest mit gültiger Signatur angenommen: %+v", s.Manifest)
			}
		}
		_ = Verify(pub, s, []byte("agent"))
	})
}

// Signaturdatei von SHA256SUMS (Etappe 32) und Schlüsseldatei: Beide kommen
// aus einem Paket, das verändert sein kann.
func FuzzSumsSig(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sums := []byte("abc  datei\n")
	sig, _ := SignSums(priv, sums)
	f.Add(sig, []byte("ed25519:"+base64.StdEncoding.EncodeToString(pub)+" aktiv\n"))
	f.Add([]byte("openwacht-sha256sums v1\nschluessel 0011223344556677\nsignatur AAAA\n"), []byte("ed25519:x reserve"))
	k := SingleKey(pub)
	f.Fuzz(func(t *testing.T, sigFile, keyFile []byte) {
		if s, err := ParseSumsSig(sigFile); err == nil {
			if k.VerifySums(sums, s) == nil && !bytes.Equal(s.Signature, mustParse(t, sig).Signature) {
				t.Fatal("fremde Signatur angenommen")
			}
		}
		if ring, err := ParseKeyring(string(keyFile)); err == nil {
			if len(ring.Keys) == 0 || len(ring.Keys) > MaxKeys {
				t.Fatalf("Schlüsselbund mit %d Schlüsseln", len(ring.Keys))
			}
			_ = ring.Active()
		}
	})
}

func mustParse(t *testing.T, b []byte) SumsSig {
	s, err := ParseSumsSig(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
