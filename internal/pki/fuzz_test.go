// SPDX-License-Identifier: AGPL-3.0-only

package pki

// Fuzz-Ziel für das CA-Bündel (Etappe 32): Es kommt in der Antwort der
// Zentrale, die übernommen sein kann. Was durchgeht, ist eine Liste von
// höchstens drei verschiedenen CAs.

import (
	"testing"
	"time"
)

func FuzzParseCABundle(f *testing.F) {
	a, _ := NewCA("A", time.Now())
	b, _ := NewCA("B", time.Now())
	f.Add(CertToPEM(a.Cert))
	f.Add(append(CertToPEM(a.Cert), CertToPEM(b.Cert)...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		cas, err := ParseCABundle(in)
		if err != nil {
			return
		}
		if len(cas) == 0 || len(cas) > MaxCABundle {
			t.Fatalf("%d CAs", len(cas))
		}
		seen := map[string]bool{}
		for _, c := range cas {
			if !c.IsCA || seen[Fingerprint(c)] {
				t.Fatal("keine CA oder doppelt")
			}
			seen[Fingerprint(c)] = true
		}
	})
}
