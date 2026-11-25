// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestPruefeZentrale(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, fremd, _ := ed25519.GenerateKey(rand.Reader)
	k := SingleKey(pub)
	paket := []byte("deb-inhalt")
	h := sha256.Sum256(paket)
	sum := hex.EncodeToString(h[:])
	datei := "openwacht-zentrale_1.0.4_amd64.deb"
	sums := []byte(sum + "  " + datei + "\n" + "0000000000000000000000000000000000000000000000000000000000000000  openwacht-agent_1.0.4_amd64.deb\n")
	sig, _ := SignSums(priv, sums)
	p, err := k.PruefeZentrale(sums, sig, datei, sum, "1.0.3", "amd64")
	if err != nil || p.Version != "1.0.4" || p.Arch != "amd64" || p.SHA256 != sum {
		t.Fatalf("gültiges Paket: %+v %v", p, err)
	}
	// Sternchen-Schreibweise von sha256sum -b
	sternSums := []byte(sum + " *" + datei + "\n")
	sternSig, _ := SignSums(priv, sternSums)
	if _, err := k.PruefeZentrale(sternSums, sternSig, datei, sum, "1.0.3", "amd64"); err != nil {
		t.Errorf("Sternchen: %v", err)
	}
	fremdSig, _ := SignSums(fremd, sums)
	andereSum := hex.EncodeToString(make([]byte, 32))
	for name, c := range map[string]struct {
		sums, sig             []byte
		datei, sum, akt, arch string
	}{
		"falscher Name":        {sums, sig, "openwacht-zentrale_1.0.4.deb", sum, "1.0.3", "amd64"},
		"Pfad im Namen":        {sums, sig, "../openwacht-zentrale_1.0.4_amd64.deb", sum, "1.0.3", "amd64"},
		"Agent statt Zentrale": {sums, sig, "openwacht-agent_1.0.4_amd64.deb", andereSum, "1.0.3", "amd64"},
		"andere Plattform":     {sums, sig, datei, sum, "1.0.3", "arm64"},
		"gleiche Version":      {sums, sig, datei, sum, "1.0.4", "amd64"},
		"Rückstufung":          {sums, sig, datei, sum, "1.0.5", "amd64"},
		"fremder Schlüssel":    {sums, fremdSig, datei, sum, "1.0.3", "amd64"},
		"ohne Signatur":        {sums, nil, datei, sum, "1.0.3", "amd64"},
		"Summen verändert":     {append([]byte("x"), sums...), sig, datei, sum, "1.0.3", "amd64"},
		"anderes Paket":        {sums, sig, datei, andereSum, "1.0.3", "amd64"},
		"Summe zu kurz":        {sums, sig, datei, sum[:10], "1.0.3", "amd64"},
	} {
		if _, err := k.PruefeZentrale(c.sums, c.sig, c.datei, c.sum, c.akt, c.arch); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
	// Widerrufener Schlüssel (mit einem zweiten, damit der Bund nutzbar bleibt)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	k2 := &Keyring{Keys: []Key{{Pub: pub, ID: KeyID(pub), State: StateActive}, {Pub: pub2, ID: KeyID(pub2), State: StateSpare}}, revoked: map[string]bool{}}
	k2.Revoke(KeyID(pub))
	if _, err := k2.PruefeZentrale(sums, sig, datei, sum, "1.0.3", "amd64"); !errors.Is(err, ErrRevoked) {
		t.Errorf("widerrufen: %v", err)
	}
}
