// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignierenUndPruefen(t *testing.T) {
	pub, priv := testKey(t)
	bin := []byte("agent-binary-0.23.0")
	s, err := Sign(priv, ManifestFor("0.23.0", "linux", "amd64", bin))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	got, err := ParseSigned(raw)
	if err != nil || Verify(pub, got, bin) != nil {
		t.Fatalf("gültig abgelehnt: %v", err)
	}
	// Jede Änderung bricht die Signatur
	for name, mod := range map[string]func(s *Signed){
		"Version":   func(s *Signed) { s.Version = "0.23.1" },
		"OS":        func(s *Signed) { s.OS = "windows" },
		"Arch":      func(s *Signed) { s.Arch = "arm64" },
		"Größe":     func(s *Signed) { s.Size++ },
		"Hash":      func(s *Signed) { s.SHA256 = strings.Repeat("0", 64) },
		"Signatur":  func(s *Signed) { s.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"Schlüssel": func(s *Signed) { s.KeyID = "0011223344556677" },
	} {
		c := got
		mod(&c)
		if err := Verify(pub, c, bin); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
	if err := Verify(pub, got, append(bin, 'x')); err == nil {
		t.Error("anderes Binary angenommen")
	}
	other, _ := testKey(t)
	if err := Verify(other, got, bin); !errors.Is(err, ErrSignature) {
		t.Errorf("fremder Schlüssel: %v", err)
	}
	// Unbekannte Felder und Unsinn
	for _, bad := range []string{`{"version":"0.23.0","x":1}`, `[]`, strings.Repeat("a", 5000)} {
		if _, err := ParseSigned([]byte(bad)); err == nil {
			t.Errorf("%q angenommen", bad[:min(20, len(bad))])
		}
	}
	for _, m := range []Manifest{{Version: "1.0", OS: "linux", Arch: "amd64"}, {Version: "1.0.0", OS: "darwin", Arch: "amd64"},
		{Version: "01.0.0", OS: "linux", Arch: "amd64"}} {
		if _, err := Sign(priv, m); err == nil {
			t.Errorf("%+v signiert", m)
		}
	}
}

func TestVersionen(t *testing.T) {
	for _, c := range []struct {
		v, cur string
		want   bool
	}{{"0.23.0", "0.22.1", true}, {"0.22.1", "0.22.1", false}, {"0.22.0", "0.22.1", false}, {"1.0.0", "0.99.99", true},
		{"0.10.0", "0.9.0", true}, {"0.23.0", "dev", true}, {"dev", "0.1.0", false}, {"0.23.0-rc1", "0.1.0", false}} {
		if Newer(c.v, c.cur) != c.want {
			t.Errorf("Newer(%s, %s) != %v", c.v, c.cur, c.want)
		}
	}
}

func line(pub ed25519.PublicKey, state string) string {
	l := "ed25519:" + base64.StdEncoding.EncodeToString(pub)
	if state != "" {
		l += " " + state
	}
	return l + "\n"
}

func TestSchluessel(t *testing.T) {
	pub, _ := testKey(t)
	k, err := ParseKeyring("# Kommentar\n" + line(pub, ""))
	if err != nil || len(k.Keys) != 1 || !k.Keys[0].Pub.Equal(pub) || k.Active() != KeyID(pub) {
		t.Fatal(err)
	}
	if _, err := ParseKeyring("# nur Kommentar\n"); !errors.Is(err, ErrNoKey) {
		t.Error("leer muss ErrNoKey sein")
	}
	if _, err := ParseKeyring(line(pub, "widerrufen")); !errors.Is(err, ErrNoKey) {
		t.Error("nur widerrufene Schlüssel müssen ErrNoKey sein")
	}
	p2, _ := testKey(t)
	p3, _ := testKey(t)
	p4, _ := testKey(t)
	for _, bad := range []string{"rsa:abc", "ed25519:!!", "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 31)),
		strings.TrimSpace(line(pub, "")) + " geheim\n", line(pub, "") + line(pub, "reserve"),
		line(pub, "") + line(p2, "aktiv"), line(pub, "") + line(p2, "reserve") + line(p3, "auslaufend") + line(p4, "reserve"),
		strings.TrimSpace(line(pub, "")) + " aktiv x\n"} {
		if _, err := ParseKeyring(bad); err == nil || errors.Is(err, ErrNoKey) {
			t.Errorf("%q", bad)
		}
	}
	k, err = ParseKeyring(line(pub, "auslaufend") + line(p2, "aktiv") + line(p3, "reserve"))
	if err != nil || len(k.Keys) != 3 || k.Active() != KeyID(p2) {
		t.Fatalf("drei Schlüssel: %v", err)
	}
	// Der eingebettete Schlüssel ist leer (Updates aus) oder lesbar.
	if _, err := Keys(); err != nil && !errors.Is(err, ErrNoKey) {
		t.Errorf("eingebetteter Schlüssel: %v", err)
	}
}

func TestMehrereSchluesselUndWiderruf(t *testing.T) {
	pubA, privA := testKey(t)
	pubB, privB := testKey(t)
	pubC, privC := testKey(t)
	k, err := ParseKeyring(line(pubA, "aktiv") + line(pubB, "reserve") + line(pubC, "widerrufen"))
	if err != nil {
		t.Fatal(err)
	}
	bin := []byte("agent-0.33.0")
	m := ManifestFor("0.33.0", "linux", "amd64", bin)
	sA, _ := Sign(privA, m)
	sB, _ := Sign(privB, m)
	sC, _ := Sign(privC, m)
	if k.Verify(sA, bin) != nil || k.Verify(sB, bin) != nil {
		t.Fatal("aktiver oder Reserve-Schlüssel abgelehnt")
	}
	if err := k.Verify(sC, bin); !errors.Is(err, ErrRevoked) {
		t.Errorf("in der Datei widerrufen: %v", err)
	}
	_, privX := testKey(t)
	sX, _ := Sign(privX, m)
	if err := k.Verify(sX, bin); !errors.Is(err, ErrSignature) {
		t.Errorf("unbekannter Schlüssel: %v", err)
	}
	// Ein Update, signiert mit B, widerruft A.
	sR, err := Sign(privB, m, KeyID(pubA))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sR)
	if !strings.Contains(string(raw), `"widerrufen":["`+KeyID(pubA)+`"]`) {
		t.Fatalf("Signaturdatei: %s", raw)
	}
	got, err := ParseSigned(raw)
	if err != nil || k.Verify(got, bin) != nil {
		t.Fatalf("Widerrufs-Update: %v", err)
	}
	// Der Widerruf ist mitsigniert: entfernen oder ändern bricht die Signatur.
	c := got
	c.Revoked = nil
	if k.Verify(c, bin) == nil {
		t.Error("Widerruf entfernt, Signatur gilt noch")
	}
	c.Revoked = []string{KeyID(pubC)}
	if k.Verify(c, bin) == nil {
		t.Error("Widerruf geändert, Signatur gilt noch")
	}
	// Ohne Widerruf bleibt die Nachricht v1 (ältere Agents prüfen dieselbe Datei).
	if string(m.message(nil)[:26]) != "openwacht-agent-update v1\n" || string(m.message([]string{"x"})[:26]) != "openwacht-agent-update v2\n" {
		t.Error("Nachrichtenformat")
	}
	// Der aktive Schlüssel darf die Reserve nicht widerrufen (wer nur ihn
	// erbeutet hat, sperrt sonst den Notfallschlüssel aus).
	sBad, err := Sign(privA, m, KeyID(pubB))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(sBad, bin); !errors.Is(err, ErrSignature) {
		t.Errorf("aktiv widerruft Reserve: %v", err)
	}
	// … wohl aber einen auslaufenden, und unbekannte Kennungen sind gleichgültig.
	pubD, _ := testKey(t)
	k2, _ := ParseKeyring(line(pubA, "aktiv") + line(pubB, "reserve") + line(pubD, "auslaufend"))
	if sOK, err := Sign(privA, m, KeyID(pubD), "00000000000000ff"); err != nil || k2.Verify(sOK, bin) != nil {
		t.Errorf("aktiv widerruft auslaufend: %v %v", err, k2.Verify(sOK, bin))
	}
	k.Revoke(got.Revoked...)
	if err := k.Verify(sA, bin); !errors.Is(err, ErrRevoked) {
		t.Errorf("nach Widerruf: %v", err)
	}
	if k.Active() != "" || !k.Usable() || k.Verify(sB, bin) != nil {
		t.Error("Reserve muss weiter gelten")
	}
	if strings.Join(k.Revoked(), ",") != strings.Join(sortedIDs(KeyID(pubA), KeyID(pubC)), ",") {
		t.Errorf("Widerrufe: %v", k.Revoked())
	}
	k.Revoke(KeyID(pubB))
	if k.Usable() || !errors.Is(k.VerifySigned(sB), ErrNoKey) {
		t.Error("alle widerrufen: Updates müssen aus sein")
	}
	// Selbst-Widerruf, unsortiert, Doppel, Unsinn: schon beim Signieren bzw. Lesen abgelehnt.
	if _, err := Sign(privA, m, KeyID(pubA)); err == nil {
		t.Error("Selbst-Widerruf signiert")
	}
	if _, err := Sign(privA, m, "zz"); err == nil {
		t.Error("ungültige Kennung signiert")
	}
	for _, bad := range [][]string{{KeyID(pubB), KeyID(pubB)}, sortedDesc(KeyID(pubB), KeyID(pubC)), {sA.KeyID}} {
		c := sA
		c.Revoked = bad
		raw, _ := json.Marshal(c)
		if _, err := ParseSigned(raw); err == nil {
			t.Errorf("Widerruf %v angenommen", bad)
		}
	}
	many := make([]string, MaxRevoked+1)
	for i := range many {
		many[i] = strings.Repeat("0", 15) + string(rune('a'+i))
	}
	if _, err := Sign(privB, m, many...); err == nil {
		t.Error("zu viele Widerrufe")
	}
}

func sortedIDs(a, b string) []string {
	if a > b {
		a, b = b, a
	}
	return []string{a, b}
}

func sortedDesc(a, b string) []string {
	s := sortedIDs(a, b)
	return []string{s[1], s[0]}
}

func TestWiderrufsdatei(t *testing.T) {
	got := ParseRevoked([]byte("0011223344556677\n# x\nzz\n  8899aabbccddeeff  \n"))
	if strings.Join(got, ",") != "0011223344556677,8899aabbccddeeff" {
		t.Errorf("%v", got)
	}
}

func TestSummenSignatur(t *testing.T) {
	pubA, privA := testKey(t)
	pubB, privB := testKey(t)
	k, _ := ParseKeyring(line(pubA, "aktiv") + line(pubB, "reserve"))
	sums := []byte("abc  openwacht-zentrale_0.33.0_amd64.deb\n")
	raw, err := SignSums(privA, sums)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSumsSig(raw)
	if err != nil || k.VerifySums(sums, s) != nil {
		t.Fatalf("gültig abgelehnt: %v", err)
	}
	if k.VerifySums(append(sums, ' '), s) == nil {
		t.Error("geänderte Prüfsummen angenommen")
	}
	// Eine Update-Signatur über dieselben Bytes gilt nicht (anderer Kontext).
	if k.VerifySums(sums, SumsSig{KeyID: KeyID(pubA), Signature: ed25519.Sign(privA, sums)}) == nil {
		t.Error("Signatur ohne Kontext angenommen")
	}
	_, privX := testKey(t)
	rawX, _ := SignSums(privX, sums)
	sx, _ := ParseSumsSig(rawX)
	if err := k.VerifySums(sums, sx); !errors.Is(err, ErrSignature) {
		t.Errorf("fremder Schlüssel: %v", err)
	}
	rawB, _ := SignSums(privB, sums)
	sb, _ := ParseSumsSig(rawB)
	k.Revoke(KeyID(pubB))
	if err := k.VerifySums(sums, sb); !errors.Is(err, ErrRevoked) {
		t.Errorf("widerrufen: %v", err)
	}
	// Auf einen Fingerabdruck festgelegt: nur dieser Schlüssel.
	p, err := k.Pin(KeyID(pubA))
	if err != nil || p.VerifySums(sums, s) != nil {
		t.Fatalf("Pin: %v", err)
	}
	if _, err := k.Pin(KeyID(pubB)); err == nil {
		t.Error("Pin auf widerrufenen Schlüssel")
	}
	if _, err := k.Pin("0011223344556677"); err == nil {
		t.Error("Pin auf unbekannten Schlüssel")
	}
	for _, bad := range []string{"", string(raw) + "x\n", strings.Replace(string(raw), "v1", "v2", 1),
		strings.Replace(string(raw), "schluessel ", "schluessel x", 1), strings.Replace(string(raw), "signatur ", "signatur !", 1)} {
		if _, err := ParseSumsSig([]byte(bad)); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	if _, err := SignSums(privA, nil); err == nil {
		t.Error("leere Prüfsummen signiert")
	}
}
