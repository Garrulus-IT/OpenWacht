// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Schnelle Parameter für Tests; das Format ist dasselbe.
var testParams = Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func TestPasswortHashUndPruefung(t *testing.T) {
	h, err := HashPassword("richtig-langes-passwort", testParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unerwartetes Format: %s", h)
	}
	if ok, _, err := VerifyPassword("richtig-langes-passwort", h, testParams); !ok || err != nil {
		t.Fatalf("richtiges Passwort abgelehnt: %v", err)
	}
	if ok, _, _ := VerifyPassword("falsches-langes-passwort", h, testParams); ok {
		t.Fatal("falsches Passwort akzeptiert")
	}
	h2, _ := HashPassword("richtig-langes-passwort", testParams)
	if h == h2 {
		t.Fatal("gleicher Hash trotz zufälligem Salt")
	}
	// Schwächere Kosten als gewünscht -> neu hashen.
	if _, rehash, _ := VerifyPassword("richtig-langes-passwort", h, DefaultParams); !rehash {
		t.Error("needsRehash bei schwächeren Kosten erwartet")
	}
	if _, rehash, _ := VerifyPassword("richtig-langes-passwort", h, testParams); rehash {
		t.Error("kein needsRehash bei gleichen Kosten erwartet")
	}
}

func TestManipulierteHashesWerdenAbgelehnt(t *testing.T) {
	bad := []string{
		"",
		"klartext",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g", // DoS-Kosten
		"$argon2id$v=19$m=64,t=999,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1,x=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1$!!$aGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5",
	}
	for _, h := range bad {
		if ok, _, err := VerifyPassword("irgendein-passwort", h, testParams); ok || err == nil {
			t.Errorf("Hash %q: ok=%v err=%v, erwartet Fehler", h, ok, err)
		}
	}
}

func TestPasswortRegeln(t *testing.T) {
	if err := ValidateNewPassword("kurz", "a@b.de"); err != ErrPasswordTooShort {
		t.Errorf("kurz: %v", err)
	}
	if err := ValidateNewPassword(strings.Repeat("x", 257), "a@b.de"); err != ErrPasswordTooLong {
		t.Errorf("lang: %v", err)
	}
	if err := ValidateNewPassword("erika@beispiel.example", "Erika@Beispiel.example"); err != ErrPasswordIsEmail {
		t.Errorf("E-Mail als Passwort: %v", err)
	}
	if err := ValidateNewPassword("ein ganz gutes Passwört", "a@b.de"); err != nil {
		t.Errorf("gutes Passwort abgelehnt: %v", err)
	}
	if err := ValidateNewPassword("ungültig\xff\xfe-langes-pw", "a@b.de"); err != ErrPasswordInvalid {
		t.Errorf("ungültiges UTF-8: %v", err)
	}
}

// Testvektoren aus RFC 6238, Anhang B (SHA1, Geheimnis "12345678901234567890").
// Die RFC nennt 8 Stellen; die letzten 6 sind der 6-stellige Code.
func TestTOTPRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for unix, want8 := range vectors {
		got := TOTPCode(secret, TOTPStep(time.Unix(unix, 0)))
		if got != want8[2:] {
			t.Errorf("T=%d: %s, erwartet %s", unix, got, want8[2:])
		}
	}
}

func TestTOTPPruefung(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := TOTPStep(now)
	code := TOTPCode(secret, cur)

	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || step != cur {
		t.Fatalf("gültiger Code abgelehnt")
	}
	if _, ok := VerifyTOTP(secret, code, now, cur); ok {
		t.Error("bereits verbrauchter Schritt akzeptiert (Replay)")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur-1), now, 0); !ok {
		t.Error("Code des vorigen Schritts (Uhrabweichung) abgelehnt")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur-2), now, 0); ok {
		t.Error("zu alter Code akzeptiert")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur+2), now, 0); ok {
		t.Error("zu weit in der Zukunft liegender Code akzeptiert")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("ungültige Eingabe %q akzeptiert", bad)
		}
	}
	other, _ := GenerateTOTPSecret()
	if _, ok := VerifyTOTP(other, code, now, 0); ok {
		t.Error("Code eines anderen Geheimnisses akzeptiert")
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("Prüf-Mandant", "erika@beispiel.example", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI %q enthält nicht %q", u, want)
		}
	}
}

func TestSecretbox(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	box, err := Seal(key, []byte("geheim"), []byte("benutzer-a"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, box, []byte("benutzer-a"))
	if err != nil || string(pt) != "geheim" {
		t.Fatalf("Open: %q, %v", pt, err)
	}
	if _, err := Open(key, box, []byte("benutzer-b")); err != ErrDecrypt {
		t.Error("Geheimtext ließ sich für einen anderen Benutzer öffnen")
	}
	other := bytes.Repeat([]byte{8}, KeySize)
	if _, err := Open(other, box, []byte("benutzer-a")); err != ErrWrongKey || !errors.Is(err, ErrDecrypt) {
		t.Errorf("falscher Schlüssel: %v", err)
	}
	box[len(box)-1] ^= 1
	if _, err := Open(key, box, []byte("benutzer-a")); err != ErrDecrypt {
		t.Error("manipulierter Geheimtext akzeptiert")
	}
	if _, err := Open(key, []byte{1, 2, 3}, nil); err != ErrDecrypt {
		t.Error("zu kurzer Geheimtext akzeptiert")
	}
}

const v1Fixture = "0185d8b34721a7909aa1bc06381b887d74dd0a7f239ccd13975a3b195a9dcc2733df32e359"

// sealV1 erzeugt einen Geheimtext im alten Format (bis 0.32) wie damals Seal.
func sealV1(t *testing.T, key, pt, aad []byte) []byte {
	t.Helper()
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 1+gcm.NonceSize())
	out[0] = 1
	rand.Read(out[1:])
	return gcm.Seal(out, out[1:], pt, aad)
}

func TestSecretboxVersion2(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	box, err := Seal(key, []byte("geheim"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if v, id := BoxKeyID(box); v != 2 || !bytes.Equal(id, KeyID(key)) {
		t.Fatalf("Version %d, Kennzeichen %x", v, id)
	}
	if len(box) != 1+KeyIDSize+12+6+16 {
		t.Fatalf("Länge %d", len(box))
	}
	// Das Kennzeichen ist authentifiziert: Wer es auf das eines anderen
	// Schlüssels setzt oder die Version auf 1 dreht, bekommt nichts.
	for i := 0; i < 1+KeyIDSize; i++ {
		b := bytes.Clone(box)
		b[i] ^= 1
		if _, err := Open(key, b, []byte("a")); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Byte %d im Kopf geändert: %v", i, err)
		}
	}
	other := bytes.Repeat([]byte{8}, KeySize)
	b := bytes.Clone(box)
	copy(b[1:], KeyID(other))
	if _, err := Open(other, b, []byte("a")); err != ErrDecrypt {
		t.Errorf("fremdes Kennzeichen eingesetzt: %v", err)
	}
	if bytes.Equal(KeyID(key), KeyID(other)) || len(KeyID(key)) != KeyIDSize {
		t.Error("Kennzeichen unterscheiden sich nicht")
	}
	if _, err := Open(key, box[:1+KeyIDSize+12+15], []byte("a")); err != ErrDecrypt {
		t.Error("zu kurz akzeptiert")
	}
	if _, err := Open(key, append([]byte{3}, box[1:]...), []byte("a")); err != ErrDecrypt {
		t.Error("unbekannte Version akzeptiert")
	}
}

func TestSecretboxVersion1BleibtLesbar(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	old := sealV1(t, key, []byte("alt"), []byte("a"))
	pt, err := Open(key, old, []byte("a"))
	if err != nil || string(pt) != "alt" {
		t.Fatalf("Version 1: %q %v", pt, err)
	}
	if v, id := BoxKeyID(old); v != 1 || id != nil {
		t.Errorf("BoxKeyID: %d %x", v, id)
	}
	if _, err := Open(key, old, []byte("b")); err != ErrDecrypt {
		t.Error("Version 1 mit falschem Kontext")
	}
	if _, err := Open(bytes.Repeat([]byte{8}, KeySize), old, []byte("a")); err != ErrDecrypt {
		t.Error("Version 1 mit falschem Schlüssel")
	}
	// Fester Geheimtext aus 0.32 (Schlüssel 7…7, AAD "a"): bleibt für immer lesbar.
	fixed, _ := hex.DecodeString(v1Fixture)
	if pt, err := Open(key, fixed, []byte("a")); err != nil || string(pt) != "aus 0.32" {
		t.Fatalf("Fixture: %q %v", pt, err)
	}
}

func TestSchluesseldatei(t *testing.T) {
	dir := t.TempDir()
	text, err := GenerateKeyText()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "schluessel")
	if err := os.WriteFile(p, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKeyFile(p)
	if err != nil || len(k) != KeySize {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	os.Chmod(p, 0o644)
	if _, err := LoadKeyFile(p); err == nil {
		t.Error("für andere lesbare Schlüsseldatei akzeptiert")
	}
	os.WriteFile(p, []byte("zu-kurz"), 0o600)
	os.Chmod(p, 0o600)
	if _, err := LoadKeyFile(p); err == nil {
		t.Error("ungültiger Schlüssel akzeptiert")
	}
}
