// SPDX-License-Identifier: AGPL-3.0-only

package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

// --- kleiner CBOR-Schreiber nur für Tests -------------------------------------

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
	b := []byte{major<<5 | 26, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(n))
	return b
}

func enc(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case kv:
		out := cborHead(5, uint64(len(x)))
		for _, p := range x {
			out = append(out, enc(p.k)...)
			out = append(out, enc(p.v)...)
		}
		return out
	}
	panic("enc")
}

type pair struct{ k, v any }
type kv []pair

// --- Authenticator-Attrappe -----------------------------------------------------

type fakeAuth struct {
	alg    int
	priv   crypto.Signer
	cose   []byte
	credID []byte
	count  uint32
}

func newFake(t *testing.T, alg int) *fakeAuth {
	t.Helper()
	f := &fakeAuth{alg: alg, credID: bytes.Repeat([]byte{byte(-alg)}, 32)}
	switch alg {
	case AlgES256:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		f.priv = k
		raw, _ := k.PublicKey.Bytes()
		f.cose = enc(kv{{1, 2}, {3, -7}, {-1, 1}, {-2, raw[1:33]}, {-3, raw[33:]}})
	case AlgEdDSA:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.priv = priv
		f.cose = enc(kv{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}})
	case AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		f.priv = k
		e := expBytes(k.E)
		f.cose = enc(kv{{1, 3}, {3, -257}, {-1, k.N.Bytes()}, {-2, e}})
	}
	return f
}

func expBytes(e int) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

var rp = RP{ID: "openwacht.example.com", Origin: "https://openwacht.example.com"}

func clientJSON(typ string, ch []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(ch), "origin": origin})
	return b
}

func (f *fakeAuth) authData(rpID string, flags byte, withKey bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, f.count)
	if withKey {
		b = append(b, make([]byte, 16)...) // AAGUID
		b = binary.BigEndian.AppendUint16(b, uint16(len(f.credID)))
		b = append(b, f.credID...)
		b = append(b, f.cose...)
	}
	return b
}

func (f *fakeAuth) register(ch []byte) (cd, att []byte) {
	cd = clientJSON("webauthn.create", ch, rp.Origin)
	att = enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", f.authData(rp.ID, flagUP|flagUV|flagAT, true)}})
	return
}

func (f *fakeAuth) sign(data []byte) []byte {
	h := sha256.Sum256(data)
	var sig []byte
	var err error
	switch k := f.priv.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, data)
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, h[:])
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	}
	if err != nil {
		panic(err)
	}
	return sig
}

func (f *fakeAuth) assert(ch []byte, flags byte) (cd, ad, sig []byte) {
	f.count++
	cd = clientJSON("webauthn.get", ch, rp.Origin)
	ad = f.authData(rp.ID, flags, false)
	h := sha256.Sum256(cd)
	sig = f.sign(append(append([]byte(nil), ad...), h[:]...))
	return
}

func mustChallenge(t *testing.T) []byte {
	ch, err := NewChallenge()
	if err != nil || len(ch) != 32 {
		t.Fatal(err)
	}
	return ch
}

func TestRegistrierungUndAnmeldung(t *testing.T) {
	for _, alg := range Algs {
		t.Run(AlgName(alg), func(t *testing.T) {
			f := newFake(t, alg)
			ch := mustChallenge(t)
			cd, att := f.register(ch)
			cred, err := rp.VerifyRegistration(ch, cd, att)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cred.ID, f.credID) || cred.Alg != alg || !bytes.Equal(cred.PublicKey, f.cose) {
				t.Fatalf("Credential %+v", cred)
			}
			if got, err := ClientChallenge(cd); err != nil || !bytes.Equal(got, ch) {
				t.Fatalf("ClientChallenge %v", err)
			}
			ch2 := mustChallenge(t)
			cd2, ad, sig := f.assert(ch2, flagUP)
			n, err := rp.VerifyAssertion(ch2, cred, cd2, ad, sig)
			if err != nil || n != f.count {
				t.Fatalf("Anmeldung: %v, Zähler %d", err, n)
			}
			// Signatur eines anderen Schlüssels
			g := newFake(t, alg)
			if _, err := rp.VerifyAssertion(ch2, cred, cd2, ad, g.sign(append(append([]byte(nil), ad...), sha(cd2)...))); !errors.Is(err, ErrSignature) {
				t.Errorf("fremde Signatur: %v", err)
			}
		})
	}
}

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func TestRegistrierungAbgelehnt(t *testing.T) {
	f := newFake(t, AlgES256)
	ch := mustChallenge(t)
	good := func() ([]byte, []byte) { return f.register(ch) }
	cases := []struct {
		name string
		mod  func(cd, att []byte) ([]byte, []byte)
		want error
	}{
		{"falsche Challenge", func(cd, att []byte) ([]byte, []byte) {
			return clientJSON("webauthn.create", mustChallenge(t), rp.Origin), att
		}, ErrClientData},
		{"falscher Ursprung", func(cd, att []byte) ([]byte, []byte) {
			return clientJSON("webauthn.create", ch, "https://openwacht.example.com.evil.example"), att
		}, ErrClientData},
		{"http statt https", func(cd, att []byte) ([]byte, []byte) {
			return clientJSON("webauthn.create", ch, "http://openwacht.example.com"), att
		}, ErrClientData},
		{"Typ get", func(cd, att []byte) ([]byte, []byte) { return clientJSON("webauthn.get", ch, rp.Origin), att }, ErrClientData},
		{"crossOrigin", func(cd, att []byte) ([]byte, []byte) {
			b, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(ch),
				"origin": rp.Origin, "crossOrigin": true})
			return b, att
		}, ErrClientData},
		{"kein JSON", func(cd, att []byte) ([]byte, []byte) { return []byte("{"), att }, ErrClientData},
		{"Attestation packed", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "packed"}, {"attStmt", kv{}}, {"authData", f.authData(rp.ID, flagUP|flagAT, true)}})
		}, ErrAttest},
		{"none mit Inhalt", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{{"sig", []byte{1}}}}, {"authData", f.authData(rp.ID, flagUP|flagAT, true)}})
		}, ErrAttest},
		{"andere RP-ID", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", f.authData("evil.example", flagUP|flagAT, true)}})
		}, ErrAuthData},
		{"ohne UP", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", f.authData(rp.ID, flagAT, true)}})
		}, ErrAuthData},
		{"ohne Schlüsseldaten", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", f.authData(rp.ID, flagUP, false)}})
		}, ErrAuthData},
		{"Müll hinter dem Objekt", func(cd, att []byte) ([]byte, []byte) { return cd, append(att, 0) }, ErrAuthData},
		{"Müll hinter dem Schlüssel", func(cd, att []byte) ([]byte, []byte) {
			return cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", append(f.authData(rp.ID, flagUP|flagAT, true), 0)}})
		}, ErrAuthData},
	}
	for _, c := range cases {
		cd, att := c.mod(good())
		if _, err := rp.VerifyRegistration(ch, cd, att); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, erwartet %v", c.name, err, c.want)
		}
	}
	// Erweiterungen: gültige Zuordnung wird hingenommen, Müll nicht.
	ad := append(f.authData(rp.ID, flagUP|flagAT|flagED, true), enc(kv{{"credProtect", 2}})...)
	cd, _ := good()
	if _, err := rp.VerifyRegistration(ch, cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", ad}})); err != nil {
		t.Errorf("mit Erweiterung: %v", err)
	}
	ad = append(f.authData(rp.ID, flagUP|flagAT|flagED, true), enc(5)...)
	if _, err := rp.VerifyRegistration(ch, cd, enc(kv{{"fmt", "none"}, {"attStmt", kv{}}, {"authData", ad}})); !errors.Is(err, ErrAuthData) {
		t.Errorf("Erweiterung keine Zuordnung: %v", err)
	}
}

func TestAnmeldungAbgelehnt(t *testing.T) {
	f := newFake(t, AlgES256)
	ch := mustChallenge(t)
	cd, att := f.register(ch)
	cred, err := rp.VerifyRegistration(ch, cd, att)
	if err != nil {
		t.Fatal(err)
	}
	ch2 := mustChallenge(t)
	cd2, ad, sig := f.assert(ch2, flagUP)
	if _, err := rp.VerifyAssertion(mustChallenge(t), cred, cd2, ad, sig); !errors.Is(err, ErrClientData) {
		t.Errorf("andere Challenge: %v", err)
	}
	if _, err := rp.VerifyAssertion(ch2, cred, clientJSON("webauthn.create", ch2, rp.Origin), ad, sig); !errors.Is(err, ErrClientData) {
		t.Errorf("Typ create: %v", err)
	}
	// Ein Bit in den Authenticator-Daten geändert (Zähler) → Signatur passt nicht.
	bad := append([]byte(nil), ad...)
	bad[36] ^= 1
	if _, err := rp.VerifyAssertion(ch2, cred, cd2, bad, sig); !errors.Is(err, ErrSignature) {
		t.Errorf("geänderte Daten: %v", err)
	}
	// Ohne „Benutzer anwesend“ (korrekt signiert)
	cd3, ad3, sig3 := f.assert(ch2, 0)
	if _, err := rp.VerifyAssertion(ch2, cred, cd3, ad3, sig3); !errors.Is(err, ErrAuthData) {
		t.Errorf("ohne UP: %v", err)
	}
	// Mit Schlüsseldaten in der Anmeldung
	if _, err := rp.VerifyAssertion(ch2, cred, cd2, f.authData(rp.ID, flagUP|flagAT, true), sig); !errors.Is(err, ErrAuthData) {
		t.Errorf("AT in der Anmeldung: %v", err)
	}
	// andere RP-ID, korrekt signiert
	f.count++
	adx := f.authData("evil.example", flagUP, false)
	if _, err := rp.VerifyAssertion(ch2, cred, cd2, adx, f.sign(append(append([]byte(nil), adx...), sha(cd2)...))); !errors.Is(err, ErrAuthData) {
		t.Errorf("andere RP-ID: %v", err)
	}
	// Algorithmus im gespeicherten Datensatz passt nicht zum Schlüssel
	c2 := cred
	c2.Alg = AlgEdDSA
	if _, err := rp.VerifyAssertion(ch2, c2, cd2, ad, sig); !errors.Is(err, ErrKey) {
		t.Errorf("falscher Algorithmus: %v", err)
	}
	if _, err := rp.VerifyAssertion(ch2, cred, cd2, ad, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("leere Signatur: %v", err)
	}
	// leere RP-ID in der Konfiguration
	if _, err := (RP{Origin: rp.Origin}).VerifyAssertion(ch2, cred, cd2, ad, sig); err == nil {
		t.Error("leere RP-ID angenommen")
	}
}

func TestSchluesselAbgelehnt(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := k.PublicKey.Bytes()
	x, y := raw[1:33], raw[33:]
	offCurve := append([]byte(nil), y...)
	offCurve[31] ^= 1
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	cases := map[string][]byte{
		"P-384":           enc(kv{{1, 2}, {3, -7}, {-1, 2}, {-2, x}, {-3, y}}),
		"nicht auf Kurve": enc(kv{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, offCurve}}),
		"kurzes x":        enc(kv{{1, 2}, {3, -7}, {-1, 1}, {-2, x[:31]}, {-3, y}}),
		"ES384":           enc(kv{{1, 2}, {3, -35}, {-1, 1}, {-2, x}, {-3, y}}),
		"Ed448":           enc(kv{{1, 1}, {3, -8}, {-1, 7}, {-2, make([]byte, 32)}}),
		"RSA 1024":        enc(kv{{1, 3}, {3, -257}, {-1, small.N.Bytes()}, {-2, []byte{1, 0, 1}}}),
		"RSA e gerade":    enc(kv{{1, 3}, {3, -257}, {-1, bytes.Repeat([]byte{0xff}, 256)}, {-2, []byte{2}}}),
		"kein Map":        enc(5),
		"Müll dahinter":   append(enc(kv{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}}), 0),
	}
	for name, cose := range cases {
		if _, _, err := PublicKey(cose); !errors.Is(err, ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, alg, err := PublicKey(enc(kv{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}})); err != nil || alg != AlgES256 {
		t.Errorf("gültiger Schlüssel: %v", err)
	}
}

func TestCBORGrenzen(t *testing.T) {
	bad := map[string][]byte{
		"leer":                {},
		"unbestimmte Länge":   {0x5f},
		"Tag":                 {0xc0, 0x00},
		"Gleitkomma":          {0xfb, 0, 0, 0, 0, 0, 0, 0, 0},
		"Länge zu groß":       {0x5a, 0xff, 0xff, 0xff, 0xff},
		"nicht kürzeste Form": {0x18, 0x05},
		"Map zu groß":         {0xb9, 0xff, 0xff},
		"doppelter Schlüssel": {0xa2, 0x01, 0x00, 0x01, 0x00},
		"Schlüssel Bytes":     {0xa1, 0x41, 0x00, 0x00},
		"kein UTF-8":          {0x61, 0xff},
		"riesige Zahl":        {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	deep := []byte{}
	for i := 0; i < 20; i++ {
		deep = append(deep, 0x81)
	}
	bad["zu tief"] = append(deep, 0)
	for name, b := range bad {
		if _, _, err := decodeCBOR(b); err == nil {
			t.Errorf("%s angenommen", name)
		}
	}
	v, rest, err := decodeCBOR([]byte{0xa2, 0x01, 0x20, 0x63, 'f', 'm', 't', 0xf5, 0xff})
	if err != nil || len(rest) != 1 {
		t.Fatal(err)
	}
	m := v.(map[any]any)
	if m[int64(1)] != int64(-1) || m["fmt"] != true {
		t.Errorf("gelesen %v", m)
	}
}

func FuzzRegistrierung(f *testing.F) {
	ch := bytes.Repeat([]byte{7}, 32)
	a := &fakeAuth{alg: AlgEdDSA, credID: bytes.Repeat([]byte{1}, 16)}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	a.cose = enc(kv{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}})
	cd, att := a.register(ch)
	f.Add(cd, att)
	f.Add([]byte("{}"), []byte{0xa0})
	f.Fuzz(func(t *testing.T, cd, att []byte) {
		c, err := rp.VerifyRegistration(ch, cd, att)
		if err == nil {
			if _, _, err := PublicKey(c.PublicKey); err != nil {
				t.Fatalf("angenommener Schlüssel nicht lesbar: %v", err)
			}
		}
	})
}

func FuzzAnmeldung(f *testing.F) {
	ch := bytes.Repeat([]byte{7}, 32)
	a := newFakeForFuzz()
	cd, ad, sig := a.assert(ch, flagUP)
	f.Add(cd, ad, sig, a.cose)
	f.Fuzz(func(t *testing.T, cd, ad, sig, cose []byte) {
		_, alg, err := PublicKey(cose)
		if err != nil {
			return
		}
		_, _ = rp.VerifyAssertion(ch, Credential{PublicKey: cose, Alg: alg}, cd, ad, sig)
	})
}

func newFakeForFuzz() *fakeAuth {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fakeAuth{alg: AlgEdDSA, priv: priv, credID: bytes.Repeat([]byte{1}, 16),
		cose: enc(kv{{1, 1}, {3, -8}, {-1, 6}, {-2, []byte(pub)}})}
}
