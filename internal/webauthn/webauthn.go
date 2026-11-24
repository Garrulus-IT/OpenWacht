// SPDX-License-Identifier: AGPL-3.0-only

// Package webauthn prüft Passkeys (W3C Web Authentication Level 2) als
// zweiten Faktor, nur mit der Standardbibliothek.
//
// Umfang (bewusst klein):
//   - Attestation „none“: Die Zentrale verlangt keine Herstellerbescheinigung
//     und prüft deshalb keine; welches Gerät den Schlüssel hält, ist egal.
//   - Algorithmen ES256 (-7), EdDSA/Ed25519 (-8) und RS256 (-257, ≥ 2048 Bit).
//   - Geprüft werden Typ, Challenge und Ursprung der Client-Daten, der Hash
//     der RP-ID, das Flag „Benutzer anwesend“, die Signatur und der Zähler.
//   - Keine Erweiterungen, kein „crossOrigin“, keine Token Binding.
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
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Algorithmen nach COSE (IANA).
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Algs: unterstützte Algorithmen in der Reihenfolge der Vorliebe.
var Algs = []int{AlgES256, AlgEdDSA, AlgRS256}

const (
	flagUP = 0x01 // Benutzer anwesend
	flagUV = 0x04 // Benutzer geprüft (PIN, Biometrie)
	flagAT = 0x40 // Schlüsseldaten folgen
	flagED = 0x80 // Erweiterungen folgen

	maxClientData = 4096
	maxAuthData   = 4096
)

var (
	ErrClientData = errors.New("Client-Daten passen nicht (Typ, Challenge oder Ursprung)")
	ErrAuthData   = errors.New("Authenticator-Daten ungültig")
	ErrKey        = errors.New("Schlüssel nicht unterstützt")
	ErrSignature  = errors.New("Signatur ungültig")
	ErrAttest     = errors.New("Attestation nicht unterstützt (erwartet: none)")
)

// RP beschreibt die Zentrale als „Relying Party“.
type RP struct {
	ID     string // Hostname der Basisadresse, z. B. openwacht.example.com
	Origin string // Ursprung, z. B. https://openwacht.example.com
}

// NewChallenge liefert 32 Zufallsbytes.
func NewChallenge() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// Credential ist ein registrierter Passkey.
type Credential struct {
	ID        []byte
	PublicKey []byte // COSE-Schlüssel, wie geliefert
	Alg       int
	SignCount uint32
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func (rp RP) checkClientData(raw []byte, typ string, challenge []byte) error {
	if len(raw) == 0 || len(raw) > maxClientData {
		return ErrClientData
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ErrClientData
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || cd.Type != typ || cd.CrossOrigin || cd.Origin != rp.Origin ||
		len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrClientData
	}
	return nil
}

// ClientChallenge liest die Challenge aus den Client-Daten (ohne sie zu
// prüfen), damit die Zentrale die passende gespeicherte Challenge findet.
func ClientChallenge(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxClientData {
		return nil, ErrClientData
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, ErrClientData
	}
	b, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(b) != 32 {
		return nil, ErrClientData
	}
	return b, nil
}

type authData struct {
	rpIDHash []byte
	flags    byte
	count    uint32
	credID   []byte
	key      []byte // COSE, nur bei Registrierung
}

func parseAuthData(b []byte, wantKey bool) (authData, error) {
	var a authData
	if len(b) < 37 || len(b) > maxAuthData {
		return a, ErrAuthData
	}
	a.rpIDHash, a.flags, a.count = b[:32], b[32], binary.BigEndian.Uint32(b[33:37])
	rest := b[37:]
	// Erweiterungen (z. B. credProtect) setzen manche Authenticatoren auch
	// ungefragt. Sie müssen gültiges CBOR (eine Zuordnung) am Ende sein und
	// werden nicht ausgewertet.
	exts := func(r []byte) error {
		if a.flags&flagED == 0 {
			if len(r) != 0 {
				return ErrAuthData
			}
			return nil
		}
		v, tail, err := decodeCBOR(r)
		if _, ok := v.(map[any]any); err != nil || !ok || len(tail) != 0 {
			return ErrAuthData
		}
		return nil
	}
	if !wantKey {
		if a.flags&flagAT != 0 {
			return a, ErrAuthData
		}
		return a, exts(rest)
	}
	if a.flags&flagAT == 0 || len(rest) < 18 {
		return a, ErrAuthData
	}
	n := int(binary.BigEndian.Uint16(rest[16:18])) // nach der AAGUID
	rest = rest[18:]
	if n < 16 || n > 1023 || len(rest) < n {
		return a, ErrAuthData
	}
	a.credID, rest = rest[:n], rest[n:]
	_, tail, err := decodeCBOR(rest)
	if err != nil {
		return a, ErrAuthData
	}
	a.key = rest[:len(rest)-len(tail)]
	return a, exts(tail)
}

// PublicKey wandelt einen COSE-Schlüssel um und prüft ihn.
func PublicKey(cose []byte) (crypto.PublicKey, int, error) {
	v, tail, err := decodeCBOR(cose)
	if err != nil || len(tail) != 0 {
		return nil, 0, ErrKey
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, ErrKey
	}
	num := func(k int64) (int64, bool) { x, ok := m[k].(int64); return x, ok }
	byt := func(k int64) []byte { x, _ := m[k].([]byte); return x }
	kty, _ := num(1)
	alg, _ := num(3)
	switch {
	case kty == 2 && alg == AlgES256:
		if crv, _ := num(-1); crv != 1 {
			return nil, 0, ErrKey
		}
		x, y := byt(-2), byt(-3)
		if len(x) != 32 || len(y) != 32 {
			return nil, 0, ErrKey
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, 0, ErrKey
		}
		return pub, AlgES256, nil
	case kty == 1 && alg == AlgEdDSA:
		if crv, _ := num(-1); crv != 6 {
			return nil, 0, ErrKey
		}
		x := byt(-2)
		if len(x) != ed25519.PublicKeySize {
			return nil, 0, ErrKey
		}
		return ed25519.PublicKey(x), AlgEdDSA, nil
	case kty == 3 && alg == AlgRS256:
		n, e := byt(-1), byt(-2)
		if len(n) < 256 || len(n) > 512 || n[0] == 0 || len(e) == 0 || len(e) > 4 {
			return nil, 0, ErrKey
		}
		ev := new(big.Int).SetBytes(e).Int64()
		if ev < 3 || ev%2 == 0 {
			return nil, 0, ErrKey
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev)}, AlgRS256, nil
	}
	return nil, 0, ErrKey
}

func verifySig(pub crypto.PublicKey, alg int, data, sig []byte) error {
	h := sha256.Sum256(data)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = alg == AlgES256 && ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		ok = alg == AlgEdDSA && ed25519.Verify(k, data, sig)
	case *rsa.PublicKey:
		ok = alg == AlgRS256 && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	}
	if !ok {
		return ErrSignature
	}
	return nil
}

func (rp RP) checkRPID(hash []byte) error {
	want := sha256.Sum256([]byte(rp.ID))
	if rp.ID == "" || !bytes.Equal(hash, want[:]) {
		return ErrAuthData
	}
	return nil
}

// VerifyRegistration prüft das Ergebnis von navigator.credentials.create().
func (rp RP) VerifyRegistration(challenge, clientDataJSON, attestationObject []byte) (Credential, error) {
	var c Credential
	if err := rp.checkClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return c, err
	}
	if len(attestationObject) > 2*maxAuthData {
		return c, ErrAuthData
	}
	v, tail, err := decodeCBOR(attestationObject)
	if err != nil || len(tail) != 0 {
		return c, ErrAuthData
	}
	m, ok := v.(map[any]any)
	if !ok {
		return c, ErrAuthData
	}
	fmtName, _ := m["fmt"].(string)
	stmt, _ := m["attStmt"].(map[any]any)
	raw, _ := m["authData"].([]byte)
	if fmtName != "none" || stmt == nil || len(stmt) != 0 {
		return c, ErrAttest
	}
	a, err := parseAuthData(raw, true)
	if err != nil {
		return c, err
	}
	if err := rp.checkRPID(a.rpIDHash); err != nil {
		return c, err
	}
	if a.flags&flagUP == 0 {
		return c, ErrAuthData
	}
	_, alg, err := PublicKey(a.key)
	if err != nil {
		return c, err
	}
	return Credential{ID: append([]byte(nil), a.credID...), PublicKey: append([]byte(nil), a.key...), Alg: alg, SignCount: a.count}, nil
}

// VerifyAssertion prüft das Ergebnis von navigator.credentials.get() gegen
// einen gespeicherten Passkey und liefert den neuen Zähler. Ob der Zähler
// steigt, prüft die Datenbank (Zähler 0 heißt: Authenticator führt keinen).
func (rp RP) VerifyAssertion(challenge []byte, cred Credential, clientDataJSON, authenticatorData, signature []byte) (uint32, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.get", challenge); err != nil {
		return 0, err
	}
	a, err := parseAuthData(authenticatorData, false)
	if err != nil {
		return 0, err
	}
	if err := rp.checkRPID(a.rpIDHash); err != nil {
		return 0, err
	}
	if a.flags&flagUP == 0 {
		return 0, ErrAuthData
	}
	pub, alg, err := PublicKey(cred.PublicKey)
	if err != nil || alg != cred.Alg {
		return 0, ErrKey
	}
	if len(signature) == 0 || len(signature) > 1024 {
		return 0, ErrSignature
	}
	h := sha256.Sum256(clientDataJSON)
	data := append(append([]byte(nil), authenticatorData...), h[:]...)
	if err := verifySig(pub, alg, data, signature); err != nil {
		return 0, err
	}
	return a.count, nil
}

// String für Logs: nie Schlüssel, nur Algorithmus.
func AlgName(alg int) string {
	switch alg {
	case AlgES256:
		return "ES256"
	case AlgEdDSA:
		return "EdDSA"
	case AlgRS256:
		return "RS256"
	}
	return fmt.Sprintf("alg %d", alg)
}
