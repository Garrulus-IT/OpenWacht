// SPDX-License-Identifier: AGPL-3.0-only

// Package webauthntest ist ein nachgebauter Passkey (ES256, Attestation
// „none“) für Tests der Zentrale. Nur in Tests verwenden.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// Authenticator hält einen Schlüssel und zählt Signaturen.
type Authenticator struct {
	key    *ecdsa.PrivateKey
	ID     []byte
	Count  uint32
	RPID   string
	Origin string
}

// New erzeugt einen Passkey für die angegebene RP-ID und den Ursprung.
func New(rpID, origin string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &Authenticator{key: k, ID: id, RPID: rpID, Origin: origin}
}

func head(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	}
	return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
}

func text(s string) []byte  { return append(head(3, len(s)), s...) }
func bytes(b []byte) []byte { return append(head(2, len(b)), b...) }
func neg(n int) []byte      { return head(1, -1-n) }

func (a *Authenticator) cose() []byte {
	raw, _ := a.key.PublicKey.Bytes()
	b := head(5, 5)
	b = append(b, head(0, 1)...)
	b = append(b, head(0, 2)...) // kty EC2
	b = append(b, head(0, 3)...)
	b = append(b, neg(-7)...) // ES256
	b = append(b, neg(-1)...)
	b = append(b, head(0, 1)...) // P-256
	b = append(b, neg(-2)...)
	b = append(b, bytes(raw[1:33])...)
	b = append(b, neg(-3)...)
	return append(b, bytes(raw[33:])...)
}

func (a *Authenticator) authData(withKey bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	b := append([]byte(nil), h[:]...)
	flags := byte(0x05)
	if withKey {
		flags |= 0x40
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, a.Count)
	if withKey {
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.ID)))
		b = append(b, a.ID...)
		b = append(b, a.cose()...)
	}
	return b
}

// ClientData baut die Client-Daten, wie der Browser sie liefert.
func (a *Authenticator) ClientData(typ string, challenge []byte) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": a.Origin})
	return b
}

// Register liefert Client-Daten und Attestation-Objekt (Base64url).
func (a *Authenticator) Register(challenge []byte) (clientData, attestation string) {
	att := head(5, 3)
	att = append(att, text("fmt")...)
	att = append(att, text("none")...)
	att = append(att, text("attStmt")...)
	att = append(att, head(5, 0)...)
	att = append(att, text("authData")...)
	att = append(att, bytes(a.authData(true))...)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(a.ClientData("webauthn.create", challenge)), enc(att)
}

// Assert signiert eine Anmeldung und zählt hoch. Liefert die Felder, wie die
// Oberfläche sie an die Zentrale schickt.
func (a *Authenticator) Assert(challenge []byte) map[string]string {
	a.Count++
	cd := a.ClientData("webauthn.get", challenge)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	sum := sha256.Sum256(append(append([]byte(nil), ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
	if err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]string{"id": enc(a.ID), "client_data": enc(cd), "authenticator_data": enc(ad), "signature": enc(sig)}
}
