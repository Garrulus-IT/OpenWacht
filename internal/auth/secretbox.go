// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Schlüsselgröße für AES-256.
const KeySize = 32

// Formate des Geheimtexts. Version 1 (bis 0.32) trägt kein Kennzeichen des
// Schlüssels; sie bleibt lesbar. Seal schreibt seit Etappe 32 immer Version 2.
const (
	boxV1 = 1
	boxV2 = 2
	// KeyIDSize: Länge des Schlüssel-Kennzeichens in Version 2.
	KeyIDSize = 8
)

var (
	ErrDecrypt = errors.New("Entschlüsseln fehlgeschlagen (falscher Schlüssel oder manipulierte Daten)")
	// ErrWrongKey: Version 2 mit dem Kennzeichen eines anderen Schlüssels.
	// errors.Is(err, ErrDecrypt) gilt auch hier.
	ErrWrongKey = fmt.Errorf("%w: mit einem anderen Schlüssel verschlüsselt", ErrDecrypt)
)

// KeyID ist das Kennzeichen eines Schlüssels: die ersten 8 Byte eines HMAC
// mit dem Schlüssel selbst. Es verrät nichts über den Schlüssel, zeigt aber,
// mit welchem Schlüssel ein Geheimtext entstand (Schlüsselwechsel).
func KeyID(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("openwacht schluessel-kennzeichen v1"))
	return m.Sum(nil)[:KeyIDSize]
}

// Seal verschlüsselt plaintext mit AES-256-GCM. aad bindet den Geheimtext an
// einen Kontext (z. B. die Benutzer-ID): Ein in der Datenbank zu einem anderen
// Benutzer kopierter Geheimtext lässt sich dort nicht entschlüsseln.
// Format (Version 2): Version (1 Byte) | Kennzeichen (8 Byte) | Nonce (12 Byte) | Geheimtext+Tag.
// Version und Kennzeichen sind mit authentifiziert.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	head := 1 + KeyIDSize
	out := make([]byte, head+gcm.NonceSize(), head+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	out[0] = boxV2
	copy(out[1:head], KeyID(key))
	if _, err := rand.Read(out[head:]); err != nil {
		return nil, err
	}
	return gcm.Seal(out, out[head:head+gcm.NonceSize()], plaintext, v2AAD(out[:head], aad)), nil
}

func v2AAD(head, aad []byte) []byte {
	return append(append(make([]byte, 0, len(head)+len(aad)), head...), aad...)
}

// Open entschlüsselt einen mit Seal erzeugten Geheimtext (Version 1 oder 2).
func Open(key, box, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(box) < 1 {
		return nil, ErrDecrypt
	}
	switch box[0] {
	case boxV1:
		if len(box) < 1+n+gcm.Overhead() {
			return nil, ErrDecrypt
		}
		pt, err := gcm.Open(nil, box[1:1+n], box[1+n:], aad)
		if err != nil {
			return nil, ErrDecrypt
		}
		return pt, nil
	case boxV2:
		head := 1 + KeyIDSize
		if len(box) < head+n+gcm.Overhead() {
			return nil, ErrDecrypt
		}
		if !hmac.Equal(box[1:head], KeyID(key)) {
			return nil, ErrWrongKey
		}
		pt, err := gcm.Open(nil, box[head:head+n], box[head+n:], v2AAD(box[:head], aad))
		if err != nil {
			return nil, ErrDecrypt
		}
		return pt, nil
	}
	return nil, ErrDecrypt
}

// BoxKeyID liefert Version und Kennzeichen eines Geheimtexts (Version 1:
// Kennzeichen nil). Nur zur Anzeige und für den Schlüsselwechsel.
func BoxKeyID(box []byte) (int, []byte) {
	if len(box) == 0 {
		return 0, nil
	}
	if box[0] == boxV2 && len(box) > KeyIDSize {
		return boxV2, box[1 : 1+KeyIDSize]
	}
	return int(box[0]), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("Schlüssel muss %d Bytes lang sein", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// GenerateKeyText erzeugt einen neuen Schlüssel als Base64-Text für die Schlüsseldatei.
func GenerateKeyText() (string, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

// LoadKeyFile liest den Base64-kodierten Schlüssel. Unter Unix wird
// abgelehnt, wenn die Datei für Gruppe oder andere lesbar ist.
func LoadKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Schlüsseldatei %s ist für andere lesbar (Rechte %o); erwartet 0600 oder 0400", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != KeySize {
		return nil, fmt.Errorf("Schlüsseldatei %s enthält keinen gültigen %d-Byte-Schlüssel (Base64)", path, KeySize)
	}
	return k, nil
}
