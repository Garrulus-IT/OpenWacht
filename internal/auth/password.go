// SPDX-License-Identifier: AGPL-3.0-only

// Package auth enthält die kryptografischen Bausteine der Anmeldung:
// Passwort-Hashes (Argon2id), Einmalcodes (TOTP) und die Verschlüsselung von
// Geheimnissen in der Datenbank (AES-256-GCM).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Params sind die Argon2id-Kosten. Memory in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultParams folgt der zweiten Empfehlung aus RFC 9106 (64 MiB, t=3, p=4).
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Threads: 4, KeyLen: 32, SaltLen: 16}

const (
	MinPasswordRunes = 12
	// Obergrenze in Bytes, damit niemand mit riesigen Passwörtern Rechenzeit erzwingt.
	MaxPasswordBytes = 256
)

var (
	ErrPasswordTooShort = fmt.Errorf("Das Passwort muss mindestens %d Zeichen lang sein.", MinPasswordRunes)
	ErrPasswordTooLong  = fmt.Errorf("Das Passwort darf höchstens %d Bytes lang sein.", MaxPasswordBytes)
	ErrPasswordInvalid  = errors.New("Das Passwort enthält ungültige Zeichen.")
	ErrPasswordIsEmail  = errors.New("Das Passwort darf nicht die E-Mail-Adresse sein.")
	ErrHashFormat       = errors.New("ungültiges Passwort-Hash-Format")
)

// CheckPasswordInput prüft nur die Länge, ohne Regeln für neue Passwörter.
// Für die Anmeldung: verhindert teure Hashes über riesige Eingaben.
func CheckPasswordInput(pw string) error {
	if len(pw) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	if !utf8.ValidString(pw) {
		return ErrPasswordInvalid
	}
	return nil
}

// ValidateNewPassword prüft ein neu gewähltes Passwort.
func ValidateNewPassword(pw, email string) error {
	if err := CheckPasswordInput(pw); err != nil {
		return err
	}
	if utf8.RuneCountInString(pw) < MinPasswordRunes {
		return ErrPasswordTooShort
	}
	if strings.EqualFold(strings.TrimSpace(pw), strings.TrimSpace(email)) {
		return ErrPasswordIsEmail
	}
	return nil
}

// HashPassword erzeugt einen Argon2id-Hash im PHC-Format:
// $argon2id$v=19$m=65536,t=3,p=4$<Salt>$<Hash>
func HashPassword(pw string, p Params) (string, error) {
	if err := CheckPasswordInput(pw); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// Grenzen beim Einlesen: Ein manipulierter Hash in der Datenbank darf die
// Zentrale nicht mit absurden Kosten lahmlegen.
const (
	maxMemory  = 1024 * 1024 // 1 GiB
	maxTime    = 10
	maxThreads = 16
)

func parseHash(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrHashFormat
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrHashFormat
	}
	var p Params
	var m, t, th uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return Params{}, nil, nil, ErrHashFormat
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Params{}, nil, nil, ErrHashFormat
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			th = n
		default:
			return Params{}, nil, nil, ErrHashFormat
		}
	}
	if m < 8 || m > maxMemory || t < 1 || t > maxTime || th < 1 || th > maxThreads {
		return Params{}, nil, nil, ErrHashFormat
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Params{}, nil, nil, ErrHashFormat
	}
	key, err := enc.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return Params{}, nil, nil, ErrHashFormat
	}
	p = Params{Memory: uint32(m), Time: uint32(t), Threads: uint8(th), KeyLen: uint32(len(key)), SaltLen: uint32(len(salt))}
	return p, salt, key, nil
}

// VerifyPassword prüft pw gegen encoded in konstanter Zeit. needsRehash ist
// true, wenn der Hash mit schwächeren Kosten als want erzeugt wurde.
func VerifyPassword(pw, encoded string, want Params) (ok, needsRehash bool, err error) {
	if err := CheckPasswordInput(pw); err != nil {
		return false, false, err
	}
	p, salt, key, err := parseHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	weaker := p.Memory < want.Memory || p.Time < want.Time || p.Threads < want.Threads || p.KeyLen < want.KeyLen
	return true, weaker, nil
}
