// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// SNMPv3-Zugangsdaten (User-based Security Model, RFC 3414) für Abfragen und
// Traps. Nur authPriv: Authentifizierung mit SHA-1 oder SHA-2 (RFC 7860),
// Verschlüsselung mit AES (RFC 3826; 192/256 Bit nach Blumenthal oder nach
// Reeder/Cisco). MD5, DES und schwächere Stufen werden abgelehnt.

import (
	"errors"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// Verfahren, wie sie in der Datenbank und in der API stehen.
const (
	AuthSHA    = "sha"
	AuthSHA224 = "sha224"
	AuthSHA256 = "sha256"
	AuthSHA384 = "sha384"
	AuthSHA512 = "sha512"

	PrivAES    = "aes"
	PrivAES192 = "aes192"
	PrivAES256 = "aes256"
	// Variante nach Reeder (Cisco und manche Hersteller)
	PrivAES192C = "aes192c"
	PrivAES256C = "aes256c"
)

var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	AuthSHA: gosnmp.SHA, AuthSHA224: gosnmp.SHA224, AuthSHA256: gosnmp.SHA256,
	AuthSHA384: gosnmp.SHA384, AuthSHA512: gosnmp.SHA512,
}

var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	PrivAES: gosnmp.AES, PrivAES192: gosnmp.AES192, PrivAES256: gosnmp.AES256,
	PrivAES192C: gosnmp.AES192C, PrivAES256C: gosnmp.AES256C,
}

// Abgelehnte Verfahren, mit verständlicher Meldung.
var weakProtocols = map[string]string{
	"md5":  "MD5 ist nicht erlaubt (unsicher). Am Gerät SHA-1 oder SHA-2 einstellen oder bei v2c bleiben.",
	"des":  "DES ist nicht erlaubt (unsicher). Am Gerät AES einstellen oder bei v2c bleiben.",
	"3des": "3DES ist nicht erlaubt. Am Gerät AES einstellen oder bei v2c bleiben.",
	"none": "SNMPv3 nur mit Authentifizierung und Verschlüsselung (authPriv).",
	"":     "SNMPv3 nur mit Authentifizierung und Verschlüsselung (authPriv).",
}

// Grenzen. RFC 3414: Benutzername bis 32 Oktette, Passphrasen mindestens 8.
const (
	MaxV3User = 32
	MinV3Pass = 8
	MaxV3Pass = 128
)

// V3Auth sind die Zugangsdaten eines SNMPv3-Benutzers. Die Passphrasen verlassen
// die Zentrale nie und stehen in keinem Fehler und keinem Log.
type V3Auth struct {
	User     string `json:"benutzer"`
	Auth     string `json:"auth"`
	AuthPass string `json:"auth_passwort"`
	Priv     string `json:"priv"`
	PrivPass string `json:"priv_passwort"`
}

// NormalizeAuth und NormalizePriv nehmen auch die Schreibweisen der Geräte an
// („SHA-256“, „AES-128“, „AES256-C“).
func NormalizeAuth(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	switch s {
	case "sha1", "hmacsha", "hmacsha1":
		return AuthSHA
	}
	return s
}

func NormalizePriv(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	switch s {
	case "aes128", "aescfb", "aescfb128":
		return PrivAES
	}
	return s
}

// ValidAuth meldet, ob ein Verfahren erlaubt ist (normalisiert).
func ValidAuth(s string) bool { _, ok := authProtocols[s]; return ok }

// ValidPriv meldet, ob ein Verfahren erlaubt ist (normalisiert).
func ValidPriv(s string) bool { _, ok := privProtocols[s]; return ok }

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Validate prüft die Zugangsdaten. Die Meldungen nennen nie eine Passphrase.
func (v *V3Auth) Validate() error {
	if v == nil {
		return errors.New("SNMPv3: Zugangsdaten fehlen")
	}
	if v.User == "" || len(v.User) > MaxV3User || !printable(v.User) || strings.TrimSpace(v.User) != v.User {
		return errors.New("SNMPv3: Benutzername mit 1 bis 32 druckbaren ASCII-Zeichen, ohne Leerzeichen am Rand")
	}
	if msg, weak := weakProtocols[v.Auth]; weak {
		return errors.New(msg)
	}
	if !ValidAuth(v.Auth) {
		return errors.New("SNMPv3: Authentifizierung SHA-1, SHA-224, SHA-256, SHA-384 oder SHA-512")
	}
	if msg, weak := weakProtocols[v.Priv]; weak {
		return errors.New(msg)
	}
	if !ValidPriv(v.Priv) {
		return errors.New("SNMPv3: Verschlüsselung AES-128, AES-192 oder AES-256")
	}
	for _, p := range []struct{ name, val string }{{"Authentifizierungs-Passwort", v.AuthPass}, {"Verschlüsselungs-Passwort", v.PrivPass}} {
		if len(p.val) < MinV3Pass || len(p.val) > MaxV3Pass || !printable(p.val) {
			return errors.New("SNMPv3: " + p.name + " mit 8 bis 128 druckbaren ASCII-Zeichen")
		}
	}
	return nil
}

// USM liefert die Sicherheitsparameter für gosnmp (für Traps mit gesetzter
// Engine-ID des Absenders bzw. der eigenen bei Informs).
func (v *V3Auth) USM(engineID string) *gosnmp.UsmSecurityParameters {
	return &gosnmp.UsmSecurityParameters{
		UserName:                 v.User,
		AuthenticationProtocol:   authProtocols[v.Auth],
		AuthenticationPassphrase: v.AuthPass,
		PrivacyProtocol:          privProtocols[v.Priv],
		PrivacyPassphrase:        v.PrivPass,
		AuthoritativeEngineID:    engineID,
	}
}

func (v *V3Auth) usm() *gosnmp.UsmSecurityParameters { return v.USM("") }

// AuthText und PrivText für die Anzeige („SHA-256“, „AES-128“).
func AuthText(s string) string {
	switch s {
	case AuthSHA:
		return "SHA-1"
	case AuthSHA224, AuthSHA256, AuthSHA384, AuthSHA512:
		return "SHA-" + s[3:]
	}
	return s
}

func PrivText(s string) string {
	switch s {
	case PrivAES:
		return "AES-128"
	case PrivAES192, PrivAES256:
		return "AES-" + s[3:]
	case PrivAES192C, PrivAES256C:
		return "AES-" + s[3:6] + " (Reeder/Cisco)"
	}
	return s
}
