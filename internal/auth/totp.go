// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP nach RFC 6238 mit den Werten, die alle gängigen Authenticator-Apps
// unterstützen: HMAC-SHA1, 6 Stellen, 30 Sekunden.
const (
	TOTPPeriod     = 30
	TOTPDigits     = 6
	totpSecretSize = 20 // 160 Bit, wie in RFC 4226 empfohlen
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret erzeugt ein neues zufälliges Geheimnis.
func GenerateTOTPSecret() ([]byte, error) {
	s := make([]byte, totpSecretSize)
	_, err := rand.Read(s)
	return s, err
}

// TOTPSecretText ist das Geheimnis in Base32 zur manuellen Eingabe in die App.
func TOTPSecretText(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPStep ist der Zeitschritt zu t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCode berechnet den Code für einen Zeitschritt (RFC 4226, dynamische Kürzung).
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, v%1_000_000)
}

// VerifyTOTP prüft code für den aktuellen Zeitschritt und je einen Schritt
// davor und danach (Uhrabweichung). Schritte bis einschließlich lastStep sind
// verbraucht und werden nicht akzeptiert. Liefert den passenden Schritt.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := TOTPStep(now)
	var found int64
	ok := false
	// Alle Kandidaten prüfen, damit die Laufzeit nicht verrät, welcher passte.
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		match := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code)) == 1
		if match && step > lastStep && !ok {
			found, ok = step, true
		}
	}
	return found, ok
}

// TOTPURI liefert die otpauth-URI für den QR-Code der Authenticator-App.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", TOTPSecretText(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
