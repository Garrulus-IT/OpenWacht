// SPDX-License-Identifier: AGPL-3.0-only

package update

// Update der Zentrale aus der Oberfläche (1.0.4). Hochgeladen werden das
// Debian-Paket und, aus demselben Build, SHA256SUMS mit SHA256SUMS.sig.
// Geprüft wird zweimal mit derselben Funktion: von der Zentrale beim
// Hochladen und vom getrennten Installationsdienst (root) vor der
// Installation. Der Installationsdienst vertraut dabei nur den Schlüsseln,
// die in seinem eigenen, von root installierten Programm stecken.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ZentraleDatei: erlaubter Name des Pakets.
var ZentraleDatei = regexp.MustCompile(`^openwacht-zentrale_((?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4}))_(amd64|arm64)\.deb$`)

// MaxZentralePaket: größtes Paket (heute rund 30 MB).
const MaxZentralePaket = 256 << 20

// ZentralePaket: geprüftes Paket.
type ZentralePaket struct {
	Datei   string `json:"datei"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
}

var (
	// ErrNichtNeuer: gleiche oder ältere Version (keine Rückstufung über die Oberfläche).
	ErrNichtNeuer = errors.New("Das Paket ist nicht neuer als die installierte Version.")
	// ErrPruefsumme: Paket passt nicht zu SHA256SUMS.
	ErrPruefsumme = errors.New("Die Prüfsumme des Pakets steht nicht in SHA256SUMS.")
)

// PruefeZentrale prüft Name, Plattform, Version, die Signatur von SHA256SUMS
// und dass die Prüfsumme sum (hex, des hochgeladenen Pakets) dort für genau
// diesen Dateinamen steht.
func (k *Keyring) PruefeZentrale(sums, sig []byte, datei, sum, aktuell, arch string) (ZentralePaket, error) {
	var p ZentralePaket
	m := ZentraleDatei.FindStringSubmatch(datei)
	if m == nil {
		return p, errors.New("Dateiname: erwartet openwacht-zentrale_<version>_<amd64|arm64>.deb.")
	}
	p = ZentralePaket{Datei: datei, Version: m[1], Arch: m[2], SHA256: strings.ToLower(sum)}
	if p.Arch != arch {
		return p, fmt.Errorf("Das Paket ist für %s, die Zentrale läuft auf %s.", p.Arch, arch)
	}
	if !Newer(p.Version, aktuell) {
		return p, ErrNichtNeuer
	}
	s, err := ParseSumsSig(sig)
	if err != nil {
		return p, err
	}
	if err := k.VerifySums(sums, s); err != nil {
		return p, fmt.Errorf("Signatur von SHA256SUMS: %w", err)
	}
	if !sumsHas(sums, p.SHA256, datei) {
		return p, ErrPruefsumme
	}
	return p, nil
}

// sumsHas: steht „<sum>  <datei>“ (oder „<sum> *<datei>“) in SHA256SUMS?
func sumsHas(sums []byte, sum, datei string) bool {
	if len(sum) != 64 {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		h, name, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		name = strings.TrimPrefix(strings.TrimPrefix(name, " "), "*")
		if name == datei && strings.EqualFold(h, sum) {
			return true
		}
	}
	return false
}
