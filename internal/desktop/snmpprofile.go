// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Seite SNMP-Profile wie web/src/SnmpProfile.tsx: Community oder v3-Zugang
// je Mandant, an vielen Geräten verwendbar. Die Zugangsdaten zeigt die
// Zentrale nie wieder an; wer sie ändert, gibt sie vollständig neu ein.
// Sehen und pflegen dürfen nur Admins.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SNMPProfil aus GET /api/v1/snmp-profile.
type SNMPProfil struct {
	ID        string    `json:"id"`
	MandantID string    `json:"mandant_id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"` // 1, 2c, 3
	V3Auth    *string   `json:"v3_auth"`
	V3Priv    *string   `json:"v3_priv"`
	Geraete   int       `json:"geraete"`
	Erstellt  time.Time `json:"erstellt"`
	Geaendert time.Time `json:"geaendert"`
}

// SNMP-Verfahren wie authText/privText im Web (Reihenfolge der Auswahl).
var (
	SNMPAuth = [][2]string{{"sha", "SHA-1"}, {"sha224", "SHA-224"}, {"sha256", "SHA-256"}, {"sha384", "SHA-384"}, {"sha512", "SHA-512"}}
	SNMPPriv = [][2]string{{"aes", "AES-128"}, {"aes192", "AES-192"}, {"aes256", "AES-256"},
		{"aes192c", "AES-192 (Cisco/Reeder)"}, {"aes256c", "AES-256 (Cisco/Reeder)"}}
)

func snmpText(l [][2]string, k *string) string {
	if k == nil {
		return ""
	}
	for _, x := range l {
		if x[0] == *k {
			return x[1]
		}
	}
	return *k
}

// VersionText wie profilVersion() im Web.
func (p SNMPProfil) VersionText() string {
	if p.Version == "3" {
		return "SNMPv3 (" + snmpText(SNMPAuth, p.V3Auth) + ", " + snmpText(SNMPPriv, p.V3Priv) + ")"
	}
	return "SNMP v" + p.Version
}

// SNMPProfilEingabe: Rumpf für Anlegen und Ändern.
type SNMPProfilEingabe struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Community string  `json:"community"`
	V3        *SNMPV3 `json:"v3"`
}

// SNMPV3: Zugang für v3 (nur authPriv).
type SNMPV3 struct {
	Benutzer     string `json:"benutzer"`
	Auth         string `json:"auth"`
	AuthPasswort string `json:"auth_passwort"`
	Priv         string `json:"priv"`
	PrivPasswort string `json:"priv_passwort"`
}

// SNMPProfilAusWerten baut den Rumpf wie senden() im Web: v3-Zugang nur, wenn
// ein Passwort eingegeben ist (sonst bleibt er unverändert).
func SNMPProfilAusWerten(w map[string]string) SNMPProfilEingabe {
	in := SNMPProfilEingabe{Name: strings.TrimSpace(w["name"]), Version: w["version"]}
	if in.Version != "3" {
		in.Community = w["community"]
		return in
	}
	if w["auth_passwort"] != "" || w["priv_passwort"] != "" {
		in.V3 = &SNMPV3{Benutzer: strings.TrimSpace(w["benutzer"]), Auth: w["auth"], AuthPasswort: w["auth_passwort"],
			Priv: w["priv"], PrivPasswort: w["priv_passwort"]}
	}
	return in
}

// SNMPProfile: alle Profile, die das Konto sehen darf.
func (c Client) SNMPProfile(ctx context.Context) ([]SNMPProfil, error) {
	var out struct {
		Profile []SNMPProfil `json:"profile"`
	}
	err := c.get(ctx, "/api/v1/snmp-profile", &out)
	return out.Profile, err
}

// SNMPProfilAnlegen legt ein Profil im Mandanten an.
func (c Client) SNMPProfilAnlegen(ctx context.Context, mandant string, in SNMPProfilEingabe) error {
	return c.send(ctx, http.MethodPost, "/api/v1/mandanten/"+p(mandant)+"/snmp-profile", in, nil)
}

// SNMPProfilAendern ändert ein Profil; liefert, wie viele Geräte neu verschlüsselt wurden.
func (c Client) SNMPProfilAendern(ctx context.Context, id string, in SNMPProfilEingabe) (int, error) {
	var out struct {
		Neu int `json:"neu_verschluesselt"`
	}
	err := c.send(ctx, http.MethodPut, "/api/v1/snmp-profile/"+p(id), in, &out)
	return out.Neu, err
}

// SNMPProfilLoeschen löscht ein Profil; die Geräte behalten ihre Zugangsdaten.
func (c Client) SNMPProfilLoeschen(ctx context.Context, id string) error {
	return c.send(ctx, http.MethodDelete, "/api/v1/snmp-profile/"+p(id), nil, nil)
}

// Vor: „gerade eben“, „vor 5 Min.“, „vor 3 Std.“, „vor 4 Tagen“ wie vor() im Web.
func Vor(t, jetzt time.Time) string {
	s := int(jetzt.Sub(t).Round(time.Second).Seconds())
	if s < 60 {
		return "gerade eben"
	}
	m := (s + 30) / 60
	if m < 60 {
		return "vor " + itoa(m) + " Min."
	}
	h := (m + 30) / 60
	if h < 48 {
		return "vor " + itoa(h) + " Std."
	}
	return "vor " + itoa((h+12)/24) + " Tagen"
}

func itoa(i int) string { return strconv.Itoa(i) }
