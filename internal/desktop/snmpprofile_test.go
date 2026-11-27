package desktop

import (
	"testing"
	"time"
)

func TestSNMPProfil(t *testing.T) {
	s := func(x string) *string { return &x }
	if v := (SNMPProfil{Version: "3", V3Auth: s("sha256"), V3Priv: s("aes")}).VersionText(); v != "SNMPv3 (SHA-256, AES-128)" {
		t.Error(v)
	}
	if v := (SNMPProfil{Version: "2c"}).VersionText(); v != "SNMP v2c" {
		t.Error(v)
	}
	in := SNMPProfilAusWerten(map[string]string{"name": " S ", "version": "3", "benutzer": "mon", "auth": "sha", "priv": "aes"})
	if in.Name != "S" || in.V3 != nil {
		t.Errorf("ohne Passwort kein neuer Zugang: %+v", in)
	}
	in = SNMPProfilAusWerten(map[string]string{"version": "3", "benutzer": " mon ", "auth": "sha", "auth_passwort": "geheim123", "priv": "aes", "priv_passwort": "geheim456"})
	if in.V3 == nil || in.V3.Benutzer != "mon" || in.Community != "" {
		t.Errorf("v3: %+v", in)
	}
	in = SNMPProfilAusWerten(map[string]string{"version": "2c", "community": "public", "auth_passwort": "x"})
	if in.V3 != nil || in.Community != "public" {
		t.Errorf("v2c: %+v", in)
	}
	j := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	for d, w := range map[time.Duration]string{30 * time.Second: "gerade eben", 5 * time.Minute: "vor 5 Min.", 3 * time.Hour: "vor 3 Std.", 96 * time.Hour: "vor 4 Tagen"} {
		if g := Vor(j.Add(-d), j); g != w {
			t.Errorf("Vor(%v) = %q", d, g)
		}
	}
}
