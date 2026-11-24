// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"strings"
	"testing"
)

func TestParseGueltig(t *testing.T) {
	s, err := Parse("tls", []byte(`{"host":"dms.beispiel.example","verbinde":"192.168.1.10"}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != 443 || s.WarnDays != 21 || s.CritDays != 7 || s.TimeoutSec != 10 {
		t.Errorf("Standardwerte: %+v", s)
	}
	for kind, raw := range map[string]string{
		"ping": `{"host":"172.16.0.1"}`,
		"tcp":  `{"host":"pve-1.example.org","port":8006,"timeout_s":3}`,
		"http": `{"url":"http://172.16.0.32:8000/","erwarte_status":[200,302],"enthaelt":"\"healthy\":true"}`,
		"tls":  `{"host":"n200.taila7a27d.ts.net","warnung_tage":0.5,"kritisch_tage":0.25}`,
	} {
		if _, err := Parse(kind, []byte(raw)); err != nil {
			t.Errorf("%s %s: %v", kind, raw, err)
		}
	}
	if a := (&Spec{URL: "https://[2001:db8::1]:8443/x"}).LiteralAddrs(); len(a) != 1 || a[0].String() != "2001:db8::1" {
		t.Errorf("LiteralAddrs: %v", a)
	}
}

func TestParseUngueltig(t *testing.T) {
	for _, tc := range []struct{ kind, raw, want string }{
		{"smtp", `{"host":"x"}`, "unbekannter Typ"},
		{"ping", `{"host":"x","unbekannt":1}`, "unknown field"},
		{"ping", `{"host":"x","port":22}`, "passt nicht zum Typ"},
		{"ping", `{"host":"http://nas"}`, "Host"},
		{"ping", `{"host":"nas;rm -rf /"}`, "Host"},
		{"ping", `{"host":"fe80::1%eth0"}`, "Host"},
		{"tcp", `{"host":"nas"}`, "Port"},
		{"tcp", `{"host":"nas","port":70000}`, "Port"},
		{"tcp", `{"host":"nas","port":22,"timeout_s":300}`, "Zeitlimit"},
		{"http", `{"url":"ftp://nas/"}`, "http://"},
		{"http", `{"url":"file:///etc/passwd"}`, "http://"},
		{"http", `{"url":"https://admin:geheim@nas/"}`, "Zugangsdaten"},
		{"http", `{"url":"https://nas/","erwarte_status":[99]}`, "Status"},
		{"http", `{"url":"https://nas/","enthaelt":"a\nb"}`, "Steuerzeichen"},
		{"http", `{"url":"https://nas/","ca_pem":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}`, "keine Schlüssel"},
		{"http", `{"url":"https://nas/","ca_pem":"kein pem"}`, "PEM"},
		{"tls", `{"host":"nas","warnung_tage":5,"kritisch_tage":7}`, "kritisch kleiner"},
		{"tls", `{"host":"nas","verbinde":"a b"}`, "Verbinden"},
		{"tcp", `{"host":"nas","port":22}{"x":1}`, "mehr als ein"},
		{"tcp", `[1,2]`, "kein gültiges JSON"},
	} {
		_, err := Parse(tc.kind, []byte(tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: %v (erwartet %q)", tc.kind, tc.raw, err, tc.want)
		}
	}
}
