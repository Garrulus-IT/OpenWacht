// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"strings"
	"testing"
)

func TestDefaultName(t *testing.T) {
	for _, c := range []struct {
		kind string
		spec Spec
		want string
	}{
		{"ping", Spec{Host: "x"}, "Ping"},
		{"tcp", Spec{Port: 53}, "TCP 53"},
		{"http", Spec{URL: "https://nas.lan/"}, "HTTP 443"},
		{"http", Spec{URL: "http://nas.lan/"}, "HTTP 80"},
		{"http", Spec{URL: "https://nas.lan:5001/x"}, "HTTP 5001"},
		{"tls", Spec{Host: "nas.lan"}, "Zertifikat nas.lan"},
		{"dns", Spec{Name: "heise.de"}, "DNS heise.de"},
		{"http_json", Spec{JSONPath: "status.ok"}, "JSON status.ok"},
		{"tcp_banner", Spec{Port: 25}, "Banner 25"},
		{"ntp", Spec{}, "NTP"},
		{"snmp_oid", Spec{OID: "1.3.6.1.2.1.1.3.0"}, "OID 1.3.6.1.2.1.1.3.0"},
		{"dienst", Spec{Name: "sshd"}, "Dienst sshd"},
		{"prozess", Spec{Name: "nginx"}, "Prozess nginx"},
		{"datei", Spec{Path: "/var/backup/db.dump"}, "Datei db.dump"},
		{"datei", Spec{Path: `D:\Backup\`, Folder: true}, "Ordner Backup"},
		{"docker", Spec{Name: "web"}, "Container web"},
		{"hyperv", Spec{Name: "dc01"}, "Hyper-V-VM dc01"},
	} {
		if got := DefaultName(c.kind, c.spec); got != c.want {
			t.Errorf("%s: %q, erwartet %q", c.kind, got, c.want)
		}
	}
	long := DefaultName("dns", Spec{Name: strings.Repeat("a", 250)})
	if n := len([]rune(long)); n != MaxName {
		t.Errorf("lang: %d Zeichen", n)
	}
	if n := NumberedName(long, 12); len([]rune(n)) != MaxName || !strings.HasSuffix(n, " 12") {
		t.Errorf("Nummer: %q", n)
	}
	if NumberedName("Ping", 1) != "Ping" || NumberedName("Ping", 2) != "Ping 2" {
		t.Error("Nummern")
	}
}
