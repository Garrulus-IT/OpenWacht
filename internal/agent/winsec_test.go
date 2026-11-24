// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"strings"
	"testing"
)

func TestServiceSID(t *testing.T) {
	// Bekannter Wert aus jedem Windows: NT SERVICE\TrustedInstaller.
	if got := ServiceSID("TrustedInstaller"); got != sidTrustedInstaller {
		t.Fatalf("ServiceSID(TrustedInstaller) = %s", got)
	}
	if ServiceSID("openwacht-agent") != ServiceSID("OPENWACHT-AGENT") {
		t.Fatal("Dienstnamen sind unter Windows unabhängig von Groß- und Kleinschreibung")
	}
	if ServiceSID("openwacht-agent") == ServiceSID("openwacht-agent2") {
		t.Fatal("verschiedene Namen, gleiche SID")
	}
}

// Rechte, wie sie ein frisch installiertes Windows hat (vereinfacht).
const (
	sidUsers     = "S-1-5-32-545"
	sidAuthUsers = "S-1-5-11"
	sidEveryone  = "S-1-1-0"
	sidCreator   = "S-1-3-0"
	sidAppPkgs   = "S-1-15-2-1"
	sidErika     = "S-1-5-21-1-2-3-1001"

	maskFull   = 0x1f01ff
	maskModify = 0x1301bf
	maskRX     = 0x1200a9
	oici       = 0x3
	oiciio     = 0xb
)

func driveRoot() Object {
	return Object{Path: `C:\`, Owner: sidTrustedInstaller, ACEs: []ACE{
		{SID: sidAdministrators, Allow: true, Mask: maskFull, Flags: oici},
		{SID: sidSystem, Allow: true, Mask: maskFull, Flags: oici},
		{SID: sidUsers, Allow: true, Mask: maskRX, Flags: oici},
		{SID: sidAuthUsers, Allow: true, Mask: fileAppendData},            // „Ordner erstellen“, nur dieser Ordner
		{SID: sidAuthUsers, Allow: true, Mask: maskModify, Flags: oiciio}, // gilt nur für Neues darunter
		{SID: sidCreator, Allow: true, Mask: genericAll, Flags: oiciio},
	}}
}

func programFiles() Object {
	return Object{Path: `C:\Program Files`, Owner: sidTrustedInstaller, ACEs: []ACE{
		{SID: sidTrustedInstaller, Allow: true, Mask: maskFull},
		{SID: sidSystem, Allow: true, Mask: maskModify},
		{SID: sidAdministrators, Allow: true, Mask: maskModify},
		{SID: sidUsers, Allow: true, Mask: maskRX, Flags: oici},
		{SID: sidCreator, Allow: true, Mask: genericAll, Flags: oiciio},
		{SID: sidAppPkgs, Allow: true, Mask: maskRX, Flags: oici},
	}}
}

func goodChain() []Object {
	return []Object{
		{Path: `C:\Program Files\OpenWacht\openwacht-agent.exe`, Owner: sidAdministrators, ACEs: []ACE{
			{SID: sidSystem, Allow: true, Mask: maskFull},
			{SID: sidAdministrators, Allow: true, Mask: maskFull},
			{SID: sidUsers, Allow: true, Mask: maskRX},
			{SID: sidAppPkgs, Allow: true, Mask: maskRX},
		}},
		{Path: `C:\Program Files\OpenWacht`, Owner: sidAdministrators, ACEs: []ACE{
			{SID: sidSystem, Allow: true, Mask: maskFull, Flags: oici},
			{SID: sidAdministrators, Allow: true, Mask: maskFull, Flags: oici},
			{SID: sidUsers, Allow: true, Mask: maskRX, Flags: oici},
			{SID: sidCreator, Allow: true, Mask: genericAll, Flags: oiciio},
		}},
		programFiles(),
		driveRoot(),
	}
}

func TestCheckBinaryACLs(t *testing.T) {
	if err := CheckBinaryACLs(goodChain()); err != nil {
		t.Fatalf("Standardinstallation unter Program Files abgelehnt: %v", err)
	}

	cases := []struct {
		name   string
		change func(c []Object) []Object
		want   string // Teil der Fehlermeldung
	}{
		{"Binary gehört einem Benutzer", func(c []Object) []Object {
			c[0].Owner, c[0].OwnerName = sidErika, `PC\erika`
			return c
		}, `PC\erika`},
		{"Verzeichnis darüber gehört einem Benutzer", func(c []Object) []Object {
			c[2].Owner = sidErika
			return c
		}, `C:\Program Files gehört`},
		{"Binary für Benutzer beschreibbar", func(c []Object) []Object {
			c[0].ACEs = append(c[0].ACEs, ACE{SID: sidUsers, Allow: true, Mask: maskModify})
			return c
		}, "openwacht-agent.exe ist für"},
		{"Jeder hat Vollzugriff auf das Binary", func(c []Object) []Object {
			c[0].ACEs = append(c[0].ACEs, ACE{SID: sidEveryone, Allow: true, Mask: genericAll})
			return c
		}, sidEveryone},
		{"nur Rechte ändern dürfen reicht", func(c []Object) []Object {
			c[0].ACEs = append(c[0].ACEs, ACE{SID: sidAuthUsers, Allow: true, Mask: writeDAC})
			return c
		}, "beschreibbar"},
		{"Dateien neben das Binary legen (wie in ProgramData)", func(c []Object) []Object {
			c[1].ACEs = append(c[1].ACEs, ACE{SID: sidUsers, Allow: true, Mask: fileWriteData | fileAppendData, Flags: 0x2})
			return c
		}, `Files\OpenWacht ist für`},
		{"Verzeichnis darüber umbenennbar", func(c []Object) []Object {
			c[2].ACEs = append(c[2].ACEs, ACE{SID: sidUsers, Allow: true, Mask: maskModify, Flags: oici})
			return c
		}, `C:\Program Files ist für`},
		{"Einträge im Verzeichnis darüber löschbar", func(c []Object) []Object {
			c[3].ACEs = append(c[3].ACEs, ACE{SID: sidAuthUsers, Allow: true, Mask: fileDeleteChild})
			return c
		}, `C:\ ist für`},
		{"keine Rechteliste", func(c []Object) []Object {
			c[1].NullDACL = true
			return c
		}, "keine Rechteliste"},
		{"zu kurzer Pfad", func(c []Object) []Object { return c[:1] }, "unvollständig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckBinaryACLs(tc.change(goodChain()))
			if err == nil {
				t.Fatal("nicht abgelehnt")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Meldung %q enthält %q nicht", err, tc.want)
			}
		})
	}

	// Was nicht schaden kann, darf nicht zur Ablehnung führen.
	harmless := []struct {
		name   string
		change func(c []Object) []Object
	}{
		{"Verweigern-Eintrag", func(c []Object) []Object {
			c[0].ACEs = append(c[0].ACEs, ACE{SID: sidEveryone, Allow: false, Mask: genericAll})
			return c
		}},
		{"nur für Neues geltender Eintrag am Binary-Verzeichnis", func(c []Object) []Object {
			c[1].ACEs = append(c[1].ACEs, ACE{SID: sidUsers, Allow: true, Mask: maskModify, Flags: oiciio})
			return c
		}},
		{"Benutzer dürfen im Verzeichnis darüber anlegen", func(c []Object) []Object {
			c[2].ACEs = append(c[2].ACEs, ACE{SID: sidUsers, Allow: true, Mask: fileWriteData | fileAppendData | genericWrite})
			return c
		}},
		{"Eigentümer SYSTEM", func(c []Object) []Object {
			c[0].Owner = sidSystem
			return c
		}},
	}
	for _, tc := range harmless {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckBinaryACLs(tc.change(goodChain())); err != nil {
				t.Fatalf("zu Unrecht abgelehnt: %v", err)
			}
		})
	}
}

func TestDirSDDL(t *testing.T) {
	svc := ServiceSID(ServiceName)
	got := DirSDDL(svc, "")
	if !strings.HasPrefix(got, "O:BAD:P(") {
		t.Fatalf("Eigentümer Administratoren und geschützte Liste erwartet: %s", got)
	}
	for _, want := range []string{"(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)", "(A;OICI;FA;;;" + svc + ")"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%s fehlt in %s", want, got)
		}
	}
	if strings.Count(got, "(A;") != 3 {
		t.Fatalf("genau drei Einträge erwartet: %s", got)
	}
	user := DirSDDL(svc, sidErika)
	if !strings.HasPrefix(user, "O:"+sidErika+"D:P(") || !strings.Contains(user, "(A;OICI;FA;;;"+sidErika+")") {
		t.Fatalf("ohne Administratorrechte gehört das Verzeichnis dem Benutzer: %s", user)
	}
}

func TestWindowsOSName(t *testing.T) {
	for _, tc := range []struct {
		product, dv string
		build       uint32
		want        string
	}{
		{"Windows 10 Pro", "24H2", 26100, "Windows 11 Pro 24H2"},
		{"Windows 10 Pro", "21H2", 22000, "Windows 11 Pro 21H2"}, // erste Windows-11-Version
		{"Windows 10 Pro", "22H2", 19045, "Windows 10 Pro 22H2"},
		{"Windows 10 Enterprise LTSC 2021", "", 19044, "Windows 10 Enterprise LTSC 2021"},
		{"Windows Server 2025 Datacenter", "24H2", 26100, "Windows Server 2025 Datacenter 24H2"},
		{"Windows Server 2016 Standard", "", 14393, "Windows Server 2016 Standard"},
		{"", "", 0, "Windows"},
	} {
		if got := WindowsOSName(tc.product, tc.dv, tc.build); got != tc.want {
			t.Errorf("WindowsOSName(%q, %q, %d) = %q, erwartet %q", tc.product, tc.dv, tc.build, got, tc.want)
		}
	}
}
