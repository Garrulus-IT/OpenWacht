// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Regeln für Windows, ohne Windows-Aufrufe. So lassen sie sich auf jedem
// System testen; install_windows.go liest nur die echten Daten aus.

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// ServiceName ist der Name des Windows-Dienstes. Daraus folgt das virtuelle
// Dienstkonto NT SERVICE\openwacht-agent.
const ServiceName = "openwacht-agent"

// Bekannte SIDs.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	sidOwnerRights      = "S-1-3-4"
)

// ServiceSID berechnet die SID des virtuellen Dienstkontos NT SERVICE\<name>:
// SHA-1 über den Namen in Großbuchstaben (UTF-16LE), in fünf Teile zerlegt.
// Weil sie feststeht, kann das Verzeichnis die richtigen Rechte bekommen,
// bevor der Dienst existiert.
func ServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h := sha1.Sum(b)
	var sb strings.Builder
	sb.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(h[4*i:]))
	}
	return sb.String()
}

// Zugriffsrechte (winnt.h). Bei Verzeichnissen haben dieselben Bits eine
// andere Bedeutung: 0x2 = Datei anlegen, 0x4 = Unterordner anlegen.
const (
	fileWriteData   = 0x2
	fileAppendData  = 0x4
	fileDeleteChild = 0x40
	accessDelete    = 0x10000
	writeDAC        = 0x40000
	writeOwner      = 0x80000
	genericAll      = 0x10000000
	genericWrite    = 0x40000000

	aceInheritOnly = 0x8
)

// Was ein nicht vertrauenswürdiges Konto auf keinen Fall dürfen darf:
var (
	// am Binary selbst: es verändern, ersetzen oder die Rechte ändern
	forbiddenOnBinary uint32 = fileWriteData | fileAppendData | accessDelete | writeDAC | writeOwner | genericAll | genericWrite
	// im Verzeichnis des Binarys zusätzlich: Dateien daneben legen (DLL-Planting)
	forbiddenOnBinaryDir uint32 = fileWriteData | fileAppendData | fileDeleteChild | accessDelete | writeDAC | writeOwner | genericAll | genericWrite
	// in Verzeichnissen darüber: Einträge löschen, umbenennen oder Rechte
	// ändern. Neue Einträge anlegen ist harmlos (C:\ erlaubt das allen
	// angemeldeten Benutzern), damit lässt sich kein bestehender Pfad ersetzen.
	forbiddenOnParent uint32 = fileDeleteChild | accessDelete | writeDAC | writeOwner | genericAll
)

// ACE ist ein Eintrag einer Rechteliste, so wie install_windows.go ihn liest.
type ACE struct {
	SID   string
	Name  string // nur für die Fehlermeldung
	Allow bool   // false = Verweigern
	Mask  uint32
	Flags uint8
}

// Object ist eine Datei oder ein Verzeichnis mit Eigentümer und Rechteliste.
type Object struct {
	Path      string
	Owner     string
	OwnerName string
	NullDACL  bool // keine Rechteliste: jeder darf alles
	ACEs      []ACE
}

func trustedSID(s string) bool {
	switch s {
	case sidSystem, sidAdministrators, sidTrustedInstaller, sidOwnerRights:
		return true
	}
	return false
}

func display(sid, name string) string {
	if name != "" {
		return fmt.Sprintf("%s (%s)", name, sid)
	}
	return sid
}

// CheckBinaryACLs prüft das Binary (chain[0]) und alle Verzeichnisse darüber
// (chain[1] = sein Verzeichnis, chain[len-1] = Laufwerkswurzel). Der Dienst
// läuft mit eigenem Konto beim Systemstart: Wer das Binary austauschen kann,
// bekommt dessen Rechte und den privaten Schlüssel. Das Gegenstück zur
// Linux-Regel „root muss Eigentümer sein, für andere nicht beschreibbar“.
func CheckBinaryACLs(chain []Object) error {
	if len(chain) < 2 {
		return fmt.Errorf("Pfad des Programms unvollständig")
	}
	for i, o := range chain {
		if !trustedSID(o.Owner) {
			return fmt.Errorf("%s gehört %s; Eigentümer muss SYSTEM, Administratoren oder TrustedInstaller sein. "+
				"Das Programm z. B. nach C:\\Program Files\\OpenWacht kopieren", o.Path, display(o.Owner, o.OwnerName))
		}
		if o.NullDACL {
			return fmt.Errorf("%s hat keine Rechteliste, damit darf jeder alles", o.Path)
		}
		forbidden := forbiddenOnParent
		switch i {
		case 0:
			forbidden = forbiddenOnBinary
		case 1:
			forbidden = forbiddenOnBinaryDir
		}
		for _, a := range o.ACEs {
			if !a.Allow || a.Flags&aceInheritOnly != 0 || trustedSID(a.SID) {
				continue
			}
			if a.Mask&forbidden != 0 {
				return fmt.Errorf("%s ist für %s beschreibbar (Rechte 0x%x). "+
					"Das Programm in ein Verzeichnis legen, das nur Administratoren ändern dürfen, z. B. C:\\Program Files\\OpenWacht",
					o.Path, display(a.SID, a.Name), a.Mask&forbidden)
			}
		}
	}
	return nil
}

// DirSDDL ist die Rechteliste des Agent-Verzeichnisses: nur SYSTEM,
// Administratoren und das Dienstkonto, nichts geerbt (P). Läuft die
// Einrichtung ohne Administratorrechte, kommt statt der Administratoren der
// aufrufende Benutzer hinein und wird Eigentümer.
func DirSDDL(serviceSID, userSID string) string {
	owner, extra := "BA", ""
	if userSID != "" {
		owner, extra = userSID, "(A;OICI;FA;;;"+userSID+")"
	}
	return "O:" + owner + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + serviceSID + ")" + extra
}

// WindowsOSName baut den angezeigten Systemnamen. Windows 11 meldet in der
// Registry weiterhin „Windows 10 …“ als ProductName; erkennbar ist es nur an
// der Build-Nummer ab 22000. Server-Ausgaben sind davon nicht betroffen.
func WindowsOSName(product, displayVersion string, build uint32) string {
	product = strings.TrimSpace(product)
	if product == "" {
		product = "Windows"
	}
	if build >= 22000 && strings.HasPrefix(product, "Windows 10") {
		product = "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	if dv := strings.TrimSpace(displayVersion); dv != "" {
		product += " " + dv
	}
	return product
}
