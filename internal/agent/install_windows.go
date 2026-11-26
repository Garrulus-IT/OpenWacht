// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// DefaultDir: C:\ProgramData\OpenWacht-Agent (bzw. wo ProgramData liegt).
var DefaultDir = func() string {
	p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || p == "" {
		p = `C:\ProgramData`
	}
	return filepath.Join(p, "OpenWacht-Agent")
}()

// ServiceAccount ist das virtuelle Dienstkonto. Es hat kein Passwort, keine
// Anmeldung und nur die Rechte, die ihm ausdrücklich gegeben werden.
const ServiceAccount = `NT SERVICE\` + ServiceName

// IsAdmin: läuft der Prozess mit erhöhten Rechten („Als Administrator ausführen“)?
func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// CheckBinary prüft, dass nur Administratoren das Programm und die
// Verzeichnisse darüber ändern können (Regeln in winsec.go).
func CheckBinary(path string) error {
	if strings.HasPrefix(path, `\\`) {
		return fmt.Errorf("%s liegt nicht auf einem lokalen Laufwerk", path)
	}
	var chain []Object
	for p := path; ; p = filepath.Dir(p) {
		o, err := readObject(p)
		if err != nil {
			return fmt.Errorf("Rechte von %s: %w", p, err)
		}
		chain = append(chain, o)
		if filepath.Dir(p) == p {
			break
		}
	}
	return CheckBinaryACLs(chain)
}

// kontoNamen: einmal aufgelöste Namen; die Prüfung der Rechte läuft bei
// jedem Start über die ganze Pfadkette, und eine nicht auflösbare SID kann
// je Abfrage spürbar dauern (im Netz ohne Domänencontroller).
var kontoNamen sync.Map

func accountName(sid *windows.SID) string {
	k := sid.String()
	if v, ok := kontoNamen.Load(k); ok {
		return v.(string)
	}
	n := lookupName(sid)
	kontoNamen.Store(k, n)
	return n
}

func lookupName(sid *windows.SID) string {
	acc, dom, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if dom != "" {
		return dom + `\` + acc
	}
	return acc
}

func readObject(path string) (Object, error) {
	o := Object{Path: path}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return o, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return o, errors.New("kein Eigentümer lesbar")
	}
	o.Owner, o.OwnerName = owner.String(), accountName(owner)
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || err == nil && dacl == nil {
		o.NullDACL = true
		return o, nil
	}
	if err != nil {
		return o, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return o, err
		}
		t := ace.Header.AceType
		if t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE {
			// z. B. bedingte Einträge: nicht sicher auswertbar, also ablehnen
			return o, fmt.Errorf("Rechteliste enthält einen Eintrag vom Typ %d, der nicht geprüft werden kann", t)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		o.ACEs = append(o.ACEs, ACE{
			SID: sid.String(), Name: accountName(sid),
			Allow: t == windows.ACCESS_ALLOWED_ACE_TYPE,
			Mask:  uint32(ace.Mask), Flags: ace.Header.AceFlags,
		})
	}
	return o, nil
}

func isReparsePoint(fi fs.FileInfo) bool {
	if a, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0
}

// prepareDir legt das Agent-Verzeichnis mit fester Rechteliste an (nur
// SYSTEM, Administratoren, Dienstkonto). Unter ProgramData dürfen normale
// Benutzer sonst Ordner anlegen und lesen. Neu angelegt wird es in einem
// Schritt samt Rechten, damit niemand dazwischenkommt. Ein vorhandenes
// Verzeichnis wird nur übernommen, wenn es und alles darin vertrauenswürdigen
// Konten gehört: Wer es vorher angelegt hat, ist Eigentümer und könnte die
// Rechte später zurückändern.
func prepareDir(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	svcSID := ServiceSID(ServiceName)
	userSID := ""
	if !IsAdmin() {
		tu, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		userSID = tu.User.Sid.String()
	}
	ok := func(sid string) bool { return trustedSID(sid) || sid == svcSID || userSID != "" && sid == userSID }
	sd, err := windows.SecurityDescriptorFromString(DirSDDL(svcSID, userSID))
	if err != nil {
		return err
	}

	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		sa := windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(sa))
		if err := windows.CreateDirectory(p, &sa); err != nil {
			return fmt.Errorf("Verzeichnis %s anlegen: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || isReparsePoint(fi) {
		return fmt.Errorf("%s ist kein normales Verzeichnis (Verknüpfung oder Datei); bitte prüfen und entfernen", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	paths := []string{dir}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() || isReparsePoint(fi) {
			return fmt.Errorf("unerwarteter Eintrag %s im Agent-Verzeichnis; bitte prüfen und entfernen", p)
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		o, err := readObject(p)
		if err != nil {
			return fmt.Errorf("Rechte von %s: %w", p, err)
		}
		if !ok(o.Owner) {
			return fmt.Errorf("%s gehört %s. Jemand anderes hat das Verzeichnis angelegt; bitte prüfen und das Verzeichnis löschen",
				p, display(o.Owner, o.OwnerName))
		}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("Rechte für %s setzen: %w", dir, err)
	}
	// Dateien darin: eigene Einträge entfernen, nur noch die Rechte des Verzeichnisses erben.
	empty := emptyACL()
	for _, p := range paths[1:] {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, empty, nil); err != nil {
			return fmt.Errorf("Rechte für %s setzen: %w", p, err)
		}
	}
	return nil
}

// Nur dieses Privileg behält der Dienst; Windows entfernt alle anderen aus
// seinem Token (SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO).
const keptPrivilege = "SeChangeNotifyPrivilege"

type serviceRequiredPrivilegesInfo struct {
	RequiredPrivileges *uint16 // Liste, mit zwei Nullen beendet
}

// InstallService richtet den Dienst ein oder aktualisiert ihn:
// virtuelles Konto statt LocalSystem, verzögerter Autostart, Neustart bei
// Fehlern, nur ein Privileg. Dazu eine Ereignisquelle für das Anwendungsprotokoll.
func InstallService(bin, dir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Dienststeuerung: %w", err)
	}
	defer m.Disconnect()
	cfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      "OpenWacht-Agent",
		Description:      "Sendet Messwerte an die OpenWacht-Zentrale. Nimmt keine Befehle an und öffnet keinen Port.",
		ServiceStartName: ServiceAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	args := []string{"starten", "-verzeichnis", dir}
	s, err := m.OpenService(ServiceName)
	if err == nil {
		cmd := syscall.EscapeArg(bin)
		for _, a := range args {
			cmd += " " + syscall.EscapeArg(a)
		}
		cfg.BinaryPathName = cmd
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("Dienst aktualisieren: %w", err)
		}
	} else if s, err = m.CreateService(ServiceName, bin, cfg, args...); err != nil {
		return fmt.Errorf("Dienst anlegen: %w", err)
	}
	defer s.Close()

	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, 24*60*60); err != nil {
		return fmt.Errorf("Neustart bei Fehlern einstellen: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("Neustart bei Fehlern einstellen: %w", err)
	}
	priv, err := windows.UTF16FromString(keptPrivilege)
	if err != nil {
		return err
	}
	priv = append(priv, 0) // zweite Null: Ende der Liste
	info := serviceRequiredPrivilegesInfo{RequiredPrivileges: &priv[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info))); err != nil {
		return fmt.Errorf("Privilegien einschränken: %w", err)
	}
	if err := eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("Ereignisquelle anlegen: %w", err)
	}
	if err := addToPerfMonUsers(); err != nil {
		return err
	}
	return InstallUpdateUnits(bin, dir)
}

// perfMonUsersSID: lokale Gruppe „Leistungsüberwachungsbenutzer“
// („Performance Monitor Users“), Name je nach Sprache verschieden.
const perfMonUsersSID = "S-1-5-32-558"

const errMemberInAlias = 1378 // ERROR_MEMBER_IN_ALIAS: schon Mitglied

var procNetLocalGroupAddMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupAddMembers")

// addToPerfMonUsers nimmt das Dienstkonto in die Gruppe auf (0.99.2), sonst
// liefert PDH für Leistungsindikatoren 0xC0000BC8 (kein Zugriff). Bisher
// erledigte das ein Ausroll-Skript. Die Gruppe darf nur Leistungsdaten lesen;
// wirksam wird die Mitgliedschaft beim nächsten Start des Dienstes.
func addToPerfMonUsers() error {
	group, err := windows.StringToSid(perfMonUsersSID)
	if err != nil {
		return err
	}
	name, _, _, err := group.LookupAccount("")
	if err != nil {
		return fmt.Errorf("Gruppe Leistungsüberwachungsbenutzer nicht gefunden: %w", err)
	}
	svc, err := windows.StringToSid(ServiceSID(ServiceName))
	if err != nil {
		return err
	}
	gname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	// LOCALGROUP_MEMBERS_INFO_0: nur die SID
	member := struct{ sid *windows.SID }{svc}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(gname)), 0, uintptr(unsafe.Pointer(&member)), 1)
	if r != 0 && r != errMemberInAlias {
		return fmt.Errorf("Dienstkonto in die Gruppe %s aufnehmen: %w", name, syscall.Errno(r))
	}
	return nil
}

var procNetLocalGroupDelMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupDelMembers")

// removeFromPerfMonUsers: beim Entfernen; Fehler (nicht Mitglied) zählen nicht.
func removeFromPerfMonUsers() {
	group, err := windows.StringToSid(perfMonUsersSID)
	if err != nil {
		return
	}
	name, _, _, err := group.LookupAccount("")
	if err != nil {
		return
	}
	svc, err := windows.StringToSid(ServiceSID(ServiceName))
	if err != nil {
		return
	}
	gname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	member := struct{ sid *windows.SID }{svc}
	procNetLocalGroupDelMembers.Call(0, uintptr(unsafe.Pointer(gname)), 0, uintptr(unsafe.Pointer(&member)), 1)
}

// UpdateTaskName: geplante Aufgabe, die bereitgelegte Updates installiert.
const UpdateTaskName = `OpenWacht-Agent-Update`

// InstallUpdateUnits legt die geplante Aufgabe an (als SYSTEM, alle 15
// Minuten). Sie installiert nur, was der Agent mit gültiger Signatur
// bereitgelegt hat, und prüft selbst noch einmal.
func InstallUpdateUnits(bin, dir string) error {
	tr := syscall.EscapeArg(bin) + " update-installieren -verzeichnis " + syscall.EscapeArg(dir)
	out, err := exec.Command(schtasks(), "/Create", "/F", "/RU", "SYSTEM", "/SC", "MINUTE", "/MO", "15",
		"/TN", UpdateTaskName, "/TR", tr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("geplante Aufgabe für Updates: %v: %s", err, out)
	}
	return nil
}

// ServiceRunning: läuft der Dienst gerade (z. B. bei erneuter Registrierung)?
func ServiceRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State != windows.SERVICE_STOPPED
}

// SetProcVisible: unter Windows sieht der Dienst die Programmnamen ohnehin.
func SetProcVisible(bool) (bool, error) { return false, nil }

// IsRoot: unter Windows ein Administrator mit erhöhten Rechten.
func IsRoot() bool { return IsAdmin() }

// StartService startet den Dienst bzw. startet ihn neu, wenn er läuft.
func StartService() error {
	if ServiceRunning() {
		return RestartService()
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	return waitRunning(s)
}

// RemoveService hält den Dienst an und entfernt ihn samt geplanter Aufgabe
// und Ereignisquelle (vor dem Entfernen des MSI). Das Agent-Verzeichnis mit
// der Registrierung bleibt; ohne Dienst sendet niemand mehr.
func RemoveService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Dienststeuerung: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		if st, err := s.Query(); err == nil && st.State != windows.SERVICE_STOPPED {
			s.Control(windows.SERVICE_CONTROL_STOP)
			for range 40 {
				time.Sleep(500 * time.Millisecond)
				if st, err := s.Query(); err == nil && st.State == windows.SERVICE_STOPPED {
					break
				}
			}
		}
		err := s.Delete()
		s.Close()
		if err != nil {
			return fmt.Errorf("Dienst entfernen: %w", err)
		}
	}
	if out, err := exec.Command(schtasks(), "/Delete", "/F", "/TN", UpdateTaskName).CombinedOutput(); err != nil &&
		!strings.Contains(strings.ToLower(string(out)), "cannot find") && !strings.Contains(string(out), "nicht gefunden") {
		return fmt.Errorf("geplante Aufgabe entfernen: %v: %s", err, out)
	}
	eventlog.Remove(ServiceName)
	removeFromPerfMonUsers() // sonst bliebe eine verwaiste SID in der Gruppe
	return nil
}

// emptyACL: eine leere, gültige ACL (Kopf ohne Einträge). Nicht
// windows.ACLFromEntries(nil, nil): SetEntriesInAcl liefert ohne Einträge und
// ohne Ausgangs-ACL NULL, und x/sys liest dann ohne Prüfung die Größe aus
// (Absturz beim Registrieren, wenn das Agent-Verzeichnis schon besteht, 0.99.0).
// Nicht nil übergeben: Eine NULL-DACL hieße „Vollzugriff für alle“.
func emptyACL() *windows.ACL {
	// ACL_REVISION 2, AclSize 8, AceCount 0 (winnt.h, Little Endian).
	b := make([]uint64, 1)
	h := (*[8]byte)(unsafe.Pointer(&b[0]))
	h[0], h[2] = 2, 8
	return (*windows.ACL)(unsafe.Pointer(&b[0]))
}

// schtasks: voller Pfad, damit kein schtasks.exe aus dem Arbeitsverzeichnis greift.
func schtasks() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "schtasks.exe")
}
