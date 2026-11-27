// SPDX-License-Identifier: AGPL-3.0-only

package main

// Win32-Aufrufe für Infobereich, Menü, Symbol, Anmeldeinformationen und
// Registry, nur mit syscall (CONTRIBUTING: keine neue Abhängigkeit). Die
// Strukturen folgen den C-Definitionen; Go legt sie mit derselben
// Ausrichtung ab (amd64 und arm64).

import (
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pRegisterClassExW         = user32.NewProc("RegisterClassExW")
	pCreateWindowExW          = user32.NewProc("CreateWindowExW")
	pDefWindowProcW           = user32.NewProc("DefWindowProcW")
	pGetMessageW              = user32.NewProc("GetMessageW")
	pTranslateMessage         = user32.NewProc("TranslateMessage")
	pDispatchMessageW         = user32.NewProc("DispatchMessageW")
	pPostMessageW             = user32.NewProc("PostMessageW")
	pPostQuitMessage          = user32.NewProc("PostQuitMessage")
	pCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	pAppendMenuW              = user32.NewProc("AppendMenuW")
	pTrackPopupMenu           = user32.NewProc("TrackPopupMenu")
	pDestroyMenu              = user32.NewProc("DestroyMenu")
	pSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	pGetCursorPos             = user32.NewProc("GetCursorPos")
	pCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	pDestroyIcon              = user32.NewProc("DestroyIcon")
	pRegisterWindowMessageW   = user32.NewProc("RegisterWindowMessageW")
	pMessageBoxW              = user32.NewProc("MessageBoxW")
	pFindWindowW              = user32.NewProc("FindWindowW")
	pAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
	pShellNotifyIconW         = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteW            = shell32.NewProc("ShellExecuteW")
	pGetModuleHandleW         = kernel32.NewProc("GetModuleHandleW")
	pCreateMutexW             = kernel32.NewProc("CreateMutexW")
	pCredWriteW               = advapi32.NewProc("CredWriteW")
	pCredReadW                = advapi32.NewProc("CredReadW")
	pCredDeleteW              = advapi32.NewProc("CredDeleteW")
	pCredFree                 = advapi32.NewProc("CredFree")
	pRegOpenKeyExW            = advapi32.NewProc("RegOpenKeyExW")
	pRegSetValueExW           = advapi32.NewProc("RegSetValueExW")
	pRegQueryValueExW         = advapi32.NewProc("RegQueryValueExW")
	pRegDeleteValueW          = advapi32.NewProc("RegDeleteValueW")
	pRegCloseKey              = advapi32.NewProc("RegCloseKey")
)

const (
	wmDestroy     = 0x0002
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmContextMenu = 0x007B
	wmApp         = 0x8000
	wmTray        = wmApp + 1 // Nachrichten vom Symbol
	wmStand       = wmApp + 2 // neuer Stand aus der Abfrage
	wmAktion      = wmApp + 3 // Ergebnis einer Änderung
	wmZeigen      = wmApp + 4 // zweiter Start: Fenster zeigen
	wmSitzungWeg  = wmApp + 6 // Sitzung abgelaufen: neu anmelden
	asfwAny       = ^uintptr(0)

	ninSelect           = 0x0400
	ninKeySelect        = 0x0401
	wmNull              = 0x0000
	ninBalloonUserClick = 0x0405

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10
	nifShowTip = 0x80

	niifInfo    = 1
	niifWarning = 2
	niifError   = 3

	notifyIconVersion4 = 4

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfChecked   = 0x0008
	mfGrayed    = 0x0001

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	swShowNormal = 1

	errorAlreadyExists = 183

	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	hkeyCurrentUser         = 0x80000001
	keySetValue             = 0x0002
	keyQueryValue           = 0x0001
	regSZ                   = 1
	mbOK                    = 0x0
	mbIconInformation       = 0x40
	mbIconWarning           = 0x30
	lrDefaultColor          = 0
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconData struct {
	Size             uint32
	Hwnd             syscall.Handle
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             syscall.Handle
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GuidItem         guid
	BalloonIcon      syscall.Handle
}

type filetime struct{ Low, High uint32 }

type credential struct {
	Flags          uint32
	Type           uint32
	TargetName     *uint16
	Comment        *uint16
	LastWritten    filetime
	BlobSize       uint32
	Blob           *byte
	Persist        uint32
	AttributeCount uint32
	Attributes     uintptr
	TargetAlias    *uint16
	UserName       *uint16
}

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// setUTF16 kopiert s gekürzt in ein festes Feld (mit abschließender 0).
func setUTF16(dst []uint16, s string) {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func ptr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }
