// SPDX-License-Identifier: AGPL-3.0-only

package main

// Text in die Zwischenablage (z. B. Link einer Wandanzeige, neues Passwort).

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pOpenClipboard    = user32.NewProc("OpenClipboard")
	pEmptyClipboard   = user32.NewProc("EmptyClipboard")
	pSetClipboardData = user32.NewProc("SetClipboardData")
	pCloseClipboard   = user32.NewProc("CloseClipboard")
	pGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	pGlobalLock       = kernel32.NewProc("GlobalLock")
	pGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	pGlobalFree       = kernel32.NewProc("GlobalFree")
	pRtlMoveMemory    = kernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func zwischenablage(owner syscall.Handle, text string) error {
	u, err := syscall.UTF16FromString(text)
	if err != nil {
		return err
	}
	if r, _, _ := pOpenClipboard.Call(uintptr(owner)); r == 0 {
		return errors.New("Zwischenablage ist belegt")
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	n := uintptr(len(u) * 2)
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, n)
	if h == 0 {
		return errors.New("kein Speicher für die Zwischenablage")
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		pGlobalFree.Call(h)
		return errors.New("Zwischenablage nicht beschreibbar")
	}
	pRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), n)
	pGlobalUnlock.Call(h)
	if r, _, _ := pSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		pGlobalFree.Call(h)
		return errors.New("Zwischenablage nicht beschreibbar")
	}
	return nil
}

// Liste zum Ankreuzen im Dialog (FeldMehrfach)
const (
	lbsNotify           = 0x0001
	lbsMultipleSel      = 0x0008
	lbsNoIntegralHeight = 0x0100
	lbsOwnerDrawFixed   = 0x0010
	lbsHasStrings       = 0x0040
	odtListbox          = 2
	lbAddString         = 0x0180
	lbSetSel            = 0x0185
	lbGetSel            = 0x0187
	lbSetItemHeight     = 0x01A0
)

// --- Datei wählen (Agent-Paket hochladen) ---------------------------------------

var (
	comdlg32          = windows.NewLazySystemDLL("comdlg32.dll")
	pGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
)

type openFileName struct {
	StructSize    uint32
	Owner         syscall.Handle
	Instance      syscall.Handle
	Filter        *uint16
	CustomFilter  *uint16
	MaxCustFilter uint32
	FilterIndex   uint32
	File          *uint16
	MaxFile       uint32
	FileTitle     *uint16
	MaxFileTitle  uint32
	InitialDir    *uint16
	Title         *uint16
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExt        *uint16
	CustData      uintptr
	Hook          uintptr
	TemplateName  *uint16
	PvReserved    uintptr
	DwReserved    uint32
	FlagsEx       uint32
}

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnNoChangeDir   = 0x00000008
	ofnExplorer      = 0x00080000
)

// dateiWaehlen: Fenster „Öffnen“ von Windows; filter wie „Name\x00*.sig\x00“. Leer bei Abbruch.
func dateiWaehlen(owner syscall.Handle, titel, filter string) string {
	buf := make([]uint16, 1024)
	f := utf16fest(filter + "\x00")
	o := openFileName{Owner: owner, Filter: &f[0], File: &buf[0], MaxFile: uint32(len(buf)), Title: utf16(titel),
		Flags: ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir | ofnExplorer}
	o.StructSize = uint32(unsafe.Sizeof(o))
	if r, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&o))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// utf16fest: UTF-16 mit eingebetteten Nullen (Filter von GetOpenFileName).
func utf16fest(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r == 0 {
			out = append(out, 0)
			continue
		}
		out = append(out, syscall.StringToUTF16(string(r))[0])
	}
	return append(out, 0)
}
