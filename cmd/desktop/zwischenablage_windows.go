// SPDX-License-Identifier: AGPL-3.0-only

package main

// Text in die Zwischenablage (z. B. Link einer Wandanzeige, neues Passwort).

import (
	"errors"
	"syscall"
	"unsafe"
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
