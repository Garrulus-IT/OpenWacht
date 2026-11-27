// SPDX-License-Identifier: AGPL-3.0-only

package main

// Bausteine für Hauptfenster und Dialoge (1.0.6): Win32-Aufrufe der Common
// Controls und von GDI, nur mit syscall. Die Strukturen folgen den
// C-Definitionen (64 bit, amd64 und arm64).

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// comctl32 löst Windows über das Manifest der App auf (Version 6 aus
	// WinSxS); das geschieht vor jeder Suche in Ordnern. Deshalb hier ohne
	// Zwang zum Systemordner, dort läge Version 5.
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	uxtheme  = windows.NewLazySystemDLL("uxtheme.dll")

	pInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
	pImageListCreate       = comctl32.NewProc("ImageList_Create")
	pImageListReplaceIcon  = comctl32.NewProc("ImageList_ReplaceIcon")
	pImageListDestroy      = comctl32.NewProc("ImageList_Destroy")
	pSetWindowTheme        = uxtheme.NewProc("SetWindowTheme")
	pSendMessageW          = user32.NewProc("SendMessageW")
	pMoveWindow            = user32.NewProc("MoveWindow")
	pShowWindow            = user32.NewProc("ShowWindow")
	pIsIconic              = user32.NewProc("IsIconic")
	pIsWindow              = user32.NewProc("IsWindow")
	pGetClientRect         = user32.NewProc("GetClientRect")
	pGetWindowRect         = user32.NewProc("GetWindowRect")
	pSetWindowPos          = user32.NewProc("SetWindowPos")
	pSetWindowTextW        = user32.NewProc("SetWindowTextW")
	pGetWindowTextW        = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW  = user32.NewProc("GetWindowTextLengthW")
	pIsDialogMessageW      = user32.NewProc("IsDialogMessageW")
	pLoadCursorW           = user32.NewProc("LoadCursorW")
	pSetCursor             = user32.NewProc("SetCursor")
	pGetDpiForWindow       = user32.NewProc("GetDpiForWindow")
	pGetDpiForSystem       = user32.NewProc("GetDpiForSystem")
	pSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	pSetFocus              = user32.NewProc("SetFocus")
	pGetFocus              = user32.NewProc("GetFocus")
	pGetSysColor           = user32.NewProc("GetSysColor")
	pGetSysColorBrush      = user32.NewProc("GetSysColorBrush")
	pDestroyWindow         = user32.NewProc("DestroyWindow")
	pEnableWindow          = user32.NewProc("EnableWindow")
	pSetCapture            = user32.NewProc("SetCapture")
	pReleaseCapture        = user32.NewProc("ReleaseCapture")
	pScreenToClient        = user32.NewProc("ScreenToClient")
	pInvalidateRect        = user32.NewProc("InvalidateRect")
	pBeginPaint            = user32.NewProc("BeginPaint")
	pEndPaint              = user32.NewProc("EndPaint")
	pFillRect              = user32.NewProc("FillRect")
	pDrawTextW             = user32.NewProc("DrawTextW")
	pDrawIconEx            = user32.NewProc("DrawIconEx")
	pGetForegroundWindow   = user32.NewProc("GetForegroundWindow")
	pGetKeyState           = user32.NewProc("GetKeyState")
	pGetAncestor           = user32.NewProc("GetAncestor")
	pRedrawWindow          = user32.NewProc("RedrawWindow")
	pGetDC                 = user32.NewProc("GetDC")
	pReleaseDC             = user32.NewProc("ReleaseDC")
	pClientToScreen        = user32.NewProc("ClientToScreen")
	pSetBkColor            = gdi32.NewProc("SetBkColor")
	pCreateFontW           = gdi32.NewProc("CreateFontW")
	pDeleteObject          = gdi32.NewProc("DeleteObject")
	pCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	pSelectObject          = gdi32.NewProc("SelectObject")
	pSetTextColor          = gdi32.NewProc("SetTextColor")
	pSetBkMode             = gdi32.NewProc("SetBkMode")
	pRoundRect             = gdi32.NewProc("RoundRect")
	pGetStockObject        = gdi32.NewProc("GetStockObject")
	pCreateCompatibleDC    = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBmp   = gdi32.NewProc("CreateCompatibleBitmap")
	pBitBlt                = gdi32.NewProc("BitBlt")
	pDeleteDC              = gdi32.NewProc("DeleteDC")
	pGetTextExtentPoint32W = gdi32.NewProc("GetTextExtentPoint32W")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsPopup            = 0x80000000
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsTabStop          = 0x00010000
	wsGroup            = 0x00020000
	wsVScroll          = 0x00200000
	wsClipChildren     = 0x02000000
	wsClipSiblings     = 0x04000000
	wsDisabled         = 0x08000000
	wsExClientEdge     = 0x00000200
	wsExControlParent  = 0x00010000
	wsExDlgModalFrame  = 0x00000001
	cwUseDefault       = 0x80000000

	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esAutoHScroll  = 0x0080
	esPassword     = 0x0020
	spiGetWorkArea = 0x0030
	esWantReturn   = 0x1000
	bsDefPushBtn   = 0x0001
	bsAutoCheckbox = 0x0003
	ssLeft         = 0x0000
	ssEndEllipsis  = 0x4000
	ssCenterImage  = 0x0200
	ssNoPrefix     = 0x0080
	cbsDropDownLst = 0x0003

	wmCreate         = 0x0001
	wmSize           = 0x0005
	wmSetFocus       = 0x0007
	wmSetRedraw      = 0x000B
	wmPaint          = 0x000F
	wmClose          = 0x0010
	wmEraseBkgnd     = 0x0014
	wmSetCursor      = 0x0020
	wmGetMinMaxInfo  = 0x0024
	wmSetFont        = 0x0030
	wmSetIcon        = 0x0080
	wmNotify         = 0x004E
	wmKeyDown        = 0x0100
	wmCtlColorEdit   = 0x0133
	wmCtlColorStatic = 0x0138
	wmMouseMove      = 0x0200
	wmLButtonDown    = 0x0201
	wmLButtonUp      = 0x0202
	wmCaptureChanged = 0x0215
	wmDpiChanged     = 0x02E0

	emSetCueBanner = 0x1501
	enChange       = 0x0300
	bnClicked      = 0x0000
	bmGetCheck     = 0x00F0
	bmSetCheck     = 0x00F1
	bstChecked     = 1
	cbAddString    = 0x0143
	cbGetCurSel    = 0x0147
	cbSetCurSel    = 0x014E
	cbnSelChange   = 1
	idOK           = 1
	idCancel       = 2

	vkReturn  = 0x0D
	vkEscape  = 0x1B
	vkDelete  = 0x2E
	vkF2      = 0x71
	vkF5      = 0x74
	vkControl = 0x11

	swHide    = 0
	swShow    = 5
	swRestore = 9

	swpNoSize       = 0x0001
	swpNoMove       = 0x0002
	swpNoZOrder     = 0x0004
	swpNoActivate   = 0x0010
	idcArrow        = 32512
	idcHand         = 32649
	wmMouseWheel    = 0x020A
	idcSizeWE       = 32644
	idcSizeNS       = 32645
	colorWindow     = 5
	colorWindowText = 8
	colorBtnFace    = 15
	colorGrayText   = 17
	fwNormal        = 400
	fwSemiBold      = 600
	nullPen         = 8
	transparent     = 1
	srcCopy         = 0x00CC0020
	diNormal        = 0x0003
	dtLeft          = 0x0000
	dtVCenter       = 0x0004
	dtSingleLine    = 0x0020
	dtNoPrefix      = 0x0800
	dtEndEllipsis   = 0x8000
	gaRoot          = 2
	mbYesNo         = 0x4
	mbIconQuestion  = 0x20
	mbDefButton2    = 0x100
	idYes           = 6

	iccListView = 0x00000001
	iccTreeView = 0x00000002
	iccBar      = 0x00000004 // Werkzeug- und Statusleiste
	ilcColor32  = 0x00000020

	nmClick      = ^uint32(1)  // -2
	nmDblClk     = ^uint32(2)  // -3
	nmReturn     = ^uint32(3)  // -4
	nmRClick     = ^uint32(4)  // -5
	nmCustomDraw = ^uint32(11) // -12

	cddsPrepaint        = 0x00000001
	cddsItemPrepaint    = 0x00010001
	cddsSubitem         = 0x00020000
	cddsPostpaint       = 0x00000002
	cdrfNotifyPostPaint = 0x10
	lvmGetItemState     = 0x102C
	wmSettingChange     = 0x001A
	emSetSel            = 0x00B1
	rdwInvalidate       = 0x0001
	rdwErase            = 0x0004
	rdwAllChildren      = 0x0080
	rdwFrame            = 0x0400
	cdisSelected        = 0x0001
	cdisFocus           = 0x0010
	cdisHot             = 0x0040
	cdrfSkipDefault     = 0x04
	nullBrush           = 5
	fwBold              = 700
	lvmSetBkColor       = 0x1001
	lvmGetItemCount     = 0x1004
	lvmGetItemRect      = 0x100E
	tvmSetIndent        = 0x1107
	tvmSetBkColor       = 0x111D
	cdrfDoDefault       = 0x00
	cdrfNewFont         = 0x02
	cdrfNotifyItem      = 0x20
	cdrfNotifySubitem   = 0x20

	// ListView
	lvsReport           = 0x0001
	lvsSingleSel        = 0x0004
	lvsShowSelAlways    = 0x0008
	lvsNoColumnHeader   = 0x4000
	lvsExGridLines      = 0x00000001
	lvsExFullRowSelect  = 0x00000020
	lvsExLabelTip       = 0x00004000
	lvsExDoubleBuffer   = 0x00010000
	lvmSetImageList     = 0x1003
	lvmDeleteAllItems   = 0x1009
	lvmGetNextItem      = 0x100C
	lvmEnsureVisible    = 0x1013
	lvmGetHeader        = 0x101F
	lvmSetColumnWidth   = 0x101E
	lvmGetTopIndex      = 0x1027
	lvmGetCountPerPage  = 0x1028
	lvmSetItemState     = 0x102B
	lvmSetExtendedStyle = 0x1036
	lvmInsertItemW      = 0x104D
	lvmInsertColumnW    = 0x1061
	lvmSetItemTextW     = 0x1074
	lvifText            = 0x0001
	lvifImage           = 0x0002
	lvifState           = 0x0008
	lvisSelected        = 0x0002
	lvisFocused         = 0x0001
	lvniSelected        = 0x0002
	lvcfFmt             = 0x0001
	lvcfWidth           = 0x0002
	lvcfText            = 0x0004
	lvsilSmall          = 1
	lvnItemChanged      = ^uint32(100) // -101
	lvnColumnClick      = ^uint32(107) // -108
	lvnKeyDown          = ^uint32(154) // -155
	hdmGetItemW         = 0x120B
	hdmSetItemW         = 0x120C
	hdiFormat           = 0x0004
	hdfSortDown         = 0x0200
	hdfSortUp           = 0x0400

	// TreeView
	tvsHasButtons     = 0x0001
	tvsLinesAtRoot    = 0x0004
	tvsShowSelAlways  = 0x0020
	tvsTrackSelect    = 0x0200
	tvsFullRowSelect  = 0x1000
	tvsExDoubleBuffer = 0x0004
	tvmInsertItemW    = 0x1132
	tvmDeleteItem     = 0x1101
	tvmExpand         = 0x1102
	tvmSetImageList   = 0x1109
	tvmGetNextItem    = 0x110A
	tvmSelectItem     = 0x110B
	tvmHitTest        = 0x1111
	tvmSetItemHeight  = 0x111B
	tvmGetItemState   = 0x1127
	tvmSetExtStyle    = 0x112C
	tvmSetItemW       = 0x113F
	tvifText          = 0x0001
	tvifImage         = 0x0002
	tvifParam         = 0x0004
	tvifState         = 0x0008
	tvifHandle        = 0x0010
	tvifSelectedImage = 0x0020
	tvisBold          = 0x0010
	tvisExpanded      = 0x0020
	tveExpand         = 0x0002
	tvgnCaret         = 0x0009
	tviRoot           = ^uintptr(0xFFFF) // (HTREEITEM)-0x10000
	tviLast           = ^uintptr(0xFFFD) // (HTREEITEM)-0xFFFE
	tvnSelChangedW    = ^uint32(450)     // -451

	// Werkzeugleiste
	tbstyleTooltips    = 0x0100
	tbstyleFlat        = 0x0800
	tbstyleList        = 0x1000
	tbstyleTransparent = 0x8000
	ccsNoResize        = 0x0004
	ccsNoParentAlign   = 0x0008
	ccsNoDivider       = 0x0040
	tbButtonStructSz   = 0x041E
	tbSetBitmapSize    = 0x0420
	tbAutoSize         = 0x0421
	tbEnableButton     = 0x0401
	tbCheckButton      = 0x0402
	tbIsButtonChecked  = 0x040A
	tbGetButtonSize    = 0x043A
	tbAddButtonsW      = 0x0444
	tbSetPadding       = 0x0457
	tbSetExtStyle      = 0x0454
	tbstateEnabled     = 0x04
	btnsSep            = 0x01
	btnsCheck          = 0x02
	btnsAutoSize       = 0x10
	btnsShowText       = 0x40
	tbstyleExMixed     = 0x08
	iImageNone         = -2

	// Statusleiste
	sbarsSizeGrip = 0x0100
	sbSetTextW    = 0x040B
	sbSetParts    = 0x0404
)

type rect struct{ Left, Top, Right, Bottom int32 }

type initCommonControlsEx struct {
	Size uint32
	ICC  uint32
}

type lvColumn struct {
	Mask      uint32
	Fmt       int32
	Cx        int32
	Text      *uint16
	TextMax   int32
	SubItem   int32
	Image     int32
	Order     int32
	CxMin     int32
	CxDefault int32
	CxIdeal   int32
}

type lvItem struct {
	Mask      uint32
	Item      int32
	SubItem   int32
	State     uint32
	StateMask uint32
	Text      *uint16
	TextMax   int32
	Image     int32
	LParam    uintptr
	Indent    int32
	GroupID   int32
	Columns   uint32
	PColumns  uintptr
	PColFmt   uintptr
	Group     int32
}

type hdItem struct {
	Mask    uint32
	Cxy     int32
	Text    *uint16
	Hbm     uintptr
	TextMax int32
	Fmt     int32
	LParam  uintptr
	Image   int32
	Order   int32
	Type    uint32
	Filter  uintptr
	State   uint32
}

type nmHdr struct {
	HwndFrom uintptr
	IDFrom   uintptr
	Code     uint32
}

type nmListView struct {
	Hdr      nmHdr
	Item     int32
	SubItem  int32
	NewState uint32
	OldState uint32
	Changed  uint32
	Action   point
	LParam   uintptr
}

type nmLVKeyDown struct {
	Hdr   nmHdr
	VKey  uint16
	Flags uint32
}

type nmCustomDrawLV struct {
	Hdr        nmHdr
	DrawStage  uint32
	Hdc        uintptr
	Rc         rect
	ItemSpec   uintptr
	ItemState  uint32
	ItemLParam uintptr
	ClrText    uint32
	ClrTextBk  uint32
	SubItem    int32
}

type tvItem struct {
	Mask          uint32
	Item          uintptr
	State         uint32
	StateMask     uint32
	Text          *uint16
	TextMax       int32
	Image         int32
	SelectedImage int32
	Children      int32
	LParam        uintptr
	// TVITEMEX (die Union in TVINSERTSTRUCT ist so groß)
	Integral      int32
	StateEx       uint32
	Hwnd          uintptr
	ExpandedImage int32
	Reserved      int32
}

type tvInsertStruct struct {
	Parent      uintptr
	InsertAfter uintptr
	Item        tvItem
}

type nmTreeView struct {
	Hdr     nmHdr
	Action  uint32
	ItemOld tvItem0
	ItemNew tvItem0
	PtDrag  point
}

// tvItem0: TVITEM ohne die Felder von TVITEMEX (in NMTREEVIEW).
type tvItem0 struct {
	Mask          uint32
	Item          uintptr
	State         uint32
	StateMask     uint32
	Text          *uint16
	TextMax       int32
	Image         int32
	SelectedImage int32
	Children      int32
	LParam        uintptr
}

type tvHitTestInfo struct {
	Pt    point
	Flags uint32
	Item  uintptr
}

type tbButton struct {
	Bitmap   int32
	Command  int32
	State    byte
	Style    byte
	Reserved [6]byte
	Data     uintptr
	String   uintptr
}

type paintStruct struct {
	Hdc      uintptr
	Erase    int32
	Rc       rect
	Restore  int32
	IncUpd   int32
	Reserved [32]byte
}

type minMaxInfo struct {
	Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize point
}

type size struct{ Cx, Cy int32 }

func send(h syscall.Handle, m uint32, wp, lp uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(uintptr(h), uintptr(m), wp, lp)
	return r
}

// sendP: wie send, lParam ist ein Zeiger. Die Umwandlung steht direkt im
// Aufruf, damit Go die Daten bis zu seinem Ende am Leben hält.
func sendP(h syscall.Handle, m uint32, wp uintptr, p unsafe.Pointer) uintptr {
	r, _, _ := pSendMessageW.Call(uintptr(h), uintptr(m), wp, uintptr(p))
	return r
}

// zeigerAus: lParam einer Fensternachricht als Zeiger auf die Struktur, die
// Windows dafür vorsieht (gültig für die Dauer der Nachricht).
func zeigerAus[T any](lp uintptr) *T {
	return *(**T)(unsafe.Pointer(&lp))
}

func kind(parent syscall.Handle, klasse string, text string, style, exStyle uint32, id int) syscall.Handle {
	inst, _, _ := pGetModuleHandleW.Call(0)
	h, _, _ := pCreateWindowExW.Call(uintptr(exStyle), uintptr(unsafe.Pointer(utf16(klasse))), uintptr(unsafe.Pointer(utf16(text))),
		uintptr(wsChild|wsVisible|style), 0, 0, 10, 10, uintptr(parent), uintptr(id), inst, 0)
	return syscall.Handle(h)
}

func move(c syscall.Handle, x, y, cx, cy int32) {
	pMoveWindow.Call(uintptr(c), uintptr(x), uintptr(y), uintptr(max(cx, 0)), uintptr(max(cy, 0)), 1)
}

func setText(h syscall.Handle, s string) {
	pSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(utf16(s))))
}

func getText(h syscall.Handle) string {
	n, _, _ := pGetWindowTextLengthW.Call(uintptr(h))
	buf := make([]uint16, n+1)
	r, _, _ := pGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf[:r])
}

func enable(h syscall.Handle, an bool) {
	v := uintptr(0)
	if an {
		v = 1
	}
	pEnableWindow.Call(uintptr(h), v)
}

func explorerThema(h syscall.Handle) {
	if pSetWindowTheme.Find() == nil {
		pSetWindowTheme.Call(uintptr(h), uintptr(unsafe.Pointer(utf16("Explorer"))), 0)
	}
}

func schrift(dpi, pt, gewicht int32) uintptr {
	h, _, _ := pCreateFontW.Call(uintptr(-pt*dpi/72), 0, 0, 0, uintptr(gewicht), 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16("Segoe UI"))))
	return h
}

func dpiVon(h syscall.Handle) int32 {
	if h == 0 && pGetDpiForSystem.Find() == nil {
		if d, _, _ := pGetDpiForSystem.Call(); d != 0 {
			return int32(d)
		}
	}
	if pGetDpiForWindow.Find() == nil {
		if d, _, _ := pGetDpiForWindow.Call(uintptr(h)); d != 0 {
			return int32(d)
		}
	}
	return 96
}

func commonControls() {
	icc := initCommonControlsEx{ICC: iccListView | iccTreeView | iccBar}
	icc.Size = uint32(unsafe.Sizeof(icc))
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
}

func istStrg() bool {
	r, _, _ := pGetKeyState.Call(vkControl)
	return int16(r) < 0
}

// hinweis: Meldung im eigenen Dialog (im Corporate Design), ohne Fenster als
// Systemmeldung.
func hinweis(owner syscall.Handle, titel, text string, warnung bool) {
	if owner != 0 {
		d := neuerDialog(owner, titel)
		d.einleitung, d.okText, d.nurOK = text, "Schließen", true
		if warnung {
			d.einleitung, d.fehler = "", text
		}
		d.aufbau = func(*dialog) {}
		d.zeigen()
		return
	}
	art := uintptr(mbOK | mbIconInformation)
	if warnung {
		art = mbOK | mbIconWarning
	}
	pMessageBoxW.Call(uintptr(owner), uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(titel))), art)
}
