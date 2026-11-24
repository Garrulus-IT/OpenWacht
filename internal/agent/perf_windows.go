// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package agent

// Lesen von Leistungsindikatoren über pdh.dll (ohne cgo): eine Abfrage je
// Messung, englische Pfade (PdhAddEnglishCounterW, funktioniert auch auf
// deutschem Windows), zweimal sammeln mit einer Sekunde Abstand, damit auch
// Raten (…/sec) einen Wert haben. Nur lesend; die Bibliothek kommt aus dem
// Systemordner (NewLazySystemDLL).

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pdh                       = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQuery          = pdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounter  = pdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData   = pdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedArray  = pdh.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery         = pdh.NewProc("PdhCloseQuery")
	errPerfLibraryUnavailable = errors.New("pdh.dll nicht verfügbar")
)

// PDH-Statuswerte (pdhmsg.h).
const (
	pdhCstatusValidData  = 0x00000000
	pdhCstatusNewData    = 0x00000001
	pdhCstatusNoObject   = 0xC0000BB8
	pdhCstatusNoCounter  = 0xC0000BB9
	pdhCstatusBadName    = 0xC0000BC0
	pdhCstatusNoInstance = 0x800007D1
	pdhMoreData          = 0x800007D2
	pdhNoData            = 0x800007D5
	pdhAccessDenied      = 0xC0000BDB
	pdhFmtDouble         = 0x00000200
	pdhFmtNoCap100       = 0x00008000
	pdhItemSize          = 24 // PDH_FMT_COUNTERVALUE_ITEM_W auf 386, amd64, arm64
	pdhItemStatusOffset  = 8
	pdhItemValueOffset   = 16
	maxPerfBuffer        = 4 << 20
	perfSampleGap        = time.Second
)

func pdhErr(st uintptr) error {
	switch uint32(st) {
	case pdhCstatusNoObject:
		return errPerfNoObject
	case pdhCstatusNoCounter, pdhCstatusBadName:
		return errPerfNoCounter
	case pdhCstatusNoInstance, pdhNoData:
		return errPerfNoInstance
	case pdhAccessDenied:
		return errPerfDenied
	}
	return fmt.Errorf("PDH-Status 0x%08X", uint32(st))
}

func windowsPerf(ctx context.Context, paths []string) ([][]perfValue, error) {
	if err := pdh.Load(); err != nil {
		return nil, errPerfLibraryUnavailable
	}
	var q windows.Handle
	if st, _, _ := procPdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&q))); st != 0 {
		return nil, pdhErr(st)
	}
	defer procPdhCloseQuery.Call(uintptr(q))
	counters := make([]windows.Handle, len(paths))
	for i, p := range paths {
		u, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return nil, errPerfNoCounter
		}
		if st, _, _ := procPdhAddEnglishCounter.Call(uintptr(q), uintptr(unsafe.Pointer(u)), 0, uintptr(unsafe.Pointer(&counters[i]))); st != 0 {
			return nil, pdhErr(st)
		}
	}
	if st, _, _ := procPdhCollectQueryData.Call(uintptr(q)); st != 0 && uint32(st) != pdhNoData {
		return nil, pdhErr(st)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(perfSampleGap):
	}
	if st, _, _ := procPdhCollectQueryData.Call(uintptr(q)); st != 0 {
		return nil, pdhErr(st)
	}
	out := make([][]perfValue, len(paths))
	for i, c := range counters {
		vals, err := pdhArray(c)
		if err != nil {
			return nil, err
		}
		out[i] = vals
	}
	return out, nil
}

// pdhArray liest alle Instanzen eines Indikators. Der Puffer ist auf 8 Byte
// ausgerichtet ([]uint64); die Einträge werden über feste Versätze gelesen,
// damit die Ausrichtung von double auf 386 keine Rolle spielt.
func pdhArray(c windows.Handle) ([]perfValue, error) {
	var size, count uint32
	st, _, _ := procPdhGetFormattedArray.Call(uintptr(c), pdhFmtDouble|pdhFmtNoCap100,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(st) != pdhMoreData {
		if st == 0 {
			return []perfValue{}, nil
		}
		return nil, pdhErr(st)
	}
	if size == 0 || size > maxPerfBuffer {
		return nil, errors.New("Antwort der Leistungsindikatoren zu groß")
	}
	buf := make([]uint64, (size+7)/8)
	st, _, _ = procPdhGetFormattedArray.Call(uintptr(c), pdhFmtDouble|pdhFmtNoCap100,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if st != 0 {
		return nil, pdhErr(st)
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	n := min(int(count), len(raw)/pdhItemSize, maxPerfInstances)
	out := make([]perfValue, 0, n)
	for i := 0; i < n; i++ {
		item := raw[i*pdhItemSize : (i+1)*pdhItemSize]
		status := *(*uint32)(unsafe.Pointer(&item[pdhItemStatusOffset]))
		if status != pdhCstatusValidData && status != pdhCstatusNewData {
			continue
		}
		name := ""
		if p := *(**uint16)(unsafe.Pointer(&item[0])); p != nil {
			name = windows.UTF16PtrToString(p)
		}
		out = append(out, perfValue{Instance: name, Value: *(*float64)(unsafe.Pointer(&item[pdhItemValueOffset]))})
	}
	return out, nil
}
