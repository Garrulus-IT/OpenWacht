// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package checks

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ping unter Windows (Zentrale auf Windows Server, 1.0.14) über die
// ICMP-Funktionen von Windows (iphlpapi: IcmpSendEcho), ohne Raw-Socket und
// ohne Administratorrechte. Nur IPv4; IPv6-Ziele melden „nicht unterstützt“.

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply: Anfang von ICMP_ECHO_REPLY. Gelesen werden nur die ersten
// drei Felder; der Puffer für IcmpSendEcho ist größer als die ganze Struktur
// unter 64 Bit (40 Byte) samt Daten.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [8]byte
}

func pingCheck(ctx context.Context, g *Guard, s Spec, timeout time.Duration) Result {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	addrs, err := g.Resolve(rctx, s.Host)
	cancel()
	if err != nil {
		return describeNetErr(err, timeout, "")
	}
	var ip4 [4]byte
	found := false
	for _, a := range addrs {
		if a.Is4() {
			ip4, found = a.As4(), true
			break
		}
	}
	if !found {
		return Result{Unknown, "Ping über IPv6 wird unter Windows nicht unterstützt", "", 0}
	}
	if err := procIcmpCreateFile.Find(); err != nil {
		return Result{Unknown, "Ping nicht möglich: " + clean(err.Error(), 120), "", 0}
	}
	h, _, callErr := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return Result{Unknown, "Ping nicht möglich: " + clean(fmt.Sprint(callErr), 120), "", 0}
	}
	defer procIcmpCloseHandle.Call(h)

	count := s.Count
	if count < 1 {
		count = 3
	}
	ms := uint32(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	addr := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	var rtts []time.Duration
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		payload := make([]byte, 16)
		rand.Read(payload)
		reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+8+64)
		start := time.Now()
		n, _, _ := procIcmpSendEcho.Call(h, uintptr(addr),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(ms))
		if n == 0 {
			continue
		}
		r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		if r.Status != 0 || r.Address != addr {
			continue
		}
		rtt := time.Duration(r.RoundTripTime) * time.Millisecond
		if rtt == 0 {
			rtt = time.Since(start)
		}
		rtts = append(rtts, rtt)
	}
	return pingResult(s, count, rtts)
}
