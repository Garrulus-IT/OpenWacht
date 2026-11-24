// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package checks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// pingCheck sendet Echo-Anfragen über einen ICMP-Datagram-Socket. Der
// braucht weder Root noch CAP_NET_RAW, nur eine Gruppe aus
// net.ipv4.ping_group_range (bei Debian und Ubuntu Standard).
func pingCheck(ctx context.Context, g *Guard, s Spec, timeout time.Duration) Result {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	addrs, err := g.Resolve(rctx, s.Host)
	cancel()
	if err != nil {
		return describeNetErr(err, timeout, "")
	}
	ip := addrs[0]
	for _, a := range addrs { // IPv4 bevorzugen
		if a.Is4() {
			ip = a
			break
		}
	}
	conn, err := openPing(ip)
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return Result{Unknown, "Ping nicht erlaubt: Die Gruppe der Zentrale fehlt in net.ipv4.ping_group_range", "", 0}
		}
		return Result{Unknown, "Ping nicht möglich: " + clean(err.Error(), 120), "", 0}
	}
	defer conn.Close()

	count := s.Count
	if count < 1 {
		count = 3
	}
	var rtts []time.Duration
	for seq := 1; seq <= count; seq++ {
		if ctx.Err() != nil {
			break
		}
		rtt, err := echo(conn, ip, uint16(seq), timeout)
		if err == nil {
			rtts = append(rtts, rtt)
		}
	}
	return pingResult(s, count, rtts)
}

func openPing(ip netip.Addr) (net.PacketConn, error) {
	family, proto := syscall.AF_INET, syscall.IPPROTO_ICMP
	if ip.Is6() {
		family, proto = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "icmp")
	defer f.Close() // FilePacketConn dupliziert den Deskriptor
	return net.FilePacketConn(f)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// echo sendet eine Anfrage und wartet auf die passende Antwort. Die Kennung
// setzt der Kernel selbst; zugeordnet wird über Folgenummer und Zufallsdaten.
func echo(conn net.PacketConn, ip netip.Addr, seq uint16, timeout time.Duration) (time.Duration, error) {
	reqType, replyType := byte(8), byte(0)
	if ip.Is6() {
		reqType, replyType = 128, 129
	}
	payload := make([]byte, 16)
	rand.Read(payload)
	msg := make([]byte, 8+len(payload))
	msg[0] = reqType
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[8:], payload)
	if ip.Is4() {
		binary.BigEndian.PutUint16(msg[2:], checksum(msg)) // bei IPv6 rechnet der Kernel
	}
	start := time.Now()
	deadline := start.Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	if _, err := conn.WriteTo(msg, &net.UDPAddr{IP: ip.AsSlice()}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(ua.IP)
		if src.Unmap() != ip || n < 8+len(payload) || buf[0] != replyType ||
			binary.BigEndian.Uint16(buf[6:]) != seq || string(buf[8:8+len(payload)]) != string(payload) {
			continue
		}
		return time.Since(start), nil
	}
}
