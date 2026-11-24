// SPDX-License-Identifier: AGPL-3.0-only

package traps

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

// ListenSystemd übernimmt den UDP-Socket, den systemd per
// Socket-Aktivierung übergibt (LISTEN_PID, LISTEN_FDS, Deskriptor 3). So
// bindet systemd Port 162, und der Dienst selbst braucht keine Capability.
// ok = false: Der Dienst wurde nicht von systemd mit Socket gestartet.
func ListenSystemd() (conn net.PacketConn, ok bool, err error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n != 1 {
		return nil, false, fmt.Errorf("systemd übergibt %q Sockets, erwartet genau einen (openwacht-traps.socket)", os.Getenv("LISTEN_FDS"))
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	f := os.NewFile(3, "openwacht-traps.socket")
	defer f.Close()
	c, err := net.FilePacketConn(f)
	if err != nil {
		return nil, false, fmt.Errorf("Socket von systemd: %w", err)
	}
	if _, isUDP := c.(*net.UDPConn); !isUDP {
		c.Close()
		return nil, false, errors.New("Socket von systemd ist kein UDP-Socket (ListenDatagram=162 erwartet)")
	}
	return c, true, nil
}
