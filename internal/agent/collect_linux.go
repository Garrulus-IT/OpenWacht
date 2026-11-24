// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Collector sammelt Messwerte. Er merkt sich die letzte CPU-Messung, damit
// die Auslastung über das Meldeintervall gemittelt wird.
type Collector struct {
	prev    cpuSample
	hasPrev bool
	root    string // Präfix für Tests; im Betrieb leer
}

func NewCollector() *Collector { return &Collector{} }

func (c *Collector) read(path string) ([]byte, error) { return os.ReadFile(c.root + path) }

// Collect liefert einen Snapshot. Beim ersten Aufruf wird die CPU zweimal im
// Abstand von einer Sekunde gemessen.
func (c *Collector) Collect() (agentproto.Snapshot, error) {
	var s agentproto.Snapshot
	stat, err := c.read("/proc/stat")
	if err != nil {
		return s, err
	}
	cur, cores, err := parseProcStat(bytes.NewReader(stat))
	if err != nil {
		return s, err
	}
	if !c.hasPrev {
		c.prev, c.hasPrev = cur, true
		time.Sleep(time.Second)
		if stat, err = c.read("/proc/stat"); err != nil {
			return s, err
		}
		if cur, _, err = parseProcStat(bytes.NewReader(stat)); err != nil {
			return s, err
		}
	}
	s.CPU.Cores = cores
	s.CPU.Percent = cpuPercent(c.prev, cur)
	c.prev = cur

	if b, err := c.read("/proc/loadavg"); err == nil {
		s.CPU.Load1, s.CPU.Load5, s.CPU.Load15, _ = parseLoadavg(string(b))
	}
	mi, err := c.read("/proc/meminfo")
	if err != nil {
		return s, err
	}
	if s.Memory.TotalBytes, s.Memory.AvailableBytes, s.Memory.SwapTotalBytes, s.Memory.SwapFreeBytes, err =
		parseMeminfo(bytes.NewReader(mi)); err != nil {
		return s, err
	}
	if b, err := c.read("/proc/uptime"); err == nil {
		s.UptimeSec, _ = parseUptime(string(b))
	}

	host, err := os.Hostname()
	if err != nil {
		return s, err
	}
	s.Hostname = strings.ToLower(host)
	if b, err := c.read("/etc/os-release"); err == nil {
		s.OS = clip(parseOSRelease(bytes.NewReader(b)), 100)
	} else if b, err := c.read("/usr/lib/os-release"); err == nil {
		s.OS = clip(parseOSRelease(bytes.NewReader(b)), 100)
	}
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		s.Kernel = clip(utsString(u.Release[:]), 100)
	}
	s.Arch = runtime.GOARCH
	s.AgentVersion = clip(version.Version, 40)

	if b, err := c.read("/proc/self/mountinfo"); err == nil {
		mounts, _ := parseMountinfo(bytes.NewReader(b))
		for _, m := range mounts {
			if len(s.Disks) >= agentproto.MaxDisks {
				break
			}
			var st syscall.Statfs_t
			if syscall.Statfs(m.Point, &st) != nil || st.Blocks == 0 {
				continue
			}
			bs := uint64(st.Bsize)
			s.Disks = append(s.Disks, agentproto.Disk{
				Mount:      clip(m.Point, 256),
				FSType:     m.FSType,
				TotalBytes: st.Blocks * bs,
				// Bavail: für normale Benutzer verfügbar (ohne Root-Reserve), wie df.
				FreeBytes: st.Bavail * bs,
			})
		}
	}
	s.CollectedAt = time.Now()
	return s, nil
}

func utsString[T int8 | uint8](b []T) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}
