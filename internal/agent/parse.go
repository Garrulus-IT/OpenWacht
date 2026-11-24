// SPDX-License-Identifier: AGPL-3.0-only

// Package agent enthält den Agent: Messwerte sammeln, bei der Zentrale
// registrieren, regelmäßig melden und das Zertifikat erneuern.
//
// Der Agent sendet nur (Leitprinzip 1): Er öffnet keinen Port und führt nichts
// aus, was die Zentrale schickt. Von der Antwort nutzt er nur das gewünschte
// Meldeintervall, begrenzt auf einen festen Bereich.
package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Diese Parser sind reine Funktionen, damit sie auf jedem System mit
// festen Beispieldaten getestet werden können.

// cpuSample sind die summierten Zeiten aus der ersten Zeile von /proc/stat.
type cpuSample struct {
	idle, total uint64
}

// parseProcStat liefert die Gesamtzeiten und die Zahl der Kerne.
func parseProcStat(r io.Reader) (cpuSample, int, error) {
	sc := bufio.NewScanner(r)
	var s cpuSample
	cores, found := 0, false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "cpu":
			if len(f) < 5 {
				return s, 0, errors.New("/proc/stat: Zeile cpu unvollständig")
			}
			for i, v := range f[1:] {
				n, err := strconv.ParseUint(v, 10, 64)
				if err != nil {
					return s, 0, fmt.Errorf("/proc/stat: %w", err)
				}
				// Feld 9 und 10 (guest, guest_nice) stecken schon in user/nice.
				if i >= 8 {
					break
				}
				s.total += n
				if i == 3 || i == 4 { // idle, iowait
					s.idle += n
				}
			}
			found = true
		case strings.HasPrefix(f[0], "cpu"):
			cores++
		}
	}
	if !found {
		return s, 0, errors.New("/proc/stat: keine Zeile cpu")
	}
	if cores == 0 {
		cores = 1
	}
	return s, cores, sc.Err()
}

// cpuPercent berechnet die Auslastung zwischen zwei Messungen.
func cpuPercent(prev, cur cpuSample) float64 {
	dt := float64(cur.total - prev.total)
	if cur.total <= prev.total || dt == 0 {
		return 0
	}
	busy := dt - float64(cur.idle-prev.idle)
	p := busy / dt * 100
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// parseMeminfo liest die Werte in Bytes.
func parseMeminfo(r io.Reader) (total, available, swapTotal, swapFree uint64, err error) {
	want := map[string]*uint64{"MemTotal:": &total, "MemAvailable:": &available, "SwapTotal:": &swapTotal, "SwapFree:": &swapFree}
	sc := bufio.NewScanner(r)
	seen := 0
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		if p, ok := want[f[0]]; ok {
			n, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, 0, 0, 0, fmt.Errorf("/proc/meminfo: %w", err)
			}
			*p = n * 1024 // Angabe in kB
			seen++
		}
	}
	if total == 0 {
		return 0, 0, 0, 0, errors.New("/proc/meminfo: MemTotal fehlt")
	}
	if available > total {
		available = total
	}
	if swapFree > swapTotal {
		swapFree = swapTotal
	}
	return total, available, swapTotal, swapFree, sc.Err()
}

func parseLoadavg(s string) (l1, l5, l15 float64, err error) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return 0, 0, 0, errors.New("/proc/loadavg: unvollständig")
	}
	v := make([]float64, 3)
	for i := range v {
		if v[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return 0, 0, 0, fmt.Errorf("/proc/loadavg: %w", err)
		}
	}
	return v[0], v[1], v[2], nil
}

func parseUptime(s string) (uint64, error) {
	f := strings.Fields(s)
	if len(f) < 1 {
		return 0, errors.New("/proc/uptime: leer")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("/proc/uptime: %v", err)
	}
	return uint64(v), nil
}

// parseOSRelease liefert PRETTY_NAME (ersatzweise NAME VERSION).
func parseOSRelease(r io.Reader) string {
	vals := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		vals[k] = v
	}
	if p := vals["PRETTY_NAME"]; p != "" {
		return p
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION"])
}

// Dateisysteme, die echte Platten oder Netzlaufwerke sind. Alles andere
// (tmpfs, proc, overlay, squashfs …) wird nicht gemeldet.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true, "reiserfs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "ceph": true, "glusterfs": true,
}

type mount struct {
	Point, FSType, Device string
}

// parseMountinfo liest /proc/self/mountinfo und liefert je Gerät nur einen
// Einhängepunkt (den kürzesten). So zählen Bind-Mounts und die Sandbox von
// systemd eine Platte nicht doppelt.
func parseMountinfo(r io.Reader) ([]mount, error) {
	byDev := map[string]mount{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) < 5 || len(rf) < 1 {
			continue
		}
		dev, point, fstype := lf[2], unescapeMount(lf[4]), rf[0]
		if !realFS[fstype] {
			continue
		}
		if old, ok := byDev[dev]; !ok || len(point) < len(old.Point) {
			byDev[dev] = mount{Point: point, FSType: fstype, Device: dev}
		}
	}
	out := make([]mount, 0, len(byDev))
	for _, m := range byDev {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })
	return out, sc.Err()
}

// unescapeMount entschlüsselt die Oktal-Escapes (\040 = Leerzeichen) in mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// clip kürzt Text auf höchstens n Zeichen und entfernt Steuerzeichen, damit
// die Zentrale die Meldung nicht wegen eines exotischen Systemnamens ablehnt.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
