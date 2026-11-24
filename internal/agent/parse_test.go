// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProcStat(t *testing.T) {
	a := "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1\n"
	b := "cpu  150 0 150 900 0 0 0 0 50 0\ncpu0 75 0 75 450 0 0 0 0 0 0\ncpu1 75 0 75 450 0 0 0 0 0 0\n"
	s1, cores, err := parseProcStat(strings.NewReader(a))
	if err != nil || cores != 2 {
		t.Fatalf("cores %d, %v", cores, err)
	}
	s2, _, _ := parseProcStat(strings.NewReader(b))
	// 200 Ticks, davon 100 Leerlauf -> 50 %. guest (50) zählt nicht doppelt.
	if p := cpuPercent(s1, s2); p != 50 {
		t.Errorf("Auslastung %v, erwartet 50", p)
	}
	if p := cpuPercent(s2, s1); p != 0 {
		t.Errorf("Rückwärts (Zähler zurückgesetzt): %v", p)
	}
	if p := cpuPercent(s1, s1); p != 0 {
		t.Errorf("ohne Zeitdifferenz: %v", p)
	}
	for _, bad := range []string{"", "cpu 1 2\n", "cpu a b c d\n"} {
		if _, _, err := parseProcStat(strings.NewReader(bad)); err == nil {
			t.Errorf("%q akzeptiert", bad)
		}
	}
}

func TestMeminfo(t *testing.T) {
	in := "MemTotal:       16384000 kB\nMemFree:  100 kB\nMemAvailable:    8192000 kB\nSwapTotal: 1024 kB\nSwapFree: 2048 kB\n"
	total, avail, st, sf, err := parseMeminfo(strings.NewReader(in))
	if err != nil || total != 16384000*1024 || avail != 8192000*1024 || st != 1024*1024 || sf != st {
		t.Fatalf("%d %d %d %d %v (SwapFree größer als gesamt muss gekappt werden)", total, avail, st, sf, err)
	}
	if _, _, _, _, err := parseMeminfo(strings.NewReader("MemFree: 1 kB\n")); err == nil {
		t.Error("ohne MemTotal akzeptiert")
	}
}

func TestMountinfo(t *testing.T) {
	in := strings.Join([]string{
		`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw`,
		`23 22 0:21 / /proc rw - proc proc rw`,
		`24 22 0:22 / /run rw - tmpfs tmpfs rw`,
		`25 22 8:1 /var/lib/openwacht-agent /var/lib/openwacht-agent rw - ext4 /dev/sda1 rw`,
		`26 22 8:17 / /mnt/daten\040neu rw - xfs /dev/sdb1 rw`,
		`27 22 0:40 / /mnt/nas rw - nfs4 nas:/export rw`,
		`28 22 0:41 / /snap/core rw - squashfs /dev/loop0 ro`,
		`kaputte zeile ohne trenner`,
	}, "\n")
	ms, err := parseMountinfo(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range ms {
		got = append(got, m.Point+"="+m.FSType)
	}
	want := "/=ext4,/mnt/daten neu=xfs,/mnt/nas=nfs4"
	if strings.Join(got, ",") != want {
		t.Errorf("Einhängepunkte %v, erwartet %s (Bind-Mount doppelt, Pseudo-Dateisysteme dabei?)", got, want)
	}
}

func TestKleineParser(t *testing.T) {
	if a, b, c, err := parseLoadavg("0.52 0.40 0.31 1/234 5678\n"); err != nil || a != 0.52 || b != 0.40 || c != 0.31 {
		t.Errorf("loadavg: %v %v %v %v", a, b, c, err)
	}
	if _, _, _, err := parseLoadavg("x"); err == nil {
		t.Error("loadavg kaputt akzeptiert")
	}
	if u, err := parseUptime("12345.67 999.0\n"); err != nil || u != 12345 {
		t.Errorf("uptime: %v %v", u, err)
	}
	if os := parseOSRelease(strings.NewReader("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n")); os != "Debian GNU/Linux 13 (trixie)" {
		t.Errorf("os-release: %q", os)
	}
	if os := parseOSRelease(strings.NewReader("NAME='Rocky Linux'\nVERSION=\"9.5 (Blue Onyx)\"\n")); os != "Rocky Linux 9.5 (Blue Onyx)" {
		t.Errorf("os-release ohne PRETTY_NAME: %q", os)
	}
	if s := clip("Debian\x1b[31m rot\xff", 100); s != "Debian[31m rot" {
		t.Errorf("clip: %q", s)
	}
	if s := clip("äöüß", 2); s != "äö" {
		t.Errorf("clip Zeichen statt Bytes: %q", s)
	}
}

func TestEchteMesswerteSindGueltig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nur unter Linux")
	}
	snap, err := NewCollector().Collect()
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.Validate(time.Now()); err != nil {
		t.Fatalf("echte Messwerte würden abgelehnt: %v", err)
	}
	if snap.CPU.Cores < 1 || snap.Memory.TotalBytes == 0 || len(snap.Disks) == 0 {
		t.Errorf("unvollständig: %+v", snap)
	}
}

func TestUnit(t *testing.T) {
	u, err := RenderUnit("/usr/local/bin/openwacht-agent", DefaultDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=openwacht-agent", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n",
		"ProtectSystem=strict", "ReadWritePaths=/var/lib/openwacht-agent", "ProtectHome=read-only",
		"ExecStart=/usr/local/bin/openwacht-agent starten -verzeichnis /var/lib/openwacht-agent"} {
		if !strings.Contains(u, want) {
			t.Errorf("Unit enthält nicht %q", want)
		}
	}
	for _, bad := range []string{"relativ/pfad", "/mit leerzeichen", "/a\nExecStartPre=/bin/sh", "/a;rm", "/a$HOME", "/a%n"} {
		if _, err := RenderUnit(bad, DefaultDir); err == nil {
			t.Errorf("Pfad %q akzeptiert", bad)
		}
	}
}
