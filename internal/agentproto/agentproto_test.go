// SPDX-License-Identifier: AGPL-3.0-only

package agentproto

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	fp := strings.Repeat("A", 42) + "_"
	// Viele Durchläufe: Geheimnisse mit "-" und "_" müssen sicher zerlegt werden.
	for i := 0; i < 200; i++ {
		tok, secret, _ := NewToken(fp)
		if s2, fp2, err := ParseToken(tok); err != nil || string(s2) != string(secret) || fp2 != fp {
			t.Fatalf("Durchlauf %d: %q: %v", i, tok, err)
		}
	}
	tok, secret, err := NewToken(fp)
	if err != nil {
		t.Fatal(err)
	}
	s2, fp2, err := ParseToken("  " + tok + "\n")
	if err != nil || string(s2) != string(secret) || fp2 != fp {
		t.Fatalf("ParseToken: %v", err)
	}
	for _, bad := range []string{"", "wae2.x.y", "owa1.kurz", "owa1." + strings.Repeat("A", 43) + ".kurz", "owa1.!!." + fp, "wae1_" + strings.Repeat("A", 43) + "_" + fp} {
		if _, _, err := ParseToken(bad); err == nil {
			t.Errorf("Token %q akzeptiert", bad)
		}
	}
}

func valid(now time.Time) Snapshot {
	return Snapshot{
		CollectedAt: now, Hostname: "srv-test.example.org", OS: "Debian GNU/Linux 13 (trixie)", Kernel: "6.12.0",
		Arch: "amd64", AgentVersion: "0.1.0", UptimeSec: 3600,
		CPU:    CPU{Cores: 4, Percent: 12.5, Load1: 0.5, Load5: 0.4, Load15: 0.3},
		Memory: Memory{TotalBytes: 8 << 30, AvailableBytes: 4 << 30, SwapTotalBytes: 1 << 30, SwapFreeBytes: 1 << 30},
		Disks:  []Disk{{Mount: "/", FSType: "ext4", TotalBytes: 100 << 30, FreeBytes: 50 << 30}},
	}
}

func TestSnapshotValidierung(t *testing.T) {
	now := time.Now()
	s := valid(now)
	if err := s.Validate(now); err != nil {
		t.Fatalf("gültiger Snapshot abgelehnt: %v", err)
	}
	cases := map[string]func(*Snapshot){
		"Hostname mit Skript":       func(s *Snapshot) { s.Hostname = "<script>alert(1)</script>" },
		"Hostname leer":             func(s *Snapshot) { s.Hostname = "" },
		"Hostname Unicode":          func(s *Snapshot) { s.Hostname = "sérver" },
		"Steuerzeichen im OS":       func(s *Snapshot) { s.OS = "Debian\x1b[31m" },
		"OS zu lang":                func(s *Snapshot) { s.OS = strings.Repeat("x", 101) },
		"ungültiges UTF-8":          func(s *Snapshot) { s.Kernel = "\xff\xfe" },
		"Zeit in der Zukunft":       func(s *Snapshot) { s.CollectedAt = now.Add(time.Hour) },
		"Zeit fehlt":                func(s *Snapshot) { s.CollectedAt = time.Time{} },
		"CPU über 100 %":            func(s *Snapshot) { s.CPU.Percent = 150 },
		"CPU NaN":                   func(s *Snapshot) { s.CPU.Percent = math.NaN() },
		"Last unendlich":            func(s *Snapshot) { s.CPU.Load1 = math.Inf(1) },
		"keine Kerne":               func(s *Snapshot) { s.CPU.Cores = 0 },
		"ohne Last, aber Lastwerte": func(s *Snapshot) { s.CPU.NoLoad = true },
		"Speicher frei > gesamt":    func(s *Snapshot) { s.Memory.AvailableBytes = s.Memory.TotalBytes + 1 },
		"Platte frei > gesamt":      func(s *Snapshot) { s.Disks[0].FreeBytes = s.Disks[0].TotalBytes + 1 },
		"Einhängepunkt mit Umbruch": func(s *Snapshot) { s.Disks[0].Mount = "/a\nb" },
		"zu viele Platten": func(s *Snapshot) {
			for i := 0; i <= MaxDisks; i++ {
				s.Disks = append(s.Disks, Disk{Mount: "/x", TotalBytes: 1})
			}
		},
	}
	// So meldet der Windows-Agent.
	w := valid(now)
	w.OS, w.Kernel = "Windows 11 Pro 24H2", "10.0.26100.4349"
	w.CPU = CPU{Cores: 8, Percent: 3, NoLoad: true}
	w.Disks = []Disk{{Mount: "C:", FSType: "ntfs", TotalBytes: 500 << 30, FreeBytes: 200 << 30}}
	if err := w.Validate(now); err != nil {
		t.Fatalf("Windows-Snapshot abgelehnt: %v", err)
	}
	for name, mod := range cases {
		s := valid(now)
		mod(&s)
		if err := s.Validate(now); err == nil {
			t.Errorf("%s: akzeptiert", name)
		}
	}
}

// Ein abgeschnittenes oder mit Anführungszeichen eingefügtes Token nennt in der
// Meldung, was zu tun ist, und die erwartete Länge stimmt mit NewToken überein.
func TestTokenKopierfehler(t *testing.T) {
	tok, _, err := NewToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != TokenLen || TokenLen != 92 {
		t.Fatalf("len(token) = %d, TokenLen = %d, erwartet 92", len(tok), TokenLen)
	}
	for _, kaputt := range []string{tok[:len(tok)-3], tok + "'", "'" + tok, tok[:40]} {
		_, _, err := ParseToken(kaputt)
		if err == nil {
			t.Fatalf("ParseToken(%q…) ohne Fehler", kaputt[:10])
		}
		if !strings.Contains(err.Error(), "neu kopieren") || !strings.Contains(err.Error(), "92 Zeichen") {
			t.Errorf("Meldung ohne Hinweis: %v", err)
		}
	}
	if _, _, err := ParseToken(" " + tok + "\n"); err != nil {
		t.Errorf("Leerzeichen am Rand sollten nicht stören: %v", err)
	}
}
