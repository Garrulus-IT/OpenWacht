// SPDX-License-Identifier: AGPL-3.0-only

package agentproto

// Fuzz-Ziele für das Agent-Protokoll (Befund M3): Alles, was ein Agent
// schickt, ist nicht vertrauenswürdig. Angenommene Daten müssen sich wieder
// speichern lassen und dürfen keine ungültigen Texte enthalten.

import (
	"encoding/json"
	"testing"
	"time"
	"unicode/utf8"
)

var fuzzNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func FuzzSnapshot(f *testing.F) {
	ok := Snapshot{CollectedAt: fuzzNow, Hostname: "srv-file01", OS: "Debian GNU/Linux 13", Kernel: "6.12", Arch: "amd64",
		AgentVersion: "0.32.0", CPU: CPU{Cores: 4}, Disks: []Disk{{Mount: "/", FSType: "ext4", TotalBytes: 100, FreeBytes: 50}},
		Collector: &Collector{Nets: []string{"10.10.0.0/16"}}, Sensors: &SensorRelease{Kinds: []string{"datei"}, Folders: []string{"/srv/backup"}}}
	b, _ := json.Marshal(ok)
	f.Add(b)
	f.Add([]byte(`{"erfasst":"2026-11-22T12:00:00Z","hostname":"a\u202eb","platten":[{"einhaengepunkt":"\u0000"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var s Snapshot
		if json.Unmarshal(b, &s) != nil || s.Validate(fuzzNow) != nil {
			return
		}
		out, err := json.Marshal(&s)
		if err != nil {
			t.Fatalf("angenommene Messwerte nicht speicherbar: %v", err)
		}
		var again Snapshot
		if err := json.Unmarshal(out, &again); err != nil || again.Validate(fuzzNow) != nil {
			t.Fatalf("gespeicherte Messwerte bestehen die Prüfung nicht mehr: %v", err)
		}
		if !utf8.ValidString(s.Hostname) {
			t.Fatal("Hostname kein UTF-8")
		}
		if s.Collector != nil {
			if _, err := ParseCollectorNets(s.Collector.Nets); err != nil {
				t.Fatalf("Netze angenommen, aber nicht lesbar: %v", err)
			}
		}
	})
}

func FuzzSensorResult(f *testing.F) {
	f.Add([]byte(`{"id":"8d6c1f0e-0000-4000-8000-000000000001","revision":1,"status":"ok","meldung":"läuft","messwert":"3"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r SensorResult
		if json.Unmarshal(b, &r) != nil || r.Validate() != nil {
			return
		}
		if !utf8.ValidString(r.Message) || !utf8.ValidString(r.Metric) {
			t.Fatal("Text kein UTF-8")
		}
	})
}

func FuzzSensorRelease(f *testing.F) {
	f.Add([]byte(`{"arten":["datei","docker"],"ordner":["/srv/backup"],"docker":"http://127.0.0.1:2375"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r SensorRelease
		if json.Unmarshal(b, &r) != nil {
			return
		}
		_ = r.Validate()
	})
}

func FuzzParseToken(f *testing.F) {
	tok, _, _ := NewToken("ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34")
	f.Add(tok)
	f.Add("owa1..")
	f.Fuzz(func(t *testing.T, s string) {
		secret, fp, err := ParseToken(s)
		if err != nil {
			return
		}
		if len(secret) == 0 || fp == "" {
			t.Fatal("leeres Token angenommen")
		}
	})
}

func FuzzParseCollectorNets(f *testing.F) {
	f.Add("10.10.0.0/16\x00fd00::/64")
	f.Add("0.0.0.0/0")
	f.Fuzz(func(t *testing.T, s string) {
		var nets []string
		for len(s) > 0 && len(nets) < 70 {
			i := 0
			for i < len(s) && s[i] != 0 {
				i++
			}
			nets = append(nets, s[:i])
			if i < len(s) {
				i++
			}
			s = s[i:]
		}
		ps, err := ParseCollectorNets(nets)
		if err != nil {
			return
		}
		for _, p := range ps {
			if p.Bits() == 0 {
				t.Fatalf("Netz %s ohne Grenze angenommen", p)
			}
		}
	})
}

// Das Startbeispiel muss die Prüfung bestehen, sonst fuzzt FuzzSnapshot nur Ablehnungen.
func TestFuzzSnapshotStart(t *testing.T) {
	s := Snapshot{CollectedAt: fuzzNow, Hostname: "srv-file01", OS: "Debian GNU/Linux 13", Kernel: "6.12", Arch: "amd64",
		AgentVersion: "0.32.0", CPU: CPU{Cores: 4}, Disks: []Disk{{Mount: "/", FSType: "ext4", TotalBytes: 100, FreeBytes: 50}},
		Collector: &Collector{Nets: []string{"10.10.0.0/16"}}, Sensors: &SensorRelease{Kinds: []string{"datei"}, Folders: []string{"/srv/backup"}}}
	if err := s.Validate(fuzzNow); err != nil {
		t.Fatal(err)
	}
}
