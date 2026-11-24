// SPDX-License-Identifier: AGPL-3.0-only

package agentproto

import (
	"strings"
	"testing"
	"time"
)

func TestParseCollectorNets(t *testing.T) {
	ok := [][]string{{"10.20.0.0/16"}, {"192.168.5.0/24", "127.0.0.1/32", "fd00::/8"}}
	for _, n := range ok {
		if _, err := ParseCollectorNets(n); err != nil {
			t.Errorf("%v: %v", n, err)
		}
	}
	many := make([]string, MaxCollectorNets+1)
	for i := range many {
		many[i] = "10.0.0.0/8"
	}
	bad := map[string][]string{
		"leer": {}, "alles v4": {"0.0.0.0/0"}, "alles v6": {"::/0"}, "nicht kanonisch": {"10.20.1.1/16"},
		"kein Netz": {"10.20.0.0"}, "Name": {"lan/24"}, "Zone": {"fe80::%eth0/64"}, "v4 in v6": {"::ffff:10.0.0.0/104"},
		"zu viele": many,
	}
	for name, n := range bad {
		if _, err := ParseCollectorNets(n); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
	if _, err := ParseCollectorNets([]string{strings.Repeat("x", 1000)}); err == nil || len(err.Error()) > 200 {
		t.Errorf("langer Eintrag: %v", err)
	}
}

func TestSnapshotMitSammler(t *testing.T) {
	s := Snapshot{CollectedAt: time.Now(), Hostname: "h", CPU: CPU{Cores: 1}, Collector: &Collector{Nets: []string{"10.0.0.0/8"}}}
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Collector.Nets = []string{"0.0.0.0/0"}
	if err := s.Validate(time.Now()); err == nil {
		t.Error("/0 angenommen")
	}
}
