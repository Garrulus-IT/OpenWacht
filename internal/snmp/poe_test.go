// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

// PoE-Ports (pethPsePortDetectionStatus) landen mit Gruppe, Port und Zustand
// im Snapshot; unplausible Zeilen fallen weg, ein Gerät ohne die Tabelle hat
// keine und meldet dafür keinen Fehler.
func TestPoEPorts(t *testing.T) {
	c := loopbackClient()
	for _, v := range []string{V1, V2c} {
		f := snmptest.New(t, "c",
			snmptest.Num(oidPethPsePortDetectionStatus+".1.1", 1),
			snmptest.Num(oidPethPsePortDetectionStatus+".1.2", 3),
			snmptest.Num(oidPethPsePortDetectionStatus+".1.3", 4),
			snmptest.Num(oidPethPsePortDetectionStatus+".1.4", 9), // kein gültiger Zustand
			snmptest.Str(oidPethPsePortDetectionStatus+".1.5", "x"),
		)
		snap, err := c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := []PoEPort{{1, 1, 1}, {1, 2, 3}, {1, 3, 4}}
		if len(snap.PoE) != len(want) {
			t.Fatalf("v%s: %+v", v, snap.PoE)
		}
		for i := range want {
			if snap.PoE[i] != want[i] {
				t.Errorf("v%s: Port %d: %+v", v, i, snap.PoE[i])
			}
		}
		if len(snap.Partial) != 0 {
			t.Errorf("v%s: teilweise %v", v, snap.Partial)
		}
		if err := roundtrip(t, snap).ValidateCollected(time.Now()); err != nil {
			t.Errorf("v%s: ValidateCollected: %v", v, err)
		}

		ohne := snmptest.New(t, "c", snmptest.Str("1.3.6.1.2.1.2.2.1.2.1", "eth0"))
		snap, err = c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: ohne.Port(), Community: "c"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.PoE) != 0 || len(snap.Partial) != 0 {
			t.Errorf("v%s ohne PoE: %+v, teilweise %v", v, snap.PoE, snap.Partial)
		}
	}
	// Ein Sammler darf keine unplausiblen Ports schicken.
	f := snmptest.New(t, "c", snmptest.Num(oidPethPsePortDetectionStatus+".1.1", 3))
	snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := roundtrip(t, snap)
	bad.PoE[0].Status = 7
	if bad.ValidateCollected(time.Now()) == nil {
		t.Error("Zustand 7 angenommen")
	}
	bad = roundtrip(t, snap)
	bad.PoE = make([]PoEPort, MaxPoEPorts+1)
	if bad.ValidateCollected(time.Now()) == nil {
		t.Error("zu viele PoE-Ports angenommen")
	}
}
