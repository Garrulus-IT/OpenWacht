// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func i64(v int64) *int64 { return &v }

func ontapSnap() *snmp.Snapshot {
	return &snmp.Snapshot{
		Disks: []snmp.Disk{{Mount: "Aggregat aggr1", TotalBytes: 100, FreeBytes: 50}, {Mount: "Aggregat aggr2", TotalBytes: 100, FreeBytes: 3},
			{Mount: "Volume svm1/daten", TotalBytes: 100, FreeBytes: 80}},
		ONTAP: &snmp.ONTAP{Cluster: "aff",
			Nodes: []snmp.ONTAPNode{
				{Name: "n1", State: "up", HA: true, Partner: "n2", Takeover: "not_attempted"},
				{Name: "n2", State: "waiting_for_giveback", HA: true, Partner: "n1"},
				{Name: "n3", State: "up", HA: false, Partner: "n4", FailedPSUs: 1},
				{Name: "n4", State: "up", HA: true, Partner: "n3", Takeover: "not_possible"},
				{Name: "solo", State: "up", Takeover: "not_possible"},
				{Name: "heiss", State: "up", OverTemp: true, FailedFans: 2},
			},
			Aggregates: []snmp.ONTAPAggregate{{Name: "aggr1", State: "online", IOPS: fp(10), LatencyMs: fp(0.4)},
				{Name: "aggr2", State: "online"}, {Name: "aggr3", State: "offline"}, {Name: "aggr4", State: "relocating"}},
			Volumes: []snmp.ONTAPVolume{{Name: "svm1/daten", State: "online", Type: "rw"}, {Name: "svm1/alt", State: "offline", Type: "rw"},
				{Name: "svm1/kaputt", State: "error", Type: "rw"}},
			Disks: snmp.ONTAPDisks{Total: 24, Spares: 1, Bad: []snmp.ONTAPDisk{{Name: "1.0.2", State: "broken", Container: "broken"},
				{Name: "1.0.7", State: "copy", Container: "aggregate"}}},
			Shelves: []snmp.ONTAPShelf{
				{ID: "1.0", State: "error", Parts: []snmp.ONTAPPart{{Kind: "psu", ID: "1", State: "ok"}, {Kind: "psu", ID: "2", State: "error"}},
					Temps: []snmp.ONTAPTemp{{ID: "1", Celsius: ip(32), Warn: ip(50), Crit: ip(60), State: "ok"}}},
				{ID: "1.1", State: "ok", Temps: []snmp.ONTAPTemp{{ID: "1", Celsius: ip(52), Warn: ip(50), Crit: ip(60), State: "ok"}}},
				{ID: "1.2", State: "ok", Parts: []snmp.ONTAPPart{{Kind: "fan", ID: "1", State: "ok"}},
					Temps: []snmp.ONTAPTemp{{ID: "1", Celsius: ip(30), Warn: ip(50), Crit: ip(60), State: "ok"}}},
				{ID: "1.3", State: "ok", Temps: []snmp.ONTAPTemp{{ID: "2", Celsius: ip(61), Warn: ip(50), Crit: ip(60), State: "ok"}}},
			},
			Mirrors: []snmp.ONTAPMirror{
				{Destination: "svm2:a", Source: "q:a", State: "snapmirrored", Healthy: true, LagS: i64(3600)},
				{Destination: "svm2:b", Source: "q:b", State: "snapmirrored", Healthy: true, LagS: i64(30 * 3600)},
				{Destination: "svm2:c", Source: "q:c", State: "snapmirrored", Healthy: true, LagS: i64(51 * 3600)},
				{Destination: "svm2:d", Source: "q:d", State: "snapmirrored", Healthy: false, Reason: "Transfer fehlgeschlagen"},
				{Destination: "svm2:e", State: "broken_off", Healthy: true},
			},
			Events: []snmp.ONTAPEvent{
				{Time: "2026-11-23T08:00:00Z", Name: "disk.outOfService", Severity: "alert", Node: "n1", Message: "Platte 1.0.2"},
				{Time: "2026-11-23T08:10:00Z", Name: "disk.outOfService", Severity: "alert", Node: "n1", Message: "Platte 1.0.3"},
				{Time: "2026-11-23T08:05:00Z", Name: "monitor.fan.critical", Severity: "emergency", Node: "n2", Message: "Lüfter"},
			},
		},
	}
}

func TestEvaluateONTAP(t *testing.T) {
	in := SNMPInput{Name: "aff", Interval: time.Minute, Snapshot: ontapSnap(), ONTAP: true}
	got := findings(EvaluateSNMP(in, nil, snmpLim))
	want := map[string]string{
		SubjectSilent: OK, "platte:Aggregat aggr1": OK, "platte:Aggregat aggr2": Crit, "platte:Volume svm1/daten": OK,
		"knoten:n1": OK, "knoten:n2": Crit, "knoten:n3": Crit, "knoten:n4": Warn, "knoten:solo": OK, "knoten:heiss": Crit,
		"aggregat:aggr3": Crit, "aggregat:aggr4": Warn,
		"volume:svm1/alt": Warn, "volume:svm1/kaputt": Crit,
		SubjectDisks: Crit,
		"shelf:1.0":  Crit, "shelf:1.1": Warn, "shelf:1.2": OK, "shelf:1.3": Crit,
		"snapmirror:svm2:a": OK, "snapmirror:svm2:b": Warn, "snapmirror:svm2:c": Crit, "snapmirror:svm2:d": Crit, "snapmirror:svm2:e": Warn,
		"ems:disk.outOfService": Crit, "ems:monitor.fan.critical": Crit,
	}
	for sub, st := range want {
		if got[sub].Status != st {
			t.Errorf("%s: %q (%s), erwartet %q", sub, got[sub].Status, got[sub].Message, st)
		}
		if !SNMPSubject(sub) {
			t.Errorf("%s gilt nicht als Gegenstand", sub)
		}
	}
	// Online-Aggregate und -Volumes ohne frühere Störung: kein eigener Sensor (Belegung steht unter „Aggregat …“).
	for _, sub := range []string{"aggregat:aggr1", "aggregat:aggr2", "volume:svm1/daten"} {
		if f, ok := got[sub]; ok {
			t.Errorf("%s bewertet: %+v", sub, f)
		}
	}
	for sub, parts := range map[string][]string{
		"platte:Aggregat aggr2":    {"97 %"},
		SubjectDisks:               {"1 Platte(n) ausgefallen: 1.0.2", "1 Ersatzplatte", "1.0.7 wird ersetzt"},
		"knoten:n1":                {"HA mit n2 bereit"},
		"knoten:n2":                {"übernommen"},
		"knoten:n3":                {"Speicher-Failover ausgeschaltet", "1 Netzteil(e) ausgefallen"},
		"knoten:n4":                {"Übernahme des Partners nicht möglich"},
		"knoten:heiss":             {"Übertemperatur", "2 Lüfter"},
		"shelf:1.0":                {"Netzteil 2 gestört"},
		"shelf:1.1":                {"52 °C", "Warnung ab 50"},
		"shelf:1.3":                {"61 °C", "kritisch ab 60"},
		"snapmirror:svm2:c":        {"Verzögerung 51 Std.", "kritisch ab 50 Std.", "von q:c"},
		"snapmirror:svm2:d":        {"Transfer fehlgeschlagen"},
		"ems:disk.outOfService":    {"n1: Platte 1.0.3", "alert"},
		"ems:monitor.fan.critical": {"n2: Lüfter", "emergency"},
	} {
		for _, p := range parts {
			if !strings.Contains(got[sub].Message, p) {
				t.Errorf("%s: %q ohne %q", sub, got[sub].Message, p)
			}
		}
	}
	if n := got["platte:Aggregat aggr2"].Name; n != "aff · Aggregat aggr2" {
		t.Errorf("Name: %q", n)
	}
	if n := got["volume:svm1/alt"].Name; n != "aff · Volume svm1/alt Zustand" {
		t.Errorf("Name: %q", n)
	}
}

func TestONTAPEntwarnungUndTeile(t *testing.T) {
	snap := ontapSnap()
	prev := map[string]string{"aggregat:aggr1": Crit, "ems:alt.meldung": Crit, "shelf:9.9": Crit, "snapmirror:svm2:x": Warn}
	got := findings(EvaluateSNMP(SNMPInput{Name: "aff", Interval: time.Minute, Snapshot: snap, ONTAP: true}, prev, snmpLim))
	if got["aggregat:aggr1"].Status != OK || got["ems:alt.meldung"].Status != OK || !strings.Contains(got["ems:alt.meldung"].Message, "letzten Stunde") {
		t.Errorf("Entwarnung: %+v %+v", got["aggregat:aggr1"], got["ems:alt.meldung"])
	}
	if got["shelf:9.9"].Status != OK || got["shelf:9.9"].Name != "aff · Shelf 9.9" {
		t.Errorf("verschwundenes Shelf: %+v", got["shelf:9.9"])
	}

	// Teile, deren Abfrage scheiterte, behalten ihren Zustand.
	snap = ontapSnap()
	snap.Partial = []string{"Shelves", "EMS", "Platten", "SnapMirror"}
	snap.ONTAP.Shelves, snap.ONTAP.Events, snap.ONTAP.Mirrors = nil, nil, nil
	snap.ONTAP.Disks = snmp.ONTAPDisks{}
	prev = map[string]string{"shelf:1.0": Crit, "ems:disk.outOfService": Crit, SubjectDisks: Crit, "snapmirror:svm2:c": Crit}
	got = findings(EvaluateSNMP(SNMPInput{Name: "aff", Interval: time.Minute, Snapshot: snap, ONTAP: true}, prev, snmpLim))
	for sub := range prev {
		if got[sub].Status != Crit || !strings.Contains(got[sub].Message, "nicht abfragbar") {
			t.Errorf("%s: %+v", sub, got[sub])
		}
	}

	// Viele EMS-Meldungen: höchstens MaxEventSubjects Gegenstände.
	snap = ontapSnap()
	snap.ONTAP.Events = nil
	for i := range 30 {
		snap.ONTAP.Events = append(snap.ONTAP.Events, snmp.ONTAPEvent{Time: "2026-11-23T08:00:00Z", Name: "m" + string(rune('a'+i)), Severity: "alert"})
	}
	n := 0
	for _, f := range EvaluateSNMP(SNMPInput{Name: "aff", Interval: time.Minute, Snapshot: snap, ONTAP: true}, nil, snmpLim) {
		if strings.HasPrefix(f.Subject, emsPrefix) {
			n++
		}
	}
	if n != MaxEventSubjects {
		t.Errorf("EMS-Gegenstände: %d", n)
	}

	// Ausgeschaltet und stumm: Texte für NetApp
	off := EvaluateSNMP(SNMPInput{Name: "aff", Disabled: true, ONTAP: true}, map[string]string{"knoten:n1": Crit}, snmpLim)
	if len(off) != 1 || !strings.Contains(off[0].Message, "NetApp") || off[0].Name != "aff · Knoten n1" {
		t.Errorf("aus: %+v", off)
	}
	silent := EvaluateSNMP(SNMPInput{Name: "aff", Silent: time.Hour, Interval: time.Minute, ONTAP: true, LastError: "Konto mit Schreibrecht abgelehnt"}, nil, snmpLim)
	if len(silent) != 1 || !strings.Contains(silent[0].Message, "ONTAP-API") || !strings.Contains(silent[0].Message, "Schreibrecht") {
		t.Errorf("stumm: %+v", silent)
	}
}

func TestONTAPGegenstaende(t *testing.T) {
	for _, bad := range []string{"knoten:", "aggregat:", "volume:", "shelf:", "snapmirror:", "ems:", "plattenx"} {
		if SNMPSubject(bad) {
			t.Errorf("%q angenommen", bad)
		}
	}
	for _, sub := range []string{"platten", "knoten:aff-01", "volume:svm1/daten", "snapmirror:svm2:a", "ems:disk.outOfService"} {
		if !SNMPSubject(sub) {
			t.Errorf("%q abgelehnt", sub)
		}
		if n := SensorName(sub); n == "" || strings.Contains(n, ":") && !strings.Contains(sub, "snapmirror") {
			t.Errorf("Sensorname %q: %q", sub, n)
		}
	}
}

func TestONTAPReihen(t *testing.T) {
	names, values := snmp.Series(ontapSnap())
	got := map[string]float64{}
	for i, n := range names {
		got[n] = values[i]
	}
	if got["iops:aggr1"] != 10 || got["latenz:aggr1"] != 0.4 || got["platte:Aggregat aggr2"] != 97 {
		t.Errorf("Reihen: %v", got)
	}
	if _, ok := got["iops:aggr2"]; ok {
		t.Error("Reihe ohne Messung")
	}
	if names[0] != "iops:aggr1" {
		t.Errorf("Leistung nicht vorn: %v", names)
	}
}
