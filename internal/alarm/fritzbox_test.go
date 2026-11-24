// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func TestEvaluateFritzBox(t *testing.T) {
	snap := func(conn string, ok bool, lastErr string) *snmp.Snapshot {
		return &snmp.Snapshot{FritzBox: &snmp.FritzBox{Model: "FRITZ!Box 7590", Connection: conn, Connected: ok, LastError: lastErr}}
	}
	in := SNMPInput{Name: "fritz", Interval: time.Minute, FritzBox: true, Snapshot: snap("Connected", true, "ERROR_NONE")}
	got := findings(EvaluateSNMP(in, nil, snmpLim))
	if f := got[SubjectWAN]; f.Status != OK || f.Name != "fritz · Internet" {
		t.Errorf("verbunden: %+v", f)
	}
	in.Snapshot = snap("Disconnected", false, "ERROR_NO_CARRIER")
	got = findings(EvaluateSNMP(in, nil, snmpLim))
	if f := got[SubjectWAN]; f.Status != Crit || !strings.Contains(f.Message, "getrennt") || !strings.Contains(f.Message, "ERROR_NO_CARRIER") {
		t.Errorf("getrennt: %+v", f)
	}
	in.Snapshot = snap("Connecting", false, "ERROR_NONE")
	got = findings(EvaluateSNMP(in, nil, snmpLim))
	if f := got[SubjectWAN]; f.Status != Warn || strings.Contains(f.Message, "ERROR_NONE") {
		t.Errorf("aufbauend: %+v", f)
	}
	// Ohne Recht für die Verbindung: kein Urteil, ein alter Alarm wird entwarnt.
	in.Snapshot = snap("", false, "")
	got = findings(EvaluateSNMP(in, map[string]string{SubjectWAN: Crit}, snmpLim))
	if f := got[SubjectWAN]; f.Status != OK || !strings.Contains(f.Message, "nicht mehr") {
		t.Errorf("unbekannt: %+v", f)
	}
	// Stumm: Text mit TR-064
	in.Silent = time.Hour
	got = findings(EvaluateSNMP(in, nil, snmpLim))
	if f := got[SubjectSilent]; f.Status != Crit || !strings.Contains(f.Message, "TR-064") {
		t.Errorf("stumm: %+v", f)
	}
	if !SNMPSubject(SubjectWAN) || SensorName(SubjectWAN) != "Internet" {
		t.Errorf("Gegenstand: %v %q", SNMPSubject(SubjectWAN), SensorName(SubjectWAN))
	}
}
