// SPDX-License-Identifier: AGPL-3.0-only

package citrix

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// Antworten des Controllers sind fremde Daten: Build darf an nichts
// scheitern und speichert nur saubere, kurze Namen.
func FuzzBuild(f *testing.F) {
	f.Add([]byte(`[{"Name":"B\\VDA-01","CurrentRegistrationState":2,"IsInMaintenanceMode":false}]`), []byte(`[{"ConnectionFailureEnumValue":3}]`))
	f.Add([]byte(`[{"DnsName":"\u0000x","CurrentRegistrationState":-5}]`), []byte(`[{"ConnectionFailureEnumValue":1e9}]`))
	f.Fuzz(func(t *testing.T, machines, failures []byte) {
		var raw Raw
		if json.Unmarshal(machines, &raw.Machines) != nil {
			raw.Machines = nil
		}
		if json.Unmarshal(failures, &raw.Failures) != nil {
			raw.Failures = nil
		}
		x := Build(raw, "")
		if x.Machines != len(raw.Machines) || x.Unregistered+x.Maintenance > x.Machines || len(x.UnregisteredNames) > 50 {
			t.Fatalf("Zahlen: %+v", x)
		}
		sum := 0
		for _, f := range x.Failures {
			sum += f.Count
		}
		if sum != x.FailureTotal {
			t.Fatal("Summe der Fehlschläge")
		}
		for _, n := range x.UnregisteredNames {
			if !utf8.ValidString(n) || utf8.RuneCountInString(n) > 120 || strings.ContainsFunc(n, func(r rune) bool { return r < 32 || r == 127 }) {
				t.Fatalf("Name %q", n)
			}
		}
	})
}
