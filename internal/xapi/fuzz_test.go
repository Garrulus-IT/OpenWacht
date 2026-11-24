// SPDX-License-Identifier: AGPL-3.0-only

package xapi

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzParseRRD: beliebige Antworten von /rrd_updates dürfen nicht abstürzen und
// keine unplausiblen Werte liefern.
func FuzzParseRRD(f *testing.F) {
	h := "11111111-1111-4111-8111-111111111111"
	f.Add([]byte(`<xport><meta><legend><entry>AVERAGE:host:` + h + `:cpu_avg</entry></legend></meta><data><row><t>1</t><v>0.5</v></row></data></xport>`))
	f.Add([]byte(`<xport><meta><legend><entry>AVERAGE:vm:` + h + `:cpu0</entry><entry>x</entry></legend></meta><data><row><t>1</t><v>NaN</v><v>1e400</v></row></data></xport>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRRD(b, h)
		if err != nil {
			return
		}
		if r.HostCPU != nil && (*r.HostCPU < 0 || *r.HostCPU > 1) {
			t.Fatalf("CPU %v", *r.HostCPU)
		}
		if r.MemFree > r.MemTotal {
			t.Fatalf("RAM %d > %d", r.MemFree, r.MemTotal)
		}
		for _, v := range r.VMCPU {
			if v < 0 || v > 1 {
				t.Fatalf("VM-CPU %v", v)
			}
		}
	})
}

// FuzzBuild: beliebige Datensätze (wie von XAPI) ergeben einen gültigen Snapshot.
func FuzzBuild(f *testing.F) {
	f.Add([]byte(`{"OpaqueRef:p":{"name_label":"p","master":"OpaqueRef:h","ha_host_failures_to_tolerate":"1"}}`),
		[]byte(`{"OpaqueRef:h":{"uuid":"11111111-1111-4111-8111-111111111111","name_label":"h","other_config":{"boot_time":"1.5"}}}`),
		[]byte(`{"OpaqueRef:v":{"uuid":"aaaaaaaa-0000-4000-8000-000000000001","name_label":"v","power_state":"Running","VCPUs_max":"4"}}`),
		[]byte(`{"OpaqueRef:s":{"name_label":"s","physical_size":"100","physical_utilisation":50,"PBDs":["OpaqueRef:x"]}}`))
	f.Fuzz(func(t *testing.T, pools, hosts, vms, srs []byte) {
		var raw Raw
		if json.Unmarshal(pools, &raw.Pools) != nil || json.Unmarshal(hosts, &raw.Hosts) != nil ||
			json.Unmarshal(vms, &raw.VMs) != nil || json.Unmarshal(srs, &raw.SRs) != nil {
			return
		}
		snap := Build(raw, time.Unix(1_800_000_000, 0))
		x := snap.XAPI
		for _, h := range x.Hosts {
			if h.Name == "" || len([]rune(h.Name)) > MaxText {
				t.Fatalf("Host %q", h.Name)
			}
		}
		for _, v := range x.VMs {
			if !uuidPattern.MatchString(v.UUID) {
				t.Fatalf("VM %q", v.UUID)
			}
		}
		for _, d := range snap.Disks {
			if d.FreeBytes > d.TotalBytes {
				t.Fatalf("SR %+v", d)
			}
		}
		if _, err := json.Marshal(snap); err != nil {
			t.Fatal(err)
		}
	})
}
