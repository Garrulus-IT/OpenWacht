// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import "sort"

// Reihen für den Verlauf (metrics_snmp_raw). Namen wie beim Agent, dazu
// Schnittstellen (Bit/s), Temperatur, USV-Ladung und Verbrauchsmaterial,
// bei NetApp IOPS und Latenz (ms) je Aggregat, bei XenServer CPU und RAM (%)
// je Host und für die VMs mit der höchsten CPU-Last.

// MaxSeries: so viele Reihen speichert eine Abfrage höchstens (die Datenbank
// prüft dieselbe Grenze).
const MaxSeries = 200

// maxIfSeries: Schnittstellen mit Verlauf; bei großen Switches die ersten
// aktiven (nach Index).
const maxIfSeries = 64

// Series liefert die Reihen einer Abfrage.
func Series(s *Snapshot) (names []string, values []float64) {
	add := func(n string, v float64) {
		if len(names) < MaxSeries {
			names, values = append(names, n), append(values, v)
		}
	}
	if s.CPU != nil {
		add("cpu", s.CPU.Percent)
	}
	if m := s.Memory; m != nil && m.TotalBytes > 0 && m.AvailableBytes <= m.TotalBytes {
		add("speicher", float64(m.TotalBytes-m.AvailableBytes)/float64(m.TotalBytes)*100)
	}
	seen := map[string]bool{}
	// NetApp: Leistung je Aggregat (nur Graph), vor den Platten, damit viele
	// Volumes sie nicht über die Grenze schieben.
	if o := s.ONTAP; o != nil {
		for _, a := range o.Aggregates {
			if seen["aggr:"+a.Name] {
				continue
			}
			seen["aggr:"+a.Name] = true
			if a.IOPS != nil {
				add("iops:"+a.Name, *a.IOPS)
			}
			if a.LatencyMs != nil {
				add("latenz:"+a.Name, *a.LatencyMs)
			}
		}
	}
	if x := s.XAPI; x != nil {
		for _, h := range x.Hosts {
			if seen["xh:"+h.Name] {
				continue
			}
			seen["xh:"+h.Name] = true
			if h.CPUPct != nil {
				add("xcpu:"+h.Name, *h.CPUPct)
			}
			if h.MemTotal > 0 && h.MemFree <= h.MemTotal {
				add("xram:"+h.Name, float64(h.MemTotal-h.MemFree)/float64(h.MemTotal)*100)
			}
		}
	}
	for _, d := range s.Disks {
		n := "platte:" + d.Mount
		if d.TotalBytes == 0 || d.FreeBytes > d.TotalBytes || seen[n] {
			continue
		}
		seen[n] = true
		add(n, float64(d.TotalBytes-d.FreeBytes)/float64(d.TotalBytes)*100)
	}
	if x := s.XAPI; x != nil {
		addXAPIVMs(x, seen, add)
	}
	ifs := 0
	for _, it := range s.Interfaces {
		if ifs >= maxIfSeries {
			break
		}
		if it.InBps == nil && it.OutBps == nil || seen["if:"+it.Name] {
			continue
		}
		seen["if:"+it.Name] = true
		ifs++
		if it.InBps != nil {
			add("if_ein:"+it.Name, *it.InBps)
		}
		if it.OutBps != nil {
			add("if_aus:"+it.Name, *it.OutBps)
		}
	}
	if s.Synology != nil && s.Synology.Temperature != nil {
		add("temperatur", float64(*s.Synology.Temperature))
	}
	if s.UPS != nil && s.UPS.ChargePct != nil {
		add("usv_ladung", *s.UPS.ChargePct)
	}
	for _, sp := range s.Supplies {
		if sp.Percent != nil && !seen["toner:"+sp.Name] {
			seen["toner:"+sp.Name] = true
			add("toner:"+sp.Name, *sp.Percent)
		}
	}
	if f := s.FritzBox; f != nil && f.DSL != nil && f.DSL.Status == "Up" {
		add("dsl_ab", float64(f.DSL.DownBps))
		add("dsl_auf", float64(f.DSL.UpBps))
	}
	if s.Proxmox != nil {
		for _, t := range s.Proxmox.ThinPools {
			if pct, ok := t.MetaPercent(); ok && !seen["meta:"+t.Name] {
				seen["meta:"+t.Name] = true
				add("meta:"+t.Name, pct)
			}
		}
	}
	return names, values
}

// maxVMSeries: so viele VMs bekommen einen Verlauf (die mit der höchsten
// CPU-Last), damit große Pools die Grenze nicht sprengen.
const maxVMSeries = 30

func addXAPIVMs(x *XAPI, seen map[string]bool, add func(string, float64)) {
	vms := make([]XAPIVM, 0, len(x.VMs))
	for _, v := range x.VMs {
		if v.State == "running" && v.CPUPct != nil {
			vms = append(vms, v)
		}
	}
	sort.SliceStable(vms, func(i, j int) bool { return *vms[i].CPUPct > *vms[j].CPUPct })
	n := 0
	for _, v := range vms {
		if n >= maxVMSeries {
			break
		}
		if seen["vm:"+v.Name] {
			continue
		}
		seen["vm:"+v.Name] = true
		n++
		add("vmcpu:"+v.Name, *v.CPUPct)
		if v.MemBytes > 0 {
			add("vmram:"+v.Name, float64(v.MemBytes))
		}
	}
}
