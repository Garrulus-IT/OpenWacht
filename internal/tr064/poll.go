// SPDX-License-Identifier: AGPL-3.0-only

package tr064

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Teile, die fehlen können (FritzBox.Missing).
const (
	PartDevice     = "Gerät"
	PartLink       = "Leitung"
	PartTraffic    = "Verkehr"
	PartConnection = "Verbindung"
	PartIP         = "Externe IP"
	PartDSL        = "DSL"
)

// WANName: Name der Schnittstelle für die Internetverbindung im Snapshot.
const WANName = "WAN"

// Info: was „Verbindung prüfen“ zeigt.
type Info struct {
	Model       string   `json:"modell"`
	Version     string   `json:"fritzos"`
	UptimeS     uint64   `json:"laufzeit_s"`
	AccessType  string   `json:"zugang"`
	Connected   bool     `json:"verbunden"`
	Missing     []string `json:"nicht_verfuegbar"`
	Reasons     []string `json:"nicht_verfuegbar_grund,omitempty"`
	Fingerprint string   `json:"fingerabdruck,omitempty"`
}

// Probe fragt die Box einmal ab (Knopf „Verbindung prüfen“).
func (c *Client) Probe(ctx context.Context, cfg Config) (Info, error) {
	snap, err := c.Poll(ctx, cfg, nil)
	if err != nil {
		return Info{}, err
	}
	fb := snap.FritzBox
	missing := fb.Missing
	if missing == nil {
		missing = []string{}
	}
	return Info{Model: fb.Model, Version: fb.Version, UptimeS: snap.System.UptimeS, AccessType: fb.AccessType,
		Connected: fb.Connected, Missing: missing, Reasons: fb.Reasons, Fingerprint: fb.Fingerprint}, nil
}

// Poll fragt die Box ab. prev: vorige Messwerte für die Rate des Verkehrs.
func (c *Client) Poll(ctx context.Context, cfg Config, prev *snmp.Snapshot) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("fritzbox", &err)
	ctx, cancel := context.WithTimeout(ctx, c.budget())
	defer cancel()
	s, err := c.open(cfg)
	if err != nil {
		return nil, err
	}
	defer s.closer()
	if err := s.describeBox(ctx); err != nil {
		return nil, err
	}
	now := c.now().UTC()
	snap := &snmp.Snapshot{CollectedAt: now, Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{}}
	fb := &snmp.FritzBox{TLS: cfg.Pin != "", Fingerprint: cfg.Pin}
	snap.FritzBox = fb

	// Fehlt nur ein Recht, fehlt nur dieser Teil. Jeder andere Fehler
	// (Anmeldung, Netz, TLS) bricht ab: Mit falschem Passwort weiter zu
	// fragen, sperrt die Box das Konto nur länger.
	// Der Grund (Aktion und UPnP-Code) steht in fb.Reasons, damit Oberfläche
	// und Journal zeigen, ob ein Recht fehlt (606) oder die Box die Aktion
	// nicht kennt (401).
	miss := func(part string, err error) error {
		var ae *ActionError
		if errors.As(err, &ae) && ae.Unauthorized() {
			if !contains(fb.Missing, part) {
				fb.Missing = append(fb.Missing, part)
			}
			if r := part + ": " + ae.Error(); !contains(fb.Reasons, r) && len(fb.Reasons) < 16 {
				fb.Reasons = append(fb.Reasons, r)
			}
			return nil
		}
		return err
	}

	// Gerät: Modell, FRITZ!OS, Laufzeit (Neustart)
	if v, err := s.call(ctx, svcDeviceInfo, "GetInfo"); err == nil {
		fb.Model = clean(v["ModelName"], MaxText)
		fb.Version = clean(v["SoftwareVersion"], 40)
		up, _ := num(v["UpTime"])
		snap.System = snmp.System{Name: fb.Model, UptimeS: up, UptimeTicks: uint32((up * 100) % (1 << 32))}
		snap.System.Descr = clean(strings.TrimSpace(fb.Model+" · FRITZ!OS "+fb.Version), MaxText)
	} else if err := miss(PartDevice, err); err != nil {
		return nil, err
	}
	snap.Counters = &snmp.CounterInfo{At: now, UptimeTicks: snap.System.UptimeTicks}

	// Leitung: Zugangsart und Leitungskapazität
	if v, err := s.call(ctx, svcCommon, "GetCommonLinkProperties"); err == nil {
		fb.AccessType = clean(v["WANAccessType"], 40)
		fb.PhysicalLink = clean(v["PhysicalLinkStatus"], 40)
		fb.Layer1UpBps, _ = num(v["Layer1UpstreamMaxBitRate"])
		fb.Layer1DnBps, _ = num(v["Layer1DownstreamMaxBitRate"])
	} else if err := miss(PartLink, err); err != nil {
		return nil, err
	}

	// Verbindung: PPP (DSL) oder IP (Kabel, Glasfaser, IP-Client)
	conn := ""
	for _, svc := range []string{svcPPP, svcIP} {
		if !s.has(svc) {
			continue
		}
		v, err := s.call(ctx, svc, "GetStatusInfo")
		if err != nil {
			if err := miss(PartConnection, err); err != nil {
				return nil, err
			}
			continue
		}
		st := clean(v["ConnectionStatus"], 40)
		if st == "" || st == "Unconfigured" {
			continue
		}
		if conn == "" || (st == "Connected" && !fb.Connected) {
			conn = svc
			fb.Connection, fb.Connected = st, st == "Connected"
			fb.LastError = clean(v["LastConnectionError"], 80)
			fb.ConnUptimeS, _ = num(v["Uptime"])
		}
	}
	if conn != "" {
		// Hat eine der beiden geantwortet, fehlt die Verbindung nicht.
		fb.Missing = remove(fb.Missing, PartConnection)
		fb.Reasons = removePrefix(fb.Reasons, PartConnection+": ")
		if fb.Connected {
			if v, err := s.call(ctx, conn, "GetExternalIPAddress"); err == nil {
				if a, err := netip.ParseAddr(strings.TrimSpace(v["ExternalIPAddress"])); err == nil && !a.IsUnspecified() && a.Zone() == "" {
					fb.ExternalIP = a.String()
				}
			} else if err := miss(PartIP, err); err != nil {
				return nil, err
			}
		}
	}

	// Verkehr: 64-Bit-Zähler (GetAddonInfos), sonst GetTotalBytesSent/
	// Received. GetAddonInfos gibt es über TR-064 nicht auf jeder Box
	// (FRITZ!Box 7590, FRITZ!OS 8.51: UPnP-Fehler 401 „Aktion unbekannt“);
	// das ist kein fehlendes Recht, also still auf den zweiten Weg.
	var sent, recv uint64
	hc, haveBytes := false, false
	if v, err := s.call(ctx, svcCommon, "GetAddonInfos"); err == nil {
		a, ok1 := num(v["X_AVM_DE_TotalBytesSent64"])
		b, ok2 := num(v["X_AVM_DE_TotalBytesReceived64"])
		if ok1 && ok2 {
			sent, recv, hc, haveBytes = a, b, true, true
		}
	} else if ae := (*ActionError)(nil); errors.As(err, &ae) && ae.Code == 401 {
		// Aktion unbekannt: kein Eintrag, Rückfall unten
	} else if err := miss(PartTraffic, err); err != nil {
		return nil, err
	}
	if !haveBytes {
		v1, err1 := s.call(ctx, svcCommon, "GetTotalBytesSent")
		v2, err2 := s.call(ctx, svcCommon, "GetTotalBytesReceived")
		switch {
		case err1 == nil && err2 == nil:
			a, ok1 := num(v1["TotalBytesSent"])
			b, ok2 := num(v2["TotalBytesReceived"])
			// Laut Spezifikation 32 Bit (ui4). Dieselbe Box liefert dort aber
			// 64-Bit-Werte (41436074157 bzw. 846820105309 gemessen). Ein Wert
			// über 2^32 heißt: Der Zähler läuft nicht bei 4 GiB über.
			if ok1 && ok2 {
				sent, recv, haveBytes = a, b, true
				hc = a > math.MaxUint32 || b > math.MaxUint32
				fb.Missing = remove(fb.Missing, PartTraffic)
				fb.Reasons = removePrefix(fb.Reasons, PartTraffic+": ")
			}
		case err1 != nil:
			if err := miss(PartTraffic, err1); err != nil {
				return nil, err
			}
		default:
			if err := miss(PartTraffic, err2); err != nil {
				return nil, err
			}
		}
	}
	if haveBytes {
		oper := "unknown"
		switch {
		case fb.Connected:
			oper = "up"
		case fb.Connection != "":
			oper = "down"
		}
		snap.Interfaces = append(snap.Interfaces, snmp.Interface{Index: 1, Name: WANName, Type: 6,
			SpeedBps: max(fb.Layer1UpBps, fb.Layer1DnBps), AdminUp: true, Oper: oper,
			InOctets: recv, OutOctets: sent, HC: hc})
	}

	// DSL: Synchronrate und Leitungskapazität (kbit/s laut AVM)
	if s.has(svcDSL) && (fb.AccessType == "DSL" || fb.AccessType == "") {
		if v, err := s.call(ctx, svcDSL, "GetInfo"); err == nil {
			kbit := func(k string) uint64 {
				n, ok := num(v[k])
				if !ok || n > 1e8 {
					return 0
				}
				return n * 1000
			}
			fb.DSL = &snmp.DSL{Status: clean(v["Status"], 40), UpBps: kbit("UpstreamCurrRate"), DownBps: kbit("DownstreamCurrRate"),
				UpMaxBps: kbit("UpstreamMaxRate"), DownMaxBps: kbit("DownstreamMaxRate")}
		} else if err := miss(PartDSL, err); err != nil {
			return nil, err
		}
	}

	if contains(fb.Missing, PartDevice) && contains(fb.Missing, PartLink) && contains(fb.Missing, PartConnection) &&
		contains(fb.Missing, PartTraffic) {
		return nil, ErrNoRights
	}
	snmp.ApplyRates(snap, ratesBase(snap, prev))
	return snap, nil
}

// ratesBase: Die vorige Abfrage taugt für eine Rate nur, wenn die Verbindung
// seitdem nicht neu aufgebaut wurde (die Zähler beginnen dann bei 0).
func ratesBase(snap, prev *snmp.Snapshot) *snmp.Snapshot {
	if prev == nil || prev.FritzBox == nil || prev.Counters == nil {
		return nil
	}
	cur, old := snap.FritzBox, prev.FritzBox
	if !cur.Connected || !old.Connected || cur.ConnUptimeS < old.ConnUptimeS {
		return nil
	}
	dt := snap.CollectedAt.Sub(prev.Counters.At).Seconds()
	if float64(cur.ConnUptimeS) < dt {
		return nil
	}
	return prev
}

// num: nicht negative ganze Zahl (TR-064 liefert ui4/ui8 als Text).
func num(s string) (uint64, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil || n > 1<<62 {
		return 0, false
	}
	return n, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	out := list[:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Rebooted: Laufzeit der Box ist kleiner geworden (Neustart).
func Rebooted(prevUptime, newUptime uint64) bool {
	return prevUptime > 0 && newUptime+60 < prevUptime
}

// removePrefix entfernt die Gründe eines Teils, der doch noch geliefert wurde.
func removePrefix(list []string, prefix string) []string {
	out := list[:0]
	for _, x := range list {
		if !strings.HasPrefix(x, prefix) {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
