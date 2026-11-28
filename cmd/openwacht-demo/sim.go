// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Die Simulation der Klick-Demo. Im Browser gibt es kein Netz: Sie spielt die
// Gegenstellen. Die Agents melden über das echte Agent-Protokoll (derselbe
// Handler wie am Agent-Port, das Zertifikat aus der Registrierung beim Bau
// steht im TLS-Zustand der Anfrage), Sensoren der Zentrale und Abfragequellen
// liefern ihre Werte über zentrale.Simulation. Alles danach (Speichern,
// Schwellen, Alarme, Verlauf) ist der echte Code.
//
// Wer was meldet, legt der Name des Hosts bzw. die Adresse fest (Profile
// unten); die Beispieldaten in demo/bauen.mjs passen dazu.

// demoAgent: ein beim Bau registrierter Agent (öffentliche Zertifikate,
// kein Schlüssel: Die Demo braucht keine TLS-Verbindung).
type demoAgent struct {
	Host string `json:"host"`
	ID   string `json:"id"`
	Cert string `json:"zertifikat"`
	CA   string `json:"ca"`
	// Still: registriert, meldet sich aber nie (Alarm „meldet sich nicht“)
	Still bool `json:"still,omitempty"`
}

type simAgent struct {
	demoAgent
	cert, ca *x509.Certificate
	stand    string // Stand der Sensorliste
	jobs     map[string]agentproto.SensorJob
}

type simulation struct {
	mu     sync.Mutex
	agents []*simAgent
	agent  http.Handler // Agent-Handler der Zentrale
	start  time.Time
}

func newSimulation(list []demoAgent) (*simulation, error) {
	s := &simulation{start: time.Now()}
	for _, a := range list {
		c, err := pki.ParseCertPEM([]byte(a.Cert))
		if err != nil {
			return nil, fmt.Errorf("Agent %s: %w", a.Host, err)
		}
		ca, err := pki.ParseCertPEM([]byte(a.CA))
		if err != nil {
			return nil, fmt.Errorf("Agent %s: CA: %w", a.Host, err)
		}
		s.agents = append(s.agents, &simAgent{demoAgent: a, cert: c, ca: ca, jobs: map[string]agentproto.SensorJob{}})
	}
	return s, nil
}

// --- Zufall ohne Zustand: gleiche Eingabe, gleicher Wert ----------------------

func streu(key string, t time.Time) float64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d", key, t.Unix()/30)
	return float64(h.Sum64()%10000)/10000*2 - 1 // −1 … 1
}

// welle: Tagesgang (am Tag höher) plus etwas Rauschen, 0 … 1.
func welle(key string, t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60
	tag := 0.5 - 0.5*math.Cos((h-3)/24*2*math.Pi)
	return math.Max(0, math.Min(1, tag*0.8+0.1+streu(key, t)*0.08))
}

// --- Agents --------------------------------------------------------------------

type hostProfil struct {
	windows    bool
	os, kernel string
	cores      int
	memGB      float64
	cpuBasis   float64 // mittlere Auslastung in %
	memAnteil  float64 // belegter Arbeitsspeicher 0 … 1
	platten    []platte
	uptimeTage float64
	freigabe   agentproto.SensorRelease
	// dienstAus: Dienste, die nicht laufen
	dienstAus []string
	// dateiAlterStd: Alter der jüngsten Datei in Sicherungsordnern
	dateiAlterStd float64
}

type platte struct {
	mount, fs string
	gesamtGB  float64
	belegt    float64 // Anteil 0 … 1
	proTag    float64 // Zuwachs je Tag (Anteil), für die Prognose
}

func profil(host string) hostProfil {
	linux := agentproto.SensorRelease{Kinds: []string{"dienst", "prozess", "datei"}, Folders: []string{"/var/backups"}}
	win := agentproto.SensorRelease{Kinds: []string{"dienst", "autodienste", "datei"}, Folders: []string{`D:\Backup`}}
	p := hostProfil{os: "Debian GNU/Linux 13 (trixie)", kernel: "6.12.48-1-amd64", cores: 4, memGB: 16, cpuBasis: 18, memAnteil: 0.45,
		platten: []platte{{"/", "ext4", 80, 0.38, 0}}, uptimeTage: 12, freigabe: linux, dateiAlterStd: 6}
	winOS := func(name string) {
		p.windows, p.os, p.kernel, p.freigabe = true, name, "10.0.20348.3807", win
		p.platten = []platte{{"C:", "ntfs", 120, 0.52, 0}}
	}
	switch host {
	case "srv-dc01":
		winOS("Windows Server 2022 Standard")
		p.cpuBasis, p.memAnteil, p.uptimeTage = 9, 0.58, 21
	case "srv-file01":
		winOS("Windows Server 2019 Standard")
		p.kernel = "10.0.17763.7009"
		p.platten = append(p.platten, platte{"D:", "ntfs", 2000, 0.905, 0.006})
		p.cpuBasis, p.memAnteil = 14, 0.47
	case "srv-app01":
		p.cores, p.memGB, p.cpuBasis, p.memAnteil = 8, 32, 26, 0.52
		p.platten = append(p.platten, platte{"/var", "xfs", 200, 0.44, 0.001})
	case "srv-db01":
		p.cores, p.memGB, p.cpuBasis, p.memAnteil = 8, 64, 38, 0.71
		p.platten = append(p.platten, platte{"/var/lib/postgresql", "xfs", 500, 0.62, 0.002})
	case "srv-bonn01":
		p.os, p.kernel = "Ubuntu 24.04.3 LTS", "6.8.0-79-generic"
		p.cpuBasis, p.memAnteil = 31, 0.64
		p.dienstAus = []string{"postgresql"}
	case "pc-empfang":
		winOS("Windows 11 Pro 24H2")
		p.kernel, p.cores, p.memGB, p.cpuBasis, p.memAnteil, p.uptimeTage = "10.0.26100.4652", 4, 16, 11, 0.44, 2.2
		p.platten = []platte{{"C:", "ntfs", 476, 0.55, 0}}
		p.freigabe = agentproto.SensorRelease{Kinds: []string{"dienst", "autodienste"}}
	case "praxis-server":
		winOS("Windows Server 2022 Standard")
		p.cpuBasis, p.memAnteil, p.uptimeTage = 12, 0.55, 6
		p.platten = append(p.platten, platte{"D:", "ntfs", 960, 0.42, 0.001})
		p.dateiAlterStd = 31
	}
	return p
}

// call: eine Anfrage an den Agent-Handler der Zentrale, als dieser Agent.
func (s *simulation) call(ctx context.Context, a *simAgent, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.20.0.250:41000"
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{a.cert}, VerifiedChains: [][]*x509.Certificate{{a.cert, a.ca}}}
	rec := httptest.NewRecorder()
	s.agent.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		return fmt.Errorf("%s %s: %d %s", a.Host, path, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if out != nil && rec.Body.Len() > 0 {
		return json.Unmarshal(rec.Body.Bytes(), out)
	}
	return nil
}

func (s *simulation) snapshot(a *simAgent, t time.Time) agentproto.Snapshot {
	p := profil(a.Host)
	cpu := math.Max(1, math.Min(99, p.cpuBasis*(0.6+0.8*welle(a.Host+"cpu", t))+streu(a.Host+"c", t)*3))
	snap := agentproto.Snapshot{CollectedAt: t, Hostname: a.Host, OS: p.os, Kernel: p.kernel, Arch: "amd64",
		AgentVersion: "1.0.11", UptimeSec: uint64(p.uptimeTage*86400 + t.Sub(s.start).Seconds()),
		CPU:    agentproto.CPU{Cores: p.cores, Percent: math.Round(cpu*10) / 10},
		Memory: agentproto.Memory{TotalBytes: uint64(p.memGB * (1 << 30))}}
	snap.Memory.AvailableBytes = uint64(float64(snap.Memory.TotalBytes) * (1 - p.memAnteil - streu(a.Host+"m", t)*0.02))
	if p.windows {
		snap.CPU.NoLoad = true
		snap.Platform = "windows/amd64"
	} else {
		snap.CPU.Load1 = cpu / 100 * float64(p.cores)
		snap.CPU.Load5, snap.CPU.Load15 = snap.CPU.Load1*0.95, snap.CPU.Load1*0.9
		snap.Memory.SwapTotalBytes, snap.Memory.SwapFreeBytes = 2<<30, 2<<30-64<<20
		snap.Platform = "linux/amd64"
	}
	for _, d := range p.platten {
		total := uint64(d.gesamtGB * (1 << 30))
		used := math.Min(0.995, d.belegt+d.proTag*t.Sub(s.start).Hours()/24)
		snap.Disks = append(snap.Disks, agentproto.Disk{Mount: d.mount, FSType: d.fs, TotalBytes: total, FreeBytes: uint64(float64(total) * (1 - used))})
	}
	rel := p.freigabe
	snap.Sensors = &rel
	return snap
}

// runde: eine Meldung je Agent und die fälligen Sensoren auf den Agents.
func (s *simulation) runde(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := time.Now()
	for _, a := range s.agents {
		if a.Still {
			continue
		}
		if err := s.call(ctx, a, agentproto.PathReport, s.snapshot(a, t), nil); err != nil {
			slog.Warn("Demo: Meldung", "fehler", err)
			continue
		}
		var jobs agentproto.SensorJobsResponse
		if err := s.call(ctx, a, agentproto.PathSensorJobs, agentproto.SensorJobsRequest{State: a.stand}, &jobs); err != nil {
			slog.Warn("Demo: Sensorliste", "fehler", err)
			continue
		}
		if !jobs.Unchanged {
			a.jobs = map[string]agentproto.SensorJob{}
			for _, j := range jobs.Sensors {
				a.jobs[j.ID] = j
			}
		}
		a.stand = jobs.State
		var res agentproto.SensorResultsRequest
		for _, id := range jobs.Due {
			if j, ok := a.jobs[id]; ok {
				res.Results = append(res.Results, s.agentSensor(a, j, t))
			}
		}
		if len(res.Results) > 0 {
			if err := s.call(ctx, a, agentproto.PathSensorResults, res, nil); err != nil {
				slog.Warn("Demo: Sensorergebnis", "fehler", err)
			}
		}
	}
}

func (s *simulation) agentSensor(a *simAgent, j agentproto.SensorJob, t time.Time) agentproto.SensorResult {
	p := profil(a.Host)
	var spec checks.Spec
	_ = json.Unmarshal(j.Target, &spec)
	r := agentproto.SensorResult{ID: j.ID, Revision: j.Revision, Status: checks.OK}
	switch j.Kind {
	case "dienst":
		r.Message = "läuft"
		for _, d := range p.dienstAus {
			if strings.EqualFold(d, spec.Name) {
				r.Status, r.Message = checks.Crit, "gestoppt"
			}
		}
	case "prozess":
		r.Message, r.Metric = "2 Prozesse", "2"
	case "autodienste":
		r.Message = "alle automatischen Dienste laufen"
	case "datei":
		alter := p.dateiAlterStd + t.Sub(s.start).Hours()
		r.Metric = fmt.Sprintf("%.0f h", alter)
		r.Message = fmt.Sprintf("jüngste Datei vor %.0f Std., 1,2 GB", alter)
		if alter > 26 {
			r.Status = checks.Warn
			r.Message += " (Warnung ab 26 Std.)"
		}
	default:
		r.Status, r.Message = checks.Unknown, "in der Demo nicht simuliert"
	}
	return r
}

// Run meldet alle 30 Sekunden, bis ctx endet (die erste Runde läuft schon
// beim Start, siehe laufen).
func (s *simulation) Run(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s.runde(ctx)
	}
}

// --- Sensoren der Zentrale (zentrale.Simulation) -----------------------------

func (s *simulation) Check(ctx context.Context, id, kind string, spec checks.Spec) checks.Result {
	t := time.Now()
	host := spec.Host
	if host == "" && spec.URL != "" {
		host = spec.URL
	}
	ms := func(base float64) (string, time.Duration) {
		v := math.Max(0.3, base*(1+0.3*streu(id, t)))
		return fmt.Sprintf("%.1f ms", v), time.Duration(v * float64(time.Millisecond))
	}
	switch kind {
	case "ping":
		m, d := ms(1.4)
		return checks.Result{Status: checks.OK, Message: "erreichbar, 0 % Verlust, " + m, Metric: m, Latency: d}
	case "tcp":
		m, d := ms(2.1)
		return checks.Result{Status: checks.OK, Message: fmt.Sprintf("Port %d offen", spec.Port), Metric: m, Latency: d}
	case "http", "http_json":
		m, d := ms(180)
		if strings.Contains(host, "intranet") || strings.Contains(host, "10.20.0.80") {
			return checks.Result{Status: checks.Crit, Message: "HTTP 502 (erwartet 200)", Metric: m, Latency: d}
		}
		return checks.Result{Status: checks.OK, Message: "HTTP 200", Metric: m, Latency: d}
	case "tls":
		tage, von := 214.0, "Beispiel GmbH Issuing CA"
		if strings.Contains(host, "praxis") || strings.Contains(host, "10.20.2.10") || strings.Contains(spec.Connect, "praxis") {
			tage, von = 12, "R11"
		}
		warn, krit := spec.WarnDays, spec.CritDays
		if warn == 0 {
			warn, krit = 21, 7
		}
		bis := t.Add(time.Duration(tage * 24 * float64(time.Hour))).Format("02.01.2006")
		if tage < warn {
			st := checks.Warn
			if tage < krit {
				st = checks.Crit
			}
			return checks.Result{Status: st, Message: fmt.Sprintf("läuft in %.0f Tagen ab (%s), Aussteller %s", tage, bis, von)}
		}
		return checks.Result{Status: checks.OK, Message: fmt.Sprintf("gültig bis %s (noch %.0f Tage), Aussteller %s", bis, tage, von)}
	case "dns":
		return checks.Result{Status: checks.OK, Message: "löst auf: 10.20.0.10"}
	case "ntp":
		return checks.Result{Status: checks.OK, Message: "Abweichung 3 ms", Metric: "3 ms"}
	case "tcp_banner":
		return checks.Result{Status: checks.OK, Message: "220 mail.beispiel.example ESMTP"}
	}
	return checks.Result{Status: checks.Unknown, Message: "in der Demo nicht simuliert"}
}

// --- Abfragequellen (zentrale.Simulation) ------------------------------------

func (s *simulation) Poll(ctx context.Context, id, version, host string) (*snmp.Snapshot, error) {
	t := time.Now()
	up := uint64(t.Sub(s.start).Seconds()) + 41*86400
	// Leere Listen wie bei der echten Abfrage (snmp.Poll), nicht nil.
	snap := &snmp.Snapshot{CollectedAt: t, Counters: &snmp.CounterInfo{At: t, UptimeTicks: uint32(up * 100)},
		Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{}}
	snap.System.UptimeS, snap.System.UptimeTicks = up, uint32(up*100)
	switch {
	case version == "pve":
		return s.proxmox(snap, t), nil
	case version == "tr064":
		return s.fritz(snap, t), nil
	case host == "10.20.0.2" || host == "10.20.1.2":
		return s.switch_(snap, host, t), nil
	case host == "10.20.0.30":
		return s.synology(snap, t), nil
	case host == "10.20.0.3":
		return s.usv(snap, t), nil
	case host == "10.20.1.40":
		return s.drucker(snap, t), nil
	}
	return nil, errors.New("keine Antwort (Zeitüberschreitung)")
}

func f(v float64) *float64 { return &v }

func (s *simulation) switch_(snap *snmp.Snapshot, host string, t time.Time) *snmp.Snapshot {
	core := host == "10.20.0.2"
	n, up := 24, 0
	snap.System.Name, snap.System.Location = "sw-bonn01", "Bonn, Büro"
	snap.System.Descr = "HPE OfficeConnect 1920S 24G"
	if core {
		n, up = 24, 4
		snap.System.Name, snap.System.Location = "sw-core01", "Köln, Serverraum"
		snap.System.Descr = "LANCOM GS-3528XP 4.30.0012"
	}
	snap.System.ObjectID = "1.3.6.1.4.1.2356.800"
	snap.CPU = &snmp.CPU{Cores: 1, Percent: math.Round((12+8*welle(host, t))*10) / 10}
	snap.Memory = &snmp.Memory{TotalBytes: 512 << 20, AvailableBytes: 301 << 20}
	frei := map[int]bool{5: true, 11: true, 14: true, 17: true, 20: true, 22: true}
	namen := map[int]string{1: "Uplink Firewall", 2: "srv-dc01", 3: "srv-file01", 4: "srv-app01", 6: "pve01", 7: "AP OG 1", 8: "AP EG", 9: "Kamera Einfahrt", 10: "Telefon Empfang", 12: "Drucker EG"}
	for i := 1; i <= n+up; i++ {
		ifc := snmp.Interface{Index: i, Type: 6, AdminUp: i != 19, Oper: "up", HC: true}
		ifc.Name = fmt.Sprintf("Port %d", i)
		if core && i > n {
			ifc.Name, ifc.SpeedBps = fmt.Sprintf("SFP+ %d", i-n), 10_000_000_000
		} else {
			ifc.SpeedBps = 1_000_000_000
			if i%7 == 0 {
				ifc.SpeedBps = 100_000_000
			}
		}
		if core {
			ifc.Alias = namen[i]
		}
		if frei[i] || i == 19 || (core && i > n+2) || (!core && i > 16) {
			ifc.Oper = "down"
		}
		if core && i == 9 {
			ifc.Oper = "down" // Kamera: PoE-Fehler
		}
		if ifc.Oper == "up" {
			last := 2e6 + 40e6*welle(fmt.Sprint(host, i), t)
			if i == 1 || (core && i > n) {
				last *= 8
			}
			ifc.InBps, ifc.OutBps = f(math.Round(last)), f(math.Round(last*0.6))
			z := uint64(0)
			ifc.NewErrors = &z
		}
		since := uint64(3600*(i%9+1)) + uint64(t.Sub(s.start).Seconds())
		ifc.SinceS = &since
		snap.Interfaces = append(snap.Interfaces, ifc)
	}
	if core {
		for i := 1; i <= 12; i++ {
			st := 1
			switch {
			case i == 9:
				st = 4
			case i == 7 || i == 8 || i == 10:
				st = 3
			}
			snap.PoE = append(snap.PoE, snmp.PoEPort{Group: 1, Port: i, Status: st})
		}
		snap.LLDP = []snmp.LLDPNeighbor{{Index: 1, Name: "fw-koeln", Port: "lan1"}, {Index: 6, Name: "pve01", Port: "enp3s0"},
			{Index: 7, Name: "ap-og1", Port: "eth0"}, {Index: 8, Name: "ap-eg", Port: "eth0"}, {Index: 25, Name: "sw-bonn01", Port: "Port 24"}}
	}
	return snap
}

func (s *simulation) synology(snap *snmp.Snapshot, t time.Time) *snmp.Snapshot {
	snap.System.Name, snap.System.Descr, snap.System.Location = "nas-backup", "Linux nas-backup 5.10.55+ #72806 SMP x86_64", "Köln, Serverraum"
	snap.CPU = &snmp.CPU{Cores: 4, Percent: math.Round((6+10*welle("nas", t))*10) / 10}
	snap.Memory = &snmp.Memory{TotalBytes: 8 << 30, AvailableBytes: 5 << 30}
	temp, d1, d2 := 41, 34, 35
	snap.Synology = &snmp.Synology{Model: "DS923+", Version: "DSM 7.2.2-72806 Update 4", SystemStatus: 1, PowerStatus: 1, SystemFan: 1, CPUFan: 1,
		Temperature: &temp, Upgrade: 2,
		Disks: []snmp.SynoDisk{{Name: "Laufwerk 1", Model: "HAT5300-8T", Status: 1, Health: 1, Temperature: &d1, Role: "data"},
			{Name: "Laufwerk 2", Model: "HAT5300-8T", Status: 1, Health: 1, Temperature: &d2, Role: "data"}},
		Raids: []snmp.SynoRaid{{Name: "Volume 1", Status: 1, TotalBytes: 14 << 40, FreeBytes: 4 << 40}}}
	snap.Disks = []snmp.Disk{{Mount: "/volume1", FSType: "btrfs", TotalBytes: 14 << 40, FreeBytes: 4 << 40}}
	return snap
}

func (s *simulation) usv(snap *snmp.Snapshot, t time.Time) *snmp.Snapshot {
	snap.System.Name, snap.System.Descr, snap.System.Location = "usv-serverraum", "APC Smart-UPS SMT1500RMI2UC", "Köln, Serverraum"
	snap.UPS = &snmp.UPS{Source: "rfc1628", Model: "Smart-UPS 1500", Status: "OL", ChargePct: f(100), RuntimeS: f(38 * 60), LoadPct: f(math.Round(28 + 6*welle("usv", t)))}
	return snap
}

func (s *simulation) drucker(snap *snmp.Snapshot, t time.Time) *snmp.Snapshot {
	snap.System.Name, snap.System.Descr, snap.System.Location = "drucker-bonn-eg", "Brother MFC-L8900CDW series", "Bonn, Empfang"
	snap.Supplies = []snmp.Supply{{Name: "Toner Schwarz", Level: 6, Max: 100, Percent: f(6)}, {Name: "Toner Cyan", Level: 54, Max: 100, Percent: f(54)},
		{Name: "Toner Magenta", Level: 61, Max: 100, Percent: f(61)}, {Name: "Toner Gelb", Level: 47, Max: 100, Percent: f(47)}}
	return snap
}

func (s *simulation) proxmox(snap *snmp.Snapshot, t time.Time) *snmp.Snapshot {
	snap.System.Name = "pve01"
	snap.CPU = &snmp.CPU{Cores: 16, Percent: math.Round((22+30*welle("pve", t))*10) / 10}
	snap.Memory = &snmp.Memory{TotalBytes: 128 << 30, AvailableBytes: 41 << 30}
	ja, nein := true, false
	gestern := time.Date(t.Year(), t.Month(), t.Day(), 1, 30, 0, 0, t.Location())
	if gestern.After(t) {
		gestern = gestern.Add(-24 * time.Hour)
	}
	gast := func(id int, typ, name, st string, boot, job bool) snmp.Guest {
		g := snmp.Guest{VMID: id, Type: typ, Name: name, Status: st, OnBoot: &boot, InJob: &job, UptimeS: 14 * 86400}
		if st != "running" {
			g.UptimeS = 0
		}
		if job {
			ok := gestern
			g.BackupOK, g.BackupTry = &ok, &ok
		}
		return g
	}
	snap.Proxmox = &snmp.Proxmox{Node: "pve01", Version: "9.0.10", BackupInfo: true, TasksUntil: t,
		Guests: []snmp.Guest{gast(100, "qemu", "srv-app01", "running", ja, ja), gast(101, "qemu", "srv-db01", "running", ja, ja),
			gast(110, "lxc", "ct-monitoring", "running", ja, ja), gast(111, "lxc", "ct-proxy", "running", ja, ja),
			gast(190, "qemu", "vm-test", "stopped", nein, nein)},
		Storages: []snmp.Storage{{Name: "local-lvm", Type: "lvmthin", Active: true, Enabled: true, TotalBytes: 1800 << 30, UsedBytes: 1116 << 30},
			{Name: "local", Type: "dir", Active: true, Enabled: true, TotalBytes: 94 << 30, UsedBytes: 17 << 30},
			{Name: "nas-backup", Type: "nfs", Active: true, Enabled: true, Shared: true, TotalBytes: 14 << 40, UsedBytes: 10 << 40}},
		ThinPools: []snmp.ThinPool{{Name: "pve/data", SizeBytes: 1800 << 30, UsedBytes: 1116 << 30, MetaSizeBytes: 16 << 30, MetaUsedBytes: 3 << 30}}}
	return snap
}

func (s *simulation) fritz(snap *snmp.Snapshot, t time.Time) *snmp.Snapshot {
	snap.System.Name = "fritzbox-bonn"
	ab := 2e6 + 30e6*welle("fritz-ab", t)
	snap.FritzBox = &snmp.FritzBox{Model: "FRITZ!Box 7590 AX", Version: "8.03", AccessType: "DSL", Connection: "Connected", Connected: true,
		LastError: "ERROR_NONE", ConnUptimeS: uint64(t.Sub(s.start).Seconds()) + 5*86400, ExternalIP: "203.0.113.47",
		Layer1UpBps: 40_000_000, Layer1DnBps: 100_000_000, PhysicalLink: "Up"}
	snap.Interfaces = []snmp.Interface{{Index: 1, Name: "Internet", Type: 6, AdminUp: true, Oper: "up", SpeedBps: 100_000_000, InBps: f(math.Round(ab)), OutBps: f(math.Round(ab * 0.2))}}
	return snap
}
