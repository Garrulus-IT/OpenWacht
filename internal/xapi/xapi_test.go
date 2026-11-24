// SPDX-License-Identifier: AGPL-3.0-only

package xapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/xapi/xapitest"
)

func client() *Client { return &Client{Guard: &net.Dialer{}, Timeout: 5 * time.Second} }

func cfgFor(s *xapitest.Server) Config {
	return Config{Host: s.Host, Port: s.Port, User: xapitest.User, Password: xapitest.Password, Pin: s.Pin}
}

// denyDialer: Netzfreigabe ohne die genannten Adressen.
type denyDialer struct {
	deny  map[string]bool
	tried []string
}

func (d *denyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	d.tried = append(d.tried, host)
	if d.deny[host] {
		return nil, errors.New("Adresse nicht freigegeben")
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestPollAlles(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	snap, err := client().Poll(context.Background(), cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	x := snap.XAPI
	if x.Pool != "pool-test" || x.Product != "XenServer 8.4.0" || x.Master != "xs-01" || x.Fingerprint != srv.Pin {
		t.Errorf("Pool: %+v", x)
	}
	if !x.HA.Enabled || x.HA.Tolerate != 1 || x.HA.Plan != 0 || x.HA.Overcommitted {
		t.Errorf("HA: %+v", x.HA)
	}
	if len(x.Hosts) != 2 {
		t.Fatalf("Hosts: %+v", x.Hosts)
	}
	h1, h2 := x.Hosts[0], x.Hosts[1]
	if h1.Name != "xs-01" || !h1.Master || !h1.Live || h1.Maintenance || h1.Updates != "aktuell" || len(h1.Pending) != 0 {
		t.Errorf("xs-01: %+v", h1)
	}
	if h1.UptimeS < 39*86400 || h1.UptimeS > 41*86400 || snap.System.UptimeS != h1.UptimeS {
		t.Errorf("Laufzeit: %d / %d", h1.UptimeS, snap.System.UptimeS)
	}
	// Messwerte beider Hosts (zweiter über eigenen Server mit Fingerabdruck aus dem Pool)
	if h1.CPUPct == nil || *h1.CPUPct < 34.9 || *h1.CPUPct > 35.1 || h2.CPUPct == nil || *h2.CPUPct < 81.9 || *h2.CPUPct > 82.1 {
		t.Errorf("CPU: %v %v (%s %s)", h1.CPUPct, h2.CPUPct, h1.MetricsError, h2.MetricsError)
	}
	if h1.MemTotal != 256<<30 || h1.MemFree != 96<<30 || h2.MemFree != 24<<30 {
		t.Errorf("RAM: %+v %+v", h1, h2)
	}
	if h2.Updates != "ausstehend" || len(h2.Pending) != 1 || h2.Pending[0] != "reboot_host" {
		t.Errorf("Updates xs-02: %+v", h2)
	}
	if snap.CPU == nil || snap.CPU.Cores != 2 || snap.CPU.Percent < 58 || snap.CPU.Percent > 59 {
		t.Errorf("CPU Pool: %+v", snap.CPU)
	}
	if snap.Memory == nil || snap.Memory.TotalBytes != 512<<30 || snap.Memory.AvailableBytes != 120<<30 {
		t.Errorf("RAM Pool: %+v", snap.Memory)
	}
	// VMs: ohne Vorlage und dom0
	if len(x.VMs) != 5 || x.VMCount.Running != 2 || x.VMCount.Halted != 2 || x.VMCount.Paused != 1 {
		t.Fatalf("VMs: %+v %+v", x.VMs, x.VMCount)
	}
	byName := map[string]snmp.XAPIVM{}
	for _, v := range x.VMs {
		byName[v.Name] = v
	}
	if v := byName["srv-db01"]; v.State != "running" || v.Host != "xs-02" || !v.AutoStart || v.VCPUs != 8 || v.MemBytes != 32<<30 ||
		v.CPUPct == nil || *v.CPUPct < 29.9 || *v.CPUPct > 30.1 {
		t.Errorf("srv-db01: %+v", v)
	}
	if v := byName["srv-app01"]; v.State != "halted" || !v.AutoStart || v.CPUPct != nil || v.MemBytes != 0 {
		t.Errorf("srv-app01: %+v", v)
	}
	if v := byName["test-vm"]; v.AutoStart {
		t.Errorf("test-vm: %+v", v)
	}
	// Speicher: ISO ohne Belegung; iSCSI auf xs-02 nicht angebunden
	if len(x.SRs) != 3 || x.SRs[0].Name != "ISO-Bibliothek" || x.SRs[0].Total != 0 {
		t.Fatalf("SRs: %+v", x.SRs)
	}
	if sr := x.SRs[2]; sr.Name != "iSCSI Daten" || len(sr.Detached) != 1 || sr.Detached[0] != "xs-02" || sr.Type != "lvmoiscsi" {
		t.Errorf("iSCSI: %+v", sr)
	}
	mounts := []string{}
	for _, d := range snap.Disks {
		mounts = append(mounts, d.Mount)
	}
	if strings.Join(mounts, ",") != "SR NFS VM-Speicher,SR iSCSI Daten" {
		t.Errorf("Platten: %v", mounts)
	}
	if !strings.Contains(snap.System.Descr, "XenServer 8.4.0") || snap.System.Name != "pool-test" {
		t.Errorf("System: %+v", snap.System)
	}
	// Nur erlaubte Methoden, Rechte zuerst, am Ende abgemeldet.
	calls := f.Calls()
	want := []string{"session.login_with_password", "session.get_is_local_superuser", "session.get_rbac_permissions",
		"role.get_by_name_label", "role.get_permissions_name_label", "pool.get_all_records"}
	if strings.Join(calls[:len(want)], ",") != strings.Join(want, ",") {
		t.Errorf("Reihenfolge: %v", calls)
	}
	rrd := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "GET /rrd_updates@") {
			rrd++
			continue
		}
		if !AllowedMethod(c) {
			t.Errorf("nicht erlaubte Methode %s", c)
		}
	}
	if f.SessionInURL() != 0 {
		t.Errorf("Sitzung in der Adresse von /rrd_updates")
	}
	if rrd != 2 || calls[len(calls)-1] != "session.logout" || f.Logouts() != 1 || f.OpenSessions() != 0 {
		t.Errorf("Ende: %v, rrd %d, logouts %d, offen %d", calls, rrd, f.Logouts(), f.OpenSessions())
	}
	// Datensparsam: nichts aus Konfiguration oder BIOS im Snapshot
	b, _ := json.Marshal(snap)
	for _, s := range []string{"nicht-gelesen", "base_template_name", "Debian", "Control domain"} {
		if strings.Contains(string(b), s) {
			t.Errorf("Snapshot enthält %q", s)
		}
	}
}

func TestRootAbgelehntOhnePasswort(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	for _, u := range []string{"root", "ROOT", " root "} {
		cfg := cfgFor(srv)
		cfg.User = u
		_, err := client().Poll(context.Background(), cfg)
		if !errors.Is(err, ErrRoot) {
			t.Errorf("%q: %v", u, err)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("Anfragen trotz root: %v", f.Calls())
	}
}

func TestAbgelehnt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*xapitest.Fake, *Config)
		check func(error) bool
	}{
		{"falsches Passwort", func(_ *xapitest.Fake, c *Config) { c.Password = "falsch" }, func(e error) bool { return errors.Is(e, ErrLogin) }},
		{"keine Rolle", func(f *xapitest.Fake, _ *Config) { f.NoRole() }, func(e error) bool { return errors.Is(e, ErrNoRole) }},
		{"Superuser", func(f *xapitest.Fake, _ *Config) { f.Superuser() }, func(e error) bool { return errors.Is(e, ErrSuperuser) }},
		{"vm-operator", func(f *xapitest.Fake, _ *Config) { f.Writable("vm-operator", "vm.start") }, func(e error) bool {
			var we *WritableError
			return errors.As(e, &we) && we.Permission == "vm-operator"
		}},
		{"Einzelrecht", func(f *xapitest.Fake, _ *Config) { f.Writable("vm.clean_shutdown") }, func(e error) bool {
			var we *WritableError
			return errors.As(e, &we) && we.Permission == "vm.clean_shutdown"
		}},
		{"pool-admin", func(f *xapitest.Fake, _ *Config) { f.Writable("pool-admin") }, func(e error) bool {
			var we *WritableError
			return errors.As(e, &we)
		}},
		{"Rechte nicht lesbar", func(f *xapitest.Fake, _ *Config) { f.RightsUnreadable() }, func(e error) bool { return errors.Is(e, ErrRightsUnknown) }},
		{"Superuser-Abfrage scheitert", func(f *xapitest.Fake, _ *Config) { f.Fail("session.get_is_local_superuser", "RBAC_PERMISSION_DENIED") },
			func(e error) bool { return errors.Is(e, ErrRightsUnknown) }},
		{"Rolle unbekannt", func(f *xapitest.Fake, _ *Config) { f.Fail("role.get_by_name_label", "MESSAGE_METHOD_UNKNOWN") },
			func(e error) bool { return errors.Is(e, ErrRightsUnknown) }},
		{"Rollenrechte nicht lesbar", func(f *xapitest.Fake, _ *Config) { f.Fail("role.get_permissions_name_label", "RBAC_PERMISSION_DENIED") },
			func(e error) bool { return errors.Is(e, ErrRightsUnknown) }},
		{"Pool-Master gewechselt", func(f *xapitest.Fake, _ *Config) { f.SlaveOf("10.20.0.12") }, func(e error) bool {
			var ne *NotMasterError
			return errors.As(e, &ne) && ne.Master == "10.20.0.12" && strings.Contains(e.Error(), "folgt nicht")
		}},
		{"Master mit Schadtext", func(f *xapitest.Fake, _ *Config) { f.SlaveOf("evil<script>") }, func(e error) bool {
			var ne *NotMasterError
			return errors.As(e, &ne) && ne.Master == "" && !strings.Contains(e.Error(), "<")
		}},
		{"ohne Fingerabdruck", func(_ *xapitest.Fake, c *Config) { c.Pin = "" }, func(e error) bool { return strings.Contains(e.Error(), "Fingerabdruck") }},
		{"falscher Fingerabdruck", func(_ *xapitest.Fake, c *Config) { c.Pin = strings.Repeat("ab", 32) }, func(e error) bool {
			var pe *PinError
			return errors.As(e, &pe) && pe.Got != ""
		}},
		{"Weiterleitung", func(f *xapitest.Fake, _ *Config) { f.Redirect() }, func(e error) bool { return strings.Contains(e.Error(), "Weiterleitung") }},
		{"übergroß", func(f *xapitest.Fake, _ *Config) { f.Huge("host.get_all_records") }, func(e error) bool { return errors.Is(e, ErrTooMuch) }},
		{"Pool fehlt", func(f *xapitest.Fake, _ *Config) { f.Fail("pool.get_all_records", "RBAC_PERMISSION_DENIED") }, func(e error) bool {
			var ae *APIError
			return errors.As(e, &ae) && ae.Name == "RBAC_PERMISSION_DENIED"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := xapitest.NewFake()
			srv := xapitest.Start(t, f)
			cfg := cfgFor(srv)
			tc.setup(f, &cfg)
			snap, err := client().Poll(context.Background(), cfg)
			if err == nil || snap != nil || !tc.check(err) {
				t.Fatalf("Fehler: %v", err)
			}
			for _, c := range f.Calls() {
				if strings.HasPrefix(c, "pool.") && tc.name != "Pool fehlt" && tc.name != "übergroß" {
					t.Errorf("Abfrage trotz Ablehnung: %v", f.Calls())
				}
			}
			if f.OpenSessions() != 0 {
				t.Errorf("Sitzung nicht abgemeldet")
			}
		})
	}
}

func TestPasswortErstNachHandshake(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	cfg := cfgFor(srv)
	cfg.Pin = strings.Repeat("cd", 32)
	if _, err := client().Poll(context.Background(), cfg); err == nil {
		t.Fatal("kein Fehler")
	}
	if len(f.Calls()) != 0 {
		t.Errorf("Anfrage trotz falschem Zertifikat: %v", f.Calls())
	}
}

func TestFingerprint(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	fp, err := client().Fingerprint(context.Background(), srv.Host, srv.Port)
	if err != nil || fp != srv.Pin {
		t.Fatalf("%v %s", err, fp)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("Anfrage beim Fingerabdruck: %v", f.Calls())
	}
}

func TestZweiterHostNichtFreigegeben(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	d := &denyDialer{deny: map[string]bool{"127.0.0.2": true}}
	c := &Client{Guard: d, Timeout: 5 * time.Second}
	snap, err := c.Poll(context.Background(), cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	h2 := snap.XAPI.Hosts[1]
	if h2.CPUPct != nil || !strings.Contains(h2.MetricsError, "nicht freigegeben") {
		t.Errorf("xs-02: %+v", h2)
	}
	if snap.XAPI.Hosts[0].CPUPct == nil {
		t.Errorf("xs-01 ohne Messwerte")
	}
}

func TestZweiterHostFalschesZertifikat(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	c := client()
	// Der Pool meldet für xs-02 den Fingerabdruck des Masters: Der Client darf nicht verbinden.
	snap, err := pollWithPins(c, srv, f, map[string]string{xapitest.Host2Ref: srv.Pin})
	if err != nil {
		t.Fatal(err)
	}
	if h2 := snap.XAPI.Hosts[1]; h2.CPUPct != nil || !strings.Contains(h2.MetricsError, "Zertifikat des Hosts passt nicht") {
		t.Errorf("xs-02: %+v", h2)
	}
}

// pollWithPins ersetzt die Fingerabdrücke, die der Pool meldet.
func pollWithPins(c *Client, srv *xapitest.Server, f *xapitest.Fake, pins map[string]string) (*snmp.Snapshot, error) {
	f.SetPins(pins)
	return c.Poll(context.Background(), cfgFor(srv))
}

func TestZweiterHostAus(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	f.Update("host_metrics", "OpaqueRef:hm-0002", func(m map[string]any) { m["live"] = false })
	f.Update("host", xapitest.Host2Ref, func(h map[string]any) {
		h["enabled"] = false
		h["other_config"] = map[string]string{"MAINTENANCE_MODE": "true"}
	})
	snap, err := client().Poll(context.Background(), cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	h2 := snap.XAPI.Hosts[1]
	if h2.Live || h2.Enabled || !h2.Maintenance || h2.CPUPct != nil || h2.MetricsError != "Host nicht erreichbar" {
		t.Errorf("xs-02: %+v", h2)
	}
	for _, c := range f.Calls() {
		if c == "GET /rrd_updates@"+xapitest.Host2Ref {
			t.Errorf("Messwerte bei ausgefallenem Host abgefragt")
		}
	}
}

func TestTeileFehlen(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	f.Fail("SR.get_all_records", "RBAC_PERMISSION_DENIED")
	f.Fail("certificate.get_all_records_where", "MESSAGE_METHOD_UNKNOWN")
	snap, err := client().Poll(context.Background(), cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.XAPI.SRs) != 0 || len(snap.Partial) != 1 || snap.Partial[0] != "Speicher" {
		t.Errorf("Teile: %v %+v", snap.Partial, snap.XAPI.SRs)
	}
	if h2 := snap.XAPI.Hosts[1]; h2.CPUPct != nil || !strings.Contains(h2.MetricsError, "Fingerabdruck") {
		t.Errorf("xs-02: %+v", h2)
	}
	for _, c := range f.Calls() {
		if c == "PBD.get_currently_attached" {
			t.Errorf("PBDs ohne SRs abgefragt")
		}
	}
}

func TestParseRRD(t *testing.T) {
	h := "11111111-1111-4111-8111-111111111111"
	v := "aaaaaaaa-0000-4000-8000-000000000001"
	ok := `<?xml version="1.0"?><xport><meta><start>0</start><step>60</step><end>60</end><rows>2</rows><columns>6</columns>
<legend><entry>AVERAGE:host:` + h + `:cpu_avg</entry><entry>AVERAGE:host:` + h + `:memory_total_kib</entry>
<entry>AVERAGE:host:` + h + `:memory_free_kib</entry><entry>AVERAGE:vm:` + v + `:cpu0</entry>
<entry>AVERAGE:vm:` + v + `:cpu1</entry><entry>MAX:host:` + h + `:cpu_avg</entry></legend></meta>
<data><row><t>0</t><v>0.5</v><v>1000</v><v>400</v><v>0.2</v><v>0.4</v><v>0.99</v></row>
<row><t>60</t><v>NaN</v><v>1000</v><v>200</v><v>0.2</v><v>0.4</v><v>0.99</v></row></data></xport>`
	r, err := ParseRRD([]byte(ok), h)
	if err != nil || r.HostCPU == nil || *r.HostCPU != 0.5 || r.MemTotal != 1000 || r.MemFree != 200 {
		t.Fatalf("%v %+v", err, r)
	}
	if c := r.VMCPU[v]; c < 0.299 || c > 0.301 {
		t.Errorf("VM-CPU aus vCPUs: %v", c)
	}
	for _, bad := range []string{
		"", "<xport>", `<!DOCTYPE x [<!ENTITY a "b">]><xport>&a;</xport>`,
		`<xport><meta><legend></legend></meta></xport>`,
	} {
		if _, err := ParseRRD([]byte(bad), h); err == nil {
			t.Errorf("angenommen: %q", bad)
		}
	}
	// fremder Host, unplausible Werte
	odd := strings.ReplaceAll(ok, "<v>0.5</v>", "<v>7</v>")
	if r, _ := ParseRRD([]byte(odd), h); r.HostCPU != nil {
		t.Errorf("CPU 700 %% angenommen")
	}
	if r, _ := ParseRRD([]byte(ok), "22222222-2222-4222-8222-222222222222"); r.HostCPU != nil || r.MemTotal != 0 {
		t.Errorf("Werte eines fremden Hosts angenommen: %+v", r)
	}
	inv := strings.ReplaceAll(ok, "<v>200</v>", "<v>5000</v>")
	if r, _ := ParseRRD([]byte(inv), h); r.MemTotal != 0 || r.MemFree != 0 {
		t.Errorf("frei > gesamt angenommen: %+v", r)
	}
}

func TestWritable(t *testing.T) {
	ro := []string{"vm.get_record", "http/get_rrd_updates"}
	if err := Writable([]string{"read-only", "vm.get_record"}, ro); err != nil {
		t.Errorf("read-only: %v", err)
	}
	if err := Writable([]string{"vm.get_record"}, ro); !errors.Is(err, ErrRightsUnknown) {
		t.Errorf("ohne Rolle: %v", err)
	}
	var we *WritableError
	if err := Writable([]string{"read-only", "vm.get_record", "vm.start"}, ro); !errors.As(err, &we) || we.Permission != "vm.start" {
		t.Errorf("vm.start: %v", err)
	}
	if err := Writable([]string{"read-only", "VM.get_record"}, ro); !errors.As(err, &we) {
		t.Errorf("Groß-/Kleinschreibung: %v", err)
	}
}

func TestBuildBereinigt(t *testing.T) {
	raw := Raw{
		Pools: map[string]poolRec{"OpaqueRef:p": {Name: "pool\u202e-x\x00", Master: "OpaqueRef:h1",
			HATolerate: flexInt{V: -5, OK: true}, HAPlan: flexInt{V: 1 << 40, OK: true}}},
		Hosts: map[string]hostRec{"OpaqueRef:h1": {UUID: "11111111-1111-4111-8111-111111111111", Name: strings.Repeat("ä", 500),
			OtherConfig: map[string]string{"boot_time": "-1"}, Pending: []string{"reboot_host", "rm -rf", "reboot_host"}}},
		VMs: map[string]vmRec{
			"OpaqueRef:v1": {UUID: "kein-uuid", Name: "x", PowerState: "Running"},
			"OpaqueRef:v2": {UUID: "aaaaaaaa-0000-4000-8000-000000000001", Name: "<b>vm</b>", PowerState: "exploding",
				VCPUs: flexInt{V: 1 << 40, OK: true}},
		},
		SRs: map[string]srRec{"OpaqueRef:s1": {Name: "sr", Type: "NFS; drop", Size: flexInt{V: 10, OK: true}, Used: flexInt{V: 20, OK: true}}},
	}
	snap := Build(raw, time.Now())
	x := snap.XAPI
	if x.Pool != "pool-x" || x.HA.Tolerate != 0 || x.HA.Plan != 0 {
		t.Errorf("Pool: %+v", x)
	}
	if len([]rune(x.Hosts[0].Name)) != MaxText || x.Hosts[0].UptimeS != 0 || len(x.Hosts[0].Pending) != 1 {
		t.Errorf("Host: %+v", x.Hosts[0])
	}
	if len(x.VMs) != 1 || x.VMs[0].State != "unknown" || x.VMs[0].VCPUs != 0 {
		t.Errorf("VMs: %+v", x.VMs)
	}
	if len(x.SRs) != 1 || x.SRs[0].Type != "" || x.SRs[0].Total != 0 || len(snap.Disks) != 0 {
		t.Errorf("SRs: %+v %+v", x.SRs, snap.Disks)
	}
}

func TestRebooted(t *testing.T) {
	prev := &snmp.XAPI{Hosts: []snmp.XAPIHost{{Name: "a", UptimeS: 100000}, {Name: "b", UptimeS: 5000}}}
	cur := &snmp.XAPI{Hosts: []snmp.XAPIHost{{Name: "a", UptimeS: 100300}, {Name: "b", UptimeS: 5300}}}
	if Rebooted(prev, cur) {
		t.Error("ohne Neustart")
	}
	cur.Hosts[1].UptimeS = 120
	if !Rebooted(prev, cur) || Rebooted(nil, cur) {
		t.Error("Neustart nicht erkannt")
	}
}

func TestFlexInt(t *testing.T) {
	var v struct{ A, B, C, D flexInt }
	if err := json.Unmarshal([]byte(`{"A":"123","B":456,"C":"x","D":1.5e3}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A.V != 123 || !v.A.OK || v.B.V != 456 || v.C.OK || v.D.V != 1500 {
		t.Errorf("%+v", v)
	}
}

func TestNichtEndlicheZahlen(t *testing.T) {
	f := xapitest.NewFake()
	srv := xapitest.Start(t, f)
	f.NonFinite()
	if _, err := client().Poll(context.Background(), cfgFor(srv)); err != nil {
		t.Fatalf("NaN im Pool: %v", err)
	}
}
