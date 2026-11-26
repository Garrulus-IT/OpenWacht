// SPDX-License-Identifier: AGPL-3.0-only

package pve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve/pvetest"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const testToken = pvetest.Token

type fake = pvetest.Fake

func newFake() *fake { return pvetest.NewFake() }

type direct struct{}

func (direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func start(t *testing.T, f *fake) (Config, *Client) {
	t.Helper()
	ts := pvetest.Start(t, f)
	return Config{Host: ts.Host, Port: uint16(ts.Port), Token: testToken, CAPEM: ts.CAPEM}, &Client{Guard: direct{}, Timeout: 3 * time.Second}
}

func TestValidToken(t *testing.T) {
	good := []string{testToken, "root@pam!a=0B8F1C2E-1111-4222-8333-944455556666", "svc.mon@pve!mon_1=0b8f1c2e-1111-4222-8333-944455556666"}
	bad := []string{"", "openwacht@pve!monitor", "openwacht@pve=0b8f1c2e-1111-4222-8333-944455556666",
		"openwacht@pve!monitor=nicht-uuid", "open wacht@pve!m=0b8f1c2e-1111-4222-8333-944455556666",
		testToken + "\n", "a@b!c=0b8f1c2e-1111-4222-8333-944455556666 x", "@pve!m=0b8f1c2e-1111-4222-8333-944455556666"}
	for _, s := range good {
		if !ValidToken(s) {
			t.Errorf("%q sollte gültig sein", s)
		}
	}
	for _, s := range bad {
		if ValidToken(s) {
			t.Errorf("%q sollte ungültig sein", s)
		}
	}
	if TokenID(testToken) != "openwacht@pve!monitor" {
		t.Fatal(TokenID(testToken))
	}
}

func selfSigned(t *testing.T, isCA bool) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Proxmox Virtual Environment"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseCA(t *testing.T) {
	ca, err := ParseCA(selfSigned(t, true))
	if err != nil || len(ca.Fingerprint) != 95 || !strings.Contains(ca.Subject, "Proxmox") {
		t.Fatalf("%v %+v", err, ca)
	}
	if _, err := ParseCA(selfSigned(t, false)); err == nil || !strings.Contains(err.Error(), "pve-root-ca.pem") {
		t.Fatalf("Hostzertifikat: %v", err)
	}
	for _, s := range []string{"", "Hallo", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
		selfSigned(t, true) + "\nMüll", strings.Repeat("x", MaxCAPEM+1)} {
		if _, err := ParseCA(s); err == nil {
			t.Errorf("%.30q sollte abgelehnt werden", s)
		}
	}
	key := "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
	if _, err := ParseCA(key); err == nil || !strings.Contains(err.Error(), "Schlüssel") {
		t.Fatalf("Schlüssel: %v", err)
	}
	five := strings.Repeat(selfSigned(t, true), 5)
	if _, err := ParseCA(five); err == nil {
		t.Fatal("5 Zertifikate angenommen")
	}
}

func TestProbe(t *testing.T) {
	f := newFake()
	cfg, c := start(t, f)
	info, err := c.Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Node != "pve-1" || info.Version != "9.2.2" || info.UptimeS != 100000 || len(info.ExtraPrivs) != 0 {
		t.Fatalf("%+v", info)
	}
	f.Mu.Lock()
	f.Privs["/vms"] = map[string]int{"VM.PowerMgmt": 1, "VM.Audit": 1, "VM.Backup": 0}
	f.Mu.Unlock()
	info, err = c.Probe(context.Background(), cfg)
	if err != nil || len(info.ExtraPrivs) != 1 || info.ExtraPrivs[0] != "VM.PowerMgmt" {
		t.Fatalf("%v %+v", err, info)
	}
	if len(f.Methods) != 1 || !f.Methods[http.MethodGet] {
		t.Fatalf("nur GET erlaubt: %v", f.Methods)
	}
}

func TestProbeFehler(t *testing.T) {
	f := newFake()
	cfg, c := start(t, f)
	ctx := context.Background()

	bad := cfg
	bad.Token = "openwacht@pve!monitor=0b8f1c2e-1111-4222-8333-000000000000"
	if _, err := c.Probe(ctx, bad); !errors.Is(err, ErrToken) {
		t.Fatalf("falsches Token: %v", err)
	}
	bad = cfg
	bad.Token = "kaputt"
	if _, err := c.Probe(ctx, bad); err == nil {
		t.Fatal("ungültiges Token angenommen")
	}
	// fremde CA: Verbindung wird abgebrochen, bevor das Token gesendet wird
	before := f.Count("/")
	bad = cfg
	bad.CAPEM = selfSigned(t, true)
	var te *TLSError
	if _, err := c.Probe(ctx, bad); !errors.As(err, &te) || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("fremde CA: %v", err)
	}
	// ohne CA: System-CAs kennen das Testzertifikat nicht
	bad.CAPEM = ""
	if _, err := c.Probe(ctx, bad); !errors.As(err, &te) || !strings.Contains(err.Error(), "pve-root-ca.pem") {
		t.Fatalf("ohne CA: %v", err)
	}
	if f.Count("/") != before {
		t.Fatal("Anfrage trotz falschem Zertifikat beim Host angekommen")
	}
	f.Status = func(p string) int {
		if p == "/nodes/pve-1/status" {
			return http.StatusForbidden
		}
		return 0
	}
	if _, err := c.Probe(ctx, cfg); !errors.Is(err, ErrForbidden) {
		t.Fatalf("403: %v", err)
	}
	f.Status = func(string) int { return http.StatusFound }
	if _, err := c.Probe(ctx, cfg); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("Weiterleitung: %v", err)
	}
}

func TestGuard(t *testing.T) {
	f := newFake()
	cfg, _ := start(t, f)
	g := checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	c := &Client{Guard: g, Timeout: time.Second}
	var na *checks.NotAllowedError
	if _, err := c.Probe(context.Background(), cfg); !errors.As(err, &na) {
		t.Fatalf("nicht freigegebene Adresse: %v", err)
	}
}

func TestZuGrosseAntwort(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"`))
		w.Write([]byte(strings.Repeat("x", maxBody)))
		w.Write([]byte(`"}`))
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	c := &Client{Guard: direct{}}
	if _, err := c.Probe(context.Background(), Config{Host: host, Port: uint16(p), Token: testToken, CAPEM: ca}); !errors.Is(err, ErrTooMuch) {
		t.Fatalf("%v", err)
	}
}

func guest(s *snmp.Snapshot, id int) *snmp.Guest {
	for i := range s.Proxmox.Guests {
		if s.Proxmox.Guests[i].VMID == id {
			return &s.Proxmox.Guests[i]
		}
	}
	return nil
}

func TestPoll(t *testing.T) {
	f := newFake()
	cfg, c := start(t, f)
	// Echte Zeit: c.Now gilt auch für die Prüfung der Testzertifikate, die
	// ab time.Now() eine Stunde zurück gültig sind (ein festes Datum war eine Zeitbombe).
	now := time.Now().UTC().Truncate(time.Second)
	c.Now = func() time.Time { return now }
	night := now.Add(-11 * time.Hour).Unix()
	f.AddTask("UPID:pve-1:0001:01:A:vzdump::root@pam:", "", "job errors", night,
		"INFO: starting new backup job: vzdump 100 101 --storage nas-backup",
		"INFO: Starting Backup of VM 100 (qemu)",
		"INFO: Finished Backup of VM 100 (00:00:12)",
		"INFO: Starting Backup of VM 101 (lxc)",
		"ERROR: Backup of VM 101 failed - unable to open file '/mnt/pve/nas-backup/dump/x' - Permission denied",
		"INFO: Backup job finished with errors")
	// älter als das Fenster: wird nicht gelesen
	f.AddTask("UPID:pve-1:0000:01:B:vzdump:100:root@pam:", "100", "OK", now.Add(-10*24*time.Hour).Unix(),
		"INFO: Finished Backup of VM 100 (00:00:10)")

	snap, err := c.Poll(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	px := snap.Proxmox
	if px.Node != "pve-1" || px.Version != "9.2.2" || snap.System.UptimeS != 100000 || !px.BackupInfo || len(snap.Partial) != 0 {
		t.Fatalf("%+v %+v", px, snap.Partial)
	}
	if len(px.Guests) != 3 || px.Guests[0].VMID != 100 || px.Guests[1].VMID != 101 || px.Guests[1].Type != "lxc" {
		t.Fatalf("Gäste: %+v", px.Guests)
	}
	g100, g101, g102 := guest(snap, 100), guest(snap, 101), guest(snap, 102)
	if g100.OnBoot == nil || !*g100.OnBoot || g101.OnBoot == nil || !*g101.OnBoot || g102.OnBoot != nil || !g102.Template {
		t.Fatalf("beim Booten: %+v %+v %+v", g100, g101, g102)
	}
	if *g100.InJob != true || *g102.InJob != false {
		t.Fatal("Backup-Job")
	}
	if g100.BackupOK == nil || g100.BackupOK.Unix() != night || g100.BackupError != "" {
		t.Fatalf("100: %+v", g100)
	}
	if g101.BackupOK != nil || g101.BackupTry == nil || !strings.Contains(g101.BackupError, "Permission denied") {
		t.Fatalf("101: %+v", g101)
	}
	if len(snap.Disks) != 2 || snap.Disks[1].Mount != "local-lvm" || snap.Disks[1].FreeBytes != 20<<30 {
		t.Fatalf("Platten: %+v", snap.Disks)
	}
	if len(px.Storages) != 3 || px.Storages[2].Active || !px.Storages[2].Shared {
		t.Fatalf("Speicher: %+v", px.Storages)
	}
	if pct, ok := px.ThinPools[0].MetaPercent(); px.ThinPools[0].Name != "pve/data" || !ok || pct != 75 {
		t.Fatalf("Thin-Pool: %+v", px.ThinPools)
	}
	if px.TasksUntil.Unix() != night {
		t.Fatalf("bis %v", px.TasksUntil)
	}
	names, _ := snmp.Series(snap)
	if strings.Join(names, ",") != "platte:local,platte:local-lvm,meta:pve/data" {
		t.Fatalf("Reihen: %v", names)
	}
	// Datensparsam: weder Benutzer noch Beschreibung im Snapshot
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "root@pam") || strings.Contains(string(raw), "geheim") {
		t.Fatalf("Personendaten im Snapshot: %s", raw)
	}
	logs, configs := f.Count("/nodes/pve-1/tasks/"), f.Count("/nodes/pve-1/qemu/")+f.Count("/nodes/pve-1/lxc/")
	if logs != 1 || configs != 2 {
		t.Fatalf("Protokolle %d, Konfigurationen %d", logs, configs)
	}

	// Zweite Abfrage: nichts Neues, keine Protokolle und Konfigurationen erneut
	now = now.Add(time.Minute)
	var prev snmp.Snapshot
	_ = json.Unmarshal(raw, &prev)
	snap2, err := c.Poll(context.Background(), cfg, &prev)
	if err != nil {
		t.Fatal(err)
	}
	if f.Count("/nodes/pve-1/tasks/") != 1 || f.Count("/nodes/pve-1/qemu/")+f.Count("/nodes/pve-1/lxc/") != 2 {
		t.Fatal("unnötige Anfragen")
	}
	if g := guest(snap2, 101); g.OnBoot == nil || !strings.Contains(g.BackupError, "Permission") {
		t.Fatalf("nicht fortgeschrieben: %+v", g)
	}

	// Neuer erfolgreicher Lauf von 101, und nach 10 Minuten neue Konfiguration
	now = now.Add(15 * time.Minute)
	f.AddTask("UPID:pve-1:0002:01:C:vzdump:101:root@pam:", "101", "OK", now.Add(-time.Minute).Unix(),
		"INFO: Starting Backup of VM 101 (lxc)", "INFO: Finished Backup of VM 101 (00:00:05)")
	f.Mu.Lock()
	f.OnBoot["qemu/100"] = 0
	f.Mu.Unlock()
	raw, _ = json.Marshal(snap2)
	prev = snmp.Snapshot{}
	_ = json.Unmarshal(raw, &prev)
	snap3, err := c.Poll(context.Background(), cfg, &prev)
	if err != nil {
		t.Fatal(err)
	}
	g101 = guest(snap3, 101)
	if g101.BackupOK == nil || g101.BackupError != "" || f.Count("/nodes/pve-1/tasks/") != 2 {
		t.Fatalf("101 neu: %+v", g101)
	}
	if g := guest(snap3, 100); *g.OnBoot {
		t.Fatal("beim Booten nicht neu gelesen")
	}
}

func TestPollTeilweise(t *testing.T) {
	f := newFake()
	cfg, c := start(t, f)
	f.Status = func(p string) int {
		if p == "/nodes/pve-1/disks/lvmthin" || p == "/cluster/backup-info/not-backed-up" {
			return http.StatusForbidden
		}
		return 0
	}
	snap, err := c.Poll(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(snap.Partial, ",") != "Backup-Jobs,Thin-Pools" || snap.Proxmox.BackupInfo || guest(snap, 100).InJob != nil {
		t.Fatalf("%v %+v", snap.Partial, snap.Proxmox)
	}
	// Token zwischendurch widerrufen: ganze Abfrage scheitert
	f.Status = func(p string) int {
		if p == "/nodes/pve-1/storage" {
			return http.StatusUnauthorized
		}
		return 0
	}
	if _, err := c.Poll(context.Background(), cfg, nil); !errors.Is(err, ErrToken) {
		t.Fatalf("%v", err)
	}
}

func TestPollUnplausibel(t *testing.T) {
	f := newFake()
	f.Guests["qemu"] = append(f.Guests["qemu"], map[string]any{"vmid": 5, "name": "zu klein"},
		map[string]any{"vmid": 103, "name": "a\x00b\u202e" + strings.Repeat("ä", 300), "status": "running"})
	f.Storage = append(f.Storage, map[string]any{"storage": "kaputt", "type": "dir", "active": 1, "enabled": 1,
		"total": 10, "used": 20})
	cfg, c := start(t, f)
	snap, err := c.Poll(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if guest(snap, 5) != nil {
		t.Fatal("VMID < 100 angenommen")
	}
	g := guest(snap, 103)
	if strings.ContainsAny(g.Name, "\x00\u202e") || len([]rune(g.Name)) > MaxText {
		t.Fatalf("Name ungeprüft: %q", g.Name)
	}
	for _, d := range snap.Disks {
		if d.Mount == "kaputt" {
			t.Fatal("belegt > gesamt als Platte angenommen")
		}
	}
}

func TestRebooted(t *testing.T) {
	// 27 h = 97200 s: erst ab dieser Laufzeit davor zählt ein Neustart (1.0.6)
	if !Rebooted(97200, 120) || Rebooted(0, 10) || Rebooted(100, 90) || Rebooted(100, 200) {
		t.Fatal()
	}
	if Rebooted(86400, 120) || Rebooted(97199, 120) {
		t.Fatal("geplanter nächtlicher Neustart (Laufzeit < 27 h) gemeldet")
	}
}
