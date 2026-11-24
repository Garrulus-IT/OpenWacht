// SPDX-License-Identifier: AGPL-3.0-only

// Package vcenter liest die REST-API eines VMware vCenter (Etappe 26),
// ausschließlich lesend: Hosts (ESXi), VMs und Datastores.
//
// Anmeldung mit einem Konto mit der Rolle „Read-only“ (POST /api/session,
// Basic Auth); danach nur GET-Anfragen, am Ende DELETE /api/session.
// Verbindungen laufen über den Guard der Zentrale (Netzfreigabe). Das
// Zertifikat prüft die hinterlegte CA (z. B. die VMCA des vCenter) oder die
// System-CAs; Weiterleitungen werden nie verfolgt. Antworten sind begrenzt,
// Texte gekürzt.
//
// Abbildung auf die Proxmox-Struktur des Snapshots, damit Anzeige, Verlauf
// und Alarme dieselbe Logik nutzen: ESXi-Hosts erscheinen als „Gäste“ der Art
// esxi mit Pflicht zu laufen (getrennt oder aus = kritisch), VMs als Gäste
// der Art vm ohne Alarm (ob eine VM laufen soll, weiß vCenter nicht), Datastores
// als Speicherorte (nicht erreichbar = kritisch, Belegung wie Platten).
package vcenter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/garrulus-it/openwacht/internal/pve"
	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const (
	MaxHosts      = 200
	MaxVMs        = 2000
	MaxDatastores = 200
	MaxText       = 200
	maxBody       = 8 << 20
	// IDs: vCenter vergibt host-12, vm-1001, datastore-15. Gäste brauchen eine
	// Zahl (Subjekt gast:<zahl>, mindestens dreistellig): VMs ab 100000,
	// Hosts ab 900000000, damit sich die Bereiche nicht überschneiden.
	vmBase   = 100000
	hostBase = 900000000
)

// Config einer Abfrage.
type Config struct {
	Host     string
	Port     uint16 // Standard 443
	User     string // z. B. svc-openwacht@vsphere.local
	Password string
	CAPEM    string // leer = System-CAs mit Namensprüfung
}

var userPattern = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{1,128}$`)

// ValidUser prüft die Form des Benutzernamens.
func ValidUser(s string) bool { return userPattern.MatchString(s) }

// Dialer verbindet nur zu freigegebenen Adressen.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Client fragt vCenter ab.
type Client struct {
	Guard   Dialer
	Timeout time.Duration
	Now     func() time.Time
}

var (
	ErrLogin     = errors.New("Anmeldung abgelehnt (401): Benutzer und Passwort prüfen")
	ErrForbidden = errors.New("Rechte fehlen (403): das Konto braucht mindestens die Rolle „Read-only“")
	ErrTooMuch   = errors.New("vCenter liefert mehr Daten als erlaubt")
)

type session struct {
	http  *http.Client
	base  string
	id    string
	close func()
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) open(ctx context.Context, cfg Config) (*session, error) {
	if !ValidUser(cfg.User) || cfg.Password == "" || len(cfg.Password) > 256 {
		return nil, errors.New("Benutzer oder Passwort ungültig")
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	host := strings.TrimSuffix(strings.TrimPrefix(cfg.Host, "["), "]")
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if strings.TrimSpace(cfg.CAPEM) != "" {
		ca, err := pve.ParseCA(cfg.CAPEM)
		if err != nil {
			return nil, err
		}
		// Kette gegen die CA prüfen, ohne Namensvergleich: die VMCA stellt oft
		// nur interne Namen aus; den Schutz gibt die CA.
		tcfg.InsecureSkipVerify = true
		tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("TLS: kein Zertifikat")
			}
			inter := x509.NewCertPool()
			for _, x := range cs.PeerCertificates[1:] {
				inter.AddCert(x)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: ca.Pool, Intermediates: inter, CurrentTime: c.now(),
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return fmt.Errorf("TLS: Zertifikat passt nicht zur hinterlegten CA (%v)", err)
			}
			return nil
		}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{Proxy: nil, DialContext: c.Guard.DialContext, TLSClientConfig: tcfg, TLSHandshakeTimeout: timeout,
		ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: true}
	s := &session{
		http: &http.Client{Transport: tr, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:  "https://" + net.JoinHostPort(host, strconv.Itoa(int(cfg.Port))),
		close: tr.CloseIdleConnections,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/api/session", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(cfg.User, cfg.Password)
	var id string
	if err := s.do(req, &id); err != nil {
		s.close()
		return nil, err
	}
	if id == "" || len(id) > 512 {
		s.close()
		return nil, errors.New("vCenter: keine Sitzung erhalten")
	}
	s.id = id
	return s, nil
}

func (s *session) logout() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.base+"/api/session", nil); err == nil {
		req.Header.Set("vmware-api-session-id", s.id)
		if resp, err := s.http.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	s.close()
}

func (s *session) do(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	switch {
	case len(b) > maxBody:
		return ErrTooMuch
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrLogin
	case resp.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated:
		return fmt.Errorf("vCenter antwortet mit HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	return dec.Decode(out)
}

func (s *session) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("vmware-api-session-id", s.id)
	return s.do(req, out)
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > MaxText {
		s = string(r[:MaxText])
	}
	return strings.TrimSpace(s)
}

var idPattern = regexp.MustCompile(`^(host|vm|datastore)-([1-9][0-9]{0,7})$`)

func number(id, kind string) (int, bool) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil || m[1] != kind {
		return 0, false
	}
	n, err := strconv.Atoi(m[2])
	return n, err == nil
}

type hostItem struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Connection string `json:"connection_state"`
	Power      string `json:"power_state"`
}

type vmItem struct {
	VM    string `json:"vm"`
	Name  string `json:"name"`
	Power string `json:"power_state"`
}

type dsItem struct {
	Datastore string `json:"datastore"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Capacity  *int64 `json:"capacity"`
	Free      *int64 `json:"free_space"`
}

// Info: was „Verbindung prüfen“ zeigt.
type Info struct {
	Hosts      int `json:"hosts"`
	VMs        int `json:"vms"`
	Datastores int `json:"datastores"`
}

// Probe meldet sich an und zählt Hosts, VMs und Datastores.
func (c *Client) Probe(ctx context.Context, cfg Config) (Info, error) {
	snap, err := c.Poll(ctx, cfg)
	if err != nil {
		return Info{}, err
	}
	info := Info{Datastores: len(snap.Proxmox.Storages)}
	for _, g := range snap.Proxmox.Guests {
		if g.Type == "esxi" {
			info.Hosts++
		} else {
			info.VMs++
		}
	}
	return info, nil
}

// Poll liest Hosts, VMs und Datastores als Snapshot.
func (c *Client) Poll(ctx context.Context, cfg Config) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("vcenter", &err)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	s, err := c.open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer s.logout()
	var hosts []hostItem
	if err := s.get(ctx, "/api/vcenter/host", &hosts); err != nil {
		return nil, fmt.Errorf("Hosts: %w", err)
	}
	var vms []vmItem
	if err := s.get(ctx, "/api/vcenter/vm", &vms); err != nil {
		return nil, fmt.Errorf("VMs: %w", err)
	}
	var dss []dsItem
	if err := s.get(ctx, "/api/vcenter/datastore", &dss); err != nil {
		return nil, fmt.Errorf("Datastores: %w", err)
	}
	if len(hosts) > MaxHosts || len(vms) > MaxVMs || len(dss) > MaxDatastores {
		return nil, ErrTooMuch
	}
	snap := &snmp.Snapshot{CollectedAt: c.now(), Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{}}
	px := &snmp.Proxmox{Node: clean(cfg.Host), Version: "vCenter", Guests: []snmp.Guest{}, Storages: []snmp.Storage{}, ThinPools: []snmp.ThinPool{}}
	on := true
	for _, h := range hosts {
		n, ok := number(h.Host, "host")
		if !ok {
			continue
		}
		status := "running"
		switch {
		case h.Connection != "CONNECTED":
			status = strings.ToLower(clean(h.Connection)) // disconnected, not_responding
		case h.Power != "POWERED_ON":
			status = strings.ToLower(clean(h.Power)) // standby, powered_off
		}
		px.Guests = append(px.Guests, snmp.Guest{VMID: hostBase + n, Type: "esxi", Name: clean(h.Name), Status: status, OnBoot: &on})
	}
	for _, v := range vms {
		n, ok := number(v.VM, "vm")
		if !ok {
			continue
		}
		status := map[string]string{"POWERED_ON": "running", "POWERED_OFF": "stopped", "SUSPENDED": "suspended"}[v.Power]
		if status == "" {
			status = "unbekannt"
		}
		px.Guests = append(px.Guests, snmp.Guest{VMID: vmBase + n, Type: "vm", Name: clean(v.Name), Status: status})
	}
	sort.Slice(px.Guests, func(i, j int) bool { return px.Guests[i].VMID < px.Guests[j].VMID })
	for _, d := range dss {
		if _, ok := number(d.Datastore, "datastore"); !ok {
			continue
		}
		st := snmp.Storage{Name: clean(d.Name), Type: strings.ToLower(clean(d.Type)), Enabled: true, Shared: true}
		// Ohne Kapazität ist der Datastore nicht erreichbar (vCenter liefert dann keine Werte).
		if d.Capacity != nil && d.Free != nil && *d.Capacity > 0 && *d.Free >= 0 && *d.Free <= *d.Capacity {
			st.Active, st.TotalBytes, st.UsedBytes = true, uint64(*d.Capacity), uint64(*d.Capacity-*d.Free)
		}
		if st.Name == "" {
			continue
		}
		px.Storages = append(px.Storages, st)
		if st.Active {
			snap.Disks = append(snap.Disks, snmp.Disk{Mount: st.Name, FSType: st.Type, TotalBytes: st.TotalBytes,
				FreeBytes: st.TotalBytes - st.UsedBytes})
		}
	}
	sort.Slice(px.Storages, func(i, j int) bool { return px.Storages[i].Name < px.Storages[j].Name })
	sort.Slice(snap.Disks, func(i, j int) bool { return snap.Disks[i].Mount < snap.Disks[j].Mount })
	snap.Proxmox = px
	snap.System.Name = clean(cfg.Host)
	snap.System.Descr = fmt.Sprintf("VMware vCenter (%d Hosts, %d VMs, %d Datastores)", len(hosts), len(vms), len(px.Storages))
	return snap, nil
}
