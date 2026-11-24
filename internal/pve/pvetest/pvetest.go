// SPDX-License-Identifier: AGPL-3.0-only

// Package pvetest: Attrappe der Proxmox-VE-API für Tests (TLS mit eigener CA).
package pvetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token: das API-Token, das die Attrappe annimmt.
const Token = "openwacht@pve!monitor=0b8f1c2e-1111-4222-8333-944455556666"

// Fake ist eine kleine Proxmox-Attrappe (nur die Endpunkte, die OpenWacht liest).
// Felder nur unter Mu ändern.
type Fake struct {
	Mu       sync.Mutex
	Requests map[string]int
	Methods  map[string]bool
	Tasks    []map[string]any
	Logs     map[string][]string
	Guests   map[string][]map[string]any
	OnBoot   map[string]int
	Missing  []int
	Privs    map[string]map[string]int
	Storage  []map[string]any
	Thin     []map[string]any
	Status   func(path string) int
	Uptime   int
}

// NewFake: Attrappe mit drei Gästen, drei Speichern und einem Thin-Pool.
func NewFake() *Fake {
	return &Fake{
		Requests: map[string]int{}, Methods: map[string]bool{},
		Guests: map[string][]map[string]any{
			"qemu": {{"vmid": 100, "name": "srv-dms", "status": "running", "uptime": 5000},
				{"vmid": 102, "name": "vorlage", "status": "stopped", "template": 1}},
			"lxc": {{"vmid": "101", "name": "openwacht", "status": "stopped"}},
		},
		OnBoot:  map[string]int{"qemu/100": 1, "lxc/101": 1},
		Missing: []int{102},
		Privs:   map[string]map[string]int{"/": {"Sys.Audit": 1, "VM.Audit": 1, "Datastore.Audit": 1}},
		Storage: []map[string]any{
			{"storage": "local", "type": "dir", "active": 1, "enabled": 1, "total": 100 << 30, "used": 30 << 30},
			{"storage": "local-lvm", "type": "lvmthin", "active": 1, "enabled": 1, "total": 400 << 30, "used": 380 << 30},
			{"storage": "nas-backup", "type": "cifs", "active": 0, "enabled": 1, "shared": 1},
		},
		Thin: []map[string]any{{"lv": "data", "vg": "pve", "lv_size": 400 << 30, "used": 380 << 30,
			"metadata_size": 4 << 30, "metadata_used": 3 << 30}},
		Logs:   map[string][]string{},
		Uptime: 86400,
	}
}

// AddTask: neue vzdump-Aufgabe (neueste zuerst) mit Protokollzeilen.
func (f *Fake) AddTask(upid, id, status string, end int64, lines ...string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Tasks = append([]map[string]any{{"upid": upid, "type": "vzdump", "id": id, "status": status, "endtime": end,
		"user": "root@pam"}}, f.Tasks...)
	f.Logs[upid] = lines
}

// Count: Anfragen auf Pfade mit diesem Anfang.
func (f *Fake) Count(prefix string) int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	n := 0
	for k, v := range f.Requests {
		if strings.HasPrefix(k, prefix) {
			n += v
		}
	}
	return n
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Methods[r.Method] = true
	if r.Header.Get("Authorization") != "PVEAPIToken="+Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	f.Requests[p]++
	if f.Status != nil {
		if code := f.Status(p); code != 0 {
			if code >= 300 && code < 400 {
				w.Header().Set("Location", "/umgeleitet")
			}
			w.WriteHeader(code)
			return
		}
	}
	var data any
	switch {
	case p == "/cluster/status":
		data = []map[string]any{{"type": "cluster", "name": "x"}, {"type": "node", "name": "pve-1", "local": 1}}
	case p == "/nodes/pve-1/status":
		data = map[string]any{"pveversion": "pve-manager/9.2.2/0123abcd", "uptime": f.Uptime}
	case p == "/access/permissions":
		data = f.Privs
	case p == "/nodes/pve-1/qemu" || p == "/nodes/pve-1/lxc":
		data = f.Guests[strings.TrimPrefix(p, "/nodes/pve-1/")]
	case strings.HasSuffix(p, "/config"):
		parts := strings.Split(p, "/") // "", nodes, pve-1, typ, vmid, config
		data = map[string]any{"onboot": f.OnBoot[parts[3]+"/"+parts[4]], "description": "geheim"}
	case p == "/cluster/backup-info/not-backed-up":
		var l []map[string]any
		for _, id := range f.Missing {
			l = append(l, map[string]any{"vmid": id, "type": "qemu"})
		}
		data = l
	case p == "/nodes/pve-1/storage":
		data = f.Storage
	case p == "/nodes/pve-1/disks/lvmthin":
		data = f.Thin
	case p == "/nodes/pve-1/tasks":
		if r.URL.Query().Get("typefilter") != "vzdump" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data = f.Tasks
	case strings.HasPrefix(p, "/nodes/pve-1/tasks/") && strings.HasSuffix(p, "/log"):
		upid, _ := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/api2/json/nodes/pve-1/tasks/"), "/log"))
		var l []map[string]any
		for i, t := range f.Logs[upid] {
			l = append(l, map[string]any{"n": i + 1, "t": t})
		}
		data = l
	default:
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// Server: laufende Attrappe.
type Server struct {
	*Fake
	Host  string
	Port  int
	CAPEM string // CA des Testservers (wie /etc/pve/pve-root-ca.pem)
}

// Start startet die Attrappe auf 127.0.0.1; sie endet mit dem Test. Wie
// Proxmox hat jede Attrappe eine eigene CA und ein davon signiertes
// Hostzertifikat. Das Hostzertifikat nennt nur „pve-1.invalid“, nicht
// 127.0.0.1: Wer den Namen prüfen würde, scheitert (so wie oft bei Proxmox).
func Start(t testing.TB, f *Fake) *Server {
	t.Helper()
	caPEM, cert := NewCA(t, "pve-1.invalid")
	ts := httptest.NewUnstartedServer(f)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // abgebrochene Handshakes sind in Tests gewollt
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	return &Server{Fake: f, Host: host, Port: p, CAPEM: caPEM}
}

// NewCA erzeugt eine CA (PEM) und ein davon signiertes Hostzertifikat für name.
func NewCA(t testing.TB, name string) (string, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	caTpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Proxmox Virtual Environment",
		OrganizationalUnit: []string{serial.String()}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
