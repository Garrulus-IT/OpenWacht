// SPDX-License-Identifier: AGPL-3.0-only

// simagent simuliert Agents für Entwicklung und Tests der Oberfläche. Er
// spricht das echte Protokoll (Registrierung mit CA-Pinning, mTLS, geprüfte
// Messwerte), erfindet aber die Messwerte. Nicht für den Betrieb.
//
//	go run ./tools/simagent -zentrale https://127.0.0.1:8444 -token owa1.… -hosts web01,db01 -runden 1
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// dialer: für alle Verbindungen (mit -quelle eigene Absenderadresse).
var dialer = &net.Dialer{Timeout: 10 * time.Second}

type agent struct {
	host   string
	client *http.Client
	cores  int
	mem    uint64
	disks  []agentproto.Disk
	load   float64
}

func main() {
	zentrale := flag.String("zentrale", "", "Adresse des Agent-Ports")
	token := flag.String("token", "", "Registrierungs-Token (für alle Hosts)")
	hosts := flag.String("hosts", "sim01", "Hostnamen, kommagetrennt")
	runden := flag.Int("runden", 1, "Anzahl Meldungen je Host (0 = endlos)")
	takt := flag.Duration("takt", 10*time.Second, "Abstand zwischen Meldungen")
	ohneMeldung := flag.String("ohne-meldung", "", "Hosts, die sich nur registrieren und nie melden")
	quelle := flag.String("quelle", "", "eigene Absenderadresse, z. B. 127.2.0.1 (Lasttest: ein Standort je Adresse)")
	flag.Parse()
	if *quelle != "" {
		ip := net.ParseIP(*quelle)
		if ip == nil {
			fmt.Fprintln(os.Stderr, "simagent: -quelle ist keine IP-Adresse")
			os.Exit(2)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	if err := run(*zentrale, *token, strings.Split(*hosts, ","), *runden, *takt, strings.Split(*ohneMeldung, ",")); err != nil {
		fmt.Fprintln(os.Stderr, "simagent:", err)
		os.Exit(1)
	}
}

func run(zentrale, token string, hosts []string, runden int, takt time.Duration, silent []string) error {
	u, err := url.Parse(zentrale)
	if err != nil {
		return err
	}
	_, fp, err := agentproto.ParseToken(token)
	if err != nil {
		return err
	}
	var agents []*agent
	for _, h := range append(hosts, silent...) {
		if h == "" {
			continue
		}
		a, err := register(u, fp, token, h)
		if err != nil {
			return fmt.Errorf("%s: %w", h, err)
		}
		fmt.Println("registriert:", h)
		if !contains(silent, h) {
			agents = append(agents, a)
		}
	}
	for i := 0; runden == 0 || i < runden; i++ {
		for _, a := range agents {
			if err := a.report(u); err != nil {
				fmt.Fprintln(os.Stderr, a.host, err)
			}
		}
		if runden == 0 || i < runden-1 {
			time.Sleep(takt)
		}
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func register(u *url.URL, fp, token, host string) (*agent, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	pinned := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			var raw [][]byte
			for _, c := range cs.PeerCertificates {
				raw = append(raw, c.Raw)
			}
			_, err := pki.VerifyPinnedServer(raw, fp, u.Hostname(), time.Now())
			return err
		},
	}}}
	body, _ := json.Marshal(agentproto.RegisterRequest{Token: token, CSR: csr, Hostname: host})
	resp, err := pinned.Post(u.String()+agentproto.PathRegister, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Registrierung: %d %s", resp.StatusCode, out)
	}
	var rr agentproto.RegisterResponse
	if err := json.Unmarshal(out, &rr); err != nil {
		return nil, err
	}
	cert, err := pki.ParseCertPEM([]byte(rr.Certificate))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(rr.CA))
	cores := []int{2, 4, 8, 16}[mrand.IntN(4)]
	a := &agent{
		host:  host,
		cores: cores,
		mem:   uint64(cores) * 2 << 30,
		load:  mrand.Float64() * 60,
		client: &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: u.Hostname(),
			Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
		}}},
		disks: []agentproto.Disk{
			{Mount: "/", FSType: "ext4", TotalBytes: 64 << 30, FreeBytes: uint64(mrand.IntN(50)+5) << 30},
			{Mount: "/var/lib/data", FSType: "xfs", TotalBytes: 2 << 40, FreeBytes: uint64(mrand.IntN(1800)+50) << 30},
		},
	}
	return a, nil
}

func (a *agent) report(u *url.URL) error {
	a.load = math.Max(1, math.Min(99, a.load+mrand.NormFloat64()*8))
	snap := agentproto.Snapshot{
		CollectedAt: time.Now(), Hostname: a.host, OS: "Debian GNU/Linux 13 (trixie)", Kernel: "6.12.48-1-amd64",
		Arch: "amd64", AgentVersion: "sim", UptimeSec: uint64(mrand.IntN(40*86400) + 3600),
		CPU: agentproto.CPU{Cores: a.cores, Percent: math.Round(a.load*10) / 10,
			Load1: a.load / 100 * float64(a.cores), Load5: a.load / 110 * float64(a.cores), Load15: a.load / 120 * float64(a.cores)},
		Memory: agentproto.Memory{TotalBytes: a.mem, AvailableBytes: a.mem / uint64(mrand.IntN(4)+2),
			SwapTotalBytes: 1 << 30, SwapFreeBytes: 1 << 30},
		Disks: a.disks,
	}
	// Hosts, deren Name mit „win“ beginnt, melden sich wie der Windows-Agent.
	if strings.HasPrefix(a.host, "win") {
		snap.OS, snap.Kernel = "Windows 11 Pro 24H2", "10.0.26100.4349"
		snap.CPU.Load1, snap.CPU.Load5, snap.CPU.Load15, snap.CPU.NoLoad = 0, 0, 0, true
		snap.Disks = []agentproto.Disk{
			{Mount: "C:", FSType: "ntfs", TotalBytes: 476 << 30, FreeBytes: 212 << 30},
			{Mount: "D:", FSType: "ntfs", TotalBytes: 1863 << 30, FreeBytes: 940 << 30},
		}
	}
	// Hosts, deren Name mit „voll“ beginnt, haben eine zu 96 % belegte Wurzelplatte (Alarm testen).
	if strings.HasPrefix(a.host, "voll") {
		snap.Disks = []agentproto.Disk{{Mount: "/", FSType: "ext4", TotalBytes: 100 << 30, FreeBytes: 4 << 30}}
	}
	body, _ := json.Marshal(snap)
	resp, err := a.client.Post(u.String()+agentproto.PathReport, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Meldung: %d %s", resp.StatusCode, out)
	}
	return nil
}
