// SPDX-License-Identifier: AGPL-3.0-only

// Package xapitest ist eine XAPI-Attrappe für Tests (JSON-RPC unter /jsonrpc
// und /rrd_updates nach dem XAPI-Datenmodell und der XenServer-8-Doku). Ein
// Pool hat zwei Hosts; jeder Host ist ein eigener HTTPS-Server mit eigenem,
// selbstsigniertem Zertifikat wie ab Werk, auf derselben Portnummer unter
// verschiedenen Loopback-Adressen (127.0.0.1 und 127.0.0.2). Nur Testdaten.
//
// Fehlerfälle: falsches Passwort (SESSION_AUTHENTICATION_FAILED), NoRole,
// Superuser (lokaler Superuser), Writable (Rolle mit Schreibrecht),
// RightsUnreadable (Rechte nicht lesbar), SlaveOf (HOST_IS_SLAVE), Huge
// (übergroße Antwort), Redirect (Weiterleitung), Fail (Fehler je Methode).
package xapitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Testwerte (keine echten Zugangsdaten).
const (
	User     = "svc-openwacht@beispiel.example"
	Password = "lese-pass-123"
	// VMExpr: der Filter, den der Client für VMs schicken muss
	VMExpr = `field "is_a_template"="false" and field "is_a_snapshot"="false" and field "is_control_domain"="false"`
)

// Refs und UUIDs der Testdaten.
const (
	PoolRef     = "OpaqueRef:pool-0001"
	Host1Ref    = "OpaqueRef:host-0001"
	Host2Ref    = "OpaqueRef:host-0002"
	Host1UUID   = "11111111-1111-4111-8111-111111111111"
	Host2UUID   = "22222222-2222-4222-8222-222222222222"
	ReadOnlyRef = "OpaqueRef:role-read-only"
)

// ReadOnlyPerms: Auszug aus den Rechten der Rolle „read-only“.
var ReadOnlyPerms = []string{"vm.get_record", "vm.get_all_records_where", "host.get_all_records", "pool.get_all_records",
	"sr.get_all_records", "pbd.get_currently_attached", "certificate.get_all_records_where", "http/get_rrd_updates",
	"session.get_rbac_permissions", "role.get_permissions_name_label"}

// Fake: Zustand der Attrappe; Felder nur über die Methoden ändern.
type Fake struct {
	mu sync.Mutex
	// Records je Klasse (pool, host, host_metrics, VM, SR, certificate): Ref → Feld → Wert
	Records    map[string]map[string]map[string]any
	Attached   map[string]bool // PBD → angebunden
	perms      []string
	super      bool
	noRole     bool
	unread     bool
	slaveOf    string
	huge       map[string]bool
	redirect   bool
	fail       map[string]string // Methode → Fehlername
	nonFinite  bool
	urlSession int
	sessions   map[string]bool
	logouts    int
	calls      []string
	next       int
	// Pins: Host-Ref → Fingerabdruck seines Servers (nach Start gesetzt)
	pins map[string]string
}

// NewFake: Pool „pool-test“ mit zwei Hosts (xs-01 Master, xs-02), fünf VMs
// (eine soll laufen, ist aber aus), drei Storage-Repositories (eines fast
// voll, eines auf xs-02 nicht angebunden, ein ISO-SR) und HA mit zu kleinem
// Plan. xs-02 hat ausstehende Updates.
func NewFake() *Fake {
	f := &Fake{Attached: map[string]bool{}, huge: map[string]bool{}, fail: map[string]string{}, sessions: map[string]bool{},
		pins: map[string]string{}}
	f.perms = append([]string{"read-only"}, ReadOnlyPerms...)
	boot1 := float64(time.Now().Add(-40*24*time.Hour).Unix()) + 0.5
	boot2 := float64(time.Now().Add(-12*24*time.Hour).Unix()) + 0.5
	f.Records = map[string]map[string]map[string]any{
		"pool": {PoolRef: {"uuid": "33333333-3333-4333-8333-333333333333", "name_label": "pool-test", "master": Host1Ref,
			"ha_enabled": true, "ha_host_failures_to_tolerate": 1, "ha_plan_exists_for": 0, "ha_overcommitted": false,
			"other_config": map[string]string{}}},
		"host": {
			Host1Ref: host(Host1UUID, "xs-01", "127.0.0.1", "OpaqueRef:hm-0001", boot1, "yes", []string{},
				[]string{"OpaqueRef:pbd-0001", "OpaqueRef:pbd-0003", "OpaqueRef:pbd-0005"}),
			Host2Ref: host(Host2UUID, "xs-02", "127.0.0.2", "OpaqueRef:hm-0002", boot2, "no", []string{"reboot_host"},
				[]string{"OpaqueRef:pbd-0002", "OpaqueRef:pbd-0004", "OpaqueRef:pbd-0006"}),
		},
		"host_metrics": {
			"OpaqueRef:hm-0001": {"live": true, "memory_total": 274877906944},
			"OpaqueRef:hm-0002": {"live": true, "memory_total": 274877906944},
		},
		"VM": {
			"OpaqueRef:vm-0001": vm("aaaaaaaa-0000-4000-8000-000000000001", "srv-dc01", "Running", Host1Ref, "restart", 4, 8),
			"OpaqueRef:vm-0002": vm("aaaaaaaa-0000-4000-8000-000000000002", "srv-db01", "Running", Host2Ref, "restart", 8, 32),
			"OpaqueRef:vm-0003": vm("aaaaaaaa-0000-4000-8000-000000000003", "srv-app01", "Halted", nullRef, "restart", 2, 4),
			"OpaqueRef:vm-0004": vm("aaaaaaaa-0000-4000-8000-000000000004", "test-vm", "Halted", nullRef, "", 1, 2),
			"OpaqueRef:vm-0005": vm("aaaaaaaa-0000-4000-8000-000000000005", "srv-print", "Paused", Host1Ref, "best-effort", 1, 2),
			// werden vom Filter ausgeschlossen
			"OpaqueRef:vm-tpl": func() map[string]any {
				v := vm("aaaaaaaa-0000-4000-8000-0000000000f1", "Vorlage Debian", "Halted", nullRef, "", 1, 1)
				v["is_a_template"] = true
				return v
			}(),
			"OpaqueRef:vm-dom0": func() map[string]any {
				v := vm("aaaaaaaa-0000-4000-8000-0000000000f2", "Control domain on host: xs-01", "Running", Host1Ref, "", 16, 4)
				v["is_control_domain"] = true
				return v
			}(),
		},
		"SR": {
			"OpaqueRef:sr-0001": sr("bbbbbbbb-0000-4000-8000-000000000001", "NFS VM-Speicher", "nfs", "", true,
				10_000_000_000_000, 9_400_000_000_000, "OpaqueRef:pbd-0001", "OpaqueRef:pbd-0002"),
			"OpaqueRef:sr-0002": sr("bbbbbbbb-0000-4000-8000-000000000002", "iSCSI Daten", "lvmoiscsi", "", true,
				4_000_000_000_000, 1_000_000_000_000, "OpaqueRef:pbd-0003", "OpaqueRef:pbd-0004"),
			"OpaqueRef:sr-0003": sr("bbbbbbbb-0000-4000-8000-000000000003", "ISO-Bibliothek", "iso", "iso", true,
				0, 0, "OpaqueRef:pbd-0005", "OpaqueRef:pbd-0006"),
		},
		"certificate": {},
	}
	for _, p := range []string{"OpaqueRef:pbd-0001", "OpaqueRef:pbd-0002", "OpaqueRef:pbd-0003", "OpaqueRef:pbd-0005", "OpaqueRef:pbd-0006"} {
		f.Attached[p] = true
	}
	f.Attached["OpaqueRef:pbd-0004"] = false // iSCSI Daten auf xs-02 nicht angebunden
	return f
}

const nullRef = "OpaqueRef:NULL"

func host(uuid, name, addr, metrics string, boot float64, updates string, pending, pbds []string) map[string]any {
	return map[string]any{"uuid": uuid, "name_label": name, "enabled": true, "address": addr, "metrics": metrics,
		"other_config":     map[string]string{"boot_time": strconv.FormatFloat(boot, 'f', 1, 64), "agent_start_time": "1.0"},
		"software_version": map[string]string{"product_brand": "XenServer", "product_version": "8.4.0", "platform_version": "3.4.0"},
		"PBDs":             pbds, "latest_synced_updates_applied": updates, "pending_guidances": pending,
		"bios_strings": map[string]string{"system-serial-number": "nicht-gelesen"}, "license_params": map[string]string{}}
}

func vm(uuid, name, state, residentOn, ha string, vcpus int, memGiB int64) map[string]any {
	return map[string]any{"uuid": uuid, "name_label": name, "power_state": state, "is_a_template": false,
		"is_a_snapshot": false, "is_control_domain": false, "resident_on": residentOn, "ha_restart_priority": ha,
		"other_config": map[string]string{"base_template_name": "Debian"}, "VCPUs_max": vcpus,
		"memory_dynamic_max": memGiB << 30, "xenstore_data": map[string]string{"vm-data": "nicht-gelesen"}}
}

func sr(uuid, name, typ, content string, shared bool, size, used int64, pbds ...string) map[string]any {
	return map[string]any{"uuid": uuid, "name_label": name, "type": typ, "content_type": content, "shared": shared,
		"physical_size": strconv.FormatInt(size, 10), "physical_utilisation": strconv.FormatInt(used, 10),
		"virtual_allocation": strconv.FormatInt(used, 10), "PBDs": pbds, "sm_config": map[string]string{}}
}

// Update ändert einen Eintrag (Klasse, Ref).
func (f *Fake) Update(class, ref string, fn func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.Records[class][ref])
}

// Writable gibt der Sitzung eine Rolle mit Schreibrecht (z. B. „vm-operator“).
func (f *Fake) Writable(role string, perms ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.perms = append(f.perms, role)
	f.perms = append(f.perms, perms...)
}

// Superuser: Die Anmeldung ergibt eine Sitzung des lokalen Superusers.
func (f *Fake) Superuser() { f.set(func() { f.super = true }) }

// NoRole: Das Konto ist im AD, hat im Pool aber keine Rolle.
func (f *Fake) NoRole() { f.set(func() { f.noRole = true }) }

// RightsUnreadable: session.get_rbac_permissions scheitert.
func (f *Fake) RightsUnreadable() { f.set(func() { f.unread = true }) }

// SlaveOf: Der Server ist nicht mehr Pool-Master (HOST_IS_SLAVE mit Adresse).
func (f *Fake) SlaveOf(master string) { f.set(func() { f.slaveOf = master }) }

// Huge lässt eine Methode mehr als 24 MiB liefern.
func (f *Fake) Huge(method string) { f.set(func() { f.huge[method] = true }) }

// Redirect lässt /jsonrpc mit einer Weiterleitung antworten.
func (f *Fake) Redirect() { f.set(func() { f.redirect = true }) }

// SetPins ersetzt die Fingerabdrücke, die der Pool für seine Hosts meldet.
func (f *Fake) SetPins(pins map[string]string) {
	f.set(func() {
		for k, v := range pins {
			f.pins[k] = v
		}
	})
}

// NonFinite lässt XAPI im Pool-Eintrag nicht endliche Zahlen ohne
// Anführungszeichen schreiben (NaN, Infinity), wie echte Versionen.
func (f *Fake) NonFinite() { f.set(func() { f.nonFinite = true }) }

// Fail lässt eine Methode mit einem XAPI-Fehler antworten.
func (f *Fake) Fail(method, name string) { f.set(func() { f.fail[method] = name }) }

func (f *Fake) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// Calls: alle Aufrufe (Methode bzw. „GET /rrd_updates@Host“).
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// ResetCalls leert die Liste der Aufrufe.
func (f *Fake) ResetCalls() { f.set(func() { f.calls = nil }) }

// Logouts: Zahl der Abmeldungen.
func (f *Fake) Logouts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logouts
}

// SessionInURL: so oft kam die Sitzung bei /rrd_updates in der Adresse statt als Cookie.
func (f *Fake) SessionInURL() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.urlSession
}

// OpenSessions: noch angemeldete Sitzungen.
func (f *Fake) OpenSessions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

type request struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
	ID     any               `json:"id"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func rpcErr(w http.ResponseWriter, id any, name string, data ...string) {
	if data == nil {
		data = []string{}
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": 1, "message": name, "data": data}})
}

// handler: ein Host des Pools.
type handler struct {
	f      *Fake
	ref    string // Host-Ref
	master bool
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f := h.f
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/rrd_updates" && r.Method == http.MethodGet:
		f.calls = append(f.calls, "GET /rrd_updates@"+h.ref)
		h.rrd(w, r)
		return
	case r.URL.Path != "/jsonrpc" || r.Method != http.MethodPost:
		http.Error(w, "nicht gefunden", http.StatusNotFound)
		return
	}
	if f.redirect {
		http.Redirect(w, r, "https://192.0.2.99/jsonrpc", http.StatusFound)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "kaputt", http.StatusBadRequest)
		return
	}
	f.calls = append(f.calls, req.Method)
	str := func(i int) string {
		var s string
		if i < len(req.Params) {
			json.Unmarshal(req.Params[i], &s)
		}
		return s
	}
	if f.huge[req.Method] {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"x":"`))
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range 25 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		w.Write([]byte(`"}}`))
		return
	}
	if name, ok := f.fail[req.Method]; ok {
		rpcErr(w, req.ID, name)
		return
	}
	if req.Method == "session.login_with_password" {
		switch {
		case !h.master || f.slaveOf != "":
			m := f.slaveOf
			if m == "" {
				m = "127.0.0.1"
			}
			rpcErr(w, req.ID, "HOST_IS_SLAVE", m)
		case str(0) != User || str(1) != Password:
			rpcErr(w, req.ID, "SESSION_AUTHENTICATION_FAILED", str(0), "Authentication failure")
		case f.noRole:
			rpcErr(w, req.ID, "RBAC_PERMISSION_DENIED", "session.login_with_password", "Subject has no roles in this pool")
		default:
			f.next++
			ref := fmt.Sprintf("OpaqueRef:sess-%04d", f.next)
			f.sessions[ref] = true
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": ref})
		}
		return
	}
	if !f.sessions[str(0)] {
		rpcErr(w, req.ID, "SESSION_INVALID", str(0))
		return
	}
	result := func(v any) { writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": v}) }
	switch req.Method {
	case "session.logout":
		delete(f.sessions, str(0))
		f.logouts++
		result("")
	case "session.get_is_local_superuser":
		result(f.super)
	case "session.get_rbac_permissions":
		if f.unread {
			rpcErr(w, req.ID, "RBAC_PERMISSION_DENIED", "session.get_rbac_permissions", "no permission")
			return
		}
		if f.super {
			result([]string{})
			return
		}
		result(f.perms)
	case "role.get_by_name_label":
		if str(1) == "read-only" {
			result([]string{ReadOnlyRef})
		} else {
			result([]string{})
		}
	case "role.get_permissions_name_label":
		if str(1) != ReadOnlyRef {
			rpcErr(w, req.ID, "HANDLE_INVALID", "role", str(1))
			return
		}
		result(ReadOnlyPerms)
	case "pool.get_all_records":
		if f.nonFinite {
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": f.Records["pool"]})
			b = []byte(strings.Replace(string(b), `"name_label"`, `"wlb_value": NaN, "wlb_max": -Infinity,"name_label"`, 1))
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
			return
		}
		result(f.Records["pool"])
	case "host.get_all_records":
		result(f.Records["host"])
	case "host_metrics.get_all_records":
		result(f.Records["host_metrics"])
	case "SR.get_all_records":
		result(f.Records["SR"])
	case "VM.get_all_records_where":
		if str(1) != VMExpr {
			rpcErr(w, req.ID, "INVALID_EXPRESSION", str(1))
			return
		}
		out := map[string]map[string]any{}
		for k, v := range f.Records["VM"] {
			if v["is_a_template"] == false && v["is_a_snapshot"] == false && v["is_control_domain"] == false {
				out[k] = v
			}
		}
		result(out)
	case "certificate.get_all_records_where":
		if str(1) != `field "type"="host"` {
			rpcErr(w, req.ID, "INVALID_EXPRESSION", str(1))
			return
		}
		out := map[string]map[string]any{}
		for href, pin := range f.pins {
			out["OpaqueRef:cert-"+href[len(href)-4:]] = map[string]any{"type": "host", "host": href,
				"fingerprint_sha256": colons(pin), "fingerprint_sha1": "", "name": ""}
		}
		result(out)
	case "PBD.get_currently_attached":
		on, ok := f.Attached[str(1)]
		if !ok {
			rpcErr(w, req.ID, "HANDLE_INVALID", "PBD", str(1))
			return
		}
		result(on)
	default:
		rpcErr(w, req.ID, "MESSAGE_METHOD_UNKNOWN", req.Method)
	}
}

func colons(pin string) string {
	var b strings.Builder
	for i := 0; i < len(pin); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(pin[i : i+2]))
	}
	return b.String()
}

// rrd antwortet wie rrdd (rrdtool-xport) mit den Werten dieses Hosts und
// seiner VMs. Die Sitzung muss als Cookie oder Parameter kommen.
func (h *handler) rrd(w http.ResponseWriter, r *http.Request) {
	f := h.f
	sid := r.URL.Query().Get("session_id")
	if sid != "" {
		f.urlSession++
	}
	if c, err := r.Cookie("session_id"); err == nil {
		sid = c.Value
	}
	if !f.sessions[sid] {
		http.Error(w, "nicht angemeldet", http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("start") == "" {
		http.Error(w, "start fehlt", http.StatusBadRequest)
		return
	}
	uuid, _ := f.Records["host"][h.ref]["uuid"].(string)
	legend := []string{"AVERAGE:host:" + uuid + ":cpu_avg", "AVERAGE:host:" + uuid + ":memory_total_kib",
		"AVERAGE:host:" + uuid + ":memory_free_kib", "AVERAGE:host:" + uuid + ":cpu0"}
	cpu := 0.35
	free := int64(96 << 20) // KiB
	if h.ref == Host2Ref {
		cpu, free = 0.82, 24<<20
	}
	vals := [][]string{{ftoa(cpu - 0.05), "268435456", strconv.FormatInt(free, 10), "0.3"},
		{ftoa(cpu + 0.05), "268435456", strconv.FormatInt(free, 10), "NaN"}}
	for _, v := range f.Records["VM"] {
		if v["resident_on"] != h.ref || v["power_state"] != "Running" || v["is_control_domain"] == true {
			continue
		}
		id := v["uuid"].(string)
		legend = append(legend, "AVERAGE:vm:"+id+":cpu_usage", "AVERAGE:vm:"+id+":memory")
		mem := strconv.FormatInt(v["memory_dynamic_max"].(int64), 10)
		vals[0] = append(vals[0], "0.20", mem)
		vals[1] = append(vals[1], "0.40", mem)
	}
	now := time.Now().Unix() / 60 * 60
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><xport><meta><start>` + strconv.FormatInt(now-120, 10) +
		`</start><step>60</step><end>` + strconv.FormatInt(now, 10) + `</end><rows>2</rows><columns>` +
		strconv.Itoa(len(legend)) + `</columns><legend>`)
	for _, l := range legend {
		b.WriteString("<entry>" + l + "</entry>")
	}
	b.WriteString("</legend></meta><data>")
	for i, row := range vals {
		b.WriteString("<row><t>" + strconv.FormatInt(now-int64(60*(1-i)), 10) + "</t>")
		for _, v := range row {
			b.WriteString("<v>" + v + "</v>")
		}
		b.WriteString("</row>")
	}
	b.WriteString("</data></xport>")
	w.Header().Set("Content-Type", "text/xml")
	io.WriteString(w, b.String())
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'E', 4, 64) }

// Server: laufender Pool (zwei Hosts).
type Server struct {
	Host string // Adresse des Pool-Masters (127.0.0.1)
	Port uint16
	// Pin: SHA-256 des Zertifikats des Pool-Masters (hex, klein); Pin2 des zweiten Hosts
	Pin, Pin2 string
	stop      func()
}

// Close beendet beide Server.
func (s *Server) Close() { s.stop() }

// Start startet den Pool: Master auf 127.0.0.1, zweiter Host auf 127.0.0.2,
// beide auf derselben Portnummer und mit eigenem Zertifikat.
func Start(t *testing.T, f *Fake) *Server {
	t.Helper()
	s, err := Serve("127.0.0.1", "127.0.0.2", 0, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Serve startet den Pool außerhalb von Tests (Bilder-Skript, Browsertest):
// Master auf host1, zweiter Host auf host2, beide auf port (0 = frei
// wählen). Die Adressen der Hosts im Datenbestand werden entsprechend
// gesetzt. Nur für Entwicklung.
func Serve(host1, host2 string, port int, f *Fake) (*Server, error) {
	var lastErr error
	for range 20 {
		ln1, err := net.Listen("tcp", net.JoinHostPort(host1, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		p := ln1.Addr().(*net.TCPAddr).Port
		ln2, err := net.Listen("tcp", net.JoinHostPort(host2, strconv.Itoa(p)))
		if err != nil {
			ln1.Close()
			lastErr = err
			if port != 0 {
				return nil, err
			}
			continue
		}
		c1, pin1, err := selfSigned("xs-01")
		if err != nil {
			return nil, err
		}
		c2, pin2, err := selfSigned("xs-02")
		if err != nil {
			return nil, err
		}
		f.set(func() {
			f.pins[Host1Ref], f.pins[Host2Ref] = pin1, pin2
			f.Records["host"][Host1Ref]["address"] = host1
			f.Records["host"][Host2Ref]["address"] = host2
		})
		s1 := &http.Server{Handler: &handler{f: f, ref: Host1Ref, master: true}, ReadHeaderTimeout: 5 * time.Second, ErrorLog: quiet}
		s2 := &http.Server{Handler: &handler{f: f, ref: Host2Ref}, ReadHeaderTimeout: 5 * time.Second, ErrorLog: quiet}
		go s1.Serve(tls.NewListener(ln1, &tls.Config{Certificates: []tls.Certificate{c1}, MinVersion: tls.VersionTLS12}))
		go s2.Serve(tls.NewListener(ln2, &tls.Config{Certificates: []tls.Certificate{c2}, MinVersion: tls.VersionTLS12}))
		return &Server{Host: host1, Port: uint16(p), Pin: pin1, Pin2: pin2, stop: func() { s1.Close(); s2.Close() }}, nil
	}
	return nil, lastErr
}

// quiet: Handshake-Fehler (Tests mit falschem Zertifikat) nicht ausgeben.
var quiet = log.New(io.Discard, "", 0)

func selfSigned(cn string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{cn + ".invalid"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}
