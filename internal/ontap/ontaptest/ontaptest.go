// SPDX-License-Identifier: AGPL-3.0-only

// Package ontaptest ist eine ONTAP-Attrappe für Tests (REST-API nach der
// Referenz auf docs.netapp.com). Jede Attrappe hat ein eigenes,
// selbstsigniertes Zertifikat wie ein Cluster ab Werk. Nur Testdaten.
//
// Fehlerfälle: falsches Passwort (401), Forbid (403 je Pfad), Writable
// (Rolle mit Schreibrecht), SetLegacy (vor 9.19: kein whoami), Huge (übergroße
// Antwort), Redirect (Weiterleitung), Set mit vielen Einträgen (über der Grenze).
package ontaptest

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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Testwerte (keine echten Zugangsdaten).
const (
	User      = "svc-openwacht"
	Password  = "lese-pass-123"
	OwnerUUID = "1cd8a442-86d1-11e0-ae1c-123478563412"
	Role      = "openwacht_lesen"
)

// Fake: Zustand der Attrappe; Felder unter mu ändern (Set, Forbid, …).
type Fake struct {
	mu sync.Mutex
	// Legacy: ONTAP vor 9.19 (kein /api/security/login/whoami)
	Legacy bool
	// WhoamiEmpty: ONTAP 9.18 (whoami antwortet 200 mit „{}“)
	WhoamiEmpty bool
	Privileges  []map[string]any
	Lists       map[string][]map[string]any // Pfad → records
	Cluster     map[string]any
	forbidden   map[string]bool
	huge        map[string]bool
	redirect    map[string]bool
	calls       []string
	queries     map[string]string // Pfad → letzte Abfrage
}

// NewFake: kleiner HA-Cluster (AFF, zwei Knoten) mit typischen Werten und
// einigen Störungen: ein Aggregat fast voll, eine ausgefallene Platte, ein
// Shelf-Netzteil ausgefallen, eine SnapMirror-Beziehung mit großer
// Verzögerung, ein EMS-Ereignis „alert“.
func NewFake() *Fake {
	f := &Fake{
		Privileges: []map[string]any{{"path": "/api", "access": "readonly"}},
		Cluster:    map[string]any{"name": "aff-test", "uuid": OwnerUUID, "version": map[string]any{"full": "NetApp Release 9.16.1: Mon Jan 01 00:00:00 UTC 2026", "generation": 9, "major": 16, "minor": 1}},
		forbidden:  map[string]bool{},
		huge:       map[string]bool{},
		redirect:   map[string]bool{},
		queries:    map[string]string{},
	}
	f.Lists = map[string][]map[string]any{
		"/api/cluster/nodes": {
			node("aff-01", "up", "aff-02", "not_attempted", 3000000),
			node("aff-02", "up", "aff-01", "not_attempted", 3000100),
		},
		"/api/storage/aggregates": {
			aggr("aggr1", "aff-01", "online", 1000_000_000_000, 500_000_000_000, 1200, 350),
			aggr("aggr2", "aff-02", "online", 1000_000_000_000, 950_000_000_000, 800, 900),
		},
		"/api/storage/volumes": {
			vol("svm1", "daten", "online", "rw", 400_000_000_000, 100_000_000_000),
			vol("svm1", "archiv", "offline", "rw", 0, 0),
			vol("svm2", "spiegel", "online", "dp", 200_000_000_000, 10_000_000_000),
		},
		"/api/storage/disks": {
			{"name": "1.0.0", "state": "present", "container_type": "aggregate", "model": "X4011S172A1T9NTE"},
			{"name": "1.0.1", "state": "present", "container_type": "shared", "model": "X4011S172A1T9NTE"},
			{"name": "1.0.2", "state": "broken", "container_type": "broken", "model": "X4011S172A1T9NTE"},
			{"name": "1.0.3", "state": "spare", "container_type": "spare", "model": "X4011S172A1T9NTE"},
		},
		"/api/storage/shelves": {
			{"uid": "10318311901725526608", "id": "1.0", "name": "1.0", "model": "NS224", "state": "error",
				"frus": []map[string]any{{"id": 0, "type": "module", "state": "ok", "installed": true},
					{"id": 1, "type": "psu", "state": "ok", "installed": true}, {"id": 2, "type": "psu", "state": "error", "installed": true}},
				"fans": []map[string]any{{"id": 1, "state": "ok", "installed": true, "rpm": 3020}},
				"temperature_sensors": []map[string]any{{"id": 1, "state": "ok", "temperature": 32, "installed": true,
					"threshold": map[string]any{"high": map[string]any{"warning": 50, "critical": 60}, "low": map[string]any{"warning": 5, "critical": 0}}}}},
		},
		"/api/snapmirror/relationships": {
			{"uuid": "4ea7a442-86d1-11e0-ae1c-123478563412", "source": map[string]any{"path": "quelle:daten"},
				"destination": map[string]any{"path": "svm2:spiegel"}, "state": "snapmirrored", "healthy": true, "lag_time": "PT60H5M"},
		},
		"/api/support/ems/events": {
			{"index": 661, "time": time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339),
				"message": map[string]any{"name": "disk.outOfService", "severity": "alert"},
				"node":    map[string]any{"name": "aff-01"}, "log_message": "disk.outOfService: Drive 1.0.2 is out of service."},
		},
		"/api/security/accounts": {
			{"name": User, "owner": map[string]any{"uuid": OwnerUUID, "name": "aff-test"}, "scope": "cluster",
				"role": map[string]any{"name": Role}},
		},
	}
	return f
}

func node(name, state, partner, takeover string, uptime int) map[string]any {
	return map[string]any{"name": name, "uuid": "00000000-0000-4000-8000-00000000000" + name[len(name)-1:], "state": state,
		"model": "AFF-C250", "uptime": uptime, "serial_number": "nicht-gelesen",
		"ha": map[string]any{"enabled": true, "partners": []map[string]any{{"name": partner}},
			"takeover": map[string]any{"state": takeover}, "giveback": map[string]any{"state": "nothing_to_giveback"}},
		"controller": map[string]any{"over_temperature": "normal", "failed_fan": map[string]any{"count": 0},
			"failed_power_supply": map[string]any{"count": 0}}}
}

func aggr(name, node, state string, size, used int64, iops, latUs float64) map[string]any {
	return map[string]any{"name": name, "uuid": "aggr-" + name, "state": state, "node": map[string]any{"name": node},
		"space":  map[string]any{"block_storage": map[string]any{"size": size, "used": used, "available": size - used}},
		"metric": map[string]any{"status": "ok", "iops": map[string]any{"total": iops}, "latency": map[string]any{"total": latUs}}}
}

func vol(svm, name, state, typ string, size, used int64) map[string]any {
	v := map[string]any{"name": name, "state": state, "type": typ, "svm": map[string]any{"name": svm}}
	if state == "online" {
		v["space"] = map[string]any{"size": size, "used": used, "available": size - used}
	}
	return v
}

// Set ersetzt die Einträge eines Pfads.
func (f *Fake) Set(path string, records []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Lists[path] = records
}

// Update ändert einen Eintrag eines Pfads (nach Index).
func (f *Fake) Update(path string, i int, fn func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.Lists[path][i])
}

// Forbid lässt einen Pfad mit 403 antworten.
func (f *Fake) Forbid(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forbidden[path] = true
}

// Huge lässt einen Pfad mehr als 8 MiB liefern.
func (f *Fake) Huge(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.huge[path] = true
}

// Redirect lässt einen Pfad mit einer Weiterleitung antworten.
func (f *Fake) Redirect(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirect[path] = true
}

// Writable gibt der Rolle Schreibrecht.
func (f *Fake) Writable(path, access string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Privileges = append(f.Privileges, map[string]any{"path": path, "access": access})
}

// SetLegacy: ONTAP vor 9.19 (ohne whoami).
func (f *Fake) SetLegacy(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Legacy = on
}

// Calls: alle Anfragen als „METHODE Pfad“.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// ResetCalls leert die Liste der Anfragen.
func (f *Fake) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// Query: letzte Abfrage (Query-String) eines Pfads.
func (f *Fake) Query(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[path]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "code": code}})
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.queries[r.URL.Path] = r.URL.RawQuery
	u, p, ok := r.BasicAuth()
	if !ok || u != User || p != Password {
		apiErr(w, http.StatusUnauthorized, "6", "not authorized for that command")
		return
	}
	if r.Method != http.MethodGet {
		apiErr(w, http.StatusMethodNotAllowed, "3", "nur GET in der Attrappe")
		return
	}
	path := r.URL.Path
	if f.forbidden[path] {
		apiErr(w, http.StatusForbidden, "6", "not authorized for that command")
		return
	}
	if f.redirect[path] {
		http.Redirect(w, r, "https://192.0.2.99/api/cluster", http.StatusTemporaryRedirect)
		return
	}
	if f.huge[path] {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"records":[{"name":"`))
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range 9 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		w.Write([]byte(`"}]}`))
		return
	}
	switch {
	case path == "/api/cluster":
		writeJSON(w, http.StatusOK, f.Cluster)
		return
	case path == "/api/security/login/whoami":
		if f.Legacy {
			apiErr(w, http.StatusNotFound, "4", "API not found")
			return
		}
		if f.WhoamiEmpty {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"username": User, "roles": []string{Role}, "privileges": f.Privileges})
		return
	case path == "/api/security/roles/"+OwnerUUID+"/"+Role+"/privileges":
		f.list(w, r, f.Privileges)
		return
	case path == "/api/security/accounts":
		var out []map[string]any
		for _, a := range f.Lists[path] {
			if a["name"] == r.URL.Query().Get("name") {
				out = append(out, a)
			}
		}
		f.list(w, r, out)
		return
	}
	recs, ok := f.Lists[path]
	if !ok {
		apiErr(w, http.StatusNotFound, "4", "API not found")
		return
	}
	f.list(w, r, recs)
}

// list antwortet wie ONTAP: records, num_records und bei mehr als
// max_records ein Verweis „next“.
func (f *Fake) list(w http.ResponseWriter, r *http.Request, recs []map[string]any) {
	out := map[string]any{"_links": map[string]any{"self": map[string]any{"href": r.URL.Path}}}
	if n, err := strconv.Atoi(r.URL.Query().Get("max_records")); err == nil && n >= 0 && n < len(recs) {
		recs = recs[:n]
		out["_links"].(map[string]any)["next"] = map[string]any{"href": r.URL.Path + "?start.index=" + strconv.Itoa(n)}
	}
	if recs == nil {
		recs = []map[string]any{}
	}
	out["records"], out["num_records"] = recs, len(recs)
	writeJSON(w, http.StatusOK, out)
}

// Server: laufende Attrappe.
type Server struct {
	*httptest.Server
	Host string
	Port uint16
	// Pin: SHA-256 des Zertifikats (hex, klein)
	Pin string
}

// Start startet die Attrappe mit TLS und eigenem, selbstsigniertem Zertifikat.
func Start(t *testing.T, f *Fake) *Server {
	t.Helper()
	cert, pin, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return &Server{Server: srv, Host: host, Port: uint16(p), Pin: pin}
}

// Serve startet die Attrappe außerhalb von Tests (Bilder-Skript, Browsertest)
// auf addr und liefert den Fingerabdruck. Nur für Entwicklung.
func Serve(addr string, f *Fake) (*http.Server, string, error) {
	cert, pin, err := selfSigned()
	if err != nil {
		return nil, "", err
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return srv, pin, nil
}

func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "aff-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"aff-test.invalid"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}
