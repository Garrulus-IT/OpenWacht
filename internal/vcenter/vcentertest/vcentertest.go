// SPDX-License-Identifier: AGPL-3.0-only

// Package vcentertest ist eine kleine vCenter-Attrappe für Tests (REST-API
// /api/session, /api/vcenter/host, /vm, /datastore). Nur Testdaten.
package vcentertest

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Fake: Zugang und Inhalte änderbar.
type Fake struct {
	Server   *httptest.Server
	CAPEM    string
	User     string
	Password string

	mu         sync.Mutex
	Hosts      []map[string]any
	VMs        []map[string]any
	Datastores []map[string]any
	Sessions   int // offene Sitzungen (Abmelden zählt herunter)
	Methods    []string
}

// Start startet die Attrappe mit TLS (eigenes Zertifikat, CAPEM als „CA“).
func Start(t *testing.T) *Fake {
	t.Helper()
	f := &Fake{User: "svc-openwacht@vsphere.local", Password: "lese-pass-123",
		Hosts: []map[string]any{{"host": "host-12", "name": "esx01", "connection_state": "CONNECTED", "power_state": "POWERED_ON"},
			{"host": "host-13", "name": "esx02", "connection_state": "NOT_RESPONDING", "power_state": "POWERED_ON"}},
		VMs: []map[string]any{{"vm": "vm-1001", "name": "dc01", "power_state": "POWERED_ON"},
			{"vm": "vm-1002", "name": "alt", "power_state": "POWERED_OFF"}},
		Datastores: []map[string]any{{"datastore": "datastore-15", "name": "ds-ssd", "type": "VMFS", "capacity": 1000, "free_space": 250},
			{"datastore": "datastore-16", "name": "ds-nfs", "type": "NFS"}},
	}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		f.mu.Lock()
		f.Methods = append(f.Methods, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("vmware-api-session-id") != "sitzung-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /api/session", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		f.mu.Lock()
		f.Methods = append(f.Methods, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if !ok || u != f.User || p != f.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.Sessions++
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode("sitzung-1")
	})
	mux.HandleFunc("DELETE /api/session", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			f.mu.Lock()
			f.Sessions--
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	})
	list := func(get func() []map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if auth(w, r) {
				f.mu.Lock()
				defer f.mu.Unlock()
				json.NewEncoder(w).Encode(get())
			}
		}
	}
	mux.HandleFunc("GET /api/vcenter/host", list(func() []map[string]any { return f.Hosts }))
	mux.HandleFunc("GET /api/vcenter/vm", list(func() []map[string]any { return f.VMs }))
	mux.HandleFunc("GET /api/vcenter/datastore", list(func() []map[string]any { return f.Datastores }))
	f.Server = httptest.NewUnstartedServer(mux)
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	f.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw}))
	return f
}

// Set ersetzt eine Liste (hosts, vms, datastores).
func (f *Fake) Set(kind string, v []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch kind {
	case "hosts":
		f.Hosts = v
	case "vms":
		f.VMs = v
	case "datastores":
		f.Datastores = v
	}
}
