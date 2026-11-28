// SPDX-License-Identifier: AGPL-3.0-only

//go:build !(js && wasm)

// Beim Bau der Demo (demo/bauen.mjs) läuft dieselbe Zentrale einmal auf diesem
// Rechner, gegen PGlite über einen lokalen Socket: Über die HTTP-API entstehen
// die Beispieldaten und Personen. Zusätzlich registriert sie die Agents der
// Demo (POST /_demo/agents) über den echten Agent-Handler. Hintergrundarbeit
// und Simulation laufen hier nicht: Messwerte und Alarme entstehen erst im
// Browser, damit ihre Zeiten stimmen. Nur für den Bau, nie im Betrieb.
//
//	OPENWACHT_DB="host=… port=…" openwacht-demo -adresse 127.0.0.1:0 -basis-url http://localhost:… -schluessel datei -rolle demo_server
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/auth"
)

var debug bool

func main() {
	addr := flag.String("adresse", "127.0.0.1:8080", "Adresse und Port")
	base := flag.String("basis-url", "", "Adresse der Demo beim Bau, z. B. http://localhost:8080")
	keyFile := flag.String("schluessel", "", "Datei mit dem Hauptschlüssel")
	rolle := flag.String("rolle", "demo_server", "Datenbankrolle der Zentrale")
	laufenAus := flag.String("laufen", "", "Zum Prüfen: demo.json; Hintergrundarbeit und Simulation wie im Browser")
	flag.Parse()
	if err := run(*addr, *base, *keyFile, *rolle, *laufenAus); err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

func run(addr, base, keyFile, rolle, laufenAus string) error {
	ctx := context.Background()
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return fmt.Errorf("-basis-url: %q", base)
	}
	key, err := auth.LoadKeyFile(keyFile)
	if err != nil {
		return err
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("OPENWACHT_DB") + " pool_max_conns=1")
	if err != nil {
		return err
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{rolle}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	sim := &simulation{}
	if laufenAus != "" {
		var dj struct {
			Agents []demoAgent `json:"agents"`
		}
		b, err := os.ReadFile(laufenAus)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &dj); err != nil {
			return err
		}
		if sim, err = newSimulation(dj.Agents); err != nil {
			return err
		}
	}
	srv, err := aufbauen(ctx, pool, bu, key, sim)
	if err != nil {
		return err
	}
	if laufenAus != "" {
		go laufen(ctx, srv, pool, sim, rolle)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /_demo/agents", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Token string   `json:"token"`
			Hosts []string `json:"hosts"`
			Still []string `json:"still"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var out []demoAgent
		for _, h := range append(append([]string{}, in.Hosts...), in.Still...) {
			a, err := registrieren(sim.agent, in.Token, h)
			if err != nil {
				http.Error(w, h+": "+err.Error(), http.StatusBadRequest)
				return
			}
			for _, s := range in.Still {
				a.Still = a.Still || s == h
			}
			out = append(out, a)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.Handle("/", srv.Handler())
	log.Printf("Demo-Zentrale für den Bau läuft auf %s", addr)
	return http.ListenAndServe(addr, mux)
}

// registrieren: ein Agent wie beim Installieren, über den echten Handler.
// Der Schlüssel wird nicht gebraucht und nicht gespeichert.
func registrieren(h http.Handler, token, host string) (demoAgent, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return demoAgent{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return demoAgent{}, err
	}
	body, _ := json.Marshal(agentproto.RegisterRequest{Token: token, CSR: csr, Hostname: host})
	req := httptest.NewRequest(http.MethodPost, agentproto.PathRegister, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.20.0.250:41000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return demoAgent{}, fmt.Errorf("Registrierung: %d %s", rec.Code, rec.Body.String())
	}
	var rr agentproto.RegisterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		return demoAgent{}, err
	}
	return demoAgent{Host: host, ID: rr.AgentID, Cert: rr.Certificate, CA: rr.CA}, nil
}
