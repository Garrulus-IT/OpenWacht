// SPDX-License-Identifier: AGPL-3.0-only

//go:build js && wasm

// openwacht-demo ist die echte Zentrale von OpenWacht für die Klick-Demo im
// Browser. Sie läuft als WebAssembly in einem Service Worker
// (demo/quelle/sw.js). Statt TCP spricht sie das PostgreSQL-Protokoll mit
// PGlite (PostgreSQL als WebAssembly) im selben Worker, statt eines
// HTTP-Listeners beantwortet sie die Anfragen, die der Service Worker abfängt.
// Alles andere ist derselbe Code wie im ausgelieferten Programm: dieselben
// Handler, Migrationen, Zeilenrichtlinien (RLS), Alarme und Verläufe. Weil es
// im Browser kein Netz gibt, spielt die Simulation (sim.go) die Agents und
// Gegenstellen. Mail, ntfy und andere Alarmwege gehen in der Demo nicht nach
// draußen.
//
// Vom Service Worker erwartet:
//
//	globalThis.ocDemo = {
//	  pg(bytes: Uint8Array): Promise<Uint8Array>   // Nachrichten an PGlite
//	  schluessel: Uint8Array                         // 32 Byte, aus dem Demo-Bau
//	  basis: string                                  // Ursprung mit Pfad
//	  rolle: string                                  // Datenbankrolle der Zentrale
//	  agents: string                                 // JSON: Agents aus dem Bau
//	  bereit(fetch: Function): void                  // meldet den Handler
//	  fehler(text: string): void
//	}
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/url"
	"os"
	"syscall/js"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	demo := js.Global().Get("ocDemo")
	if demo.IsUndefined() {
		panic("ocDemo fehlt")
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err := run(demo); err != nil {
		demo.Call("fehler", err.Error())
		return
	}
	select {}
}

func run(demo js.Value) error {
	ctx := context.Background()
	key := make([]byte, demo.Get("schluessel").Length())
	js.CopyBytesToGo(key, demo.Get("schluessel"))
	base, err := url.Parse(demo.Get("basis").String())
	if err != nil {
		return err
	}
	rolle := demo.Get("rolle").String()
	debug = demo.Get("debug").Truthy()
	var agents []demoAgent
	if err := json.Unmarshal([]byte(demo.Get("agents").String()), &agents); err != nil {
		return err
	}
	sim, err := newSimulation(agents)
	if err != nil {
		return err
	}

	cfg, err := pgxpool.ParseConfig("host=pglite user=" + rolle + " dbname=postgres sslmode=disable pool_max_conns=4")
	if err != nil {
		return err
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	cfg.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
		return []string{host}, nil
	}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return newPGConn(demo.Get("pg")), nil
	}
	// PGlite meldet sich immer als Superuser an; die Zentrale arbeitet wie im
	// Betrieb als Rolle in openwacht_app.
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{rolle}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	srv, err := aufbauen(ctx, pool, base, key, sim)
	if err != nil {
		return err
	}
	h := newBridge(srv.Handler())
	demo.Call("bereit", h.fn)
	go laufen(ctx, srv, pool, sim, rolle)
	return nil
}
