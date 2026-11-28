// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// aufbauen: die echte Zentrale für die Klick-Demo, mit einer einzigen
// Datenbank-Verbindung (PGlite hat nur eine Sitzung) und der Simulation statt
// des Netzes. Die Agent-Adresse erscheint nur in Befehlen der Oberfläche.
func aufbauen(ctx context.Context, pool *pgxpool.Pool, base *url.URL, key []byte, sim *simulation) (*zentrale.Server, error) {
	cfg := zentrale.Config{BaseURL: base, Issuer: "OpenWacht Demo",
		AgentNames: []string{"openwacht.beispiel.example"}, AgentURL: "https://openwacht.beispiel.example:8444",
		// Die Zertifikate der Agents stammen aus dem Bau der Demo und sollen
		// bei späteren Besuchen nicht als abgelaufen gelten.
		AgentCertLifetime: 10 * 365 * 24 * time.Hour,
		SettingsFromDB:    true}
	if sim != nil {
		cfg.Simulation = sim
	}
	srv, err := zentrale.New(cfg, pool, key)
	if err != nil {
		return nil, err
	}
	if err := srv.ReloadSettings(ctx); err != nil {
		return nil, err
	}
	if err := srv.InitAgentCA(ctx); err != nil {
		return nil, err
	}
	if sim != nil {
		sim.agent = srv.AgentHandler()
	}
	return srv, nil
}

// laufen: die Hintergrundarbeit der Zentrale wie im Betrieb (Sensoren,
// Abfragen, Alarme, Verlauf) und die Simulation. Ohne Verzeichnisabgleich,
// Berichte per Mail, Audit-Export und Selbstüberwachung (Sicherungen, Platten
// der Zentrale): Die gibt es im Browser nicht.
func laufen(ctx context.Context, srv *zentrale.Server, pool *pgxpool.Pool, sim *simulation, rolle string) {
	sim.runde(ctx)
	go srv.RunChecks(ctx)
	go srv.RunSNMP(ctx)
	go srv.RunAlerts(ctx)
	go func() {
		// Erst wenn alle Quellen einmal gemeldet haben, gibt es Werte, aus
		// denen sich der Verlauf fortschreiben lässt.
		select {
		case <-ctx.Done():
			return
		case <-time.After(8 * time.Second):
		}
		if err := lueckeFuellen(ctx, pool, rolle); err != nil {
			slog.Warn("Demo: Verlauf", "fehler", err)
		}
		srv.RunMetrics(ctx)
	}()
	go sim.Run(ctx)
}

func logDauer(was string, start time.Time) {
	slog.Info("Demo: "+was, "dauer", time.Since(start).Round(time.Millisecond))
}
