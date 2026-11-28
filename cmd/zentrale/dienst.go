// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
)

// Betrieb ohne systemd (1.0.14): Docker und Windows Server.
//
//	openwacht-zentrale dienst [-daten <ordner>] [Optionen von starten …]
//
// Ein Aufruf erledigt, was unter Linux `installieren` und systemd tun:
//  1. Einstellungen aus <daten>/zentrale.env übernehmen (Zeilen NAME=Wert;
//     was schon in der Umgebung steht, gilt vorrangig);
//  2. den Hauptschlüssel <daten>/schluessel anlegen, wenn er fehlt;
//  3. die Datenbank migrieren (OPENWACHT_DB_EIGENTUEMER; wartet bis zu zwei
//     Minuten, bis PostgreSQL erreichbar ist);
//  4. die Zentrale starten (OPENWACHT_DB), Oberfläche auf :8443 (Windows:
//     :443) und Agent-Port auf :8444, wenn nichts anderes angegeben ist;
//  5. solange die Einrichtung offen ist, den Link zum Assistenten ausgeben.
//
// Datenbankrollen und Datenbank legt PostgreSQL selbst an (Docker:
// deploy/docker/postgres-init.sh, Windows: Handbuch Kapitel 1).

const (
	dienstAdresse      = ":8443"
	dienstAgentAdresse = ":8444"
)

// datenStandard: Ordner für Schlüssel und zentrale.env.
func datenStandard() string {
	if d := os.Getenv("OPENWACHT_DATEN"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "OpenWacht")
		}
		return `C:\ProgramData\OpenWacht`
	}
	return "/var/lib/openwacht"
}

func cmdDienst(ctx context.Context, args []string, out io.Writer) error {
	daten, rest := datenArg(args)
	return runDienst(ctx, daten, rest, out)
}

// datenArg: -daten <ordner> (oder -daten=<ordner>) herausnehmen; alles
// andere geht unverändert an starten.
func datenArg(args []string) (string, []string) {
	daten := datenStandard()
	var rest []string
	for i := 0; i < len(args); i++ {
		a := strings.TrimLeft(args[i], "-")
		switch {
		case a == "daten" && i+1 < len(args) && strings.HasPrefix(args[i], "-"):
			daten = args[i+1]
			i++
		case strings.HasPrefix(a, "daten=") && strings.HasPrefix(args[i], "-"):
			daten = strings.TrimPrefix(a, "daten=")
		default:
			rest = append(rest, args[i])
		}
	}
	return daten, rest
}

// runDienst: Ablauf wie oben; serveArgs gehen an starten.
func runDienst(ctx context.Context, daten string, serveArgs []string, out io.Writer) error {
	if err := os.MkdirAll(daten, 0o700); err != nil {
		return err
	}
	if err := ladeEnvDatei(filepath.Join(daten, "zentrale.env")); err != nil {
		return err
	}
	key := filepath.Join(daten, "schluessel")
	if neu, err := schluesselAnlegen(key); err != nil {
		return err
	} else if neu {
		slog.Warn("Hauptschlüssel neu angelegt; mit der Sicherung der Datenbank aufbewahren (ohne ihn ist sie unlesbar)", "datei", key)
	}
	if os.Getenv("OPENWACHT_DB_EIGENTUEMER") == "" || os.Getenv("OPENWACHT_DB") == "" {
		return errors.New("OPENWACHT_DB_EIGENTUEMER und OPENWACHT_DB setzen (Umgebung oder " + filepath.Join(daten, "zentrale.env") + ")")
	}
	conn, err := warteAufDatenbank(ctx, 2*time.Minute)
	if err != nil {
		return err
	}
	n, err := db.Migrate(ctx, conn)
	conn.Close(ctx)
	if err != nil {
		return fmt.Errorf("Migrationen: %w", err)
	}
	slog.Info("Datenbank bereit", "migrationen", n)

	args := []string{"-schluessel", key}
	if !hatOption(serveArgs, "adresse") {
		a := dienstAdresse
		if runtime.GOOS == "windows" {
			a = ":443" // Windows-Dienst als LocalSystem; Docker bildet 443 auf 8443 ab
		}
		args = append(args, "-adresse", a)
	}
	if !hatOption(serveArgs, "agent-adresse") {
		args = append(args, "-agent-adresse", dienstAgentAdresse)
	}
	args = append(args, serveArgs...)

	if runtime.GOOS == "windows" {
		neuerLinkHinweis = `openwacht-zentrale.exe einrichtungslink (als Administrator, mit OPENWACHT_DB_EIGENTUEMER)`
	} else {
		neuerLinkHinweis = "docker compose exec zentrale openwacht-zentrale einrichtungslink"
	}
	go einrichtungslinkAusgeben(ctx, out)
	return cmdServe(ctx, args)
}

// einrichtungslinkAusgeben: Link zum Assistenten, solange die Einrichtung
// offen ist (wartet auf das vorläufige Zertifikat der gerade startenden Zentrale).
func einrichtungslinkAusgeben(ctx context.Context, out io.Writer) {
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		slog.Warn("Einrichtungslink", "fehler", err)
		return
	}
	defer conn.Close(ctx)
	l, err := newSetupLink(ctx, conn, 30*time.Second)
	if err != nil {
		slog.Warn("Einrichtungslink", "fehler", err)
		return
	}
	if l.Offen {
		printSetupLink(out, l, false)
	}
}

func hatOption(args []string, name string) bool {
	for _, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// schluesselAnlegen: Hauptschlüssel erzeugen, wenn die Datei fehlt.
func schluesselAnlegen(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	k, err := auth.GenerateKeyText()
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := fmt.Fprintln(f, k); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

// ladeEnvDatei: Zeilen NAME=Wert; leere Zeilen und # Kommentare zählen nicht.
// Was schon in der Umgebung steht, bleibt.
func ladeEnvDatei(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for nr := 1; sc.Scan(); nr++ {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, wert, ok := strings.Cut(l, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return fmt.Errorf("%s, Zeile %d: erwartet NAME=Wert", path, nr)
		}
		wert = strings.Trim(strings.TrimSpace(wert), `"`)
		if _, gesetzt := os.LookupEnv(name); !gesetzt {
			os.Setenv(name, wert)
		}
	}
	return sc.Err()
}

// warteAufDatenbank: Verbindung als Eigentümer, sobald PostgreSQL antwortet.
func warteAufDatenbank(ctx context.Context, max time.Duration) (*pgx.Conn, error) {
	ende := time.Now().Add(max)
	for {
		conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
		if err == nil {
			return conn, nil
		}
		if time.Now().After(ende) {
			return nil, fmt.Errorf("Datenbank nicht erreichbar: %w", err)
		}
		slog.Info("Warte auf die Datenbank", "fehler", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
