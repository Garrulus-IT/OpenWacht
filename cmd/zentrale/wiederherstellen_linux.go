// SPDX-License-Identifier: AGPL-3.0-only

package main

// openwacht-zentrale wiederherstellen (Etappe 21b): Datenbank aus einer
// Sicherung zurückholen.
//
// Ablauf, damit nichts verloren geht:
//  1. Sicherung als postgres in eine neue, leere Datenbank openwacht_neu
//     einspielen (root öffnet die Datei, pg_restore liest sie von stdin;
//     Eigentümer der Objekte wird openwacht_owner). Die laufende Datenbank
//     bleibt dabei unberührt.
//  2. Prüfen, ob der Hauptschlüssel zur Sicherung passt (Agent-CA lässt sich
//     entschlüsseln). Sonst abbrechen und openwacht_neu löschen.
//  3. Dienste anhalten, openwacht in openwacht_vor_<Zeit> umbenennen (nicht
//     löschen), openwacht_neu in openwacht.
//  4. Migrationen (falls die Sicherung älter ist), Dienste starten.
//
// Hat die laufende Datenbank Inhalt, ist -ersetzen nötig.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

const restoreDB = "openwacht_neu"

var suffixRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

type restoreStatus struct {
	Exists bool   `json:"exists"`
	Tables int    `json:"tables"`
	CAKey  []byte `json:"ca_key,omitempty"`
}

// internRestore: die Schritte, die postgres ausführt.
func internRestore(ctx context.Context, conn *pgx.Conn, socket, step, suffix string, out io.Writer) error {
	switch step {
	case "status":
		var st restoreStatus
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'openwacht')`).Scan(&st.Exists); err != nil {
			return err
		}
		if st.Exists {
			c, err := pgx.Connect(ctx, "host="+socket+" user=postgres dbname=openwacht")
			if err != nil {
				return err
			}
			defer c.Close(ctx)
			if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = 'openwacht'`).Scan(&st.Tables); err != nil {
				return err
			}
		}
		return json.NewEncoder(out).Encode(st)
	case "leere-db":
		if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+restoreDB+` WITH (FORCE)`); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+restoreDB+` OWNER openwacht_owner ENCODING 'UTF8' TEMPLATE template0`); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]bool{"ok": true})
	case "ca-schluessel":
		c, err := pgx.Connect(ctx, "host="+socket+" user=postgres dbname="+restoreDB)
		if err != nil {
			return err
		}
		defer c.Close(ctx)
		var st restoreStatus
		key, err := zentrale.BackupCAKey(ctx, c)
		if err != nil {
			return fmt.Errorf("Agent-CA in der Sicherung: %w", err)
		}
		st.CAKey = key
		return json.NewEncoder(out).Encode(st)
	case "verwerfen":
		_, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+restoreDB+` WITH (FORCE)`)
		return err
	case "alte-verwerfen":
		// Zweitinstanz: die vorige Bereitschaftskopie nach dem Tausch löschen.
		if !suffixRe.MatchString(suffix) {
			return errors.New("ungültiger Zeitstempel")
		}
		_, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS openwacht_vor_`+strings.ToLower(suffix)+` WITH (FORCE)`)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]bool{"ok": true})
	case "tauschen":
		if !suffixRe.MatchString(suffix) {
			return errors.New("ungültiger Zeitstempel")
		}
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'openwacht')`).Scan(&exists); err != nil {
			return err
		}
		old := "openwacht_vor_" + strings.ToLower(suffix) // ohne Anführungszeichen schreibt PostgreSQL klein
		if exists {
			if _, err := conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'openwacht' AND pid <> pg_backend_pid()`); err != nil {
				return err
			}
			if _, err := conn.Exec(ctx, `ALTER DATABASE openwacht RENAME TO `+old); err != nil {
				return err
			}
		}
		if _, err := conn.Exec(ctx, `ALTER DATABASE `+restoreDB+` RENAME TO openwacht`); err != nil {
			return err
		}
		for _, stmt := range []string{`REVOKE ALL ON DATABASE openwacht FROM PUBLIC`,
			`GRANT CONNECT ON DATABASE openwacht TO openwacht_owner, openwacht_zentrale, openwacht_trapdienst`} {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		return json.NewEncoder(out).Encode(map[string]string{"alt": map[bool]string{true: old}[exists]})
	}
	return fmt.Errorf("unbekannter Schritt %q", step)
}

func cmdRestore(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("wiederherstellen", flag.ContinueOnError)
	file := fs.String("datei", "", "Sicherung (Standard: die neueste in "+backupDir+")")
	replace := fs.Bool("ersetzen", false, "die laufende Datenbank ersetzen (sie bleibt als openwacht_vor_<Zeit> erhalten)")
	socket := fs.String("pg-socket", "/run/postgresql", "Verzeichnis des PostgreSQL-Sockets")
	noServices := fs.Bool("ohne-dienste", false, "Dienste weder anhalten noch starten")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("wiederherstellen braucht root (sudo openwacht-zentrale wiederherstellen)")
	}
	path := *file
	if path == "" {
		files, err := listBackups(backupDir)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return fmt.Errorf("keine Sicherung in %s", backupDir)
		}
		path = filepath.Join(backupDir, files[0].name)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in := &installer{out: out, self: self, pgSocket: *socket, services: !*noServices,
		systemctl: func(a ...string) error {
			c := exec.Command("systemctl", a...)
			c.Stdout, c.Stderr = io.Discard, os.Stderr
			return c.Run()
		}}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		in.services = false
	}
	pgStep := func(step string, extra ...string) ([]byte, error) {
		return in.asUser(ctx, "postgres", append([]string{"intern-postgres", "-pg-socket", *socket, "-wiederherstellen", step}, extra...), nil)
	}

	b, err := pgStep("status")
	if err != nil {
		return err
	}
	var st restoreStatus
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Tables > 0 && !*replace {
		return errors.New("die Datenbank openwacht hat Inhalt. Mit -ersetzen wird sie ersetzt; sie bleibt dann als openwacht_vor_<Zeit> erhalten")
	}
	fmt.Fprintf(out, "Rücksicherung aus %s:\n", path)

	// 1. in eine neue Datenbank einspielen
	if _, err := pgStep("leere-db"); err != nil {
		return err
	}
	discard := func() { pgStep("verwerfen") }
	if err := pgRestore(ctx, path, *socket); err != nil {
		discard()
		return err
	}
	in.step("Sicherung in %s eingespielt", restoreDB)

	// 2. passt der Hauptschlüssel?
	if b, err = pgStep("ca-schluessel"); err != nil {
		discard()
		return err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		discard()
		return err
	}
	key, err := auth.LoadKeyFile(keyPath)
	if err != nil {
		discard()
		return err
	}
	if err := zentrale.CheckAgentCAKey(key, st.CAKey); err != nil {
		discard()
		return fmt.Errorf("%w; nichts geändert", err)
	}
	in.step("Hauptschlüssel %s passt zur Sicherung", keyPath)

	// 3. Dienste anhalten, tauschen
	units := []string{"openwacht-zentrale.socket", "openwacht-zentrale.service", "openwacht-traps.socket", "openwacht-traps.service"}
	if in.services {
		in.systemctl(append([]string{"stop"}, units...)...)
		in.step("Dienste angehalten")
	}
	suffix := time.Now().UTC().Format("20060102T150405Z")
	if b, err = pgStep("tauschen", "-zeit", suffix); err != nil {
		return fmt.Errorf("Tauschen: %w (Dienste sind angehalten; Zustand mit psql prüfen)", err)
	}
	var sw map[string]string
	json.Unmarshal(b, &sw)
	if sw["alt"] != "" {
		in.step("Bisherige Datenbank heißt jetzt %s", sw["alt"])
	}

	// 4. Migrationen, Dienste
	mig, err := in.asUser(ctx, userDB, []string{"migrieren"}, []string{"OPENWACHT_DB_EIGENTUEMER=" + ownerDSN(*socket)})
	if err != nil {
		return fmt.Errorf("Migrationen: %w", err)
	}
	in.step("Datenbank: %s", strings.TrimSpace(string(mig)))
	if in.services {
		start := []string{"start", "openwacht-traps.socket", "openwacht-zentrale.service", "openwacht-traps.service"}
		if !in.legacyProxyMode() {
			start = append(start, "openwacht-zentrale.socket")
		}
		if err := in.systemctl(start...); err != nil {
			return fmt.Errorf("Dienste starten: %w (journalctl -u openwacht-zentrale)", err)
		}
		in.step("Dienste gestartet")
	}
	fmt.Fprintln(out, "\nFertig. Alles prüfen, dann die alte Datenbank löschen:")
	if sw["alt"] != "" {
		fmt.Fprintf(out, "    runuser -u postgres -- psql -c 'DROP DATABASE %s'\n", sw["alt"])
	}
	return nil
}

// pgRestore spielt die Sicherung als postgres in openwacht_neu ein. root öffnet
// die Datei (sie gehört svc_openwacht_db, 0600) und gibt sie über stdin weiter.
func pgRestore(ctx context.Context, path, socket string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	uid, gid, err := lookupIDs("postgres")
	if err != nil {
		return err
	}
	c := exec.CommandContext(ctx, "pg_restore", "--exit-on-error", "--single-transaction", "--no-owner",
		"--role=openwacht_owner", "-d", "host="+socket+" user=postgres dbname="+restoreDB)
	c.Dir = "/"
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	c.Stdin = f
	var stderr strings.Builder
	c.Stdout, c.Stderr = io.Discard, &stderr
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	if err := c.Run(); err != nil {
		return fmt.Errorf("pg_restore: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
