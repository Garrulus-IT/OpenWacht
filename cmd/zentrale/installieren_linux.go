// SPDX-License-Identifier: AGPL-3.0-only

package main

// Installation und Betrieb ohne Handarbeit (Etappe 21a):
//
//	openwacht-zentrale installieren      alles anlegen bzw. prüfen (root, mehrfach ausführbar)
//	openwacht-zentrale einrichtungslink  neuen Link für den Einrichtungsassistenten ausgeben
//	openwacht-zentrale sichern           Datenbank sichern, wenn fällig (Timer)
//
// `installieren` läuft als root. Was die Datenbank betrifft, erledigt es mit
// den Rechten des jeweiligen Systembenutzers: Es startet sich selbst erneut als
// postgres (Rollen, Datenbank) bzw. als svc_openwacht_db (Migrationen,
// Einrichtungslink). So gibt es keine Datenbankpasswörter, und root bekommt
// keine eigene Datenbankrolle.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	deploylinux "github.com/garrulus-it/openwacht/deploy/linux"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/traps"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// Feste Namen und Pfade der Installation.
const (
	userZentrale = "svc_openwacht"
	userDB       = "svc_openwacht_db"
	userTraps    = "svc_openwacht_traps"
	etcDir       = "/etc/openwacht"
	trapsDir     = "/etc/openwacht-traps"
	keyPath      = etcDir + "/schluessel"
	trapKeyPath  = trapsDir + "/schluessel"
	envPath      = etcDir + "/zentrale.env"
	backupDir    = "/var/backups/openwacht"
	unitDirPkg   = "/usr/lib/systemd/system"
	unitDirEtc   = "/etc/systemd/system"
	legacyBin    = "/usr/local/bin/openwacht-zentrale"
	unitMarker   = "# Verwaltet von openwacht-zentrale installieren"
)

// ownerDSN: Eigentümer-Rolle über den Unix-Socket (Peer-Authentifizierung).
func ownerDSN(socket string) string {
	return "host=" + socket + " user=openwacht_owner dbname=openwacht"
}

type installer struct {
	out       io.Writer
	pkg       bool   // aus dem Debian-Paket: Units liegen schon in /usr/lib/systemd/system
	services  bool   // systemctl aufrufen
	link      bool   // Einrichtungslink ausgeben
	pgSocket  string // Verzeichnis des PostgreSQL-Sockets
	self      string // Pfad dieses Programms
	root      string // nur für Tests: Präfix für alle Pfade
	systemctl func(args ...string) error
	stdin     []byte
}

func (in *installer) path(p string) string { return filepath.Join(in.root, p) }

func (in *installer) step(format string, a ...any) { fmt.Fprintf(in.out, "  ✓ "+format+"\n", a...) }
func (in *installer) note(format string, a ...any) { fmt.Fprintf(in.out, "  ! "+format+"\n", a...) }

func cmdInstall(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("installieren", flag.ContinueOnError)
	pkg := fs.Bool("paket", false, "aus dem Debian-Paket aufgerufen (postinst): Units nicht selbst schreiben")
	noServices := fs.Bool("ohne-dienste", false, "systemd-Dienste weder einrichten noch starten")
	noLink := fs.Bool("ohne-link", false, "keinen Einrichtungslink ausgeben")
	socket := fs.String("pg-socket", "/run/postgresql", "Verzeichnis des PostgreSQL-Sockets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("installieren braucht root (sudo openwacht-zentrale installieren)")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	in := &installer{out: out, pkg: *pkg, services: !*noServices, link: !*noLink, pgSocket: *socket, self: self,
		systemctl: func(a ...string) error {
			c := exec.Command("systemctl", a...)
			c.Stdout, c.Stderr = io.Discard, os.Stderr
			return c.Run()
		}}
	if _, err := os.Stat("/run/systemd/system"); err != nil && in.services {
		in.services = false
		defer in.note("kein systemd: Dienste nicht eingerichtet und nicht gestartet")
	}
	return in.run(ctx)
}

func (in *installer) run(ctx context.Context) error {
	fmt.Fprintln(in.out, "OpenWacht-Zentrale einrichten:")
	for _, u := range []string{userZentrale, userDB, userTraps} {
		if err := in.ensureUser(u); err != nil {
			return err
		}
	}
	in.step("Systembenutzer %s, %s, %s", userZentrale, userDB, userTraps)
	if err := in.ensureDirs(); err != nil {
		return err
	}
	if err := in.ensureKeys(); err != nil {
		return err
	}
	if err := in.ensureEnv(); err != nil {
		return err
	}
	pg, err := in.asUserJSON(ctx, "postgres", []string{"intern-postgres", "-pg-socket", in.pgSocket}, nil)
	if err != nil {
		return fmt.Errorf("PostgreSQL (läuft der Dienst? apt install postgresql): %w", err)
	}
	var info pgInfo
	if err := json.Unmarshal(pg, &info); err != nil {
		return fmt.Errorf("PostgreSQL: %w", err)
	}
	in.step("PostgreSQL %s: Rollen und Datenbank openwacht", info.Version)
	changed, err := in.ensurePgAuth(info)
	if err != nil {
		return err
	}
	if changed {
		if _, err := in.asUserJSON(ctx, "postgres", []string{"intern-postgres", "-pg-socket", in.pgSocket, "-neu-laden"}, nil); err != nil {
			return fmt.Errorf("pg_hba/pg_ident neu laden: %w", err)
		}
		in.step("pg_hba.conf und pg_ident.conf ergänzt (Sicherung: *.vor-openwacht)")
	} else {
		in.step("pg_hba.conf und pg_ident.conf schon passend")
	}
	if err := in.ensureUnits(); err != nil {
		return err
	}
	env := []string{"OPENWACHT_DB_EIGENTUEMER=" + ownerDSN(in.pgSocket)}
	if os.Getenv("OPENWACHT_OHNE_SICHERUNG") == "1" {
		in.note("Keine Sicherung vor dem Update (OPENWACHT_OHNE_SICHERUNG=1)")
	} else {
		b, err := in.asUser(ctx, userDB, []string{"sichern", "-vor-update", "-verzeichnis", backupDir}, env)
		if err != nil {
			return fmt.Errorf("Sicherung vor dem Update fehlgeschlagen, es wurde nichts migriert: %w\n"+
				"  Platz in %s prüfen (df -h). Nur wenn eine eigene Sicherung vorliegt: OPENWACHT_OHNE_SICHERUNG=1 vor den Befehl setzen", err, backupDir)
		}
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" {
				in.step("%s", l)
			}
		}
	}
	mig, err := in.asUser(ctx, userDB, []string{"migrieren"}, env)
	if err != nil {
		return fmt.Errorf("Migrationen: %w", err)
	}
	in.step("Datenbank: %s", strings.TrimSpace(string(mig)))
	if b, err := in.asUser(ctx, userDB, []string{"sichern", "-nur-abgleichen", "-verzeichnis", backupDir}, env); err != nil {
		in.note("Liste der Sicherungen nicht abgeglichen: %v", err)
	} else if l := strings.TrimSpace(string(b)); l != "" {
		in.step("%s", l)
	}
	if err := in.startServices(); err != nil {
		return err
	}
	if _, err := os.Stat(in.path(legacyBin)); err == nil && in.self != legacyBin {
		in.note("Altes Programm %s gefunden: bitte löschen (rm %s), sonst ruft die Shell weiter die alte Version auf", legacyBin, legacyBin)
	}
	if !in.link {
		return nil
	}
	return in.printLink(ctx, env)
}

func (in *installer) ensureUser(name string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	c := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", name)
	if b, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %v: %s", name, err, bytes.TrimSpace(b))
	}
	return nil
}

func lookupIDs(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	return uid, gid, err
}

// ensureDir legt ein Verzeichnis an und setzt Eigentümer und Rechte.
func ensureDir(p string, uid, gid int, mode os.FileMode) error {
	if err := os.MkdirAll(p, mode); err != nil {
		return err
	}
	if err := os.Chown(p, uid, gid); err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

func (in *installer) ensureDirs() error {
	_, gZ, err := lookupIDs(userZentrale)
	if err != nil {
		return err
	}
	_, gT, err := lookupIDs(userTraps)
	if err != nil {
		return err
	}
	uD, gD, err := lookupIDs(userDB)
	if err != nil {
		return err
	}
	if err := ensureDir(in.path(etcDir), 0, gZ, 0o750); err != nil {
		return err
	}
	if err := ensureDir(in.path(trapsDir), 0, gT, 0o750); err != nil {
		return err
	}
	// Sicherungen gehören der Eigentümer-Rolle (früher postgres): übernehmen.
	if err := ensureDir(in.path(backupDir), uD, gD, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(in.path(backupDir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "openwacht-") {
			if err := os.Chown(filepath.Join(in.path(backupDir), e.Name()), uD, gD); err != nil {
				return err
			}
		}
	}
	in.step("Verzeichnisse %s, %s, %s", etcDir, trapsDir, backupDir)
	return nil
}

// writeNew schreibt eine Datei nur, wenn es sie noch nicht gibt.
func writeNew(p string, data []byte, uid, gid int, mode os.FileMode) (bool, error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := os.Chown(p, uid, gid); err != nil {
		return false, err
	}
	return true, os.Chmod(p, mode)
}

func (in *installer) ensureKeys() error {
	uZ, gZ, err := lookupIDs(userZentrale)
	if err != nil {
		return err
	}
	kp := in.path(keyPath)
	if _, err := os.Stat(kp); errors.Is(err, fs.ErrNotExist) {
		k, err := auth.GenerateKeyText()
		if err != nil {
			return err
		}
		if _, err := writeNew(kp, []byte(k+"\n"), uZ, gZ, 0o400); err != nil {
			return err
		}
		in.step("Hauptschlüssel %s erzeugt – bitte getrennt sichern (Passwortmanager)", keyPath)
	} else {
		in.step("Hauptschlüssel %s vorhanden", keyPath)
	}
	key, err := auth.LoadKeyFile(kp)
	if err != nil {
		return err
	}
	uT, gT, err := lookupIDs(userTraps)
	if err != nil {
		return err
	}
	tk := []byte(base64.StdEncoding.EncodeToString(traps.DeriveKey(key)) + "\n")
	if made, err := writeNew(in.path(trapKeyPath), tk, uT, gT, 0o400); err != nil {
		return err
	} else if made {
		in.step("Trap-Schlüssel %s abgeleitet", trapKeyPath)
	}
	return nil
}

// newEnv: Startoptionen einer neuen Installation. Alles andere kommt aus der
// Einrichtung und der Seite Einstellungen.
const newEnv = `# /etc/openwacht/zentrale.env – Startoptionen der Zentrale (root:svc_openwacht, 0640).
# Angelegt von openwacht-zentrale installieren. Adresse, Zertifikat, Netze,
# Alarmziele und Schwellen stehen in der Oberfläche (Einrichtung, Einstellungen).
# Die Oberfläche lauscht auf Port 443 (openwacht-zentrale.socket), der Agent-Port hier.
OPENWACHT_ARGS=-agent-adresse :8444
`

func (in *installer) ensureEnv() error {
	_, gZ, err := lookupIDs(userZentrale)
	if err != nil {
		return err
	}
	made, err := writeNew(in.path(envPath), []byte(newEnv), 0, gZ, 0o640)
	if err != nil {
		return err
	}
	if made {
		in.step("Startoptionen %s angelegt", envPath)
	} else {
		in.step("Startoptionen %s vorhanden (unverändert)", envPath)
	}
	return nil
}

// legacyProxyMode: Steht -adresse in zentrale.env, läuft die Oberfläche hinter
// einem Reverse Proxy (Installation vor Etappe 21); dann bleibt Port 443 aus.
func (in *installer) legacyProxyMode() bool {
	b, err := os.ReadFile(in.path(envPath))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// „OPENWACHT_ARGS=-adresse …“: die erste Option hängt am Namen.
		if _, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "-") {
			line = v
		}
		for _, f := range strings.Fields(line) {
			if f == "-adresse" || strings.HasPrefix(f, "-adresse=") || f == "--adresse" {
				return true
			}
		}
	}
	return false
}

// --- PostgreSQL -------------------------------------------------------------------

type pgInfo struct {
	Version string `json:"version"`
	HBA     string `json:"hba"`
	Ident   string `json:"ident"`
}

const hbaLine = "local   openwacht  openwacht_zentrale,openwacht_owner,openwacht_trapdienst  peer map=openwacht"

var identLines = [][3]string{
	{"openwacht", userZentrale, "openwacht_zentrale"},
	{"openwacht", userDB, "openwacht_owner"},
	{"openwacht", userTraps, "openwacht_trapdienst"},
}

// editHBA fügt die Zeile für OpenWacht vor der ersten „local“-Zeile ein bzw.
// ersetzt eine ältere Fassung (ohne Trap-Rolle). Unverändert = gleicher Text.
func editHBA(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && !strings.HasPrefix(f[0], "#") && strings.Contains(l, "map=openwacht") {
			if strings.Join(f, " ") == strings.Join(strings.Fields(hbaLine), " ") {
				return text
			}
			lines[i] = hbaLine
			return strings.Join(lines, "\n")
		}
	}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && f[0] == "local" {
			out := append([]string{}, lines[:i]...)
			out = append(out, "# OpenWacht (openwacht-zentrale installieren)", hbaLine)
			return strings.Join(append(out, lines[i:]...), "\n")
		}
	}
	if !strings.HasSuffix(text, "\n") && text != "" {
		text += "\n"
	}
	return text + "# OpenWacht (openwacht-zentrale installieren)\n" + hbaLine + "\n"
}

// editIdent hängt fehlende Zuordnungen an.
func editIdent(text string) string {
	have := map[[3]string]bool{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && !strings.HasPrefix(f[0], "#") {
			have[[3]string{f[0], f[1], f[2]}] = true
		}
	}
	var add []string
	for _, m := range identLines {
		if !have[m] {
			add = append(add, fmt.Sprintf("%-11s %-19s %s", m[0], m[1], m[2]))
		}
	}
	if len(add) == 0 {
		return text
	}
	if !strings.HasSuffix(text, "\n") && text != "" {
		text += "\n"
	}
	return text + "# OpenWacht (openwacht-zentrale installieren)\n" + strings.Join(add, "\n") + "\n"
}

// rewrite schreibt eine Konfigurationsdatei atomar neu (Rechte und Eigentümer
// bleiben); vorher einmalig eine Sicherung *.vor-openwacht.
func rewrite(p, newText string) (bool, error) {
	old, err := os.ReadFile(p)
	if err != nil {
		return false, err
	}
	if string(old) == newText {
		return false, nil
	}
	st, err := os.Stat(p)
	if err != nil {
		return false, err
	}
	sys := st.Sys().(*syscall.Stat_t)
	if _, err := os.Stat(p + ".vor-openwacht"); errors.Is(err, fs.ErrNotExist) {
		if _, err := writeNew(p+".vor-openwacht", old, int(sys.Uid), int(sys.Gid), st.Mode().Perm()); err != nil {
			return false, err
		}
	}
	tmp := p + ".neu-openwacht"
	if err := os.WriteFile(tmp, []byte(newText), st.Mode().Perm()); err != nil {
		return false, err
	}
	if err := os.Chown(tmp, int(sys.Uid), int(sys.Gid)); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, os.Rename(tmp, p)
}

func (in *installer) ensurePgAuth(info pgInfo) (bool, error) {
	changed := false
	for _, f := range []struct {
		path string
		edit func(string) string
	}{{info.HBA, editHBA}, {info.Ident, editIdent}} {
		if f.path == "" {
			return false, errors.New("PostgreSQL nennt keinen Pfad für pg_hba/pg_ident")
		}
		b, err := os.ReadFile(in.path(f.path))
		if err != nil {
			return false, err
		}
		c, err := rewrite(in.path(f.path), f.edit(string(b)))
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	return changed, nil
}

// cmdInternPostgres läuft als postgres: Rollen und Datenbank anlegen (fehlende
// nur), Pfade von pg_hba/pg_ident melden; mit -neu-laden die Dateien prüfen
// und neu laden. Ausgabe JSON auf stdout.
func cmdInternPostgres(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("intern-postgres", flag.ContinueOnError)
	socket := fs.String("pg-socket", "/run/postgresql", "Socket-Verzeichnis")
	reload := fs.Bool("neu-laden", false, "pg_hba/pg_ident prüfen und neu laden")
	restore := fs.String("wiederherstellen", "", "Schritt der Rücksicherung: leere-db, ca-schluessel, status, tauschen")
	suffix := fs.String("zeit", "", "Zeitstempel für openwacht_vor_<zeit> (tauschen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, "host="+*socket+" user=postgres dbname=postgres")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if *restore != "" {
		return internRestore(ctx, conn, *socket, *restore, *suffix, out)
	}
	if *reload {
		var bad int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL`).Scan(&bad); err != nil {
			return err
		}
		if bad > 0 {
			return fmt.Errorf("pg_hba.conf enthält %d fehlerhafte Zeile(n), nicht neu geladen", bad)
		}
		if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]bool{"neu_geladen": true})
	}
	for _, stmt := range []string{
		`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_app') THEN CREATE ROLE openwacht_app NOLOGIN; END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_owner') THEN CREATE ROLE openwacht_owner LOGIN; END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_zentrale') THEN CREATE ROLE openwacht_zentrale LOGIN IN ROLE openwacht_app; END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_traps') THEN CREATE ROLE openwacht_traps NOLOGIN; END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_trapdienst') THEN CREATE ROLE openwacht_trapdienst LOGIN IN ROLE openwacht_traps; END IF;
		END $$`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'openwacht')`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		if _, err := conn.Exec(ctx, `CREATE DATABASE openwacht OWNER openwacht_owner ENCODING 'UTF8' TEMPLATE template0`); err != nil {
			return err
		}
	}
	for _, stmt := range []string{
		`REVOKE ALL ON DATABASE openwacht FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE openwacht TO openwacht_owner, openwacht_zentrale, openwacht_trapdienst`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	var info pgInfo
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version'), current_setting('hba_file'), current_setting('ident_file')`).
		Scan(&info.Version, &info.HBA, &info.Ident); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(info)
}

// --- als anderer Benutzer ausführen ----------------------------------------------

func (in *installer) asUser(ctx context.Context, name string, args, env []string) ([]byte, error) {
	uid, gid, err := lookupIDs(name)
	if err != nil {
		return nil, err
	}
	c := exec.CommandContext(ctx, in.self, args...)
	c.Dir = "/"
	c.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}, env...)
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if in.stdin != nil {
		c.Stdin = bytes.NewReader(in.stdin)
	}
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(stderr.String()), "Fehler:"))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}

func (in *installer) asUserStdin(ctx context.Context, name string, args, env []string, stdin []byte) ([]byte, error) {
	in.stdin = stdin
	defer func() { in.stdin = nil }()
	return in.asUser(ctx, name, args, env)
}

func (in *installer) asUserJSON(ctx context.Context, name string, args, env []string) ([]byte, error) {
	return in.asUser(ctx, name, args, env)
}

// --- systemd ------------------------------------------------------------------

// unitContent: Inhalt einer Unit; ohne Paket mit dem Pfad dieses Programms.
func (in *installer) unitContent(name string) ([]byte, error) {
	b, err := deploylinux.Unit(name)
	if err != nil {
		return nil, err
	}
	if !in.pkg {
		b = bytes.ReplaceAll(b, []byte("/usr/bin/openwacht-zentrale"), []byte(in.self))
		b = append([]byte(unitMarker+"\n"), b...)
	}
	return b, nil
}

// ensureUnits: Mit Paket liegen die Units unter /usr/lib/systemd/system. Alte
// Units aus /etc/systemd/system (Installation von Hand vor Etappe 21) würden
// sie verdecken; sie werden nach /etc/openwacht/units-vor-paket verschoben.
// Ohne Paket schreibt installieren die Units nach /etc/systemd/system.
func (in *installer) ensureUnits() error {
	moved, err := in.moveLegacyUnits()
	if err != nil {
		return err
	}
	if len(moved) > 0 {
		in.step("Alte Units nach %s/units-vor-paket verschoben: %s", etcDir, strings.Join(moved, ", "))
	}
	if in.pkg {
		return nil
	}
	if err := os.MkdirAll(in.path(unitDirEtc), 0o755); err != nil {
		return err
	}
	for _, n := range deploylinux.UnitNames {
		b, err := in.unitContent(n)
		if err != nil {
			return err
		}
		if err := os.WriteFile(in.path(filepath.Join(unitDirEtc, n)), b, 0o644); err != nil {
			return err
		}
	}
	in.step("Units nach %s geschrieben", unitDirEtc)
	return nil
}

// ownUnit: Stammt die Unit von OpenWacht?
func ownUnit(b []byte) bool {
	for _, m := range []string{"openwacht", "OpenWacht"} {
		if bytes.Contains(b, []byte(m)) {
			return true
		}
	}
	return false
}

func (in *installer) moveLegacyUnits() ([]string, error) {
	var moved []string
	dest := in.path(filepath.Join(etcDir, "units-vor-paket"))
	for _, n := range deploylinux.UnitNames {
		p := in.path(filepath.Join(unitDirEtc, n))
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// Eigene (von installieren ohne Paket geschriebene) Units ersetzt
		// installieren ohne Paket ohnehin; mit Paket müssen auch sie weichen.
		if bytes.HasPrefix(b, []byte(unitMarker)) && !in.pkg {
			continue
		}
		if !ownUnit(b) {
			continue // fremde Datei gleichen Namens: nicht anfassen
		}
		if err := os.MkdirAll(dest, 0o750); err != nil {
			return nil, err
		}
		if err := os.Rename(p, filepath.Join(dest, n)); err != nil {
			return nil, err
		}
		moved = append(moved, n)
	}
	// Verwaiste Verweise in *.wants entfernen (systemctl enable legt neue an).
	for _, wants := range []string{"multi-user.target.wants", "sockets.target.wants", "timers.target.wants"} {
		d := in.path(filepath.Join(unitDirEtc, wants))
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "openwacht-") || e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			l := filepath.Join(d, e.Name())
			if _, err := os.Stat(l); errors.Is(err, fs.ErrNotExist) {
				os.Remove(l)
			}
		}
	}
	return moved, nil
}

func (in *installer) startServices() error {
	if !in.services {
		return nil
	}
	sc := in.systemctl
	if err := sc("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	legacy := in.legacyProxyMode()
	if err := sc("enable", "openwacht-zentrale.service", "openwacht-traps.service"); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}
	if err := sc("enable", "--now", "openwacht-sicherung.timer", "openwacht-traps.socket"); err != nil {
		return fmt.Errorf("systemctl enable --now (Timer, Trap-Socket): %w", err)
	}
	if legacy {
		// Port 443 gehört dem Reverse Proxy (Caddy); Socket aus.
		sc("disable", "--now", "openwacht-zentrale.socket")
		in.note("-adresse in %s: Oberfläche weiter hinter dem Reverse Proxy, Port 443 bleibt aus (Umstieg: siehe Runbook)", envPath)
	} else {
		// Läuft die Zentrale schon (Update), startet systemd den Socket nicht
		// („already active, refusing“). Sie startet unten ohnehin neu.
		sc("stop", "openwacht-zentrale.service")
		if err := sc("enable", "--now", "openwacht-zentrale.socket"); err != nil {
			return fmt.Errorf("Port 443 (openwacht-zentrale.socket) belegt? %w", err)
		}
	}
	if err := sc("restart", "openwacht-zentrale.service"); err != nil {
		return fmt.Errorf("openwacht-zentrale starten (journalctl -u openwacht-migrieren -u openwacht-zentrale): %w", err)
	}
	if err := sc("restart", "openwacht-traps.service"); err != nil {
		in.note("Trap-Dienst startet nicht (journalctl -u openwacht-traps): %v", err)
	}
	in.step("Dienste eingerichtet und gestartet")
	return nil
}

// --- Einrichtungslink ----------------------------------------------------------

type setupLink struct {
	Offen         bool     `json:"offen"`
	Token         string   `json:"token,omitempty"`
	Fingerabdruck string   `json:"fingerabdruck,omitempty"`
	Namen         []string `json:"namen,omitempty"`
	Adresse       string   `json:"adresse,omitempty"`
}

func (in *installer) printLink(ctx context.Context, env []string) error {
	args := []string{"intern-einrichtung"}
	if in.services && !in.legacyProxyMode() {
		args = append(args, "-warten", "30s")
	}
	b, err := in.asUser(ctx, userDB, args, env)
	if err != nil {
		return fmt.Errorf("Einrichtungslink: %w", err)
	}
	var l setupLink
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	printSetupLink(in.out, l, in.legacyProxyMode())
	return nil
}

func printSetupLink(out io.Writer, l setupLink, proxy bool) {
	if !l.Offen {
		if l.Adresse != "" {
			fmt.Fprintf(out, "\nOpenWacht ist eingerichtet: %s\n", l.Adresse)
		} else {
			fmt.Fprintln(out, "\nOpenWacht ist eingerichtet.")
		}
		return
	}
	fmt.Fprintf(out, "\nEinrichtung im Browser öffnen (gilt %d Minuten, nur einmal bis „Fertig“):\n\n", int(zentrale.SetupTokenTTL/time.Minute))
	hosts := l.Namen
	if len(hosts) == 0 && !proxy {
		hosts = zentrale.HostNames() // Zentrale noch nicht gestartet (ohne systemd)
	}
	if proxy || len(hosts) == 0 {
		hosts = []string{"<Adresse der Oberfläche>"}
	}
	for _, h := range hosts {
		if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
			h = "[" + h + "]"
		}
		fmt.Fprintf(out, "    https://%s/einrichtung#%s\n", h, l.Token)
	}
	if l.Fingerabdruck != "" {
		fmt.Fprintf(out, "\nDer Browser warnt vor dem vorläufigen Zertifikat. Weiter nur, wenn er diesen\nSHA-256-Fingerabdruck zeigt:\n\n    %s\n", l.Fingerabdruck)
	}
	fmt.Fprintln(out, "\nNeuer Link: sudo openwacht-zentrale einrichtungslink")
}

// cmdInternSetup läuft als svc_openwacht_db (Eigentümer-Rolle): neues Token,
// wenn die Einrichtung offen ist, dazu der Fingerabdruck des vorläufigen
// Zertifikats (mit -warten, bis die Zentrale es angelegt hat).
func cmdInternSetup(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("intern-einrichtung", flag.ContinueOnError)
	wait := fs.Duration("warten", 0, "so lange auf das vorläufige Zertifikat warten")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	l, err := newSetupLink(ctx, conn, *wait)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(l)
}

func newSetupLink(ctx context.Context, conn *pgx.Conn, wait time.Duration) (setupLink, error) {
	var l setupLink
	raw, hash, err := zentrale.NewSetupToken()
	if err != nil {
		return l, err
	}
	tag, err := conn.Exec(ctx, `UPDATE openwacht.setup_state SET token_hash = $1, expires_at = now() + $2::interval
		WHERE done_at IS NULL AND NOT EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id IS NULL)`,
		hash, fmt.Sprintf("%d seconds", int(zentrale.SetupTokenTTL/time.Second)))
	if err != nil {
		return l, err
	}
	if tag.RowsAffected() == 0 {
		var base *string
		_ = conn.QueryRow(ctx, `SELECT base_url FROM openwacht.settings`).Scan(&base)
		if base != nil {
			l.Adresse = *base
		}
		return l, nil
	}
	l.Offen, l.Token = true, raw
	deadline := time.Now().Add(wait)
	for {
		var certPEM string
		var names []string
		err := conn.QueryRow(ctx, `SELECT cert_pem, names FROM openwacht.https_material WHERE kind = 'einrichtung'`).Scan(&certPEM, &names)
		if err == nil {
			if c, err := pki.ParseCertPEM([]byte(certPEM)); err == nil {
				l.Fingerabdruck, l.Namen = pki.SHA256Hex(c), names
			}
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return l, err
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return l, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return l, nil
}

// cmdSetupLink: neuer Einrichtungslink (der alte wird ungültig).
func cmdSetupLink(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("einrichtungslink", flag.ContinueOnError)
	socket := fs.String("pg-socket", "/run/postgresql", "Verzeichnis des PostgreSQL-Sockets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Getenv("OPENWACHT_DB_EIGENTUEMER") != "" {
		conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		l, err := newSetupLink(ctx, conn, 0)
		if err != nil {
			return err
		}
		printSetupLink(out, l, false)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("als root aufrufen (sudo openwacht-zentrale einrichtungslink) oder OPENWACHT_DB_EIGENTUEMER setzen")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in := &installer{out: out, pgSocket: *socket, self: self}
	return in.printLink(ctx, []string{"OPENWACHT_DB_EIGENTUEMER=" + ownerDSN(*socket)})
}

// --- Sicherung ------------------------------------------------------------------

// backupFile: eine Sicherung im Verzeichnis.
type backupFile struct {
	name string
	mod  time.Time
}

func listBackups(dir string) ([]backupFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []backupFile
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), "openwacht-") || !strings.HasSuffix(e.Name(), ".dump") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupFile{e.Name(), fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	return out, nil
}

// backupDue: jetzt sichern? Zur eingestellten Stunde (Ortszeit), wenn die
// letzte Sicherung mindestens 20 Stunden alt ist, oder nachholen, wenn sie
// älter als 25 Stunden ist (Rechner war zur Uhrzeit aus).
func backupDue(now time.Time, loc *time.Location, hour int, newest *time.Time) bool {
	if newest == nil {
		return true
	}
	age := now.Sub(*newest)
	if age > 25*time.Hour {
		return true
	}
	return now.In(loc).Hour() == hour && age >= 20*time.Hour
}

// expiredBackups: älter als days Tage, die neueste bleibt immer.
func expiredBackups(files []backupFile, now time.Time, days int) []string {
	var out []string
	for i, f := range files {
		if i > 0 && now.Sub(f.mod) > time.Duration(days)*24*time.Hour {
			out = append(out, f.name)
		}
	}
	return out
}

func cmdBackup(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sichern", flag.ContinueOnError)
	dir := fs.String("verzeichnis", backupDir, "Ordner für die Sicherungen")
	now := fs.Bool("jetzt", false, "sofort sichern, unabhängig von der Uhrzeit")
	beforeUpdate := fs.Bool("vor-update", false, "nur sichern, wenn Migrationen ausstehen (installieren vor einem Update)")
	onlySync := fs.Bool("nur-abgleichen", false, "nicht sichern, nur die Liste der Sicherungen mit dem Ordner abgleichen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dsn := os.Getenv("OPENWACHT_DB_EIGENTUEMER")
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if *beforeUpdate {
		return backupBeforeUpdate(ctx, conn, dsn, *dir, out)
	}
	if *onlySync {
		return syncBackupLog(ctx, conn, *dir, out)
	}
	var hour, days *int16
	var tz *string
	if err := conn.QueryRow(ctx, `SELECT backup_hour, backup_days, timezone FROM openwacht.settings`).Scan(&hour, &days, &tz); err != nil {
		return err
	}
	inst := zentrale.Install{BackupHour: hour, BackupDays: days, Timezone: tz}
	h, d := inst.Backup()
	loc, _ := inst.Zone()
	files, err := listBackups(*dir)
	if err != nil {
		return err
	}
	var newest *time.Time
	if len(files) > 0 {
		newest = &files[0].mod
	}
	t := time.Now()
	if *now || backupDue(t, loc, h, newest) {
		name, size, derr := dump(ctx, dsn, *dir, t, out)
		// Jeden Lauf eintragen, auch Fehler (Seite Einstellungen → Installation).
		var file *string
		var sz *int64
		msg := ""
		if derr == nil {
			file, sz = &name, &size
		} else {
			msg = derr.Error()
			if len(msg) > 500 {
				msg = msg[:497] + "…"
			}
		}
		if _, err := conn.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok, message)
			VALUES ($1, $2, $3, $4, nullif($5, ''))`, t, file, sz, derr == nil, msg); err != nil {
			fmt.Fprintf(os.Stderr, "Protokoll der Sicherung: %v\n", err)
		}
		if derr != nil {
			return derr
		}
		if files, err = listBackups(*dir); err != nil {
			return err
		}
	}
	for _, n := range expiredBackups(files, t, d) {
		if err := os.Remove(filepath.Join(*dir, n)); err != nil {
			return err
		}
		conn.Exec(ctx, `UPDATE openwacht.backup_log SET removed_at = now() WHERE file = $1 AND removed_at IS NULL`, n)
		fmt.Fprintf(out, "Gelöscht (älter als %d Tage): %s\n", d, n)
	}
	// Protokoll nicht endlos wachsen lassen.
	conn.Exec(ctx, `DELETE FROM openwacht.backup_log WHERE started_at < now() - interval '400 days'`)
	return syncBackupLog(ctx, conn, *dir, out)
}

// syncBackupLog gleicht die Liste (Einstellungen → Sicherungen) mit dem Ordner
// ab: Dateien ohne Eintrag kommen dazu (Sicherung vor einem Update von einem
// Stand ohne backup_log, Sicherungen der alten Unit, eine Datei, deren Eintrag
// nach einer Rücksicherung fehlt), Einträge ohne Datei gelten als entfernt.
func syncBackupLog(ctx context.Context, conn *pgx.Conn, dir string, out io.Writer) error {
	files, err := listBackups(dir)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	added := 0
	for _, f := range files {
		present[f.name] = true
		t, err := time.Parse("20060102T150405Z", strings.TrimSuffix(strings.TrimPrefix(f.name, "openwacht-"), ".dump"))
		if err != nil {
			continue // fremder Name: nicht ins Protokoll (CHECK)
		}
		fi, err := os.Stat(filepath.Join(dir, f.name))
		if err != nil {
			continue
		}
		tag, err := conn.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, finished_at, file, size_bytes, ok, message)
			SELECT $1, $2, $3, $4, true, 'nachgetragen'
			WHERE NOT EXISTS (SELECT 1 FROM openwacht.backup_log WHERE file = $3 AND removed_at IS NULL)`,
			t, f.mod, f.name, fi.Size())
		if err != nil {
			return fmt.Errorf("Sicherung %s nachtragen: %w", f.name, err)
		}
		added += int(tag.RowsAffected())
	}
	rows, err := conn.Query(ctx, `SELECT file FROM openwacht.backup_log WHERE ok AND removed_at IS NULL`)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil && !present[n] {
			gone = append(gone, n)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range gone {
		if _, err := conn.Exec(ctx, `UPDATE openwacht.backup_log SET removed_at = now() WHERE file = $1 AND removed_at IS NULL`, n); err != nil {
			return err
		}
	}
	if added > 0 || len(gone) > 0 {
		fmt.Fprintf(out, "Liste der Sicherungen abgeglichen: %d nachgetragen, %d als entfernt markiert.\n", added, len(gone))
	}
	return nil
}

// backupBeforeUpdate sichert vor dem Migrieren, aber nur, wenn das Update
// das Schema ändert: Migrationen sind nicht umkehrbar, der Rückweg ist diese
// Sicherung plus das alte Paket. Liest nichts aus Tabellen, die es in älteren
// Ständen noch nicht gibt (settings.backup_hour ab 0026, backup_log ab 0027).
func backupBeforeUpdate(ctx context.Context, conn *pgx.Conn, dsn, dir string, out io.Writer) error {
	n, fresh, err := db.Pending(ctx, conn)
	if err != nil {
		return err
	}
	if fresh {
		fmt.Fprintln(out, "Neue Datenbank, keine Sicherung vor dem Update nötig.")
		return nil
	}
	if n == 0 {
		fmt.Fprintln(out, "Keine ausstehenden Migrationen, keine Sicherung vor dem Update nötig.")
		return nil
	}
	t := time.Now()
	name, size, derr := dump(ctx, dsn, dir, t, out)
	var hasLog bool
	if conn.QueryRow(ctx, `SELECT to_regclass('openwacht.backup_log') IS NOT NULL`).Scan(&hasLog) == nil && hasLog {
		var file *string
		var sz *int64
		msg := "vor dem Update"
		if derr == nil {
			file, sz = &name, &size
		} else {
			msg = "vor dem Update: " + derr.Error()
			if len(msg) > 500 {
				msg = msg[:497] + "…"
			}
		}
		if _, err := conn.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok, message)
			VALUES ($1, $2, $3, $4, $5)`, t, file, sz, derr == nil, msg); err != nil {
			fmt.Fprintf(os.Stderr, "Protokoll der Sicherung: %v\n", err)
		}
	}
	if derr != nil {
		return derr
	}
	fmt.Fprintf(out, "Vor dem Update gesichert (%d Migration(en) stehen aus).\n", n)
	return nil
}

// dump schreibt eine Sicherung (pg_dump, Custom-Format, 0600) und liefert
// Dateiname und Größe.
func dump(ctx context.Context, dsn, dir string, t time.Time, out io.Writer) (string, int64, error) {
	name := "openwacht-" + t.UTC().Format("20060102T150405Z") + ".dump"
	tmp := filepath.Join(dir, name+".neu")
	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, "pg_dump", "-Fc", "-d", dsn, "-f", tmp)
	c.Stdout, c.Stderr = out, io.MultiWriter(os.Stderr, &stderr)
	if err := c.Run(); err != nil {
		os.Remove(tmp)
		return "", 0, fmt.Errorf("pg_dump: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	// enthält verschlüsselte Geheimnisse: nur für den Eigentümer
	if err := os.Chmod(tmp, 0o600); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return "", 0, err
	}
	fi, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return "", 0, err
	}
	fmt.Fprintf(out, "Gesichert: %s\n", filepath.Join(dir, name))
	return name, fi.Size(), nil
}

// --- Umstieg auf HTTPS durch die Zentrale (Installationen vor Etappe 21) ------

// legacyFlags: Startoptionen, die mit HTTPS der Zentrale wegfallen (Adresse
// und Namen kommen dann aus der Datenbank, Port 443 von systemd).
var legacyFlags = map[string]bool{"-adresse": true, "-proxy": true, "-basis-url": true, "-agent-namen": true,
	"-tls-zertifikat": true, "-tls-schluessel": true}

// stripLegacyArgs entfernt diese Optionen (mit Wert) aus OPENWACHT_ARGS.
func stripLegacyArgs(env string) (string, []string) {
	var removed []string
	lines := strings.Split(env, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "OPENWACHT_ARGS=") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "OPENWACHT_ARGS="))
		var keep []string
		for j := 0; j < len(f); j++ {
			name := strings.SplitN(strings.TrimLeft(f[j], "-"), "=", 2)[0]
			if legacyFlags["-"+name] {
				removed = append(removed, "-"+name)
				if !strings.Contains(f[j], "=") && j+1 < len(f) {
					j++
				}
				continue
			}
			keep = append(keep, f[j])
		}
		lines[i] = "OPENWACHT_ARGS=" + strings.Join(keep, " ")
	}
	return strings.Join(lines, "\n"), removed
}

type umstiegData struct {
	BaseURL string   `json:"base_url"`
	Names   []string `json:"names"`
	Cert    string   `json:"cert"`
	Key     []byte   `json:"key"`
	CACert  string   `json:"ca_cert"`
	CAKey   []byte   `json:"ca_key"`
}

// cmdHTTPSSwitch: `https-umstieg -adressen name,ip` (root). Legt Adresse und
// eigene CA in der Datenbank an und nimmt -adresse, -proxy, -basis-url und
// -agent-namen aus zentrale.env. Port 443 übergibt man danach per systemctl.
func cmdHTTPSSwitch(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("https-umstieg", flag.ContinueOnError)
	addrs := fs.String("adressen", "", "Namen und IP-Adressen der Zentrale, kommagetrennt, der erste ist die Adresse der Oberfläche (Pflicht)")
	socket := fs.String("pg-socket", "/run/postgresql", "Verzeichnis des PostgreSQL-Sockets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("als root aufrufen (sudo openwacht-zentrale https-umstieg …)")
	}
	names, err := pki.NormalizeNames(strings.Split(*addrs, ","))
	if err != nil {
		return fmt.Errorf("-adressen: %w", err)
	}
	key, err := auth.LoadKeyFile(keyPath)
	if err != nil {
		return err
	}
	sm, caFP, err := zentrale.NewOwnCA(key, names)
	if err != nil {
		return err
	}
	host := names[0]
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		host = "[" + host + "]"
	}
	data := umstiegData{BaseURL: "https://" + host, Names: names, Cert: sm.Cert, Key: sm.Key, CACert: sm.CACert, CAKey: sm.CAKey}
	payload, _ := json.Marshal(data)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in := &installer{self: self}
	if _, err := in.asUserStdin(ctx, userDB, []string{"intern-https"}, []string{"OPENWACHT_DB_EIGENTUEMER=" + ownerDSN(*socket)}, payload); err != nil {
		return fmt.Errorf("Datenbank: %w", err)
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	nu, removed := stripLegacyArgs(string(b))
	if len(removed) > 0 {
		if _, err := writeNew(envPath+".vor-umstieg", b, 0, 0, 0o640); err != nil {
			return err
		}
		if _, err := rewrite(envPath, nu); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Adresse %s und eigene OpenWacht-Wurzel für %s angelegt.\n", data.BaseURL, strings.Join(names, ", "))
	if len(removed) > 0 {
		fmt.Fprintf(out, "Aus %s entfernt: %s (alte Fassung: %s.vor-umstieg).\n", envPath, strings.Join(removed, " "), envPath)
	}
	fmt.Fprintf(out, "\nFingerabdruck der Wurzel (SHA-256), auf PC und Handy vergleichen:\n\n    %s\n", caFP)
	fmt.Fprintln(out, "\n"+switchHint+"\n\nWurzel laden: "+data.BaseURL+"/openwacht-wurzel.crt")
	return nil
}

// switchHint: Reihenfolge nach dem Umstieg. systemd startet einen Socket nicht,
// solange sein Dienst schon läuft („Socket service … already active,
// refusing“, in einer Testinstallation am 22.11.2026 passiert); deshalb erst anhalten.
const switchHint = "Jetzt Port 443 vom Reverse Proxy lösen (z. B. den 443-Block aus /etc/caddy/Caddyfile nehmen und\n" +
	"systemctl restart caddy), dann in dieser Reihenfolge:\n\n" +
	"    systemctl stop openwacht-zentrale\n" +
	"    systemctl enable --now openwacht-zentrale.socket\n" +
	"    systemctl start openwacht-zentrale"

// cmdInternHTTPS läuft als svc_openwacht_db: schreibt Adresse und Zertifikat
// (JSON auf stdin, Schlüssel schon verschlüsselt).
func cmdInternHTTPS(ctx context.Context, stdin io.Reader) error {
	var d umstiegData
	if err := json.NewDecoder(io.LimitReader(stdin, 1<<20)).Decode(&d); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE openwacht.settings SET base_url = $1, names = $2`, d.BaseURL, d.Names); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names)
			VALUES ('eigene-ca', $1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, cert_pem = EXCLUDED.cert_pem,
			key_enc = EXCLUDED.key_enc, ca_cert_pem = EXCLUDED.ca_cert_pem, ca_key_enc = EXCLUDED.ca_key_enc, names = EXCLUDED.names,
			updated_at = now()`, d.Cert, d.Key, d.CACert, d.CAKey, d.Names); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details)
			VALUES (NULL, 'https.geaendert', jsonb_build_object('art', 'eigene-ca', 'namen', to_jsonb($1::text[]), 'umstieg', true))`, d.Names)
		return err
	})
}
