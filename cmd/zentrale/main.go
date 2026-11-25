// SPDX-License-Identifier: AGPL-3.0-only

// Befehl openwacht-zentrale: die Zentrale mit API, Web-Oberfläche, aktiven
// Checks und Alarmierung.
//
//	openwacht-zentrale installieren Zentrale einrichten oder aktualisieren (root)
//	openwacht-zentrale einrichtungslink  Link für den Einrichtungsassistenten
//	openwacht-zentrale sichern      Datenbank sichern (Timer)
//	openwacht-zentrale migrieren    Datenbankschema anlegen oder aktualisieren
//	openwacht-zentrale einrichten   Hauptmandant und ersten Admin anlegen
//	openwacht-zentrale schluessel   neuen Hauptschlüssel ausgeben
//	openwacht-zentrale starten      Server starten
//	openwacht-zentrale traps        Trap-Dienst (eigener Dienst, Port 162 von systemd)
//	openwacht-zentrale trapschluessel  Trap-Schlüssel aus dem Hauptschlüssel ableiten
//	openwacht-zentrale -version
//
// Zugangsdaten zur Datenbank kommen nur aus Umgebungsvariablen, nie aus
// Kommandozeilenargumenten (die wären in der Prozessliste sichtbar):
//
//	OPENWACHT_DB_EIGENTUEMER  Verbindung der Eigentümer-Rolle (migrieren, einrichten)
//	OPENWACHT_DB              Verbindung der Anwendungsrolle (starten) bzw. der Trap-Rolle (traps)
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/traps"
	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

const programName = "openwacht-zentrale"

const usage = `Aufruf: openwacht-zentrale <befehl> [optionen]

Befehle:
  installieren Zentrale einrichten oder aktualisieren (root, mehrfach ausführbar; ruft das Debian-Paket auf)
  einrichtungslink  neuen Link für den Einrichtungsassistenten im Browser ausgeben (root)
  https-umstieg  ältere Installation (Reverse Proxy) auf HTTPS der Zentrale umstellen (root, -adressen)
  wiederherstellen  Datenbank aus einer Sicherung zurückholen (root; -datei, -ersetzen)
  sichern      Datenbank sichern, wenn fällig (Timer; -jetzt sofort; OPENWACHT_DB_EIGENTUEMER)
  migrieren    Datenbankschema anlegen oder aktualisieren (OPENWACHT_DB_EIGENTUEMER)
  einrichten   Hauptmandant und ersten Admin anlegen (OPENWACHT_DB_EIGENTUEMER),
               Passwort am Terminal verdeckt (zweimal), sonst eine Zeile von der Standardeingabe
  schluessel   neuen Hauptschlüssel ausgeben (in eine Datei mit Rechten 0600 schreiben)
  schluessel-wechseln  alle Geheimnisse mit einem neuen Hauptschlüssel neu verschlüsseln
               (root, Zentrale und Trap-Dienst gestoppt; -neu, -nur-pruefen; OPENWACHT_DB_EIGENTUEMER)
  starten      Server starten (OPENWACHT_DB)
  traps        Trap-Dienst starten (OPENWACHT_DB mit der Trap-Rolle; Socket von systemd)
  trapschluessel  Trap-Schlüssel aus dem Hauptschlüssel ableiten und ausgeben
  betreiber    Betreiber festlegen, entziehen oder anzeigen (Seite Einstellungen; OPENWACHT_DB_EIGENTUEMER)
  entsperren   Sperren nach Fehlversuchen für ein Konto aufheben (-email; OPENWACHT_DB_EIGENTUEMER)
  zweifaktor-zuruecksetzen  Zwei-Faktor-Anmeldung eines Kontos zurücksetzen, z. B. bei verlorenem
               Gerät ohne Wiederherstellungscode (-email; OPENWACHT_DB_EIGENTUEMER)
  passwort-setzen  neues Passwort für ein lokales Konto setzen, z. B. wenn das einzige Admin-Passwort
               verloren ist (-email; OPENWACHT_DB_EIGENTUEMER); beendet alle Sitzungen
  pruefe-signatur  Signatur von SHA256SUMS eines Pakets prüfen (-summen; -abdruck)
  update-installieren  Update aus der Oberfläche installieren (root, über openwacht-zentrale-update.service)
  agent-ca     Agent-CA anzeigen oder wechseln (-neu, -umstellen, -alte-entfernen; OPENWACHT_DB_EIGENTUEMER)
  audit-pruefen  Hash-Kette des Audit-Logs prüfen, auf Wunsch gegen einen Export
               (-datei audit.jsonl; OPENWACHT_DB_EIGENTUEMER)

  -version     Version anzeigen

Hilfe zu einem Befehl: openwacht-zentrale <befehl> -h
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "-version", "--version", "version":
		fmt.Fprintln(stdout, version.String(programName))
		return 0
	case "migrieren":
		err = cmdMigrate(ctx, args[1:], stdout)
	case "einrichten":
		err = cmdSetup(ctx, args[1:], stdin, stdout)
	case "schluessel":
		err = cmdKey(stdout)
	case "starten":
		err = cmdServe(ctx, args[1:])
	case "traps":
		err = cmdTraps(ctx, args[1:])
	case "trapschluessel":
		err = cmdTrapKey(args[1:], stdout)
	case "betreiber":
		err = cmdOperator(ctx, args[1:], stdout)
	case "entsperren":
		err = cmdUnlock(ctx, args[1:], stdout)
	case "audit-pruefen":
		err = cmdAuditCheck(ctx, args[1:], stdout)
	case "zweifaktor-zuruecksetzen":
		err = cmd2FAReset(ctx, args[1:], stdout)
	case "passwort-setzen":
		err = cmdPasswordSet(ctx, args[1:], stdin, stdout)
	case "installieren":
		err = cmdInstall(ctx, args[1:], stdout)
	case "einrichtungslink":
		err = cmdSetupLink(ctx, args[1:], stdout)
	case "sichern":
		err = cmdBackup(ctx, args[1:], stdout)
	case "intern-postgres":
		err = cmdInternPostgres(ctx, args[1:], stdout)
	case "wiederherstellen":
		err = cmdRestore(ctx, args[1:], stdout)
	case "schluessel-wechseln":
		err = cmdRekey(ctx, args[1:], stdout)
	case "update-installieren":
		err = cmdZentraleUpdate(ctx, args[1:], stdout)
	case "pruefe-signatur":
		err = cmdVerifySums(args[1:], stdout)
	case "agent-ca":
		err = cmdAgentCA(ctx, args[1:], stdout)
	case "https-umstieg":
		err = cmdHTTPSSwitch(ctx, args[1:], stdout)
	case "intern-https":
		err = cmdInternHTTPS(ctx, stdin)
	case "intern-einrichtung":
		err = cmdInternSetup(ctx, args[1:], stdout)
	case "-h", "--help", "hilfe":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "Unbekannter Befehl %q.\n\n%s", args[0], usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if errors.Is(err, update.ErrNoKey) {
		fmt.Fprintln(stderr, "Fehler:", err)
		return exitNoKey
	}
	if errors.Is(err, errRestart) {
		fmt.Fprintln(stderr, "Neustart angefordert (systemd startet die Zentrale wieder).")
		return 75
	}
	if err != nil {
		fmt.Fprintln(stderr, "Fehler:", err)
		return 1
	}
	return 0
}

func connectEnv(ctx context.Context, env string) (*pgx.Conn, error) {
	dsn := os.Getenv(env)
	if dsn == "" {
		return nil, fmt.Errorf("Umgebungsvariable %s ist nicht gesetzt", env)
	}
	return pgx.Connect(ctx, dsn)
}

func cmdMigrate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("migrieren", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	n, err := db.Migrate(ctx, conn)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%d Migration(en) angewendet.\n", n)
	return nil
}

// cmdOperator vergibt oder entzieht das Kennzeichen „Betreiber“. Nur auf der
// Shell (als Eigentümer der Datenbank), nie über die Oberfläche: Wer ein
// Admin-Konto übernimmt, soll damit nicht die Netzfreigabe ändern können.
func cmdOperator(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("betreiber", flag.ContinueOnError)
	email := fs.String("email", "", "E-Mail-Adresse des Benutzers (Hauptmandant)")
	revoke := fs.Bool("entziehen", false, "Kennzeichen entziehen statt vergeben")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if *email == "" {
		rows, err := conn.Query(ctx, `SELECT u.email, u.totp_enabled, u.disabled FROM openwacht.users u
			WHERE u.platform_operator ORDER BY lower(u.email)`)
		if err != nil {
			return err
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var e string
			var totp, disabled bool
			if err := rows.Scan(&e, &totp, &disabled); err != nil {
				return err
			}
			note := ""
			if !totp {
				note = " (unwirksam: ohne Zwei-Faktor-Anmeldung)"
			}
			if disabled {
				note = " (unwirksam: deaktiviert)"
			}
			fmt.Fprintf(out, "%s%s\n", e, note)
			n++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if n == 0 {
			fmt.Fprintln(out, "Kein Betreiber. Festlegen mit: openwacht-zentrale betreiber -email <adresse>")
		}
		return nil
	}
	var totp bool
	err = conn.QueryRow(ctx, `UPDATE openwacht.users SET platform_operator = $2 WHERE lower(email) = lower($1)
		RETURNING totp_enabled`, strings.TrimSpace(*email), !*revoke).Scan(&totp)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("kein Benutzer mit der E-Mail-Adresse %q", *email)
	}
	if err != nil {
		return err
	}
	if *revoke {
		fmt.Fprintf(out, "%s ist kein Betreiber mehr.\n", *email)
		return nil
	}
	fmt.Fprintf(out, "%s ist Betreiber.\n", *email)
	if !totp {
		fmt.Fprintln(out, "Hinweis: Wirksam erst mit eingerichteter Zwei-Faktor-Anmeldung.")
	}
	return nil
}

// cmdUnlock hebt die Sperren eines Kontos nach Fehlversuchen auf (Etappe 30).
// Nur auf der Shell als Eigentümer der Datenbank, mit Audit-Eintrag.
func cmdUnlock(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("entsperren", flag.ContinueOnError)
	email := fs.String("email", "", "E-Mail-Adresse des Kontos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*email) == "" {
		return errors.New("-email ist Pflicht")
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var n *int
	if err := conn.QueryRow(ctx, `SELECT openwacht.auth_unlock($1)`, *email).Scan(&n); err != nil {
		return err
	}
	if n == nil {
		return fmt.Errorf("kein Benutzer mit der E-Mail-Adresse %q", *email)
	}
	fmt.Fprintf(out, "%s entsperrt (%d gesperrte Quelle(n) aufgehoben, Wartezeit zurückgesetzt).\n", *email, *n)
	return nil
}

// cmdPasswordSet setzt das Passwort eines lokalen Kontos neu (Notfall, nur
// auf der Shell als Eigentümer der Datenbank). Die Zwei-Faktor-Anmeldung
// bleibt; Sitzungen enden, Sperren nach Fehlversuchen werden aufgehoben.
func cmdPasswordSet(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("passwort-setzen", flag.ContinueOnError)
	email := fs.String("email", "", "E-Mail-Adresse des lokalen Kontos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*email) == "" {
		return errors.New("-email ist Pflicht")
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return passwordSet(ctx, conn, *email, in, out, auth.DefaultParams)
}

func passwordSet(ctx context.Context, conn *pgx.Conn, email string, in io.Reader, out io.Writer, p auth.Params) error {
	var source *string
	// Erst prüfen, ob es das Konto gibt, dann nach dem Passwort fragen.
	if err := conn.QueryRow(ctx, `SELECT auth_source FROM openwacht.users WHERE email = lower(btrim($1))`, email).
		Scan(&source); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if source == nil {
		return fmt.Errorf("kein Benutzer mit der E-Mail-Adresse %q", email)
	}
	if *source != "lokal" {
		return fmt.Errorf("%s meldet sich über %s an; das Passwort wird dort geändert", email, authSourceName(*source))
	}
	password, err := readPassword(in, out, email)
	if err != nil {
		return err
	}
	if err := auth.ValidateNewPassword(password, email); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, p)
	if err != nil {
		return err
	}
	var res *string
	if err := conn.QueryRow(ctx, `SELECT openwacht.auth_password_set_shell($1, $2)`, email, hash).Scan(&res); err != nil {
		return err
	}
	if res == nil || *res != "lokal" {
		return errors.New("Konto hat sich während der Eingabe geändert; nichts gesetzt")
	}
	fmt.Fprintf(out, "Passwort von %s gesetzt, alle Sitzungen beendet, Sperren aufgehoben. Die Zwei-Faktor-Anmeldung bleibt.\n", email)
	return nil
}

func authSourceName(s string) string {
	switch s {
	case "ldap":
		return "das AD bzw. LDAP"
	case "oidc":
		return "SSO (OIDC)"
	case "token":
		return "ein API-Token (Konto ohne Passwort)"
	}
	return s
}

// cmd2FAReset setzt die Zwei-Faktor-Anmeldung eines Kontos zurück (Etappe 30,
// Entscheidung: nicht in der Oberfläche). Beendet alle Sitzungen des Kontos.
func cmd2FAReset(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("zweifaktor-zuruecksetzen", flag.ContinueOnError)
	email := fs.String("email", "", "E-Mail-Adresse des Kontos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*email) == "" {
		return errors.New("-email ist Pflicht")
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var had *bool
	if err := conn.QueryRow(ctx, `SELECT openwacht.auth_2fa_reset($1)`, *email).Scan(&had); err != nil {
		return err
	}
	if had == nil {
		return fmt.Errorf("kein Benutzer mit der E-Mail-Adresse %q", *email)
	}
	if !*had {
		fmt.Fprintf(out, "%s hatte keine Zwei-Faktor-Anmeldung eingerichtet; ein angefangenes Einrichten ist verworfen.\n", *email)
	} else {
		fmt.Fprintf(out, "Zwei-Faktor-Anmeldung von %s zurückgesetzt, alle Sitzungen beendet.\n", *email)
	}
	fmt.Fprintln(out, "Ist 2FA für das Konto Pflicht, richtet es sie bei der nächsten Anmeldung neu ein. Vorher die Identität der Person prüfen.")
	return nil
}

func cmdSetup(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("einrichten", flag.ContinueOnError)
	tenant := fs.String("mandant", "", "Name des Hauptmandanten, z. B. \"IT\"")
	email := fs.String("email", "", "E-Mail-Adresse des ersten Admins")
	name := fs.String("name", "", "Anzeigename des ersten Admins")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || *email == "" || *name == "" {
		return errors.New("-mandant, -email und -name sind Pflicht")
	}
	// Erst verbinden, dann fragen: Wer das Passwort tippt, soll nicht danach
	// an einer fehlenden Verbindung scheitern.
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	password, err := readPassword(in, out, "den ersten Admin")
	if err != nil {
		return err
	}
	if err := zentrale.Bootstrap(ctx, conn, *tenant, *email, *name, password, auth.DefaultParams); err != nil {
		return err
	}
	fmt.Fprintf(out, "Eingerichtet: Hauptmandant %q, Admin %s.\nBeim ersten Anmelden muss die Zwei-Faktor-Anmeldung eingerichtet werden.\n", *tenant, *email)
	return nil
}

// readPassword liest ein Passwort (für wen: „den ersten Admin“). Am Terminal
// verdeckt und zur Kontrolle zweimal; aus einer Pipe (printf … |) eine Zeile.
func readPassword(in io.Reader, out io.Writer, wer string) (string, error) {
	r := bufio.NewReader(in)
	line := func() (string, error) {
		l, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(l, "\r\n"), nil
	}
	f, isFile := in.(*os.File)
	var restore func()
	terminal := false
	if isFile {
		restore, terminal = echoOff(f)
	}
	if !terminal {
		fmt.Fprintf(out, "Passwort für %s eingeben (eine Zeile, mindestens 12 Zeichen):\n", wer)
		return line()
	}
	defer restore()
	fmt.Fprintf(out, "Passwort für %s (mindestens 12 Zeichen, wird nicht angezeigt): ", wer)
	first, err := line()
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	fmt.Fprint(out, "Passwort wiederholen: ")
	second, err := line()
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("die beiden Eingaben stimmen nicht überein")
	}
	return first, nil
}

func cmdKey(out io.Writer) error {
	k, err := auth.GenerateKeyText()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, k)
	return nil
}

// cmdTrapKey gibt den Trap-Schlüssel aus. Er ist vom Hauptschlüssel
// abgeleitet: Wer ihn hat, kann nur die Trap-Zugangsdaten lesen, nicht den
// Hauptschlüssel zurückrechnen.
func cmdTrapKey(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("trapschluessel", flag.ContinueOnError)
	keyFile := fs.String("schluessel", "", "Datei mit dem Hauptschlüssel (Pflicht)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-schluessel ist Pflicht")
	}
	key, err := auth.LoadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, base64.StdEncoding.EncodeToString(traps.DeriveKey(key)))
	return nil
}

// cmdTraps startet den Trap-Dienst. Den UDP-Socket (Port 162) übergibt
// systemd (openwacht-traps.socket); -adresse nur für Tests ohne systemd.
func cmdTraps(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("traps", flag.ContinueOnError)
	keyFile := fs.String("trap-schluessel", "", "Datei mit dem Trap-Schlüssel (Pflicht, Rechte 0600, siehe trapschluessel)")
	addr := fs.String("adresse", "", "nur ohne systemd: Adresse und Port zum Lauschen, z. B. 127.0.0.1:1162")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-trap-schluessel ist Pflicht")
	}
	key, err := auth.LoadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	conn, fromSystemd, err := traps.ListenSystemd()
	if err != nil {
		return err
	}
	if !fromSystemd {
		if *addr == "" {
			return errors.New("kein Socket von systemd (openwacht-traps.socket); für Tests -adresse angeben")
		}
		if conn, err = net.ListenPacket("udp", *addr); err != nil {
			return err
		}
	} else if *addr != "" {
		return errors.New("-adresse nicht zusammen mit dem Socket von systemd")
	}
	defer conn.Close()
	dsn := os.Getenv("OPENWACHT_DB")
	if dsn == "" {
		return errors.New("Umgebungsvariable OPENWACHT_DB ist nicht gesetzt")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := traps.CheckRole(ctx, pool); err != nil {
		return err
	}
	svc, err := traps.New(ctx, traps.Config{Pool: pool, Key: key, Conn: conn})
	if err != nil {
		return err
	}
	return svc.Run(ctx)
}

// pinnedFlags: Startoptionen, die auch auf der Seite Einstellungen stehen.
var pinnedFlags = map[string]string{"check-netze": "netze", "alarm-ziele": "alarmziele", "totmann-datei": "totmann",
	"stumm-nach": "stumm_nach_s", "platte-warn": "platte_warn", "platte-krit": "platte_krit",
	"speicher-warn": "speicher_warn", "speicher-krit": "speicher_krit", "cpu-warn": "cpu_warn", "cpu-krit": "cpu_krit"}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("starten", flag.ContinueOnError)
	addr := fs.String("adresse", "127.0.0.1:8443", "Adresse und Port (ohne Socket von systemd); Loopback ohne TLS-Dateien = ohne TLS hinter einem Reverse Proxy")
	base := fs.String("basis-url", "", "öffentliche Adresse der Oberfläche, z. B. https://openwacht.example.com (Standard: aus der Einrichtung)")
	keyFile := fs.String("schluessel", "", "Datei mit dem Hauptschlüssel (Pflicht, Rechte 0600)")
	certFile := fs.String("tls-zertifikat", "", "TLS-Zertifikat (PEM); ohne TLS nur auf Loopback hinter einem Reverse Proxy")
	certKey := fs.String("tls-schluessel", "", "privater TLS-Schlüssel (PEM)")
	proxies := fs.String("proxy", "", "vertrauenswürdige Reverse Proxys, kommagetrennt (z. B. 127.0.0.1/32)")
	agentAddr := fs.String("agent-adresse", "", "Adresse des Agent-Ports (TLS 1.3 mit Client-Zertifikaten), z. B. :8444; leer = aus")
	agentNames := fs.String("agent-namen", "", "Hostnamen/IPs, unter denen Agents die Zentrale erreichen, kommagetrennt (Standard: Adressen aus der Einrichtung)")
	checkNets := fs.String("check-netze", "", "Netze, die Sensoren der Zentrale (Ping, Ports, Webseiten) und SNMP-Abfragen erreichen dürfen, kommagetrennt, z. B. 10.10.0.0/16; "+
		"Loopback und Link-Local nur mit einem Eintrag darin (z. B. 127.0.0.1/32); gesetzt = gilt statt der Seite Einstellungen")
	alertTargets := fs.String("alarm-ziele", "", "ntfy-Server, die Mandanten als Alarmziel wählen dürfen, kommagetrennt, "+
		"z. B. https://ntfy.example,http://127.0.0.1:2586 (http nur für Loopback); gesetzt = gilt statt der Seite Einstellungen")
	silentAfter := fs.Duration("stumm-nach", 3*time.Minute, "Alarm, wenn sich ein Agent so lange nicht meldet (mindestens 2m)")
	diskWarn := fs.Float64("platte-warn", 90, "Warnung ab dieser Belegung einer Platte in Prozent; 0 = aus")
	diskCrit := fs.Float64("platte-krit", 95, "kritischer Alarm ab dieser Belegung einer Platte in Prozent; 0 = aus")
	memWarn := fs.Float64("speicher-warn", 90, "Warnung ab dieser Belegung des Arbeitsspeichers in Prozent; 0 = aus")
	memCrit := fs.Float64("speicher-krit", 95, "kritischer Alarm ab dieser Belegung des Arbeitsspeichers in Prozent; 0 = aus")
	cpuWarn := fs.Float64("cpu-warn", 90, "Warnung ab dieser CPU-Auslastung im Mittel über 15 Minuten in Prozent; 0 = aus")
	cpuCrit := fs.Float64("cpu-krit", 98, "kritischer Alarm ab dieser CPU-Auslastung im Mittel über 15 Minuten in Prozent; 0 = aus")
	deadManFile := fs.String("totmann-datei", "", "Datei mit der Ping-Adresse des Totmannschalters (healthchecks.io, Rechte 0600); leer = aus")
	auditFile := fs.String("audit-datei", "", "Audit-Log fortlaufend als JSON-Zeilen in diese Datei schreiben (z. B. /var/log/openwacht/audit.jsonl); leer = aus")
	auditSyslog := fs.String("audit-syslog", "", "Audit-Log fortlaufend per Syslog über TLS (RFC 5425) an host:port senden; das Ziel muss in der Netzfreigabe liegen; leer = aus")
	secContact := fs.String("sicherheitskontakt", "", "Meldeweg für Sicherheitslücken dieser Installation in /.well-known/security.txt, "+
		"kommagetrennt mailto:… oder https://… (vor dem Kontakt des Herstellers)")
	secTxt := fs.Bool("security-txt", true, "/.well-known/security.txt ausliefern (false = aus)")
	auditSyslogCA := fs.String("audit-syslog-ca", "", "CA-Datei (PEM) für das Zertifikat des Syslog-Ziels; leer = Zertifikate des Systems")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secContacts, err := zentrale.ParseSecurityContacts(*secContact)
	if err != nil {
		return fmt.Errorf("-sicherheitskontakt: %w", err)
	}
	var auditSys *zentrale.AuditSyslog
	if *auditSyslog != "" {
		host, port, err := net.SplitHostPort(*auditSyslog)
		if err != nil || host == "" || port == "" {
			return errors.New("-audit-syslog: als host:port angeben, z. B. siem.example.com:6514")
		}
		auditSys = &zentrale.AuditSyslog{Addr: *auditSyslog}
		if *auditSyslogCA != "" {
			if auditSys.CAPEM, err = os.ReadFile(*auditSyslogCA); err != nil {
				return fmt.Errorf("-audit-syslog-ca: %w", err)
			}
		}
	} else if *auditSyslogCA != "" {
		return errors.New("-audit-syslog-ca nur zusammen mit -audit-syslog")
	}
	if *auditFile != "" && !filepath.IsAbs(*auditFile) {
		return errors.New("-audit-datei: absoluten Pfad angeben")
	}
	// In der Konfiguration heißt 0 „Standard“, aus ist negativ.
	off := func(v float64) float64 {
		if v == 0 {
			return -1
		}
		return v
	}
	for name, v := range map[string]float64{"-platte-warn": *diskWarn, "-platte-krit": *diskCrit,
		"-speicher-warn": *memWarn, "-speicher-krit": *memCrit, "-cpu-warn": *cpuWarn, "-cpu-krit": *cpuCrit} {
		if v < 0 || v > 100 {
			return fmt.Errorf("%s: 0 bis 100", name)
		}
	}
	if *keyFile == "" {
		return errors.New("-schluessel ist Pflicht")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	key, err := auth.LoadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	deadManURL := ""
	if *deadManFile != "" {
		if deadManURL, err = zentrale.LoadDeadManFile(*deadManFile); err != nil {
			return fmt.Errorf("-totmann-datei: %w", err)
		}
	}
	var trusted []netip.Prefix
	for _, p := range strings.Split(*proxies, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("-proxy %q: %w", p, err)
		}
		trusted = append(trusted, pre)
	}
	var nets []netip.Prefix
	for _, p := range strings.Split(*checkNets, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("-check-netze %q: %w (Form 10.10.0.0/16)", p, err)
		}
		nets = append(nets, pre.Masked())
	}
	targets, err := alarm.ParseTargets(*alertTargets)
	if err != nil {
		return fmt.Errorf("-alarm-ziele: %w", err)
	}
	// Woher kommt der Socket der Oberfläche, und wer macht TLS?
	//   - Socket von systemd (openwacht-zentrale.socket, Port 443): TLS aus der Datenbank.
	//   - -adresse auf Loopback ohne TLS-Dateien: ohne TLS, hinter einem Reverse Proxy.
	//   - -adresse sonst: TLS aus Dateien, wenn angegeben, sonst aus der Datenbank.
	fileTLS := *certFile != "" || *certKey != ""
	if fileTLS && (*certFile == "" || *certKey == "") {
		return errors.New("-tls-zertifikat und -tls-schluessel nur zusammen")
	}
	ln, fromSystemd, err := listenSystemdTCP()
	if err != nil {
		return err
	}
	if fromSystemd && set["adresse"] {
		ln.Close()
		return errors.New("-adresse nicht zusammen mit dem Socket von systemd (openwacht-zentrale.socket)")
	}
	plain := false
	if !fromSystemd {
		host, _, err := net.SplitHostPort(*addr)
		if err != nil {
			return fmt.Errorf("-adresse: %w", err)
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() && !fileTLS {
			plain = true
		}
		if ln, err = net.Listen("tcp", *addr); err != nil {
			return fmt.Errorf("-adresse: %w", err)
		}
	}
	defer ln.Close()
	queue := newConnQueue(ln)
	dbTLS := !fileTLS && !plain
	listenPort := ""
	if _, p, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		listenPort = p
	}

	dsn := os.Getenv("OPENWACHT_DB")
	if dsn == "" {
		return errors.New("Umgebungsvariable OPENWACHT_DB ist nicht gesetzt")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := zentrale.CheckAppRole(ctx, pool); err != nil {
		return err
	}
	// Einrichtung offen: erst den Assistenten ausliefern, danach im selben
	// Prozess und auf demselben Socket in den Normalbetrieb wechseln.
	open, err := zentrale.SetupOpen(ctx, pool)
	if err != nil {
		return fmt.Errorf("Zustand der Einrichtung: %w (Migrationen gelaufen?)", err)
	}
	if open {
		if err := runSetup(ctx, pool, key, queue, dbTLS, *certFile, *certKey); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	inst, err := zentrale.ReadInstall(ctx, pool)
	if err != nil {
		return err
	}
	if !set["basis-url"] {
		if inst.BaseURL == nil {
			return errors.New("-basis-url fehlt und ist auch nicht eingerichtet")
		}
		*base = *inst.BaseURL
	}
	baseURL, err := url.Parse(*base)
	if err != nil {
		return fmt.Errorf("-basis-url: %w", err)
	}
	if !set["agent-namen"] && len(inst.Names) > 0 {
		*agentNames = strings.Join(inst.Names, ",")
	}
	var httpsStore *zentrale.HTTPS
	var origins []string
	// Neustart aus der Oberfläche (neue Adresse) nur unter systemd, das die
	// Zentrale nach Exit-Code 75 wieder startet (Restart=on-failure).
	restartCh := make(chan struct{}, 1)
	var restartFn func()
	if os.Getenv("INVOCATION_ID") != "" {
		restartFn = func() {
			select {
			case restartCh <- struct{}{}:
			default:
			}
		}
	}
	if dbTLS {
		if httpsStore, err = zentrale.LoadHTTPS(ctx, pool, key); err != nil {
			return err
		}
		for _, n := range inst.Names {
			o := "https://" + hostForURL(n)
			if listenPort != "" && listenPort != "443" {
				o += ":" + listenPort
			}
			origins = append(origins, o)
		}
	}
	var names []string
	for _, n := range strings.Split(*agentNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if *agentAddr != "" && len(names) == 0 {
		return errors.New("-agent-namen ist Pflicht, wenn -agent-adresse gesetzt ist")
	}
	agentURL := ""
	if *agentAddr != "" {
		_, port, err := net.SplitHostPort(*agentAddr)
		if err != nil {
			return fmt.Errorf("-agent-adresse: %w", err)
		}
		agentURL = "https://" + net.JoinHostPort(names[0], port)
	}
	// Gesetzte Startoptionen gewinnen über die Seite Einstellungen (Etappe 19).
	pinned := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		if name, ok := pinnedFlags[f.Name]; ok {
			pinned[name] = true
		}
	})
	if auditSys != nil {
		auditSys.Source = names0(names, baseURL.Hostname())
	}
	srv, err := zentrale.New(zentrale.Config{BaseURL: baseURL, TrustedProxies: trusted, AgentNames: names, AgentURL: agentURL,
		CheckNetworks: nets, AlertTargets: targets, HostSilentAfter: *silentAfter,
		DiskWarn: off(*diskWarn), DiskCrit: off(*diskCrit), MemWarn: off(*memWarn), MemCrit: off(*memCrit),
		CPUWarn: off(*cpuWarn), CPUCrit: off(*cpuCrit), DeadManURL: deadManURL,
		SettingsFromDB: true, Pinned: pinned, HTTPS: httpsStore, Origins: origins, Restart: restartFn,
		AuditFile: *auditFile, AuditSyslog: auditSys, SecurityContacts: secContacts, SecurityTxtOff: !*secTxt,
		ZentraleUpdateDir: zentraleUpdateAblage()}, pool, key)
	if err != nil {
		return err
	}
	if n, err := srv.ImportStartOptions(ctx); err != nil {
		return fmt.Errorf("Startoptionen übernehmen: %w", err)
	} else if n > 0 {
		slog.Info("Startoptionen in die Einstellungen übernommen; solange sie in der Unit stehen, gelten sie", "felder", n)
	}
	if err := srv.ReloadSettings(ctx); err != nil {
		return fmt.Errorf("Einstellungen laden: %w", err)
	}
	if err := srv.InitAgentCA(ctx); err != nil {
		return err
	}
	slog.Info("Agent-CA bereit", "fingerabdruck", srv.AgentCAFingerprint())

	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 2)
	var as *http.Server
	if *agentAddr != "" {
		ln, err := tls.Listen("tcp", *agentAddr, srv.AgentTLSConfig())
		if err != nil {
			return fmt.Errorf("Agent-Port: %w", err)
		}
		as = &http.Server{
			Handler:           srv.AgentHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
		}
		go func() {
			slog.Info("Agent-Port gestartet", "adresse", *agentAddr, "namen", names)
			errc <- as.Serve(ln)
		}()
	}
	go func() {
		mode := "ohne TLS (Reverse Proxy)"
		switch {
		case fileTLS:
			mode = "TLS aus Dateien"
		case dbTLS:
			mode = "HTTPS der Zentrale"
		}
		slog.Info("Zentrale gestartet", "version", version.Version, "adresse", ln.Addr().String(), "tls", mode, "systemd", fromSystemd)
		mainLn := queue.listener()
		switch {
		case fileTLS:
			errc <- hs.ServeTLS(mainLn, *certFile, *certKey)
		case dbTLS:
			// ServeTLS mit GetCertificate (keine Dateien), damit HTTP/2 mitläuft.
			hs.TLSConfig = httpsStore.TLSConfig()
			errc <- hs.ServeTLS(mainLn, "", "")
		default:
			errc <- hs.Serve(mainLn)
		}
	}()
	if httpsStore != nil {
		go httpsStore.RunRenewal(ctx)
	}
	go srv.RunDirectorySync(ctx)
	go srv.RunReports(ctx)
	checksCtx, stopChecks := context.WithCancel(ctx)
	checksDone := make(chan struct{})
	go func() {
		defer close(checksDone)
		if n := srv.CheckNetworks(); len(n) == 0 {
			slog.Warn("Checks: keine Netze freigegeben (Einstellungen bzw. -check-netze); alle Checks melden „nicht freigegeben“")
		} else {
			slog.Info("Checks gestartet", "netze", n)
		}
		srv.RunChecks(checksCtx)
	}()
	defer func() { stopChecks(); <-checksDone }()
	alertsDone := make(chan struct{})
	go func() {
		defer close(alertsDone)
		if t := srv.AlertTargetList(); len(t) == 0 {
			// Mail geht über das Relay und braucht kein Alarmziel.
			slog.Warn("Alarme: keine Alarmziele freigegeben (Einstellungen bzw. -alarm-ziele); Mail geht, ntfy, Webhook, Teams und SMS sind gesperrt")
		} else {
			slog.Info("Alarme gestartet", "ziele", t)
		}
		if !srv.DeadManOn() {
			slog.Warn("Totmannschalter aus (Einstellungen bzw. -totmann-datei): Fällt die Zentrale aus, merkt das niemand")
		} else {
			slog.Info("Totmannschalter an")
		}
		srv.RunAlerts(checksCtx)
	}()
	defer func() { stopChecks(); <-alertsDone }()
	snmpDone := make(chan struct{})
	go func() {
		defer close(snmpDone)
		srv.RunSNMP(checksCtx)
	}()
	defer func() { stopChecks(); <-snmpDone }()
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		srv.RunMetrics(checksCtx)
	}()
	defer func() { stopChecks(); <-metricsDone }()
	// Etappe 31: Audit (Prüfung, Export, Aufbewahrung) und Selbstüberwachung
	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		if *auditFile != "" || auditSys != nil {
			slog.Info("Audit-Export an", "datei", *auditFile, "syslog", *auditSyslog)
		}
		srv.RunAudit(checksCtx)
	}()
	defer func() { stopChecks(); <-auditDone }()
	go srv.RunSelfWatch(checksCtx)

	restarting := false
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	case <-restartCh:
		restarting = true
	}
	slog.Info("Zentrale wird beendet", "neustart", restarting)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if as != nil {
		as.Shutdown(shutdownCtx)
	}
	if err := hs.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if restarting {
		return errRestart
	}
	return nil
}

// connQueue: Der Assistent und danach die Zentrale benutzen denselben
// Socket (von systemd). Eine Schleife nimmt Verbindungen an und verteilt sie
// an den jeweils aktiven Server; dessen Close beendet nur sein Accept, nicht
// den Socket.
type connQueue struct {
	ln   net.Listener
	ch   chan net.Conn
	errc chan error
}

func newConnQueue(ln net.Listener) *connQueue {
	q := &connQueue{ln: ln, ch: make(chan net.Conn), errc: make(chan error, 1)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				q.errc <- err
				return
			}
			q.ch <- c
		}
	}()
	return q
}

// listener liefert einen Listener für einen Server; Close beendet nur ihn.
func (q *connQueue) listener() net.Listener {
	return &queueListener{q: q, done: make(chan struct{})}
}

type queueListener struct {
	q    *connQueue
	done chan struct{}
	once sync.Once
}

func (l *queueListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.q.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case err := <-l.q.errc:
		l.q.errc <- err
		return nil, err
	}
}

func (l *queueListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *queueListener) Addr() net.Addr { return l.q.ln.Addr() }

// runSetup liefert den Einrichtungsassistenten aus, bis er abgeschlossen ist.
func runSetup(ctx context.Context, pool *pgxpool.Pool, key []byte, q *connQueue, dbTLS bool, certFile, certKey string) error {
	ln := q.listener()
	setup, err := zentrale.NewSetup(pool, key, nil)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           setup.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	switch {
	case dbTLS:
		if err := zentrale.EnsureSetupCert(ctx, pool, key, zentrale.HostNames()); err != nil {
			return fmt.Errorf("vorläufiges Zertifikat: %w", err)
		}
		h, err := zentrale.LoadHTTPS(ctx, pool, key)
		if err != nil {
			return err
		}
		hs.TLSConfig = h.TLSConfig()
		go func() { errc <- hs.ServeTLS(ln, "", "") }()
	case certFile != "":
		go func() { errc <- hs.ServeTLS(ln, certFile, certKey) }()
	default:
		go func() { errc <- hs.Serve(ln) }()
	}
	slog.Info("Einrichtung offen: nur der Assistent ist erreichbar (Link aus `installieren` bzw. `einrichtungslink`)",
		"adresse", ln.Addr().String())
	select {
	case <-setup.Done():
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// listenSystemdTCP übernimmt den Socket von openwacht-zentrale.socket.
func listenSystemdTCP() (net.Listener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	if n := os.Getenv("LISTEN_FDS"); n != "1" {
		return nil, false, fmt.Errorf("systemd übergibt %q Sockets, erwartet genau einen (openwacht-zentrale.socket)", n)
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	f := os.NewFile(3, "openwacht-zentrale.socket")
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, false, fmt.Errorf("Socket von systemd: %w", err)
	}
	return ln, true, nil
}

// hostForURL setzt IPv6-Adressen in eckige Klammern.
func hostForURL(n string) string {
	if a, err := netip.ParseAddr(n); err == nil && a.Is6() {
		return "[" + n + "]"
	}
	return n
}

// errRestart: Die Zentrale beendet sich für einen Neustart durch systemd.
var errRestart = errors.New("Neustart angefordert")

// names0: erster Name der Zentrale (für den Syslog-Kopf).
func names0(names []string, fallback string) string {
	if len(names) > 0 {
		return names[0]
	}
	return fallback
}
