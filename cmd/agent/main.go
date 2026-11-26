// SPDX-License-Identifier: AGPL-3.0-only

// Befehl openwacht-agent: läuft auf den überwachten Rechnern und sendet
// Messwerte an die Zentrale.
//
// Grundregel (Leitprinzip 1): Der Agent sendet nur. Er nimmt von der Zentrale
// keine Befehle entgegen und öffnet keinen Port.
//
//	openwacht-agent registrieren -zentrale https://host:8444 -token owa1.…
//	openwacht-agent starten
//	openwacht-agent pruefen
//	openwacht-agent sammler -netze 10.20.0.0/16
//	openwacht-agent sensoren -arten dienst,prozess,datei -ordner /var/backups
//	openwacht-agent sensoren -arten dienst,leistungsindikator -indikatoren "SwyxServer,Swyx Trunk"
//	openwacht-agent -version
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/garrulus-it/openwacht/internal/agent"
	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
)

const programName = "openwacht-agent"

const usage = `Aufruf: openwacht-agent <befehl> [optionen]

Befehle:
  registrieren  bei der Zentrale anmelden (Token aus der Oberfläche);
                als root (Linux) bzw. Administrator (Windows) wird dabei
                auch der Dienst eingerichtet
  starten       Messwerte regelmäßig senden (läuft normalerweise als Dienst)
  pruefen       Messwerte einmal sammeln und anzeigen, ohne zu senden
  sammler       diesen Agent als Sammler für SNMP-Geräte in den angegebenen
                Netzen freigeben (-netze), zurücknehmen (-aus) oder anzeigen
  sensoren      Sensoren auf diesem Rechner freigeben (-arten, -ordner),
                zurücknehmen (-aus) oder anzeigen
  updates-einrichten
                Installationsdienst für signierte Updates nachrüsten (bei
                Agents, die vor 0.23 registriert wurden; root/Administrator)
  update-installieren
                bereitgelegtes, signiertes Update installieren (läuft als
                Dienst bzw. geplante Aufgabe, nicht von Hand nötig)
  paket-einrichten
                nach der Installation aus .deb, .rpm oder MSI: Dienst
                einrichten und, mit Token, registrieren (ruft der
                Paketmanager auf)
  paket-entfernen
                vor dem Entfernen des MSI: Dienst und geplante Aufgabe
                entfernen (ruft Windows Installer auf)

  -version      Version anzeigen

Hilfe zu einem Befehl: openwacht-agent <befehl> -h
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
	case "registrieren":
		err = cmdRegister(ctx, args[1:], stdin, stdout)
	case "starten":
		err = cmdRun(ctx, args[1:])
	case "pruefen":
		err = cmdCheck(stdout)
	case "sammler":
		err = cmdCollector(args[1:], stdout)
	case "sensoren":
		err = cmdSensors(args[1:], stdout)
	case "updates-einrichten":
		err = cmdUpdatesSetup(args[1:], stdout)
	case "update-installieren":
		err = cmdUpdateInstall(args[1:], stdout)
	case "paket-einrichten":
		err = cmdPackageSetup(ctx, args[1:], stdin, stdout)
	case "paket-entfernen":
		err = cmdPackageRemove(args[1:], stdout)
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
	if err != nil {
		fmt.Fprintln(stderr, "Fehler:", err)
		return 1
	}
	return 0
}

func cmdRegister(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("registrieren", flag.ContinueOnError)
	zentrale := fs.String("zentrale", "", "Adresse des Agent-Ports der Zentrale, z. B. https://openwacht.example:8444")
	token := fs.String("token", "", "Registrierungs-Token aus der Oberfläche; \"-\" liest es von der Standardeingabe")
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis für Schlüssel, Zertifikat und Einstellungen")
	hostname := fs.String("hostname", "", "Name, unter dem der Rechner erscheint (Standard: Hostname des Systems)")
	replace := fs.Bool("neu", false, "bestehende Registrierung ersetzen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *zentrale == "" || *token == "" {
		return errors.New("-zentrale und -token sind Pflicht")
	}
	// Der Dienst startet in einem anderen Arbeitsverzeichnis.
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	*dir = abs
	if *token == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		*token = strings.TrimSpace(line)
	}
	if *hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		*hostname = strings.ToLower(h)
	}

	var finish func(string) error
	finish, err = prepareService(out)
	if err != nil {
		return err
	}

	regCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	id, err := agent.Register(regCtx, *dir, *zentrale, *token, *hostname, *replace)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Registriert als %q (Agent-ID %s).\n", *hostname, id)
	if finish == nil {
		fmt.Fprintf(out, noServiceHint, *dir)
		return nil
	}
	return finish(*dir)
}

// executable: Pfad des laufenden Programms, Verknüpfungen aufgelöst. Geprüft
// und in den Dienst eingetragen wird derselbe Pfad.
func executable() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(bin)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("starten", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis aus der Registrierung")
	if err := fs.Parse(args); err != nil {
		return err
	}
	work := func(ctx context.Context) error {
		c := agent.NewCollector()
		r, err := agent.NewRunner(*dir, c.Collect)
		if err != nil {
			return err
		}
		slog.Info("Agent gestartet", "version", version.Version, "agent", r.AgentID(), "zertifikat_bis", r.CertNotAfter())
		r.Run(ctx)
		slog.Info("Agent beendet")
		return nil
	}
	if handled, err := runAsService(work); handled {
		return err
	}
	return work(ctx)
}

func cmdCheck(out io.Writer) error {
	snap, err := agent.NewCollector().Collect()
	if err != nil {
		return err
	}
	if err := snap.Validate(time.Now()); err != nil {
		return fmt.Errorf("die Zentrale würde diese Messwerte ablehnen: %w", err)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

// cmdCollector: lokale Freigabe als Sammler (Etappe 15). Nur hier, auf dem
// Rechner selbst, lässt sich der Sammler einschalten; die Zentrale kann das
// nicht. Der Dienst liest die Datei bei jedem Meldezyklus, ein Neustart ist
// nicht nötig.
func cmdCollector(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sammler", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis aus der Registrierung")
	nets := fs.String("netze", "", "Netze, in denen der Agent SNMP-Geräte abfragen darf, kommagetrennt, z. B. 10.20.0.0/16")
	off := fs.Bool("aus", false, "Freigabe zurücknehmen; Geräteliste und Zugangsdaten verwirft der Dienst beim nächsten Meldezyklus")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unerwartetes Argument %q", fs.Arg(0))
	}
	switch {
	case *off && *nets != "":
		return errors.New("-aus und -netze schließen sich aus")
	case *off:
		if err := agent.RemoveCollectorConfig(*dir); err != nil {
			return err
		}
		fmt.Fprintln(out, "Sammler ausgeschaltet. Der Dienst verwirft Geräteliste und Zugangsdaten beim nächsten Meldezyklus (bis 1 Minute).")
		return nil
	case *nets != "":
		var list []string
		for _, n := range strings.Split(*nets, ",") {
			if n = strings.TrimSpace(n); n != "" {
				list = append(list, n)
			}
		}
		parsed, err := agent.WriteCollectorConfig(*dir, list)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Sammler freigegeben für: %s\n", joinPrefixes(parsed))
		fmt.Fprintln(out, "Der Dienst meldet das beim nächsten Meldezyklus (bis 1 Minute). Danach in der Oberfläche beim Gerät unter SNMP „Abgefragt von“ diesen Agent wählen.")
		return nil
	}
	parsed, err := agent.ReadCollectorConfig(*dir)
	if err != nil {
		return err
	}
	if parsed == nil {
		fmt.Fprintln(out, "Sammler: aus (freigeben mit: openwacht-agent sammler -netze <Netz>)")
		return nil
	}
	fmt.Fprintf(out, "Sammler: an, Netze %s\n", joinPrefixes(parsed))
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// cmdSensors: lokale Freigabe für Sensoren auf dem Agent (Etappe 18). Nur
// hier, auf dem Rechner selbst, lassen sich Arten und Ordner freigeben; die
// Zentrale kann das nicht. Der Dienst liest die Datei bei jedem Durchlauf.
func cmdSensors(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sensoren", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis aus der Registrierung")
	kinds := fs.String("arten", "", "freigegebene Arten, kommagetrennt: dienst, prozess, datei, docker, hyperv, leistungsindikator, autodienste (die letzten drei nur Windows)")
	folders := fs.String("ordner", "", "Ordner, unter denen Datei-Sensoren messen dürfen, kommagetrennt (absolute Pfade)")
	counters := fs.String("indikatoren", "", "Objekte der Leistungsindikatoren, kommagetrennt, z. B. \"SwyxServer,Swyx Trunk,APP_POOL_WAS\" (für die Art leistungsindikator)")
	docker := fs.String("docker", "", "Adresse des lokalen, nur-lesenden Docker-Socket-Proxys, z. B. http://127.0.0.1:2375 (für die Art docker)")
	off := fs.Bool("aus", false, "Freigabe zurücknehmen; der Dienst meldet seine Sensoren dann als „nicht freigegeben“")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unerwartetes Argument %q", fs.Arg(0))
	}
	procHint := func(on bool) error {
		changed, err := agent.SetProcVisible(on)
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintln(out, "Unit-Ergänzung für den Prozess-Sensor geändert (ProtectProc). Wirksam nach: systemctl restart openwacht-agent")
		}
		return nil
	}
	switch {
	case *off && (*kinds != "" || *folders != "" || *docker != "" || *counters != ""):
		return errors.New("-aus und -arten/-ordner/-docker/-indikatoren schließen sich aus")
	case *off:
		if err := agent.RemoveSensorConfig(*dir); err != nil {
			return err
		}
		fmt.Fprintln(out, "Sensoren ausgeschaltet. Der Dienst meldet seine Sensoren ab dem nächsten Durchlauf als „nicht freigegeben“.")
		if agent.IsRoot() {
			return procHint(false)
		}
		return nil
	case *kinds != "":
		k := splitList(*kinds)
		rel, err := agent.WriteSensorRelease(*dir, &agentproto.SensorRelease{Kinds: k, Folders: splitList(*folders),
			Docker: strings.TrimSpace(*docker), Counters: splitList(*counters)})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Sensoren freigegeben: %s\n", strings.Join(rel.Kinds, ", "))
		for _, f := range rel.Folders {
			if fi, err := os.Stat(f); err != nil || !fi.IsDir() {
				fmt.Fprintf(out, "Hinweis: Ordner %s gibt es (noch) nicht.\n", f)
			} else {
				fmt.Fprintf(out, "Ordner: %s\n", f)
			}
		}
		if rel.Docker != "" {
			fmt.Fprintf(out, "Docker über den Socket-Proxy %s (nur lesend; den Docker-Socket selbst öffnet der Agent nie)\n", rel.Docker)
		}
		if len(rel.Counters) > 0 {
			fmt.Fprintf(out, "Leistungsindikatoren aus den Objekten: %s (nur lesend, englische Namen)\n", strings.Join(rel.Counters, ", "))
			if runtime.GOOS != "windows" {
				fmt.Fprintln(out, "Hinweis: Leistungsindikatoren gibt es nur unter Windows.")
			}
		}
		if agent.IsRoot() {
			if err := procHint(slices.Contains(rel.Kinds, "prozess")); err != nil {
				return err
			}
		} else if slices.Contains(rel.Kinds, "prozess") && runtime.GOOS == "linux" {
			fmt.Fprintln(out, "Hinweis: Ohne root bleibt ProtectProc unverändert; der Prozess-Sensor sieht dann nur eigene Prozesse.")
		}
		fmt.Fprintln(out, "Der Dienst übernimmt das beim nächsten Durchlauf (bis 1 Minute). Sensoren legst du in der Oberfläche am Gerät an (Reiter „Sensoren“).")
		return nil
	case *folders != "" || *docker != "" || *counters != "":
		return errors.New("-ordner, -docker und -indikatoren nur zusammen mit -arten (mit datei, docker bzw. leistungsindikator)")
	}
	rel, err := agent.ReadSensorConfig(*dir)
	if err != nil {
		return err
	}
	if rel == nil {
		fmt.Fprintln(out, "Sensoren: aus (freigeben mit: openwacht-agent sensoren -arten dienst,prozess,datei -ordner <Ordner>)")
		return nil
	}
	fmt.Fprintf(out, "Sensoren: an, Arten %s\n", strings.Join(rel.Kinds, ", "))
	if len(rel.Folders) > 0 {
		fmt.Fprintf(out, "Ordner: %s\n", strings.Join(rel.Folders, ", "))
	}
	if rel.Docker != "" {
		fmt.Fprintf(out, "Docker-Socket-Proxy: %s\n", rel.Docker)
	}
	if len(rel.Counters) > 0 {
		fmt.Fprintf(out, "Leistungsindikatoren: %s\n", strings.Join(rel.Counters, ", "))
	}
	return nil
}

func joinPrefixes[T fmt.Stringer](list []T) string {
	s := make([]string, len(list))
	for i, p := range list {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func cmdUpdatesSetup(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("updates-einrichten", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis aus der Registrierung")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !agent.IsRoot() {
		return errors.New("bitte als root bzw. Administrator ausführen")
	}
	bin, err := executable()
	if err != nil {
		return err
	}
	if err := agent.CheckBinary(bin); err != nil {
		return err
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if err := agent.InstallUpdateUnits(bin, abs); err != nil {
		return err
	}
	if _, err := update.Keys(); err != nil {
		fmt.Fprintln(out, "Hinweis: Dieses Binary enthält keinen Update-Schlüssel; Updates bleiben aus, bis ein signierter Build installiert ist.")
	}
	fmt.Fprintln(out, "Installationsdienst für signierte Updates eingerichtet. Freigabe je Gerät in der Oberfläche (Verwaltung › Agent-Updates).")
	return nil
}

func cmdUpdateInstall(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("update-installieren", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis aus der Registrierung")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !agent.IsRoot() {
		return errors.New("bitte als root bzw. Administrator ausführen")
	}
	bin, err := executable()
	if err != nil {
		return err
	}
	key, _ := update.Keys()
	in := agent.Installer{Dir: *dir, Key: key, Current: version.Version, Exe: bin,
		Replace: agent.ReplaceBinary, Restart: agent.RestartService}
	err = in.Run()
	if errors.Is(err, agent.ErrNothing) {
		return nil
	}
	if err == nil {
		fmt.Fprintln(out, "Update installiert, Dienst startet neu.")
	}
	return err
}

// Umgebungsvariablen für die Registrierung bei der Paket-Installation
// (z. B. „sudo OPENWACHT_ZENTRALE=… OPENWACHT_TOKEN=… apt install ./…deb“).
// Ein Token in der Umgebung sieht nur root; es ist kurzlebig und begrenzt.
const (
	envZentrale = "OPENWACHT_ZENTRALE"
	envToken    = "OPENWACHT_TOKEN"
	envHostname = "OPENWACHT_HOSTNAME"
)

// packageOptions: Angaben für paket-einrichten.
type packageOptions struct {
	dir, zentrale, token, hostname string
	// Freigaben aus dem Assistenten des MSI (1.0.6), leer = unverändert
	arten, ordner, indikatoren, netze string
}

func cmdPackageSetup(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("paket-einrichten", flag.ContinueOnError)
	dir := fs.String("verzeichnis", agent.DefaultDir, "Verzeichnis für Schlüssel, Zertifikat und Einstellungen")
	zentrale := fs.String("zentrale", "", "Adresse des Agent-Ports der Zentrale (nur für die erste Registrierung)")
	token := fs.String("token", "", "Registrierungs-Token; \"-\" liest es von der Standardeingabe")
	hostname := fs.String("hostname", "", "Name, unter dem der Rechner erscheint (Standard: Hostname des Systems)")
	fromEnv := fs.Bool("aus-umgebung", false, "Zentrale, Token und Hostname aus "+envZentrale+", "+envToken+" und "+envHostname+" lesen")
	kinds := fs.String("arten", "", "Sensoren freigeben wie „sensoren -arten“ (leer = Freigabe unverändert)")
	folders := fs.String("ordner", "", "Ordner für Datei-Sensoren wie „sensoren -ordner“")
	counters := fs.String("indikatoren", "", "Objekte der Leistungsindikatoren wie „sensoren -indikatoren“")
	nets := fs.String("netze", "", "als Sammler für SNMP-Geräte in diesen Netzen freigeben wie „sammler -netze“ (leer = unverändert)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unerwartetes Argument %q", fs.Arg(0))
	}
	if !agent.IsRoot() {
		return errors.New("bitte als root bzw. Administrator ausführen (läuft normalerweise im Paketmanager)")
	}
	o := packageOptions{dir: *dir, zentrale: *zentrale, token: *token, hostname: *hostname,
		arten: *kinds, ordner: *folders, indikatoren: *counters, netze: *nets}
	if *fromEnv {
		o.zentrale = firstNonEmpty(o.zentrale, os.Getenv(envZentrale))
		o.token = firstNonEmpty(o.token, os.Getenv(envToken))
		o.hostname = firstNonEmpty(o.hostname, os.Getenv(envHostname))
	}
	o.zentrale, o.token, o.hostname = strings.TrimSpace(o.zentrale), strings.TrimSpace(o.token), strings.TrimSpace(o.hostname)
	if o.token == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		o.token = strings.TrimSpace(line)
	}
	if (o.zentrale == "") != (o.token == "") {
		return errors.New("für die Registrierung Zentrale und Token zusammen angeben (oder beide weglassen)")
	}
	abs, err := filepath.Abs(o.dir)
	if err != nil {
		return err
	}
	o.dir = abs
	if o.token != "" && o.hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		o.hostname = strings.ToLower(h)
	}
	if err := packageSetup(ctx, o, out); err != nil {
		return err
	}
	return releaseFromPackage(o, out)
}

// releaseFromPackage: Freigaben, die im Assistenten des MSI gewählt wurden.
// Nur was angegeben ist, ändert etwas; ein Update ohne Angaben lässt die
// bestehende Freigabe stehen. Zurücknehmen geht mit „sensoren -aus“ bzw.
// „sammler -aus“. Eine ungültige Angabe bricht die Installation nicht ab:
// Der Agent läuft dann ohne diese Freigabe, die Meldung steht im Protokoll.
func releaseFromPackage(o packageOptions, out io.Writer) error {
	if k := splitList(o.arten); len(k) > 0 {
		rel, err := agent.WriteSensorRelease(o.dir, &agentproto.SensorRelease{Kinds: k, Folders: splitList(o.ordner),
			Counters: splitList(o.indikatoren)})
		if err != nil {
			fmt.Fprintf(out, "Sensoren nicht freigegeben: %v\n", err)
		} else {
			fmt.Fprintf(out, "Sensoren freigegeben: %s\n", strings.Join(rel.Kinds, ", "))
		}
	}
	if n := splitList(o.netze); len(n) > 0 {
		parsed, err := agent.WriteCollectorConfig(o.dir, n)
		if err != nil {
			fmt.Fprintf(out, "Sammler nicht freigegeben: %v\n", err)
		} else {
			fmt.Fprintf(out, "Sammler freigegeben für: %s\n", joinPrefixes(parsed))
		}
	}
	return nil
}

// registerFromPackage registriert, wenn ein Token da ist und der Rechner
// noch nicht registriert ist. Ein vorhandenes Token bei bestehender
// Registrierung bleibt unbenutzt (ein Update soll nichts neu registrieren).
func registerFromPackage(ctx context.Context, o packageOptions, out io.Writer) error {
	if o.token == "" {
		return nil
	}
	if agent.Registered(o.dir) {
		fmt.Fprintln(out, "Bereits registriert; das angegebene Token wurde nicht benutzt.")
		return nil
	}
	regCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	id, err := agent.Register(regCtx, o.dir, o.zentrale, o.token, o.hostname, false)
	if err != nil {
		return fmt.Errorf("Registrierung: %w", err)
	}
	fmt.Fprintf(out, "Registriert als %q (Agent-ID %s).\n", o.hostname, id)
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cmdPackageRemove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("paket-entfernen", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !agent.IsRoot() {
		return errors.New("bitte als root bzw. Administrator ausführen")
	}
	return packageRemove(out)
}
