// SPDX-License-Identifier: AGPL-3.0-only

package main

// openwacht-zentrale zweitinstanz (1.0.6): kalte Zweitinstanz als geführter
// Ablauf.
//
//	zweitinstanz -einrichten -quelle DIR  einmal auf dem Zweitrechner
//	zweitinstanz -lauf                    Timer: neueste Sicherung einspielen und prüfen
//	zweitinstanz -status                  Stand anzeigen
//	zweitinstanz -umschalten              Zweitinstanz wird die Zentrale
//
// Die Sicherungen bringt der Betreiber selbst in den Ordner -quelle (rsync
// über SSH, NFS, USB). OpenWacht holt nichts über das Netz: kein neuer
// Netzweg, keine Zugangsdaten, offline nutzbar.
//
// Schutz gegen Verwechslung: Gearbeitet wird nur mit der Markierung
// /etc/openwacht/zweitinstanz (legt -einrichten an, -umschalten entfernt
// sie) und nur, solange hier keine Zentrale läuft. Die Bereitschaftskopie
// wird erst ersetzt, wenn die neue Sicherung vollständig eingespielt und
// geprüft ist; bis dahin bleibt die alte unverändert.

import (
	"bufio"
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
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

const (
	standbyConf     = etcDir + "/zweitinstanz"
	standbyStateDir = "/var/lib/openwacht-zweitinstanz"
	standbyStatus   = "status.json"
	standbyOK       = "ok" // Zeitstempel = letzte erfolgreich eingespielte Sicherung
	standbyTimer    = "openwacht-zweitinstanz.timer"
	// Neueste Sicherung älter als das: Lauf scheitert (tägliche Sicherung + Puffer).
	standbyMaxAge = 26 * time.Hour
	// So lange muss eine Datei unverändert sein, bevor sie gilt (Kopie läuft noch).
	standbySettle = time.Minute
)

// Dienste der Hauptrolle, die auf einer Zweitinstanz aus sind.
var primaryUnits = []string{"openwacht-zentrale.socket", "openwacht-zentrale.service", "openwacht-traps.socket",
	"openwacht-traps.service", "openwacht-sicherung.timer", "openwacht-zentrale-update.path"}

var backupNameRe = regexp.MustCompile(`^openwacht-([0-9]{8}T[0-9]{6}Z)\.dump$`)

// standbyState: Inhalt von status.json (keine Geheimnisse, für -status und
// einen Datei-Sensor lesbar).
type standbyState struct {
	Quelle         string    `json:"quelle"`
	Geprueft       time.Time `json:"geprueft"`
	OK             bool      `json:"ok"`
	Fehler         string    `json:"fehler,omitempty"`
	Hinweis        string    `json:"hinweis,omitempty"`
	Datei          string    `json:"datei,omitempty"`
	Groesse        int64     `json:"groesse,omitempty"`
	SicherungZeit  time.Time `json:"sicherung_zeit,omitzero"`
	Eingespielt    time.Time `json:"eingespielt,omitzero"`
	Schema         int       `json:"schema,omitempty"`
	Mandanten      int       `json:"mandanten,omitempty"`
	Konten         int       `json:"konten,omitempty"`
	Geraete        int       `json:"geraete,omitempty"`
	Agents         int       `json:"agents,omitempty"`
	AuditEintraege int64     `json:"audit_eintraege,omitempty"`
}

// standbyInspect: was der Prüfschritt als postgres meldet.
type standbyInspect struct {
	Versions  []int  `json:"versionen"`
	Tenants   int    `json:"mandanten"`
	Users     int    `json:"konten"`
	Devices   int    `json:"geraete"`
	Agents    int    `json:"agents"`
	AuditOK   bool   `json:"audit_ok"`
	AuditBad  *int64 `json:"audit_gebrochen,omitempty"`
	AuditRows int64  `json:"audit_eintraege"`
}

// backupCandidate: eine Sicherung im Quellordner.
type backupCandidate struct {
	name string
	at   time.Time // aus dem Namen
	mod  time.Time
	size int64
}

// listStandbySources: Sicherungen im Quellordner, neueste zuerst (nach dem
// Zeitstempel im Namen; rsync ohne -t verfälscht sonst die Reihenfolge).
// Andere Dateien, Unterordner, Links und versteckte Dateien (Zwischenstände
// von rsync) zählen nicht.
func listStandbySources(dir string) ([]backupCandidate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []backupCandidate
	for _, e := range entries {
		m := backupNameRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		at, err := time.Parse("20060102T150405Z", m[1])
		if err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupCandidate{name: e.Name(), at: at, mod: fi.ModTime(), size: fi.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at.After(out[j].at) })
	return out, nil
}

// pickStandbySource: die neueste Sicherung, die seit standbySettle
// unverändert ist. settling = eine neuere wird gerade noch kopiert.
func pickStandbySource(files []backupCandidate, now time.Time) (c backupCandidate, settling bool, ok bool) {
	for _, f := range files {
		if now.Sub(f.mod) < standbySettle {
			settling = true
			continue
		}
		if f.size == 0 {
			continue
		}
		return f, settling, true
	}
	return backupCandidate{}, settling, false
}

// checkSchemaVersions: Kennt dieses Paket jede Migration der Sicherung?
// Neuere Sicherung als Paket: Zweitinstanz zuerst aktualisieren. Ältere
// Sicherung ist in Ordnung (Migrationen laufen beim Umschalten).
func checkSchemaVersions(backup []int) (latest int, err error) {
	migs, err := db.Migrations()
	if err != nil {
		return 0, err
	}
	known := map[int]bool{}
	for _, m := range migs {
		known[m.Version] = true
	}
	var unknown []string
	for _, v := range backup {
		if v > latest {
			latest = v
		}
		if !known[v] {
			unknown = append(unknown, fmt.Sprintf("%04d", v))
		}
	}
	if len(backup) == 0 {
		return 0, errors.New("die Sicherung enthält kein Schema von OpenWacht")
	}
	if len(unknown) > 0 {
		return latest, fmt.Errorf("die Sicherung hat Migrationen, die dieses Paket nicht kennt (%s): Zweitinstanz auf die Version der Hauptinstanz aktualisieren",
			strings.Join(unknown, ", "))
	}
	return latest, nil
}

// readStandbyConf liest die Markierung (Zeilen schluessel=wert).
func readStandbyConf(p string) (quelle string, err error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.TrimSpace(k) == "quelle" {
			quelle = strings.TrimSpace(v)
		}
	}
	if err := checkStandbySourcePath(quelle); err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	return quelle, nil
}

// checkStandbySourcePath: absolut, sauber, nicht der eigene Sicherungsordner
// (sonst spielte die Zweitinstanz ihre eigene Sicherung vor einem Update ein)
// und nicht unter /etc/openwacht.
func checkStandbySourcePath(p string) error {
	if p == "" {
		return errors.New("-quelle fehlt")
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\n\r") {
		return fmt.Errorf("Quelle %q: absoluter Pfad ohne .. und ohne / am Ende nötig", p)
	}
	if p == backupDir || strings.HasPrefix(backupDir, p+"/") || strings.HasPrefix(p, backupDir+"/") {
		return fmt.Errorf("Quelle darf nicht %s sein (dort legt diese Instanz ihre eigenen Sicherungen ab); z. B. /var/lib/openwacht-zweitinstanz-eingang", backupDir)
	}
	if p == "/" || p == etcDir || strings.HasPrefix(p, etcDir+"/") {
		return fmt.Errorf("Quelle %q nicht erlaubt", p)
	}
	return nil
}

type standby struct {
	in       *installer
	out      io.Writer
	socket   string
	stateDir string
	conf     string
	now      func() time.Time
	// active meldet, ob hier eine Zentrale läuft (systemctl is-active).
	active func() bool
}

func newStandby(out io.Writer, socket string, services bool) (*standby, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	in := &installer{out: out, self: self, pgSocket: socket, services: services,
		systemctl: func(a ...string) error {
			c := exec.Command("systemctl", a...)
			c.Stdout, c.Stderr = io.Discard, os.Stderr
			return c.Run()
		}}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		in.services = false
	}
	s := &standby{in: in, out: out, socket: socket, stateDir: standbyStateDir, conf: standbyConf, now: time.Now}
	s.active = func() bool {
		if !in.services {
			return false
		}
		for _, u := range []string{"openwacht-zentrale.service", "openwacht-zentrale.socket"} {
			if exec.Command("systemctl", "is-active", "--quiet", u).Run() == nil {
				return true
			}
		}
		return false
	}
	return s, nil
}

func (s *standby) pgStep(ctx context.Context, step string, extra ...string) ([]byte, error) {
	return s.in.asUser(ctx, "postgres", append([]string{"intern-postgres", "-pg-socket", s.socket, "-wiederherstellen", step}, extra...), nil)
}

func (s *standby) inspect(ctx context.Context, dbName string) (standbyInspect, error) {
	var r standbyInspect
	b, err := s.pgStep(ctx, "pruefen", "-db", dbName)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

func (s *standby) readState() (standbyState, error) {
	var st standbyState
	b, err := os.ReadFile(filepath.Join(s.stateDir, standbyStatus))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// writeState schreibt status.json atomar (0644, keine Geheimnisse) und bei
// Erfolg mit neuer Sicherung die Datei ok (ihr Alter misst ein Datei-Sensor).
func (s *standby) writeState(st standbyState, restored bool) error {
	if err := os.MkdirAll(s.stateDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.stateDir, standbyStatus+".neu")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.stateDir, standbyStatus)); err != nil {
		return err
	}
	if restored {
		okPath := filepath.Join(s.stateDir, standbyOK)
		line := st.Datei + "\n"
		if err := os.WriteFile(okPath+".neu", []byte(line), 0o644); err != nil {
			return err
		}
		return os.Rename(okPath+".neu", okPath)
	}
	return nil
}

// run: ein Lauf des Timers. Liefert den neuen Stand; Fehler auch dann, wenn
// die neueste Sicherung zu alt ist (Unit scheitert, Datei ok altert).
func (s *standby) run(ctx context.Context) (standbyState, error) {
	quelle, err := readStandbyConf(s.conf)
	if errors.Is(err, os.ErrNotExist) {
		return standbyState{}, fmt.Errorf("keine Zweitinstanz eingerichtet (%s fehlt); nichts geändert", s.conf)
	}
	if err != nil {
		return standbyState{}, err
	}
	if s.active() {
		return standbyState{}, errors.New("hier läuft eine Zentrale (openwacht-zentrale ist aktiv); als Zweitinstanz wird nichts eingespielt")
	}
	prev, _ := s.readState()
	now := s.now()
	st := prev
	st.Quelle, st.Geprueft, st.Fehler, st.Hinweis, st.OK = quelle, now, "", "", false
	fail := func(err error) (standbyState, error) {
		st.Fehler = err.Error()
		if werr := s.writeState(st, false); werr != nil {
			fmt.Fprintf(os.Stderr, "Stand schreiben: %v\n", werr)
		}
		return st, err
	}

	files, err := listStandbySources(quelle)
	if err != nil {
		return fail(fmt.Errorf("Quelle %s: %w", quelle, err))
	}
	c, settling, ok := pickStandbySource(files, now)
	if !ok {
		if settling {
			st.Hinweis = "eine Sicherung wird gerade noch kopiert"
		}
		return fail(fmt.Errorf("keine fertige Sicherung (openwacht-<Zeit>.dump) in %s", quelle))
	}
	if settling {
		st.Hinweis = "eine neuere Sicherung wird gerade noch kopiert"
	}
	restored := false
	if c.name != prev.Datei || c.size != prev.Groesse || prev.Eingespielt.IsZero() {
		if err := s.restore(ctx, quelle, c, &st); err != nil {
			return fail(err)
		}
		restored = true
	}
	if age := now.Sub(c.at); age > standbyMaxAge {
		return fail(fmt.Errorf("die neueste Sicherung %s ist %s alt (höchstens %s); kommen keine Sicherungen mehr an?",
			c.name, age.Round(time.Minute), standbyMaxAge))
	}
	st.OK = true
	if err := s.writeState(st, restored); err != nil {
		return st, err
	}
	return st, nil
}

// restore spielt c in openwacht_neu ein, prüft und tauscht erst dann gegen die
// Bereitschaftskopie. Jeder Fehler vor dem Tausch verwirft nur openwacht_neu.
func (s *standby) restore(ctx context.Context, quelle string, c backupCandidate, st *standbyState) error {
	path := filepath.Join(quelle, c.name)
	if _, err := s.pgStep(ctx, "leere-db"); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			s.pgStep(ctx, "verwerfen")
		}
	}()
	if err := pgRestore(ctx, path, s.socket); err != nil {
		return fmt.Errorf("%s einspielen: %w", c.name, err)
	}
	b, err := s.pgStep(ctx, "ca-schluessel")
	if err != nil {
		return err
	}
	var rs restoreStatus
	if err := json.Unmarshal(b, &rs); err != nil {
		return err
	}
	if len(rs.CAKey) == 0 {
		// Ohne Agent-CA ließe sich der Hauptschlüssel nicht prüfen.
		return errors.New("die Sicherung enthält keine Agent-CA (Hauptinstanz noch nie gestartet?); nicht übernommen")
	}
	key, err := auth.LoadKeyFile(keyPath)
	if err != nil {
		return err
	}
	if err := zentrale.CheckAgentCAKey(key, rs.CAKey); err != nil {
		return fmt.Errorf("%w; den Hauptschlüssel der Hauptinstanz nach %s kopieren", err, keyPath)
	}
	r, err := s.inspect(ctx, restoreDB)
	if err != nil {
		return err
	}
	latest, err := checkSchemaVersions(r.Versions)
	if err != nil {
		return err
	}
	if !r.AuditOK {
		at := int64(0)
		if r.AuditBad != nil {
			at = *r.AuditBad
		}
		return fmt.Errorf("Audit-Hash-Kette in der Sicherung ab Eintrag %d gebrochen; Sicherung nicht übernommen", at)
	}
	if r.Tenants == 0 {
		return errors.New("die Sicherung enthält keinen Mandanten (leere Installation?); nicht übernommen")
	}
	suffix := s.now().UTC().Format("20060102T150405Z")
	b, err = s.pgStep(ctx, "tauschen", "-zeit", suffix)
	if err != nil {
		return fmt.Errorf("Tauschen: %w", err)
	}
	ok = true
	var sw map[string]string
	json.Unmarshal(b, &sw)
	if sw["alt"] != "" {
		// Die bisherige Bereitschaftskopie ist nur eine Kopie: weg damit.
		if _, err := s.pgStep(ctx, "alte-verwerfen", "-zeit", suffix); err != nil {
			fmt.Fprintf(os.Stderr, "Alte Bereitschaftskopie %s nicht gelöscht: %v\n", sw["alt"], err)
		}
	}
	st.Datei, st.Groesse, st.SicherungZeit, st.Eingespielt = c.name, c.size, c.at, s.now()
	st.Schema, st.Mandanten, st.Konten, st.Geraete, st.Agents, st.AuditEintraege =
		latest, r.Tenants, r.Users, r.Devices, r.Agents, r.AuditRows
	return nil
}

func (s *standby) setup(ctx context.Context, quelle string, replace bool) error {
	if err := checkStandbySourcePath(quelle); err != nil {
		return err
	}
	fi, err := os.Stat(quelle)
	if err != nil {
		return fmt.Errorf("Quelle: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("Quelle %s ist kein Ordner", quelle)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("Hauptschlüssel %s fehlt: zuerst das Paket installieren (Kapitel 1) und den Schlüssel der Hauptinstanz kopieren", keyPath)
	}
	if s.active() && !replace {
		return errors.New("hier läuft eine Zentrale. Ist das wirklich der Zweitrechner? Wenn ja: -ersetzen (die Daten hier werden dann durch die Sicherungen der Hauptinstanz ersetzt)")
	}
	cur, err := s.inspect(ctx, "openwacht")
	if err != nil {
		return err
	}
	if cur.Users > 0 && !replace {
		return fmt.Errorf("die Datenbank hier enthält schon Konten (%d). Ist das wirklich der Zweitrechner? Wenn ja: -ersetzen", cur.Users)
	}
	conf := "# Kalte Zweitinstanz (openwacht-zentrale zweitinstanz). Entfernt -umschalten.\nquelle=" + quelle + "\n"
	if err := os.WriteFile(s.conf+".neu", []byte(conf), 0o644); err != nil {
		return err
	}
	if err := os.Rename(s.conf+".neu", s.conf); err != nil {
		return err
	}
	s.in.step("Markierung %s (Quelle %s)", s.conf, quelle)
	if err := os.MkdirAll(s.stateDir, 0o755); err != nil {
		return err
	}
	if s.in.services {
		sc := s.in.systemctl
		sc("daemon-reload")
		sc(append([]string{"disable", "--now"}, primaryUnits...)...)
		s.in.step("Zentrale, Trap-Dienst und Sicherung hier aus")
		if err := sc("enable", "--now", standbyTimer); err != nil {
			return fmt.Errorf("systemctl enable --now %s: %w", standbyTimer, err)
		}
		s.in.step("%s an (stündlich)", standbyTimer)
	} else {
		s.in.note("kein systemd: Dienste nicht umgestellt, Timer nicht eingerichtet")
	}
	fmt.Fprintln(s.out, "\nErster Lauf:")
	st, err := s.run(ctx)
	if err != nil {
		return fmt.Errorf("erster Lauf: %w (Einrichtung bleibt; der Timer versucht es stündlich wieder)", err)
	}
	s.printState(st)
	return nil
}

func (s *standby) printState(st standbyState) {
	w := s.out
	state := "in Ordnung"
	if !st.OK {
		state = "FEHLER: " + st.Fehler
	}
	fmt.Fprintf(w, "  Zustand:       %s\n", state)
	if st.Hinweis != "" {
		fmt.Fprintf(w, "  Hinweis:       %s\n", st.Hinweis)
	}
	fmt.Fprintf(w, "  Quelle:        %s\n", st.Quelle)
	if !st.Geprueft.IsZero() {
		fmt.Fprintf(w, "  Geprüft:       %s\n", st.Geprueft.Local().Format("02.01.2006 15:04"))
	}
	if st.Datei == "" {
		fmt.Fprintln(w, "  Bereitschaftskopie: noch keine")
		return
	}
	fmt.Fprintf(w, "  Sicherung:     %s (%s, %.1f MB)\n", st.Datei, st.SicherungZeit.Local().Format("02.01.2006 15:04"), float64(st.Groesse)/1e6)
	fmt.Fprintf(w, "  Eingespielt:   %s, Schema %04d\n", st.Eingespielt.Local().Format("02.01.2006 15:04"), st.Schema)
	fmt.Fprintf(w, "  Inhalt:        %d Mandanten, %d Konten, %d Geräte, %d Agents, %d Audit-Einträge (Kette heil)\n",
		st.Mandanten, st.Konten, st.Geraete, st.Agents, st.AuditEintraege)
}

func (s *standby) status() error {
	if _, err := os.Stat(s.conf); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(s.out, "Keine Zweitinstanz eingerichtet (%s fehlt).\n", s.conf)
		return nil
	}
	st, err := s.readState()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(s.out, "Zweitinstanz eingerichtet, noch kein Lauf.")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(s.out, "Kalte Zweitinstanz:")
	s.printState(st)
	return nil
}

// switchover: Die Zweitinstanz wird die Zentrale.
func (s *standby) switchover(ctx context.Context, yes bool, stdin io.Reader) error {
	if _, err := os.Stat(s.conf); err != nil {
		return fmt.Errorf("keine Zweitinstanz eingerichtet (%s fehlt)", s.conf)
	}
	if !yes {
		fmt.Fprint(s.out, "Diese Zweitinstanz wird die Zentrale. Die Hauptinstanz muss aus sein und aus bleiben.\n"+
			"Weiter? Mit „ja“ bestätigen: ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "ja" {
			return errors.New("abgebrochen, nichts geändert")
		}
	}
	fmt.Fprintln(s.out, "Umschalten:")
	st, err := s.run(ctx)
	if err != nil {
		if st.Eingespielt.IsZero() {
			return fmt.Errorf("%w; es gibt keine Bereitschaftskopie, nichts geändert", err)
		}
		s.in.note("Letzter Lauf: %v", err)
		s.in.note("Es gilt die Bereitschaftskopie aus %s, eingespielt %s",
			st.Datei, st.Eingespielt.Local().Format("02.01.2006 15:04"))
	} else {
		s.in.step("Bereitschaftskopie aus %s (Sicherung vom %s)", st.Datei, st.SicherungZeit.Local().Format("02.01.2006 15:04"))
	}
	mig, err := s.in.asUser(ctx, userDB, []string{"migrieren"}, []string{"OPENWACHT_DB_EIGENTUEMER=" + ownerDSN(s.socket)})
	if err != nil {
		return fmt.Errorf("Migrationen: %w (Markierung bleibt, Dienste aus)", err)
	}
	s.in.step("Datenbank: %s", strings.TrimSpace(string(mig)))
	if err := os.Remove(s.conf); err != nil {
		return err
	}
	s.in.step("Markierung %s entfernt", s.conf)
	if s.in.services {
		s.in.systemctl("disable", "--now", standbyTimer)
		s.in.step("%s aus", standbyTimer)
	}
	if err := s.in.startServices(); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "\nFertig. Jetzt:\n"+
		"  1. DNS-Namen der Zentrale auf diesen Rechner umstellen (Agents und Browser folgen nach der TTL).\n"+
		"  2. Prüfen: Oberfläche anmelden, curl -k https://<name>/api/v1/gesund, Agents „melden sich“.\n"+
		"  3. Die alte Hauptinstanz nicht wieder starten. Zurück nur wie in Handbuch Kapitel 16 beschrieben.\n"+
		"  Verloren ist alles seit der Sicherung vom %s.\n", st.SicherungZeit.Local().Format("02.01.2006 15:04"))
	return nil
}

func cmdStandby(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("zweitinstanz", flag.ContinueOnError)
	setup := fs.Bool("einrichten", false, "diesen Rechner als kalte Zweitinstanz einrichten (mit -quelle)")
	quelle := fs.String("quelle", "", "Ordner, in den die Sicherungen der Hauptinstanz kopiert werden")
	replace := fs.Bool("ersetzen", false, "mit -einrichten: auch wenn hier schon Konten existieren")
	runOnce := fs.Bool("lauf", false, "neueste Sicherung einspielen und prüfen (Timer)")
	showStatus := fs.Bool("status", false, "Stand anzeigen")
	sw := fs.Bool("umschalten", false, "Zweitinstanz wird die Zentrale")
	yes := fs.Bool("ja", false, "mit -umschalten: ohne Rückfrage")
	socket := fs.String("pg-socket", "/run/postgresql", "Verzeichnis des PostgreSQL-Sockets")
	noServices := fs.Bool("ohne-dienste", false, "systemd-Dienste weder anhalten noch starten")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n := 0
	for _, b := range []bool{*setup, *runOnce, *showStatus, *sw} {
		if b {
			n++
		}
	}
	if n != 1 {
		return errors.New("genau eins von -einrichten, -lauf, -status, -umschalten angeben")
	}
	if os.Geteuid() != 0 {
		return errors.New("zweitinstanz braucht root (sudo openwacht-zentrale zweitinstanz …)")
	}
	s, err := newStandby(out, *socket, !*noServices)
	if err != nil {
		return err
	}
	switch {
	case *setup:
		fmt.Fprintln(out, "Kalte Zweitinstanz einrichten:")
		return s.setup(ctx, *quelle, *replace)
	case *runOnce:
		st, err := s.run(ctx)
		if err == nil {
			s.printState(st)
		}
		return err
	case *showStatus:
		return s.status()
	default:
		return s.switchover(ctx, *yes, stdin)
	}
}

// isStandby: Ist dieser Rechner als Zweitinstanz markiert? (installieren
// startet dann die Zentrale nicht, auch nicht bei einem Paket-Update.)
func (in *installer) isStandby() bool {
	_, err := os.Stat(in.path(standbyConf))
	return err == nil
}

// internStandbyInspect läuft als postgres: Schema-Stand, Zahlen und
// Audit-Kette einer Datenbank (openwacht_neu oder openwacht).
func internStandbyInspect(ctx context.Context, socket, dbName string, out io.Writer) error {
	if dbName != restoreDB && dbName != "openwacht" {
		return fmt.Errorf("Datenbank %q nicht erlaubt", dbName)
	}
	c, err := pgx.Connect(ctx, "host="+socket+" user=postgres dbname="+dbName)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	r, err := inspectStandbyDB(ctx, c, dbName == restoreDB)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(r)
}

// inspectStandbyDB: Schema-Stand, Zahlen und (withAudit) die Hash-Kette.
func inspectStandbyDB(ctx context.Context, c *pgx.Conn, withAudit bool) (standbyInspect, error) {
	var r standbyInspect
	var hasSchema bool
	if err := c.QueryRow(ctx, `SELECT to_regclass('openwacht.schema_migrations') IS NOT NULL`).Scan(&hasSchema); err != nil {
		return r, err
	}
	if !hasSchema {
		r.AuditOK = true
		return r, nil
	}
	rows, err := c.Query(ctx, `SELECT version FROM openwacht.schema_migrations ORDER BY version`)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return r, err
		}
		r.Versions = append(r.Versions, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{`SELECT count(*) FROM openwacht.tenants`, &r.Tenants},
		{`SELECT count(*) FROM openwacht.users`, &r.Users},
		{`SELECT count(*) FROM openwacht.devices`, &r.Devices},
		{`SELECT count(*) FROM openwacht.agents`, &r.Agents},
	} {
		if err := c.QueryRow(ctx, q.sql).Scan(q.dst); err != nil {
			return r, err
		}
	}
	if !withAudit {
		r.AuditOK = true
		return r, nil
	}
	a, err := zentrale.CheckAudit(ctx, c)
	if err != nil {
		return r, fmt.Errorf("Audit-Kette: %w", err)
	}
	r.AuditOK, r.AuditBad, r.AuditRows = a.OK, a.BrokenSeq, a.Entries
	return r, nil
}
