// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
)

func TestStandbyQuelleAuswahl(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	write := func(name string, mod time.Time, data string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	// rsync ohne -t: Änderungszeit sagt nichts über das Alter, der Name schon
	write("openwacht-20261124T000500Z.dump", now.Add(-2*time.Minute), "alt")
	write("openwacht-20261125T000500Z.dump", now.Add(-time.Hour), "neu")
	write(".openwacht-20261125T110000Z.dump.Xa12", now, "rsync-Zwischenstand")
	write("openwacht-20261125T110000Z.dump.neu", now, "pg_dump läuft")
	write("fremd.dump", now.Add(-time.Hour), "x")
	write("openwacht-2026.dump", now.Add(-time.Hour), "x")
	os.Symlink(filepath.Join(dir, "openwacht-20261124T000500Z.dump"), filepath.Join(dir, "openwacht-20261125T113000Z.dump"))
	os.Mkdir(filepath.Join(dir, "openwacht-20261125T114000Z.dump"), 0o700)

	files, err := listStandbySources(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].name != "openwacht-20261125T000500Z.dump" {
		t.Fatalf("Auswahl: %+v", files)
	}
	c, settling, ok := pickStandbySource(files, now)
	if !ok || settling || c.name != "openwacht-20261125T000500Z.dump" {
		t.Fatalf("neueste: %+v %v %v", c, settling, ok)
	}
	// neueste wird gerade kopiert: die davor gilt, Hinweis
	write("openwacht-20261125T113500Z.dump", now.Add(-10*time.Second), "kommt noch")
	files, _ = listStandbySources(dir)
	c, settling, ok = pickStandbySource(files, now)
	if !ok || !settling || c.name != "openwacht-20261125T000500Z.dump" {
		t.Fatalf("Kopie läuft: %+v %v %v", c, settling, ok)
	}
	// leere Datei zählt nicht
	write("openwacht-20261125T113600Z.dump", now.Add(-time.Hour), "")
	files, _ = listStandbySources(dir)
	if c, _, _ = pickStandbySource(files, now); c.name != "openwacht-20261125T000500Z.dump" {
		t.Fatalf("leere Datei gewählt: %s", c.name)
	}
}

func TestStandbyQuellePfad(t *testing.T) {
	for _, p := range []string{"", "relativ", "/var/backups/openwacht", "/var/backups", "/var/backups/openwacht/x",
		"/etc/openwacht", "/etc/openwacht/x", "/", "/a/../b", "/a/", "/a\nb"} {
		if checkStandbySourcePath(p) == nil {
			t.Errorf("%q angenommen", p)
		}
	}
	for _, p := range []string{"/var/lib/openwacht-zweitinstanz-eingang", "/srv/sicherungen/openwacht", "/var/backups/openwacht-haupt"} {
		if err := checkStandbySourcePath(p); err != nil {
			t.Errorf("%q abgelehnt: %v", p, err)
		}
	}
	conf := filepath.Join(t.TempDir(), "zweitinstanz")
	os.WriteFile(conf, []byte("# Kommentar\nquelle = /srv/eingang\nunbekannt=1\n"), 0o644)
	if q, err := readStandbyConf(conf); err != nil || q != "/srv/eingang" {
		t.Fatalf("Markierung: %q %v", q, err)
	}
	os.WriteFile(conf, []byte("quelle=/var/backups/openwacht\n"), 0o644)
	if _, err := readStandbyConf(conf); err == nil {
		t.Fatal("eigener Sicherungsordner als Quelle angenommen")
	}
}

func TestStandbySchemaStand(t *testing.T) {
	migs, err := db.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var all []int
	for _, m := range migs {
		all = append(all, m.Version)
	}
	if latest, err := checkSchemaVersions(all); err != nil || latest != all[len(all)-1] {
		t.Fatalf("gleicher Stand: %d %v", latest, err)
	}
	// ältere Sicherung: in Ordnung, Migrationen laufen beim Umschalten
	if _, err := checkSchemaVersions(all[:len(all)-3]); err != nil {
		t.Fatalf("ältere Sicherung: %v", err)
	}
	// neuere Sicherung als Paket: Zweitinstanz aktualisieren
	_, err = checkSchemaVersions(append(append([]int{}, all...), all[len(all)-1]+1))
	if err == nil || !strings.Contains(err.Error(), "Zweitinstanz auf die Version der Hauptinstanz aktualisieren") {
		t.Fatalf("neuere Sicherung: %v", err)
	}
	if _, err := checkSchemaVersions(nil); err == nil {
		t.Fatal("Sicherung ohne Schema angenommen")
	}
}

// Ohne Markierung und bei laufender Zentrale ändert ein Lauf nichts.
func TestStandbyLaufNurMitMarkierung(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	s := &standby{in: &installer{out: &out}, out: &out, stateDir: filepath.Join(dir, "stand"),
		conf: filepath.Join(dir, "zweitinstanz"), now: time.Now, active: func() bool { return false }}
	if _, err := s.run(context.Background()); err == nil || !strings.Contains(err.Error(), "keine Zweitinstanz eingerichtet") {
		t.Fatalf("ohne Markierung: %v", err)
	}
	quelle := filepath.Join(dir, "eingang")
	os.Mkdir(quelle, 0o700)
	os.WriteFile(s.conf, []byte("quelle="+quelle+"\n"), 0o644)
	s.active = func() bool { return true }
	if _, err := s.run(context.Background()); err == nil || !strings.Contains(err.Error(), "hier läuft eine Zentrale") {
		t.Fatalf("laufende Zentrale: %v", err)
	}
	if _, err := os.Stat(s.stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Stand geschrieben, obwohl nichts geprüft wurde")
	}
	// Markierung da, Quelle leer: Fehler im Stand, keine Datei ok
	s.active = func() bool { return false }
	st, err := s.run(context.Background())
	if err == nil || st.OK || !strings.Contains(st.Fehler, "keine fertige Sicherung") {
		t.Fatalf("leere Quelle: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, standbyOK)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ok geschrieben trotz Fehler")
	}
	got, err := s.readState()
	if err != nil || got.Fehler == "" || got.Quelle != quelle {
		t.Fatalf("Stand: %+v %v", got, err)
	}
	// Nichts Neues, aber zu alt: Lauf scheitert, auch ohne neues Einspielen
	name := "openwacht-20261120T000500Z.dump"
	os.WriteFile(filepath.Join(quelle, name), []byte("x"), 0o600)
	at, _ := time.Parse("20060102T150405Z", "20261120T000500Z")
	os.Chtimes(filepath.Join(quelle, name), at, at)
	got.Datei, got.Groesse, got.Eingespielt, got.SicherungZeit = name, 1, at, at
	s.writeState(got, true)
	s.now = func() time.Time { return at.Add(30 * time.Hour) }
	st, err = s.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "kommen keine Sicherungen mehr an") || st.Datei != name {
		t.Fatalf("zu alt: %+v %v", st, err)
	}
	s.now = func() time.Time { return at.Add(2 * time.Hour) }
	if st, err = s.run(context.Background()); err != nil || !st.OK {
		t.Fatalf("nichts Neues, jung genug: %+v %v", st, err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.stateDir, standbyOK)); string(b) != name+"\n" {
		t.Fatalf("ok: %q", b)
	}
}

// installieren startet auf einer Zweitinstanz keine Zentrale (Paket-Update).
func TestStandbyInstallierenStartetNichts(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, etcDir), 0o750)
	os.WriteFile(filepath.Join(root, standbyConf), []byte("quelle=/srv/eingang\n"), 0o644)
	var calls []string
	var out bytes.Buffer
	in := &installer{out: &out, root: root, services: true, systemctl: func(a ...string) error {
		calls = append(calls, strings.Join(a, " "))
		return nil
	}}
	if err := in.startServices(); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(calls, "\n")
	if strings.Contains(all, "restart") || strings.Contains(all, "enable --now openwacht-zentrale") ||
		!strings.Contains(all, "disable --now openwacht-zentrale.socket") || !strings.Contains(all, "enable --now "+standbyTimer) {
		t.Fatalf("Aufrufe:\n%s", all)
	}
}

// Prüfung der eingespielten Datenbank: Zahlen, Schema, Audit-Kette.
func TestStandbyPruefungDerDatenbank(t *testing.T) {
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	owner, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	sup, err := pgx.ConnectConfig(ctx, tdb.SuperCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(ctx)
	// vor den Migrationen: kein Schema
	if r, err := inspectStandbyDB(ctx, sup, true); err != nil || len(r.Versions) != 0 || !r.AuditOK {
		t.Fatalf("leer: %+v %v", r, err)
	}
	if _, err := checkSchemaVersions(nil); err == nil {
		t.Fatal("leere Sicherung angenommen")
	}
	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	var tenant string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('Beispiel GmbH') RETURNING id::text`).Scan(&tenant)
	owner.Exec(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Werkstatt')`, tenant)
	for i := 0; i < 3; i++ {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.audit_log (action, details) VALUES ('test.eintrag', $1)`, map[string]any{"nr": i}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := inspectStandbyDB(ctx, sup, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tenants != 2 || r.Users != 0 || !r.AuditOK || r.AuditRows < 3 {
		t.Fatalf("Prüfung: %+v", r)
	}
	if _, err := checkSchemaVersions(r.Versions); err != nil {
		t.Fatalf("Schema der Testdatenbank: %v", err)
	}
	// Kette brechen: muss auffallen
	for _, q := range []string{
		`ALTER TABLE openwacht.audit_log DISABLE TRIGGER audit_no_update`,
		`UPDATE openwacht.audit_log SET details = '{"nr": 42}' WHERE chain_seq = 2`,
		`ALTER TABLE openwacht.audit_log ENABLE TRIGGER audit_no_update`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	r, err = inspectStandbyDB(ctx, sup, true)
	if err != nil || r.AuditOK || r.AuditBad == nil || *r.AuditBad != 2 {
		t.Fatalf("gebrochene Kette nicht erkannt: %+v %v", r, err)
	}
	// ohne Audit (Vorprüfung der laufenden Datenbank bei -einrichten)
	if r, err = inspectStandbyDB(ctx, sup, false); err != nil || !r.AuditOK || r.Tenants != 2 {
		t.Fatalf("ohne Audit: %+v %v", r, err)
	}
}
