// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const debianHBA = `# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
`

func TestEditHBA(t *testing.T) {
	got := editHBA(debianHBA)
	lines := strings.Split(got, "\n")
	idx := func(sub string) int {
		for i, l := range lines {
			if strings.Contains(l, sub) {
				return i
			}
		}
		return -1
	}
	if idx("map=openwacht") < 0 || idx("map=openwacht") > idx("local   all             postgres") {
		t.Fatalf("Zeile fehlt oder steht nicht vor der ersten local-Zeile:\n%s", got)
	}
	if again := editHBA(got); again != got {
		t.Fatal("zweiter Lauf ändert etwas")
	}
	// ältere Fassung (vor Etappe 14, ohne Trap-Rolle) wird ersetzt
	old := strings.Replace(debianHBA, "local   all             postgres", "local   openwacht  openwacht_zentrale,openwacht_owner  peer map=openwacht\nlocal   all             postgres", 1)
	got = editHBA(old)
	if strings.Count(got, "map=openwacht") != 1 || !strings.Contains(got, "openwacht_trapdienst") {
		t.Fatalf("alte Zeile nicht ersetzt:\n%s", got)
	}
	// auskommentierte Zeile zählt nicht
	if got := editHBA("#local openwacht x peer map=openwacht\n"); !strings.Contains(got, hbaLine) {
		t.Fatal("Kommentar als vorhandene Zeile gewertet")
	}
}

func TestEditIdent(t *testing.T) {
	base := "# MAPNAME  SYSTEM-USERNAME  PG-USERNAME\n"
	got := editIdent(base)
	for _, m := range identLines {
		if !strings.Contains(got, m[1]) {
			t.Fatalf("%s fehlt", m[1])
		}
	}
	if editIdent(got) != got {
		t.Fatal("zweiter Lauf ändert etwas")
	}
	partial := base + "openwacht    svc_openwacht      openwacht_zentrale\n"
	got = editIdent(partial)
	if strings.Count(got, "openwacht_zentrale") != 1 || !strings.Contains(got, "svc_openwacht_traps") {
		t.Fatalf("Ergänzung falsch:\n%s", got)
	}
}

func TestLegacyProxyMode(t *testing.T) {
	dir := t.TempDir()
	in := &installer{root: dir, out: io.Discard}
	os.MkdirAll(filepath.Join(dir, etcDir), 0o755)
	write := func(s string) { os.WriteFile(filepath.Join(dir, envPath), []byte(s), 0o640) }
	if in.legacyProxyMode() {
		t.Fatal("ohne Datei kein Proxy-Betrieb")
	}
	write(newEnv)
	if in.legacyProxyMode() {
		t.Fatal("neue Installation gilt als Proxy-Betrieb")
	}
	write("OPENWACHT_ARGS=-basis-url https://x -adresse 127.0.0.1:8443 -proxy 127.0.0.1/32\n")
	if !in.legacyProxyMode() {
		t.Fatal("alte Installation nicht erkannt")
	}
	write("OPENWACHT_ARGS=-adresse 127.0.0.1:8443 -proxy 127.0.0.1/32\n")
	if !in.legacyProxyMode() {
		t.Fatal("-adresse als erste Option nicht erkannt")
	}
	write("# -adresse 127.0.0.1:8443\nOPENWACHT_ARGS=-agent-adresse :8444\n")
	if in.legacyProxyMode() {
		t.Fatal("Kommentar gewertet")
	}
}

func TestBackupDue(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Berlin")
	at := func(s string) time.Time { v, _ := time.ParseInLocation("2006-01-02 15:04", s, loc); return v }
	ptr := func(t time.Time) *time.Time { return &t }
	cases := []struct {
		now    time.Time
		newest *time.Time
		want   bool
	}{
		{at("2026-11-22 00:05"), nil, true},                          // noch keine
		{at("2026-11-22 00:05"), ptr(at("2026-11-21 00:06")), true},  // 0 Uhr, gestern
		{at("2026-11-22 01:05"), ptr(at("2026-11-21 00:06")), false}, // nicht die Stunde, 25 h
		{at("2026-11-22 02:05"), ptr(at("2026-11-21 00:06")), true},  // nachholen (> 25 h)
		{at("2026-11-22 00:35"), ptr(at("2026-11-22 00:06")), false}, // schon gesichert
		{at("2026-11-22 13:05"), ptr(at("2026-11-21 23:10")), false}, // 14 h alt
		{at("2026-11-22 00:05"), ptr(at("2026-11-21 13:00")), false}, // nur 11 h alt
	}
	for i, c := range cases {
		if got := backupDue(c.now, loc, 0, c.newest); got != c.want {
			t.Errorf("Fall %d: %v, erwartet %v", i, got, c.want)
		}
	}
}

func TestExpiredBackups(t *testing.T) {
	now := time.Now()
	files := []backupFile{{"neu", now.AddDate(0, 0, -20)}, {"alt1", now.AddDate(0, 0, -21)}, {"alt2", now.AddDate(0, 0, -30)}}
	got := expiredBackups(files, now, 14)
	if strings.Join(got, ",") != "alt1,alt2" {
		t.Fatalf("%v (die neueste muss bleiben)", got)
	}
	if got := expiredBackups(files[:1], now, 1); len(got) != 0 {
		t.Fatal("einzige Sicherung gelöscht")
	}
}

func TestMoveLegacyUnits(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, unitDirEtc)
	os.MkdirAll(filepath.Join(etc, "multi-user.target.wants"), 0o755)
	os.WriteFile(filepath.Join(etc, "openwacht-zentrale.service"), []byte("ExecStart=/usr/local/bin/openwacht-zentrale starten\n"), 0o644)
	os.WriteFile(filepath.Join(etc, "openwacht-traps.socket"), []byte("[Socket]\nListenDatagram=162\n"), 0o644) // fremd
	os.WriteFile(filepath.Join(etc, "openwacht-sicherung.timer"), []byte("[Unit]\nDescription=OpenWacht: Datenbank nächtlich sichern\n"), 0o644)
	os.Symlink(filepath.Join(etc, "openwacht-zentrale.service"), filepath.Join(etc, "multi-user.target.wants", "openwacht-zentrale.service"))
	os.MkdirAll(filepath.Join(dir, etcDir), 0o750)
	in := &installer{root: dir, pkg: true, out: io.Discard}
	moved, err := in.moveLegacyUnits()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(moved, ",") != "openwacht-sicherung.timer,openwacht-zentrale.service" {
		t.Fatalf("verschoben: %v", moved)
	}
	if _, err := os.Stat(filepath.Join(dir, etcDir, "units-vor-paket", "openwacht-zentrale.service")); err != nil {
		t.Fatal("Sicherung fehlt")
	}
	if _, err := os.Lstat(filepath.Join(etc, "multi-user.target.wants", "openwacht-zentrale.service")); err == nil {
		t.Fatal("verwaister Verweis bleibt")
	}
	if _, err := os.Stat(filepath.Join(etc, "openwacht-traps.socket")); err != nil {
		t.Fatal("fremde Datei verschoben")
	}
	// ohne Paket bleiben eigene Units liegen (werden überschrieben)
	os.WriteFile(filepath.Join(etc, "openwacht-migrieren.service"), []byte(unitMarker+"\nExecStart=/opt/openwacht-zentrale migrieren\n"), 0o644)
	in.pkg = false
	if moved, _ := in.moveLegacyUnits(); len(moved) != 0 {
		t.Fatalf("eigene Unit verschoben: %v", moved)
	}
	in.pkg = true
	if moved, _ := in.moveLegacyUnits(); len(moved) != 1 {
		t.Fatalf("mit Paket muss auch die eigene Unit weichen: %v", moved)
	}
}

func TestUnitInhaltOhnePaket(t *testing.T) {
	in := &installer{self: "/opt/openwacht/openwacht-zentrale"}
	b, err := in.unitContent("openwacht-zentrale.service")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, unitMarker) || !strings.Contains(s, "ExecStart=/opt/openwacht/openwacht-zentrale starten") || strings.Contains(s, "/usr/bin/") {
		t.Fatalf("Unit:\n%s", s)
	}
}

// Der Socket wechselt vom Assistenten zur Zentrale, ohne zu schließen.
func TestConnQueueUebergabe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	q := newConnQueue(ln)
	serve := func(text string) (*http.Server, chan error) {
		hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, text) })}
		errc := make(chan error, 1)
		go func() { errc <- hs.Serve(q.listener()) }()
		return hs, errc
	}
	get := func() string {
		c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		r, err := c.Get("http://" + ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}
	a, aerr := serve("assistent")
	if got := get(); got != "assistent" {
		t.Fatal(got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown hängt: %v", err)
	}
	if err := <-aerr; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	serve("zentrale")
	for i := 0; i < 3; i++ {
		if got := get(); got != "zentrale" {
			t.Fatalf("Anfrage %d an %q", i, got)
		}
	}
}

func TestStripLegacyArgs(t *testing.T) {
	in := "# Kommentar -adresse x\nOPENWACHT_ARGS=-basis-url https://w.example -adresse 127.0.0.1:8443 -proxy=127.0.0.1/32 -agent-adresse 10.10.0.5:8444 -agent-namen w.example -check-netze 10.10.0.0/16\n"
	out, removed := stripLegacyArgs(in)
	if !strings.Contains(out, "OPENWACHT_ARGS=-agent-adresse 10.10.0.5:8444 -check-netze 10.10.0.0/16\n") || !strings.HasPrefix(out, "# Kommentar -adresse x") {
		t.Fatalf("%q", out)
	}
	if strings.Join(removed, " ") != "-basis-url -adresse -proxy -agent-namen" {
		t.Fatalf("%v", removed)
	}
}

// TestDiensteReihenfolge: Ohne Reverse Proxy hält installieren die Zentrale an,
// bevor es den Socket startet (systemd: „Socket service … already active,
// refusing“, im LXC 101 passiert). Hinter dem Proxy bleibt der Socket aus.
func TestDiensteReihenfolge(t *testing.T) {
	run := func(env string) []string {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, etcDir), 0o755)
		os.WriteFile(filepath.Join(dir, envPath), []byte(env), 0o640)
		var calls []string
		in := &installer{root: dir, out: io.Discard, services: true,
			systemctl: func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }}
		if err := in.startServices(); err != nil {
			t.Fatal(err)
		}
		return calls
	}
	idx := func(calls []string, s string) int {
		for i, c := range calls {
			if c == s {
				return i
			}
		}
		return -1
	}
	c := run(newEnv)
	stop, sock, restart := idx(c, "stop openwacht-zentrale.service"), idx(c, "enable --now openwacht-zentrale.socket"), idx(c, "restart openwacht-zentrale.service")
	if stop < 0 || sock < 0 || restart < 0 || !(stop < sock && sock < restart) {
		t.Errorf("Reihenfolge ohne Proxy: %v", c)
	}
	c = run("OPENWACHT_ARGS=-adresse 127.0.0.1:8443 -proxy 127.0.0.1/32\n")
	if idx(c, "enable --now openwacht-zentrale.socket") >= 0 || idx(c, "disable --now openwacht-zentrale.socket") < 0 {
		t.Errorf("hinter dem Proxy: %v", c)
	}
	if !strings.Contains(switchHint, "systemctl stop openwacht-zentrale\n    systemctl enable --now openwacht-zentrale.socket\n    systemctl start openwacht-zentrale") {
		t.Error("Hinweis nach https-umstieg in falscher Reihenfolge")
	}
}
