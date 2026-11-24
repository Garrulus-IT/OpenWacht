// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
)

func job(kind, target string) agentproto.SensorJob {
	return agentproto.SensorJob{ID: "00000000-0000-0000-0000-000000000001", Revision: 1, Kind: kind,
		Target: json.RawMessage(target), IntervalSeconds: 60}
}

func testEnv(now time.Time) *sensorEnv {
	return &sensorEnv{
		service: func(_ context.Context, name string) checks.Result {
			return checks.Result{Status: checks.OK, Message: "Dienst läuft", Metric: name}
		},
		processes: func(context.Context) ([]string, error) {
			return []string{"nginx", "nginx", "postgres", "very-long-proce"}, nil
		},
		now: func() time.Time { return now },
	}
}

func TestSensorFreigabeDatei(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Pfade unter Linux")
	}
	dir := t.TempDir()
	if _, err := ReadSensorConfig(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSensorConfig(dir, []string{"datei"}, nil, ""); err == nil {
		t.Error("datei ohne Ordner angenommen")
	}
	if _, err := WriteSensorConfig(dir, []string{"skript"}, nil, ""); err == nil {
		t.Error("unbekannte Art angenommen")
	}
	if _, err := WriteSensorConfig(dir, []string{"dienst"}, []string{"/var"}, ""); err == nil {
		t.Error("Ordner ohne datei angenommen")
	}
	rel, err := WriteSensorConfig(dir, []string{"dienst", "datei"}, []string{dir + "/frei"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadSensorConfig(dir)
	if err != nil || got == nil || strings.Join(got.Kinds, ",") != "dienst,datei" {
		t.Fatalf("gelesen: %+v %v", got, err)
	}
	// unbekannte Felder in der Datei werden abgelehnt
	os.WriteFile(filepath.Join(dir, fileSensors), []byte(`{"arten":["dienst"],"skript":"rm -rf /"}`), 0o644)
	if _, err := ReadSensorConfig(dir); err == nil {
		t.Error("unbekanntes Feld angenommen")
	}
	WriteSensorConfig(dir, rel.Kinds, rel.Folders, "")

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	free := filepath.Join(dir, "frei")
	secret := filepath.Join(dir, "geheim")
	os.MkdirAll(free, 0o755)
	os.MkdirAll(secret, 0o755)
	write := func(p string, size int, age time.Duration) {
		os.WriteFile(p, make([]byte, size), 0o644)
		os.Chtimes(p, now.Add(-age), now.Add(-age))
	}
	write(filepath.Join(free, "db.dump"), 2048, 30*time.Hour)
	write(filepath.Join(secret, "shadow"), 10, time.Hour)
	os.Symlink(filepath.Join(secret, "shadow"), filepath.Join(free, "link"))
	os.Symlink(secret, filepath.Join(free, "ordnerlink"))

	env := testEnv(now)
	ctx := context.Background()
	for _, tc := range []struct {
		target, status, msg string
	}{
		{`{"pfad":"` + free + `/db.dump","warnung_stunden":26,"kritisch_stunden":50}`, checks.Warn, "älter als 26 Std."},
		{`{"pfad":"` + free + `/db.dump","warnung_stunden":12,"kritisch_stunden":24}`, checks.Crit, "älter als 24 Std."},
		{`{"pfad":"` + free + `/db.dump","kritisch_stunden":48}`, checks.OK, "Datei aktuell"},
		{`{"pfad":"` + free + `/db.dump","mindestgroesse":4096}`, checks.Crit, "kleiner als 4,1 KB"},
		{`{"pfad":"` + free + `/fehlt","kritisch_stunden":1}`, checks.Crit, "Datei fehlt"},
		{`{"pfad":"` + free + `","ordner":true,"kritisch_stunden":48}`, checks.OK, "jüngster Eintrag"},
		{`{"pfad":"` + free + `/db.dump","ordner":true,"kritisch_stunden":48}`, checks.Crit, "kein Ordner"},
		// außerhalb der Freigabe: geprüft, bevor das Dateisystem gefragt wird
		{`{"pfad":"` + secret + `/shadow","kritisch_stunden":1}`, checks.Unknown, "nicht in einem freigegebenen Ordner"},
		{`{"pfad":"/etc/passwd","kritisch_stunden":1}`, checks.Unknown, "nicht in einem freigegebenen Ordner"},
		{`{"pfad":"` + dir + `/frei2/x","kritisch_stunden":1}`, checks.Unknown, "nicht in einem freigegebenen Ordner"},
		// Links aus dem freigegebenen Ordner hinaus
		{`{"pfad":"` + free + `/link","kritisch_stunden":1}`, checks.Unknown, "Link"},
		{`{"pfad":"` + free + `/ordnerlink/shadow","kritisch_stunden":1}`, checks.Unknown, "Link"},
		// Pfad mit .. lehnt schon die Prüfung der Parameter ab
		{`{"pfad":"` + free + `/../geheim/shadow","kritisch_stunden":1}`, checks.Unknown, "Parameter ungültig"},
	} {
		res := env.measure(ctx, rel, job("datei", tc.target))
		if res.Status != tc.status || !strings.Contains(res.Message, tc.msg) {
			t.Errorf("%s: %+v", tc.target, res)
		}
		if strings.Contains(res.Message+res.Metric, "shadow") || strings.Contains(res.Message+res.Metric, "db.dump") {
			t.Errorf("Name in der Meldung: %+v", res)
		}
	}
	// leerer Ordner
	empty := filepath.Join(free, "leer")
	os.Mkdir(empty, 0o755)
	if res := env.measure(ctx, rel, job("datei", `{"pfad":"`+empty+`","ordner":true,"kritisch_stunden":1}`)); res.Status != checks.Crit ||
		!strings.Contains(res.Message, "leer") {
		t.Errorf("leer: %+v", res)
	}
}

func TestSensorFreigabeArten(t *testing.T) {
	env := testEnv(time.Now())
	ctx := context.Background()
	rel := &agentproto.SensorRelease{Kinds: []string{"prozess"}}
	// Dienst nicht freigegeben: unbekannt mit Hinweis, Messfunktion nie gerufen
	called := false
	env.service = func(context.Context, string) checks.Result { called = true; return checks.Result{Status: checks.OK} }
	if res := env.measure(ctx, rel, job("dienst", `{"name":"nginx"}`)); res.Status != checks.Unknown ||
		!strings.Contains(res.Message, "nicht freigegeben") || called {
		t.Errorf("nicht freigegeben: %+v %v", res, called)
	}
	if res := env.measure(ctx, nil, job("prozess", `{"name":"nginx"}`)); res.Status != checks.Unknown {
		t.Errorf("ohne Freigabe: %+v", res)
	}
	// Art der Zentrale oder unbekannte Art: nie ausgeführt
	for _, k := range []string{"http", "skript"} {
		if res := env.measure(ctx, rel, job(k, `{"url":"http://x/"}`)); res.Status != checks.Unknown {
			t.Errorf("%s: %+v", k, res)
		}
	}
	// Parameter prüft der Agent selbst
	if res := env.measure(ctx, &agentproto.SensorRelease{Kinds: []string{"dienst"}}, job("dienst", `{"name":"-x; rm"}`)); res.Status != checks.Unknown ||
		!strings.Contains(res.Message, "Parameter ungültig") || called {
		t.Errorf("Parameter: %+v", res)
	}
	for _, tc := range []struct{ target, status, msg string }{
		{`{"name":"nginx"}`, checks.OK, "läuft"},
		{`{"name":"nginx","mindestens":3}`, checks.Crit, "weniger als 3"},
		{`{"name":"nginx","hoechstens":1}`, checks.Warn, "mehr als 1"},
		{`{"name":"apache2"}`, checks.Crit, "läuft nicht"},
		{`{"name":"very-long-process-name"}`, checks.OK, "läuft"}, // Linux kürzt auf 15 Zeichen
	} {
		res := env.measure(ctx, rel, job("prozess", tc.target))
		if runtime.GOOS == "windows" && strings.Contains(tc.target, "very") {
			continue
		}
		if res.Status != tc.status || !strings.Contains(res.Message, tc.msg) {
			t.Errorf("%s: %+v", tc.target, res)
		}
	}
	env.processes = func(context.Context) ([]string, error) { return nil, errors.New("nicht sichtbar") }
	if res := env.measure(ctx, rel, job("prozess", `{"name":"nginx"}`)); res.Status != checks.Unknown {
		t.Errorf("Fehler: %+v", res)
	}
}

func TestSensorAblauf(t *testing.T) {
	r := &Runner{dir: t.TempDir(), now: time.Now}
	c := newSensorRunner(r)
	c.env = testEnv(time.Now())
	// ungültige Einträge der Zentrale werden übersprungen
	for _, j := range []agentproto.SensorJob{
		{ID: "x", Revision: 1, Kind: "dienst", IntervalSeconds: 60},
		{ID: "00000000-0000-0000-0000-000000000002", Revision: 1, Kind: "http", IntervalSeconds: 60},
		{ID: "00000000-0000-0000-0000-000000000003", Revision: 1, Kind: "dienst", IntervalSeconds: 10},
	} {
		if validJob(j) {
			t.Errorf("angenommen: %+v", j)
		}
	}
	if !validJob(job("dienst", `{"name":"x"}`)) {
		t.Error("gültiger Eintrag abgelehnt")
	}
	// Zeitlimit: ein hängendes Dateisystem hält den Agent nicht auf
	old := sensorTimeout
	sensorTimeout = 200 * time.Millisecond
	defer func() { sensorTimeout = old }()
	c.env.service = func(ctx context.Context, _ string) checks.Result {
		time.Sleep(2 * time.Second)
		return checks.Result{Status: checks.OK}
	}
	start := time.Now()
	res := c.measureWithTimeout(context.Background(), &agentproto.SensorRelease{Kinds: []string{"dienst"}}, job("dienst", `{"name":"x"}`))
	if res.Status != checks.Unknown || time.Since(start) > time.Second {
		t.Errorf("Zeitlimit: %+v nach %v", res, time.Since(start))
	}
}

// TestSensorDateiLinkTausch (Befund N1): Ein lokaler Benutzer tauscht ein
// Verzeichnis im freigegebenen Ordner laufend gegen einen Link nach außen.
// Der Sensor darf dabei nie Alter oder Größe der Datei außerhalb melden.
func TestSensorDateiLinkTausch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Pfade unter Linux")
	}
	dir := t.TempDir()
	free, secret := filepath.Join(dir, "frei"), filepath.Join(dir, "geheim")
	os.MkdirAll(filepath.Join(free, "echt"), 0o755)
	os.MkdirAll(secret, 0o755)
	os.WriteFile(filepath.Join(free, "echt", "x"), make([]byte, 5), 0o644)
	os.WriteFile(filepath.Join(secret, "x"), make([]byte, 777), 0o644)
	os.Symlink(secret, filepath.Join(free, "link"))
	rel, err := WriteSensorConfig(dir, []string{"datei"}, []string{free}, "")
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv(time.Now())
	sub := filepath.Join(free, "sub")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Rename(filepath.Join(free, "echt"), sub)
			os.Rename(sub, filepath.Join(free, "echt"))
			os.Rename(filepath.Join(free, "link"), sub)
			os.Rename(sub, filepath.Join(free, "link"))
		}
	}()
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	var n, inside int
	for time.Now().Before(deadline) {
		res := env.measure(ctx, rel, job("datei", `{"pfad":"`+sub+`/x","kritisch_stunden":100}`))
		n++
		if strings.Contains(res.Metric, "777") {
			close(stop)
			<-done
			t.Fatalf("Datei außerhalb gemessen (Versuch %d): %+v", n, res)
		}
		if strings.Contains(res.Metric, "5 B") {
			inside++
		}
	}
	close(stop)
	<-done
	// Links direkt und als Zwischenverzeichnis bleiben abgelehnt.
	for _, p := range []string{filepath.Join(free, "link", "x"), filepath.Join(free, "link")} {
		res := env.measure(ctx, rel, job("datei", `{"pfad":"`+p+`","kritisch_stunden":100}`))
		if res.Status != checks.Unknown || !strings.Contains(res.Message, "Link") || res.Metric != "" {
			t.Errorf("%s: %+v", p, res)
		}
	}
	t.Logf("%d Messungen, %d davon innerhalb", n, inside)
}
