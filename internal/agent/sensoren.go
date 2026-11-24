// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Sensoren auf dem Agent (Etappe 18): Dienst läuft, Prozess läuft, Datei- oder
// Ordneralter.
//
// Leitprinzip 1 bleibt gewahrt:
//   - Der Agent holt bei der Zentrale nur eine Liste mit Art und Parametern
//     (Daten, keine Skripte, keine Befehle) und schickt Ergebnisse. Er öffnet
//     keinen Port.
//   - Gemessen wird nur, was auf diesem Rechner freigegeben ist
//     (openwacht-agent sensoren -arten … -ordner …). Eine übernommene Zentrale
//     kann keine Art einschalten und keine Datei außerhalb der freigegebenen
//     Ordner ansehen; geprüft wird hier, vor jedem Zugriff, auch hinter Links.
//   - Parameter prüft der Agent selbst noch einmal (checks.Parse), denn auch
//     die Zentrale ist für ihn nur eine Datenquelle.
//
// Leitprinzip 5: Prozesse nur nach Name gezählt, ohne Benutzer und
// Kommandozeile; von Dateien nur Alter und Größe, von Ordnern nur das Alter
// des jüngsten Eintrags, nie Namen oder Inhalte.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/safe"
)

// fileSensors: lokale Freigabe für Sensoren. Nur root bzw. Administratoren
// schreiben sie (openwacht-agent sensoren); der Dienst liest sie bei jedem
// Meldezyklus.
const fileSensors = "sensoren.json"

// ReadSensorConfig liest die Freigabe; nil ohne Fehler = nichts freigegeben.
func ReadSensorConfig(dir string) (*agentproto.SensorRelease, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileSensors))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r agentproto.SensorRelease
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s unlesbar: %w", fileSensors, err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", fileSensors, err)
	}
	return &r, nil
}

// WriteSensorConfig gibt Arten und Ordner frei. Ordner werden als absolute,
// saubere Pfade gespeichert; ob sie existieren, prüft erst die Messung.
func WriteSensorConfig(dir string, kinds, folders []string, docker string) (*agentproto.SensorRelease, error) {
	return WriteSensorRelease(dir, &agentproto.SensorRelease{Kinds: kinds, Folders: folders, Docker: docker})
}

// WriteSensorRelease schreibt die ganze Freigabe (seit 0.44.0 auch die
// Objekte der Leistungsindikatoren).
func WriteSensorRelease(dir string, r *agentproto.SensorRelease) (*agentproto.SensorRelease, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return r, writeFileAtomic(filepath.Join(dir, fileSensors), append(b, '\n'), 0o644)
}

// RemoveSensorConfig nimmt die Freigabe zurück.
func RemoveSensorConfig(dir string) error {
	err := os.Remove(filepath.Join(dir, fileSensors))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// --- Freigabe eines Pfads -------------------------------------------------------

func pathSep(p string) string {
	if strings.HasPrefix(p, "/") {
		return "/"
	}
	return `\`
}

// within: p liegt in root oder ist root. Unter Windows ohne Groß/Klein.
func within(p, root string) bool {
	if pathSep(p) != pathSep(root) {
		return false
	}
	if pathSep(p) == `\` {
		p, root = strings.ToLower(p), strings.ToLower(root)
	}
	if p == root {
		return true
	}
	sep := pathSep(root)
	return strings.HasPrefix(p, strings.TrimSuffix(root, sep)+sep)
}

func withinAny(p string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool { return within(p, r) })
}

// errOutside: Pfad außerhalb der Freigabe; die Meldung nennt den Pfad nicht
// weiter, als die Zentrale ihn ohnehin kennt.
var errOutside = errors.New("liegt nicht in einem freigegebenen Ordner")

// errViaLink: Der Pfad führt über einen Link aus dem freigegebenen Ordner hinaus.
var errViaLink = errors.New("führt über einen Link aus dem freigegebenen Ordner hinaus")

// openReleased öffnet p innerhalb eines freigegebenen Ordners: erst die
// Prüfung als Text (vor jedem Zugriff auf das Dateisystem), dann das Öffnen
// über os.Root des Ordners. os.Root folgt keinem Link, der den Ordner
// verlässt, auch nicht als Zwischenverzeichnis, und Stat läuft danach auf
// dem geöffneten Handle (fstat). So gibt es keine Lücke zwischen Prüfen und
// Lesen, in der jemand einen Link tauschen könnte (Befund N1).
func openReleased(p string, folders []string) (*os.File, error) {
	if !withinAny(p, folders) {
		return nil, errOutside
	}
	var firstErr error
	for _, f := range folders {
		if !within(p, f) {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(f), filepath.Clean(p))
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		file, err := openInRoot(f, rel)
		if err == nil {
			return file, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errOutside
	}
	return nil, firstErr
}

func openInRoot(folder, rel string) (*os.File, error) {
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, err
	}
	defer root.Close() // geöffnete Dateien bleiben gültig
	file, err := root.Open(rel)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) && strings.Contains(pe.Err.Error(), "escapes") {
			return nil, errViaLink
		}
		return nil, err
	}
	return file, nil
}

// --- Messen ---------------------------------------------------------------------

// sensorEnv: Messfunktionen je Betriebssystem, in Tests ersetzbar.
type sensorEnv struct {
	docker    func(ctx context.Context, base, name string) checks.Result
	service   func(ctx context.Context, name string) checks.Result
	processes func(ctx context.Context) ([]string, error)
	hyperv    func(ctx context.Context) ([]hypervVM, error)                    // nil: gibt es hier nicht
	perf      func(ctx context.Context, paths []string) ([][]perfValue, error) // nil: nur Windows
	now       func() time.Time

	hvMu   sync.Mutex // kurzer Zwischenspeicher der VM-Liste
	hvAt   time.Time
	hvList []hypervVM
	hvErr  error
}

// maxFolderEntries: mehr Einträge liest der Ordner-Sensor nicht.
const maxFolderEntries = 10000

func notReleased(kind string) checks.Result {
	hint := "openwacht-agent sensoren -arten " + kind
	switch kind {
	case "datei":
		hint += " -ordner <Ordner>"
	case "docker":
		hint += " -docker http://127.0.0.1:<Port>"
	case "leistungsindikator":
		hint += " -indikatoren <Objekt>"
	}
	return checks.Result{Status: checks.Unknown, Message: "am Rechner nicht freigegeben (" + hint + ")"}
}

// measure misst einen Sensor nach Prüfung von Art, Parametern und Freigabe.
func (e *sensorEnv) measure(ctx context.Context, rel *agentproto.SensorRelease, job agentproto.SensorJob) (res checks.Result) {
	defer func() {
		if p := recover(); safe.Handle("sensor", p) {
			res = checks.Result{Status: checks.Unknown, Message: "interner Fehler im Sensor"}
		}
	}()
	if !checks.IsAgentKind(job.Kind) {
		return checks.Result{Status: checks.Unknown, Message: "Art läuft nicht auf dem Agent"}
	}
	s, err := checks.Parse(job.Kind, job.Target)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Parameter ungültig: " + clipText(err.Error(), 200)}
	}
	if rel == nil || !slices.Contains(rel.Kinds, job.Kind) {
		return notReleased(job.Kind)
	}
	switch job.Kind {
	case "dienst":
		return e.service(ctx, s.Name)
	case "prozess":
		return e.process(ctx, s)
	case "datei":
		return e.file(s, rel.Folders)
	case "docker":
		return e.docker(ctx, rel.Docker, s.Name)
	case "hyperv":
		return e.hypervState(ctx, s.Name)
	case "leistungsindikator":
		if !rel.CounterReleased(s.Object) {
			return checks.Result{Status: checks.Unknown, Message: "Objekt " + clipText(s.Object, 60) +
				" am Rechner nicht freigegeben (openwacht-agent sensoren -indikatoren …)"}
		}
		return e.perfCounter(ctx, s)
	}
	return checks.Result{Status: checks.Unknown, Message: "unbekannte Art"}
}

// processMatch: Linux kürzt Prozessnamen (comm) auf 15 Zeichen, Windows
// hängt .exe an und unterscheidet nicht nach Groß/Klein.
func processMatch(have, want string) bool {
	if runtime.GOOS == "windows" {
		h, w := strings.ToLower(have), strings.ToLower(want)
		return h == w || h == w+".exe"
	}
	return have == want || len(want) > 15 && have == want[:15]
}

func (e *sensorEnv) process(ctx context.Context, s checks.Spec) checks.Result {
	names, err := e.processes(ctx)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: clipText(err.Error(), 250)}
	}
	n := 0
	for _, x := range names {
		if processMatch(x, s.Name) {
			n++
		}
	}
	metric := fmt.Sprintf("%d laufend", n)
	switch {
	case n == 0 && s.Min > 0:
		return checks.Result{Status: checks.Crit, Message: "Prozess " + s.Name + " läuft nicht", Metric: metric}
	case n < s.Min:
		return checks.Result{Status: checks.Crit, Message: fmt.Sprintf("weniger als %d Prozesse %s", s.Min, s.Name), Metric: metric}
	case s.Max > 0 && n > s.Max:
		return checks.Result{Status: checks.Warn, Message: fmt.Sprintf("mehr als %d Prozesse %s", s.Max, s.Name), Metric: metric}
	}
	return checks.Result{Status: checks.OK, Message: "Prozess " + s.Name + " läuft", Metric: metric}
}

func ageText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("vor %d Std. %d Min.", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("vor %d Tagen", int(d.Hours()/24))
}

func sizeText(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v, i := float64(b), 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", b)
	}
	return strings.Replace(fmt.Sprintf("%.1f %s", v, units[i]), ".", ",", 1)
}

func hoursText(h float64) string {
	return strings.Replace(strings.TrimSuffix(fmt.Sprintf("%.1f", h), ".0"), ".", ",", 1) + " Std."
}

func fsError(err error, what string) checks.Result {
	switch {
	case errors.Is(err, errOutside):
		return checks.Result{Status: checks.Unknown, Message: "Pfad " + errOutside.Error() + " (openwacht-agent sensoren -ordner …)"}
	case errors.Is(err, fs.ErrNotExist):
		return checks.Result{Status: checks.Crit, Message: what + " fehlt"}
	case errors.Is(err, fs.ErrPermission):
		return checks.Result{Status: checks.Unknown, Message: "kein Zugriff (Rechte des Dienstkontos des Agents)"}
	}
	return checks.Result{Status: checks.Unknown, Message: what + " nicht lesbar: " + clipText(err.Error(), 150)}
}

// file bewertet Alter (und Größe) einer Datei bzw. das Alter des jüngsten
// Eintrags eines Ordners. Gemeldet werden nie Namen oder Inhalte.
func (e *sensorEnv) file(s checks.Spec, folders []string) checks.Result {
	what := "Datei"
	if s.Folder {
		what = "Ordner"
	}
	h, err := openReleased(s.Path, folders)
	if err != nil {
		return fsError(err, what)
	}
	defer h.Close()
	fi, err := h.Stat()
	if err != nil {
		return fsError(err, what)
	}
	var mod time.Time
	var size int64
	switch {
	case s.Folder && !fi.IsDir():
		return checks.Result{Status: checks.Crit, Message: "ist kein Ordner"}
	case !s.Folder && !fi.Mode().IsRegular():
		return checks.Result{Status: checks.Crit, Message: "ist keine Datei"}
	case s.Folder:
		entries, err := h.ReadDir(maxFolderEntries)
		if err != nil && len(entries) == 0 {
			if errors.Is(err, io.EOF) {
				return checks.Result{Status: checks.Crit, Message: "Ordner ist leer"}
			}
			return fsError(err, what)
		}
		for _, en := range entries {
			if info, err := en.Info(); err == nil && info.ModTime().After(mod) {
				mod = info.ModTime()
			}
		}
		if mod.IsZero() {
			return checks.Result{Status: checks.Crit, Message: "Ordner ist leer"}
		}
	default:
		mod, size = fi.ModTime(), fi.Size()
	}
	age := max(e.now().Sub(mod), 0)
	metric := ageText(age)
	if !s.Folder {
		metric += ", " + sizeText(size)
	}
	hours := age.Hours()
	switch {
	case s.MinBytes > 0 && size < s.MinBytes:
		return checks.Result{Status: checks.Crit, Message: "kleiner als " + sizeText(s.MinBytes), Metric: metric}
	case s.CritHours > 0 && hours >= s.CritHours:
		return checks.Result{Status: checks.Crit, Message: "älter als " + hoursText(s.CritHours), Metric: metric}
	case s.WarnHours > 0 && hours >= s.WarnHours:
		return checks.Result{Status: checks.Warn, Message: "älter als " + hoursText(s.WarnHours), Metric: metric}
	}
	if s.Folder {
		return checks.Result{Status: checks.OK, Message: "jüngster Eintrag aktuell", Metric: metric}
	}
	return checks.Result{Status: checks.OK, Message: "Datei aktuell", Metric: metric}
}

func clipText(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// --- Ablauf -----------------------------------------------------------------------

const (
	sensorTick     = 5 * time.Second
	sensorParallel = 4
)

// sensorTimeout: längste Messung (in Tests kürzer).
var sensorTimeout = 10 * time.Second

type sensorJob struct {
	job     agentproto.SensorJob
	next    time.Time
	running bool
}

// sensorRunner holt die Liste, misst fällige Sensoren und schickt die
// Ergebnisse gesammelt, höchstens einmal je sensorTick.
type sensorRunner struct {
	r    *Runner
	env  *sensorEnv
	kick chan struct{}

	mu      sync.Mutex
	state   string
	jobs    map[string]*sensorJob
	pending []agentproto.SensorResult
}

func newSensorRunner(r *Runner) *sensorRunner {
	return &sensorRunner{r: r, env: defaultSensorEnv(), kick: make(chan struct{}, 1), jobs: map[string]*sensorJob{}}
}

func (c *sensorRunner) trigger() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *sensorRunner) run(ctx context.Context) {
	tick := time.NewTicker(sensorTick)
	defer tick.Stop()
	sem := make(chan struct{}, sensorParallel)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
			if err := c.sync(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("Sensoren: Liste nicht abgeglichen", "fehler", err)
			}
		case <-tick.C:
		}
		rel, err := ReadSensorConfig(c.r.dir)
		if err != nil {
			slog.Warn("Sensoren: lokale Freigabe unlesbar, alle Sensoren gelten als nicht freigegeben", "fehler", err)
			rel = nil
		}
		now := c.r.now()
		c.mu.Lock()
		for _, j := range c.jobs {
			if j.running || now.Before(j.next) || len(sem) == cap(sem) {
				continue
			}
			sem <- struct{}{}
			j.running = true
			j.next = now.Add(time.Duration(j.job.IntervalSeconds) * time.Second)
			wg.Add(1)
			go func(j *sensorJob) {
				defer func() { <-sem; wg.Done() }()
				res := c.measureWithTimeout(ctx, rel, j.job)
				c.mu.Lock()
				j.running = false
				c.pending = append(c.pending, agentproto.SensorResult{ID: j.job.ID, Revision: j.job.Revision,
					Status: res.Status, Message: clipText(res.Message, 300), Metric: clipText(res.Metric, 50)})
				c.mu.Unlock()
			}(j)
		}
		c.mu.Unlock()
		c.flush(ctx)
	}
}

// measureWithTimeout: Ein hängendes Dateisystem (NFS) darf den Agent nicht
// aufhalten. Die Messung läuft dann im Hintergrund zu Ende und wird verworfen.
func (c *sensorRunner) measureWithTimeout(ctx context.Context, rel *agentproto.SensorRelease, job agentproto.SensorJob) checks.Result {
	ctx, cancel := context.WithTimeout(ctx, sensorTimeout)
	defer cancel()
	done := make(chan checks.Result, 1)
	go func() { done <- c.env.measure(ctx, rel, job) }()
	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		return checks.Result{Status: checks.Unknown, Message: "Messung dauerte länger als " + sensorTimeout.String()}
	}
}

func (c *sensorRunner) flush(ctx context.Context) {
	c.mu.Lock()
	n := min(len(c.pending), agentproto.MaxSensorResults)
	batch := append([]agentproto.SensorResult(nil), c.pending[:n]...)
	c.mu.Unlock()
	if n == 0 {
		return
	}
	status, err := postJSON(ctx, c.r.client, c.r.zentrale.String()+agentproto.PathSensorResults,
		agentproto.SensorResultsRequest{Results: batch}, nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil, status == http.StatusBadRequest, status == http.StatusUnauthorized:
		// angenommen oder endgültig abgelehnt: nicht noch einmal schicken
		c.pending = c.pending[n:]
		if err != nil {
			slog.Warn("Sensoren: Ergebnisse abgelehnt", "fehler", err)
		}
	default:
		// später erneut; höchstens zwei Pakete aufheben
		if len(c.pending) > 2*agentproto.MaxSensorResults {
			c.pending = c.pending[len(c.pending)-2*agentproto.MaxSensorResults:]
		}
		if ctx.Err() == nil {
			slog.Warn("Sensoren: Ergebnisse nicht gesendet", "fehler", err)
		}
	}
}

// validJob prüft einen Eintrag der Zentrale (auch sie ist für den Agent nur
// eine Datenquelle). Die Parameter prüft measure vor jeder Messung.
func validJob(j agentproto.SensorJob) bool {
	return validID(j.ID) && j.Revision >= 1 && checks.IsAgentKind(j.Kind) &&
		j.IntervalSeconds >= 60 && j.IntervalSeconds <= 86400 && len(j.Target) <= 32<<10
}

func (c *sensorRunner) sync(ctx context.Context) error {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	var resp agentproto.SensorJobsResponse
	status, err := postJSONLimit(ctx, c.r.client, c.r.zentrale.String()+agentproto.PathSensorJobs,
		agentproto.SensorJobsRequest{State: state}, &resp, 2<<20)
	if err != nil {
		if status == http.StatusUnauthorized {
			c.mu.Lock()
			c.jobs, c.state = map[string]*sensorJob{}, ""
			c.mu.Unlock()
		}
		if status == http.StatusNotFound {
			return nil // ältere Zentrale ohne Sensoren
		}
		return err
	}
	now := c.r.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !resp.Unchanged {
		if len(resp.Sensors) > agentproto.MaxSensorJobs {
			return fmt.Errorf("Zentrale schickt %d Sensoren, höchstens %d", len(resp.Sensors), agentproto.MaxSensorJobs)
		}
		jobs := make(map[string]*sensorJob, len(resp.Sensors))
		spread := min(15*time.Second, time.Duration(len(resp.Sensors))*100*time.Millisecond)
		for _, j := range resp.Sensors {
			if !validJob(j) {
				slog.Warn("Sensoren: Eintrag übersprungen", "sensor", clipText(j.ID, 40))
				continue
			}
			sj := &sensorJob{job: j}
			if old := c.jobs[j.ID]; old != nil && old.job.Revision == j.Revision {
				old.job = j
				sj = old
			} else {
				sj.next = now.Add(time.Duration(rand.Int64N(int64(spread) + 1)))
			}
			jobs[j.ID] = sj
		}
		if len(jobs) != len(c.jobs) {
			slog.Info("Sensoren: Liste übernommen", "sensoren", len(jobs))
		}
		c.jobs = jobs
		c.state = resp.State
	}
	for _, id := range resp.Due {
		if j := c.jobs[id]; j != nil && !j.running {
			j.next = now
		}
	}
	return nil
}
