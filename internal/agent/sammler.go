// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Agent als Sammler (Etappe 15): Der Agent fragt SNMP-Geräte in seinem Netz
// ab, die die Zentrale nicht erreicht (Außenstelle, Fertigung).
//
// Leitprinzip 1 bleibt gewahrt:
//   - Der Agent holt Geräteliste und Zugangsdaten bei der Zentrale ab (Daten,
//     kein Code) und schickt Ergebnisse. Er öffnet keinen Port, auch nicht
//     für Traps.
//   - Gesammelt wird nur nach lokaler Freigabe auf diesem Rechner
//     (openwacht-agent sammler -netze …), und nur in diesen Netzen. Eine
//     übernommene Zentrale kann den Agent weder einschalten noch auf andere
//     Adressen lenken; geprüft wird vor jedem connect() (checks.Guard).
//   - Zugangsdaten liegen nur im Speicher, nie auf der Platte und nie im Log.
//   - Abgefragt wird nur lesend (GET, GETNEXT, GETBULK).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// fileCollector: lokale Freigabe als Sammler. Nur root schreibt sie
// (openwacht-agent sammler); der Dienst liest sie bei jedem Meldezyklus.
const fileCollector = "sammler.json"

type collectorConfig struct {
	Nets []string `json:"netze"`
}

// ReadCollectorConfig liest die lokale Freigabe; nil ohne Fehler = nicht freigegeben.
func ReadCollectorConfig(dir string) ([]netip.Prefix, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileCollector))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c collectorConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s unlesbar: %w", fileCollector, err)
	}
	nets, err := agentproto.ParseCollectorNets(c.Nets)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileCollector, err)
	}
	return nets, nil
}

// WriteCollectorConfig gibt den Agent als Sammler für die Netze frei.
func WriteCollectorConfig(dir string, nets []string) ([]netip.Prefix, error) {
	parsed, err := agentproto.ParseCollectorNets(nets)
	if err != nil {
		return nil, err
	}
	canon := make([]string, len(parsed))
	for i, p := range parsed {
		canon[i] = p.String()
	}
	b, _ := json.MarshalIndent(collectorConfig{Nets: canon}, "", "  ")
	return parsed, writeFileAtomic(filepath.Join(dir, fileCollector), append(b, '\n'), 0o644)
}

// RemoveCollectorConfig nimmt die Freigabe zurück.
func RemoveCollectorConfig(dir string) error {
	err := os.Remove(filepath.Join(dir, fileCollector))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func netStrings(nets []netip.Prefix) []string {
	out := make([]string, len(nets))
	for i, p := range nets {
		out[i] = p.String()
	}
	return out
}

// Grenzen des Sammlers.
const (
	collectorParallel = 4
	collectorTick     = time.Second
)

type collectorJob struct {
	dev     agentproto.CollectorDevice
	cfg     snmp.Config
	next    time.Time
	running bool
}

// snmpCollector fragt die zugewiesenen Geräte ab.
type snmpCollector struct {
	r    *Runner
	kick chan struct{}

	mu     sync.Mutex
	nets   []netip.Prefix
	client *snmp.Client
	state  string
	jobs   map[string]*collectorJob
	// poll: Abfrage, in Tests ersetzbar
	poll func(ctx context.Context, c *snmp.Client, cfg snmp.Config) (*snmp.Snapshot, error)
}

func newSNMPCollector(r *Runner) *snmpCollector {
	return &snmpCollector{r: r, kick: make(chan struct{}, 1), jobs: map[string]*collectorJob{},
		poll: func(ctx context.Context, c *snmp.Client, cfg snmp.Config) (*snmp.Snapshot, error) {
			// ohne vorige Werte: die Raten rechnet die Zentrale
			return c.Poll(ctx, cfg, nil)
		}}
}

// trigger: nach einer Meldung die Geräteliste abgleichen (nicht blockierend).
func (c *snmpCollector) trigger() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *snmpCollector) run(ctx context.Context) {
	tick := time.NewTicker(collectorTick)
	defer tick.Stop()
	sem := make(chan struct{}, collectorParallel)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
			if err := c.sync(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("Sammler: Geräteliste nicht abgeglichen", "fehler", err)
			}
		case <-tick.C:
		}
		now := c.r.now()
		c.mu.Lock()
		var due []*collectorJob
		for _, j := range c.jobs {
			if !j.running && !now.Before(j.next) {
				due = append(due, j)
			}
		}
		slices.SortFunc(due, func(a, b *collectorJob) int { return a.next.Compare(b.next) })
		client := c.client
		for _, j := range due {
			if len(sem) == cap(sem) {
				break
			}
			sem <- struct{}{}
			j.running = true
			// Takt ab dem geplanten Zeitpunkt, nicht ab dem Ende der Abfrage
			j.next = now.Add(time.Duration(j.dev.IntervalSeconds) * time.Second)
			wg.Add(1)
			go func(j *collectorJob) {
				defer func() { <-sem; wg.Done() }()
				c.pollOne(ctx, client, j)
			}(j)
		}
		c.mu.Unlock()
	}
}

// sync holt die Geräteliste. Ohne lokale Freigabe werden alle Geräte und
// Zugangsdaten verworfen.
func (c *snmpCollector) sync(ctx context.Context) error {
	nets, err := ReadCollectorConfig(c.r.dir)
	if err != nil || nets == nil {
		c.mu.Lock()
		if len(c.jobs) > 0 {
			slog.Info("Sammler: lokal nicht freigegeben, Geräteliste verworfen", "geraete", len(c.jobs))
		}
		c.jobs, c.state, c.nets, c.client = map[string]*collectorJob{}, "", nil, nil
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	if !slices.Equal(c.nets, nets) || c.client == nil {
		c.nets = nets
		c.client = &snmp.Client{Guard: checks.NewGuard(nets)}
	}
	state := c.state
	c.mu.Unlock()

	var resp agentproto.CollectorDevicesResponse
	status, err := postJSONLimit(ctx, c.r.client, c.r.zentrale.String()+agentproto.PathCollectorDevices,
		agentproto.CollectorDevicesRequest{State: state}, &resp, 2<<20)
	if err != nil {
		if status == http.StatusUnauthorized {
			c.clear()
		}
		return err
	}
	now := c.r.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !resp.Unchanged {
		if len(resp.Devices) > agentproto.MaxCollectorDevices {
			return fmt.Errorf("Zentrale schickt %d Geräte, höchstens %d", len(resp.Devices), agentproto.MaxCollectorDevices)
		}
		jobs := make(map[string]*collectorJob, len(resp.Devices))
		// neue Geräte gestreut, je Gerät 100 ms, höchstens über 15 s
		spread := min(15*time.Second, time.Duration(len(resp.Devices))*100*time.Millisecond)
		for _, d := range resp.Devices {
			cfg, err := deviceConfig(d)
			if err != nil {
				slog.Warn("Sammler: Gerät übersprungen", "quelle", d.ID, "fehler", err)
				continue
			}
			j := &collectorJob{dev: d, cfg: cfg}
			if old := c.jobs[d.ID]; old != nil && old.dev.Revision == d.Revision {
				j.next, j.running = old.next, old.running
				*old = *j // laufende Abfrage schreibt in denselben Eintrag
				j = old
			} else {
				j.next = now.Add(time.Duration(rand.Int64N(int64(spread) + 1)))
			}
			jobs[d.ID] = j
		}
		c.jobs = jobs
		c.state = resp.State
		slog.Info("Sammler: Geräteliste übernommen", "geraete", len(jobs))
	}
	for _, id := range resp.Due {
		if j := c.jobs[id]; j != nil && !j.running {
			j.next = now
		}
	}
	return nil
}

func (c *snmpCollector) clear() {
	c.mu.Lock()
	c.jobs, c.state = map[string]*collectorJob{}, ""
	c.mu.Unlock()
}

// deviceConfig prüft einen Eintrag der Zentrale (auch sie ist für den Agent
// nur eine Datenquelle) und baut die Abfrage.
func deviceConfig(d agentproto.CollectorDevice) (snmp.Config, error) {
	if !validID(d.ID) || d.Revision < 1 || d.Port < 1 || d.Port > 65535 || d.IntervalSeconds < 30 || d.IntervalSeconds > 3600 {
		return snmp.Config{}, errors.New("Eintrag unplausibel")
	}
	if !checks.ValidHost(d.Host) {
		if _, err := netip.ParseAddr(d.Host); err != nil {
			return snmp.Config{}, errors.New("Adresse ungültig")
		}
	}
	cfg := snmp.Config{Version: d.Version, Host: d.Host, Port: uint16(d.Port)}
	switch d.Version {
	case snmp.V1, snmp.V2c:
		if !snmp.ValidCommunity(d.Community) || d.V3 != nil {
			return snmp.Config{}, errors.New("Community ungültig")
		}
		cfg.Community = d.Community
	case snmp.V3:
		if d.V3 == nil || d.Community != "" {
			return snmp.Config{}, errors.New("v3-Zugangsdaten fehlen")
		}
		cfg.V3 = &snmp.V3Auth{User: d.V3.User, Auth: d.V3.Auth, AuthPass: d.V3.AuthPass, Priv: d.V3.Priv, PrivPass: d.V3.PrivPass}
		if err := cfg.V3.Validate(); err != nil {
			return snmp.Config{}, err
		}
	default:
		return snmp.Config{}, errors.New("Version nicht unterstützt")
	}
	// Eigene OIDs (Etappe 18b): nur lesend, Anzahl und Form geprüft
	if err := snmp.CheckExtraOIDs(d.Extra); err != nil {
		return snmp.Config{}, err
	}
	cfg.Extra = d.Extra
	for _, t := range d.ExtraText {
		cfg.ExtraText = append(cfg.ExtraText, snmp.TextZahl{OID: t.OID, N: t.N, Nach: t.Nach})
	}
	if err := snmp.CheckExtraText(cfg.ExtraText, d.Extra); err != nil {
		return snmp.Config{}, err
	}
	if err := snmp.CheckExtraShow(d.ExtraShow, d.Extra); err != nil {
		return snmp.Config{}, err
	}
	cfg.ExtraShow = d.ExtraShow
	if err := snmp.CheckColumns(d.Columns); err != nil {
		return snmp.Config{}, err
	}
	cfg.Columns = d.Columns
	return cfg, nil
}

func validID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// collectorError: Fehlermeldung aus Sicht des Sammlers (die Texte des
// SNMP-Pakets sprechen von der Zentrale).
func collectorError(err error, nets []netip.Prefix) string {
	var na *checks.NotAllowedError
	switch {
	case errors.As(err, &na):
		return fmt.Sprintf("Adresse %s liegt nicht in den Netzen, die der Sammler freigegeben hat (%s)", na.Addr,
			joinNets(nets))
	case errors.Is(err, snmp.ErrNoResponse):
		return "keine Antwort (Adresse, Port, Zugangsdaten und Erreichbarkeit vom Sammler aus prüfen)"
	}
	return err.Error()
}

func joinNets(nets []netip.Prefix) string {
	s := ""
	for i, n := range netStrings(nets) {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}

func (c *snmpCollector) pollOne(ctx context.Context, client *snmp.Client, j *collectorJob) {
	c.mu.Lock()
	dev, cfg, nets := j.dev, j.cfg, c.nets
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		j.running = false
		c.mu.Unlock()
	}()
	if client == nil {
		return
	}
	res := agentproto.CollectorResult{ID: dev.ID, Revision: dev.Revision}
	snap, err := c.poll(ctx, client, cfg)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		res.Error = collectorError(err, nets)
	} else if res.Snapshot, err = json.Marshal(snap); err != nil {
		res.Error = "Messwerte nicht darstellbar"
	} else {
		res.OK = true
	}
	status, err := postJSON(ctx, c.r.client, c.r.zentrale.String()+agentproto.PathCollectorResult, res, nil)
	switch {
	case err == nil:
	case status == http.StatusConflict || status == http.StatusNotFound:
		// Gerät geändert oder nicht mehr zugewiesen: beim nächsten Abgleich neu holen
		c.mu.Lock()
		c.state = ""
		c.mu.Unlock()
		c.trigger()
	case ctx.Err() == nil:
		slog.Warn("Sammler: Ergebnis nicht gesendet", "quelle", dev.ID, "fehler", err)
	}
}
