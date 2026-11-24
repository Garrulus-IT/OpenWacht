// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Einstellungen in der Oberfläche (Etappe 19).
//
// Was früher nur per Startoption ging (Netzfreigabe, Alarmziele, Totmann,
// Schwellen, -stumm-nach), liegt jetzt in der Datenbank und lässt sich auf
// der Seite Einstellungen ändern, aber nur vom Betreiber (Kennzeichen am
// Benutzer, vergeben per Shell, mit Zwei-Faktor-Anmeldung).
//
// Vorrang (Entscheidung, 21.11.2026): Eine gesetzte Startoption gewinnt. Beim Start
// übernimmt die Zentrale sie einmalig in die Datenbank, wenn das Feld dort
// noch keinen Wert hat; solange sie in der Unit steht, ist das Feld in der
// Oberfläche gesperrt. Ohne Startoption gilt der Wert aus der Datenbank, ohne
// beides der Standard.
//
// Je Mandant gibt es eigene Netze (grenzen nur ein, entlang des Baums) und
// Schwellen; je Gerät eigene Schwellen. Für Netzfreigabe, Alarmziele und
// Totmann verlangt die Zentrale beim Speichern einen frischen 2FA-Code.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
	"github.com/garrulus-it/openwacht/internal/verzeichnis"
)

// Namen der Felder, wie sie in Config.Pinned, der API und der Oberfläche heißen.
const (
	setNets     = "netze"
	setTargets  = "alarmziele"
	setDeadMan  = "totmann"
	setSilent   = "stumm_nach_s"
	setDiskWarn = "platte_warn"
	setDiskCrit = "platte_krit"
	setMemWarn  = "speicher_warn"
	setMemCrit  = "speicher_krit"
	setCPUWarn  = "cpu_warn"
	setCPUCrit  = "cpu_krit"
	// setDiskDays: Warnung, wenn die Platten-Prognose weniger Tage ergibt (Etappe 20b)
	setDiskDays = "platte_tage"
)

// limitFields: die Schwellen in fester Reihenfolge (API, DB, Oberfläche).
var limitFields = []string{setSilent, setDiskWarn, setDiskCrit, setMemWarn, setMemCrit, setCPUWarn, setCPUCrit, setDiskDays}

// Standardwerte, wenn weder Startoption noch Datenbank etwas sagen.
var limitDefaults = map[string]float64{setSilent: 180, setDiskWarn: 90, setDiskCrit: 95, setMemWarn: 90,
	setMemCrit: 95, setCPUWarn: 90, setCPUCrit: 98, setDiskDays: 14}

// limitRow: Schwellen aus der Datenbank, NULL = erbt bzw. Standard, 0 = aus.
type limitRow [8]*float64

func (l *limitRow) dest() []any {
	return []any{&l[0], &l[1], &l[2], &l[3], &l[4], &l[5], &l[6], &l[7]}
}

func (l limitRow) empty() bool {
	for _, v := range l {
		if v != nil {
			return false
		}
	}
	return true
}

// apply überschreibt die gesetzten Felder in lim.
func (l limitRow) apply(lim alarm.HostLimits) alarm.HostLimits {
	set := func(i int, f *float64) {
		if l[i] != nil {
			*f = *l[i]
		}
	}
	if l[0] != nil {
		lim.SilentAfter = time.Duration(*l[0]) * time.Second
	}
	set(1, &lim.DiskWarn)
	set(2, &lim.DiskCrit)
	set(3, &lim.MemWarn)
	set(4, &lim.MemCrit)
	set(5, &lim.CPUWarn)
	set(6, &lim.CPUCrit)
	set(7, &lim.DiskDays)
	return lim
}

func (l limitRow) json() map[string]*float64 {
	out := make(map[string]*float64, len(limitFields))
	for i, f := range limitFields {
		out[f] = l[i]
	}
	return out
}

// limitsJSON: wirksame Schwellen für die Oberfläche (0 = aus).
func limitsJSON(l alarm.HostLimits) map[string]float64 {
	return map[string]float64{setSilent: l.SilentAfter.Seconds(), setDiskWarn: l.DiskWarn, setDiskCrit: l.DiskCrit,
		setMemWarn: l.MemWarn, setMemCrit: l.MemCrit, setCPUWarn: l.CPUWarn, setCPUCrit: l.CPUCrit, setDiskDays: l.DiskDays}
}

// dbSettings: die Zeile openwacht.settings.
type dbSettings struct {
	nets    []netip.Prefix // nil = nie gesetzt
	netsSet bool
	targets []string
	tgtSet  bool
	deadEnc []byte // nil = nie gesetzt, leer = aus
	limits  limitRow
}

// liveSettings: was die Zentrale gerade anwendet.
type liveSettings struct {
	mu        sync.RWMutex
	limits    alarm.HostLimits            // global wirksam
	overrides map[string]alarm.HostLimits // "agent:<id>" bzw. "snmp:<id>", vollständig aufgelöst
	chains    map[string][][]netip.Prefix // Mandant → Netzlisten der Kette
	db        dbSettings
	deadURL   string            // wirksame Ping-Adresse ("" = aus)
	mail      *alarm.SMTPConfig // nil = Mailversand nicht eingerichtet
	loaded    time.Time
	zone      *time.Location // Zeitzone der Installation (Mails, neue Wartungsfenster)
	zoneName  string
}

// zone: Zeitzone der Installation (Standard Europe/Berlin).
func (s *Server) zone() (*time.Location, string) {
	s.live.mu.RLock()
	defer s.live.mu.RUnlock()
	if s.live.zone == nil {
		return defaultZone, DefaultZoneName
	}
	return s.live.zone, s.live.zoneName
}

// hostLimits: die globalen Schwellen (ohne Abweichungen je Mandant/Gerät).
func (s *Server) hostLimits() alarm.HostLimits {
	s.live.mu.RLock()
	defer s.live.mu.RUnlock()
	return s.live.limits
}

// limitsFor: Schwellen für einen Agent ("agent") oder eine Abfragequelle ("snmp").
func (s *Server) limitsFor(kind, id string) alarm.HostLimits {
	s.live.mu.RLock()
	defer s.live.mu.RUnlock()
	if l, ok := s.live.overrides[kind+":"+id]; ok {
		return l
	}
	return s.live.limits
}

// netChains: Netzlisten des Mandanten und seiner Vorfahren (leer = keine Eingrenzung).
func (s *Server) netChains(tenant string) [][]netip.Prefix {
	s.live.mu.RLock()
	defer s.live.mu.RUnlock()
	return s.live.chains[tenant]
}

// guardFor: der Guard für Verbindungen im Auftrag eines Mandanten.
func (s *Server) guardFor(tenant string) *checks.Guard {
	return s.guard.Restrict(s.netChains(tenant))
}

func (s *Server) runnerFor(tenant string) *checks.Runner {
	g := s.guardFor(tenant)
	if g == s.checker.Guard {
		return s.checker
	}
	r := *s.checker
	r.Guard = g
	return &r
}

func (s *Server) snmpFor(tenant string) *snmp.Client {
	if len(s.netChains(tenant)) == 0 {
		return s.snmp
	}
	c := *s.snmp
	c.Guard = s.guardFor(tenant)
	return &c
}

func (s *Server) pveFor(tenant string) *pve.Client {
	if len(s.netChains(tenant)) == 0 {
		return s.pve
	}
	c := *s.pve
	c.Guard = s.guardFor(tenant)
	return &c
}

func (s *Server) tr064For(tenant string) *tr064.Client {
	if len(s.netChains(tenant)) == 0 {
		return s.tr064
	}
	c := *s.tr064
	c.Guard = s.guardFor(tenant)
	return &c
}

// pinned: Gilt für das Feld die Startoption (oder ist die Datenbank aus)?
func (s *Server) pinned(field string) bool {
	return !s.cfg.SettingsFromDB || s.cfg.Pinned[field]
}

// cfgLimit: Wert der Startoption bzw. aus Config (0 = aus).
func (s *Server) cfgLimit(field string) float64 {
	pos := func(v float64) float64 { return max(v, 0) }
	c := s.cfg
	switch field {
	case setSilent:
		return c.HostSilentAfter.Seconds()
	case setDiskWarn:
		return pos(c.DiskWarn)
	case setDiskCrit:
		return pos(c.DiskCrit)
	case setMemWarn:
		return pos(c.MemWarn)
	case setMemCrit:
		return pos(c.MemCrit)
	case setCPUWarn:
		return pos(c.CPUWarn)
	case setCPUCrit:
		return pos(c.CPUCrit)
	case setDiskDays:
		return pos(c.DiskDays)
	}
	return 0
}

func (s *Server) deadManKey() []byte { return deriveKey(s.boxKey, "openwacht totmann v1") }

var deadManAAD = []byte("openwacht totmann v1")

func (s *Server) sealDeadMan(raw string) ([]byte, error) {
	if raw == "" {
		return []byte{}, nil
	}
	return auth.Seal(s.deadManKey(), []byte(raw), deadManAAD)
}

func (s *Server) openDeadMan(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	b, err := auth.Open(s.deadManKey(), enc, deadManAAD)
	return string(b), err
}

func readDBSettings(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sql string) (dbSettings, error) {
	var d dbSettings
	var nets []netip.Prefix
	var targets []string
	var silent *int32
	var l limitRow
	if err := q.QueryRow(ctx, sql).Scan(&nets, &targets, &d.deadEnc, &silent, l.dest()[1], l.dest()[2], l.dest()[3],
		l.dest()[4], l.dest()[5], l.dest()[6], l.dest()[7]); err != nil {
		return d, err
	}
	if silent != nil {
		v := float64(*silent)
		l[0] = &v
	}
	d.limits = l
	d.nets, d.netsSet = nets, nets != nil
	d.targets, d.tgtSet = targets, targets != nil
	return d, nil
}

const settingsColumns = `check_nets, alert_targets, deadman_enc, silent_s, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit, disk_days`

// ImportStartOptions übernimmt gesetzte Startoptionen in die Datenbank, wo das
// Feld noch leer ist (einmalig, beim Start). Liefert die Zahl der Felder.
func (s *Server) ImportStartOptions(ctx context.Context) (int, error) {
	if !s.cfg.SettingsFromDB {
		return 0, nil
	}
	p := s.cfg.Pinned
	var nets []netip.Prefix
	var targets []string
	var dead []byte
	if p[setNets] {
		nets = append([]netip.Prefix{}, s.cfg.CheckNetworks...)
	}
	if p[setTargets] {
		targets = s.cfg.AlertTargets.List()
	}
	if p[setDeadMan] {
		var err error
		if dead, err = s.sealDeadMan(s.cfg.DeadManURL); err != nil {
			return 0, err
		}
	}
	// Ohne „Platte voll in < N Tagen“: dafür gibt es keine Startoption.
	startLimits := limitFields[:len(limitFields)-1]
	vals := make([]any, len(startLimits))
	for i, f := range startLimits {
		if !p[f] {
			continue
		}
		v := s.cfgLimit(f)
		if f == setSilent {
			vals[i] = int32(v)
		} else {
			vals[i] = v
		}
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT openwacht.settings_import($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		append([]any{nets, targets, dead}, vals...)...).Scan(&n)
	return n, err
}

// ReloadSettings liest Einstellungen, Netzketten und Abweichungen neu und
// wendet sie an. Bei einem Fehler bleibt der bisherige Stand.
func (s *Server) ReloadSettings(ctx context.Context) error {
	var d dbSettings
	var err error
	if s.cfg.SettingsFromDB {
		if d, err = readDBSettings(ctx, s.pool, `SELECT `+settingsColumns+` FROM openwacht.runtime_settings()`); err != nil {
			return err
		}
	}
	chains := map[string][][]netip.Prefix{}
	rows, err := s.pool.Query(ctx, `SELECT tenant_id::text, nets FROM openwacht.tenant_net_chains()`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var t string
		var nets []netip.Prefix
		if err := rows.Scan(&t, &nets); err != nil {
			rows.Close()
			return err
		}
		chains[t] = append(chains[t], append([]netip.Prefix{}, nets...))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Globale Werte: Startoption, sonst Datenbank, sonst Standard.
	global := s.cfg.hostLimits()
	if s.cfg.SettingsFromDB {
		for i, f := range limitFields {
			if s.cfg.Pinned[f] || d.limits[i] == nil {
				continue
			}
			var one limitRow
			one[i] = d.limits[i]
			global = one.apply(global)
		}
	}
	overrides := map[string]alarm.HostLimits{}
	rows, err = s.pool.Query(ctx, `SELECT kind, id::text, silent_s::double precision, disk_warn, disk_crit, mem_warn,
		mem_crit, cpu_warn, cpu_crit, disk_days FROM openwacht.limit_overrides()`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var kind, id string
		var l limitRow
		if err := rows.Scan(append([]any{&kind, &id}, l.dest()...)...); err != nil {
			rows.Close()
			return err
		}
		overrides[kind+":"+id] = l.apply(global)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	mail, err := s.loadMail(ctx)
	if err != nil {
		return fmt.Errorf("Mail-Einstellung: %w", err)
	}
	inst, err := ReadInstall(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("Einstellungen der Installation: %w", err)
	}
	deadURL := s.cfg.DeadManURL
	if s.cfg.SettingsFromDB && !s.cfg.Pinned[setDeadMan] && d.deadEnc != nil {
		if deadURL, err = s.openDeadMan(d.deadEnc); err != nil {
			return fmt.Errorf("Totmann-Adresse nicht lesbar: %w", err)
		}
	}
	if s.cfg.SettingsFromDB {
		if !s.cfg.Pinned[setNets] && d.netsSet {
			s.guard.SetNetworks(d.nets)
		} else {
			s.guard.SetNetworks(s.cfg.CheckNetworks)
		}
		if !s.cfg.Pinned[setTargets] && d.tgtSet {
			t, err := alarm.ParseTargets(strings.Join(d.targets, ","))
			if err != nil {
				return fmt.Errorf("Alarmziele in der Datenbank: %w", err)
			}
			s.alertTargets.Set(t)
		} else {
			s.alertTargets.Set(s.cfg.AlertTargets)
		}
	}

	s.live.mu.Lock()
	oldURL := s.live.deadURL
	s.live.limits, s.live.overrides, s.live.chains, s.live.db = global, overrides, chains, d
	s.live.deadURL, s.live.loaded, s.live.mail = deadURL, s.now(), mail
	s.live.zone, s.live.zoneName = inst.Zone()
	s.live.mu.Unlock()
	if deadURL != oldURL {
		dm, err := newDeadMan(deadURL, s.cfg.DeadManEvery)
		if err != nil {
			return fmt.Errorf("Totmann: %w", err)
		}
		if old := s.deadMan.Swap(dm); old != nil {
			old.wait()
		}
		if dm == nil {
			slog.Warn("Totmannschalter aus: Fällt die Zentrale aus, merkt das niemand")
		} else {
			slog.Info("Totmannschalter an")
		}
	}
	return nil
}

// reloadIfDue: in den Schleifen höchstens alle 30 s.
func (s *Server) reloadIfDue(ctx context.Context) {
	s.live.mu.RLock()
	due := s.now().Sub(s.live.loaded) >= 30*time.Second
	s.live.mu.RUnlock()
	if !due {
		return
	}
	if err := s.ReloadSettings(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("Einstellungen: nicht neu geladen, es bleibt der bisherige Stand", "fehler", err)
	}
}

// --- API -----------------------------------------------------------------------

// valueOut: ein Wert mit Herkunft für die Oberfläche.
type valueOut struct {
	Wert   any    `json:"wert"`
	Quelle string `json:"quelle"` // startoption, einstellung, standard
}

func prefixStrings(p []netip.Prefix) []string {
	out := make([]string, 0, len(p))
	for _, x := range p {
		out = append(out, x.String())
	}
	return out
}

// requireOperator: nur Betreiber (sonst 403). Läuft in der Transaktion des Benutzers.
func requireOperator(ctx context.Context, tx pgx.Tx) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT openwacht.is_platform_operator()`).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return &apiError{http.StatusForbidden, "Einstellungen ändern darf nur der Betreiber."}
	}
	return nil
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		d, err := readDBSettings(ctx, tx, `SELECT `+settingsColumns+` FROM openwacht.settings`)
		if err != nil {
			return 0, nil, err
		}
		src := func(field string, inDB bool) string {
			switch {
			case s.pinned(field):
				return "startoption"
			case inDB:
				return "einstellung"
			}
			return "standard"
		}
		global := map[string]valueOut{}
		global[setNets] = valueOut{prefixStrings(s.guard.Networks()), src(setNets, d.netsSet)}
		global[setTargets] = valueOut{s.alertTargets.List(), src(setTargets, d.tgtSet)}
		s.live.mu.RLock()
		deadURL := s.live.deadURL
		lim := s.live.limits
		s.live.mu.RUnlock()
		dead := map[string]any{"an": deadURL != ""}
		if deadURL != "" {
			if u, err := ParseDeadManURL(deadURL); err == nil {
				dead["host"] = u.Host // die Kennung im Pfad ist geheim
			}
		}
		global[setDeadMan] = valueOut{dead, src(setDeadMan, d.deadEnc != nil)}
		eff := limitsJSON(lim)
		for i, f := range limitFields {
			global[f] = valueOut{eff[f], src(f, d.limits[i] != nil)}
		}

		type tenantOut struct {
			ID     string              `json:"id"`
			Parent *string             `json:"eltern"`
			Name   string              `json:"name"`
			Netze  []string            `json:"netze"` // nil = keine eigene Eingrenzung
			Eigene map[string]*float64 `json:"schwellen"`
		}
		rows, err := tx.Query(ctx, `SELECT t.id::text, t.parent_id::text, t.name, ts.check_nets,
				ts.silent_s::double precision, ts.disk_warn, ts.disk_crit, ts.mem_warn, ts.mem_crit, ts.cpu_warn, ts.cpu_crit,
				ts.disk_days
			FROM openwacht.settings_tenants() t LEFT JOIN openwacht.tenant_settings ts ON ts.tenant_id = t.id`)
		if err != nil {
			return 0, nil, err
		}
		tenants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantOut, error) {
			var t tenantOut
			var nets []netip.Prefix
			var l limitRow
			err := row.Scan(append([]any{&t.ID, &t.Parent, &t.Name, &nets}, l.dest()...)...)
			if nets != nil {
				t.Netze = prefixStrings(nets)
			}
			t.Eigene = l.json()
			return t, err
		})
		if err != nil {
			return 0, nil, err
		}
		standard := map[string]float64{}
		for k, v := range limitDefaults {
			standard[k] = v
		}
		return http.StatusOK, map[string]any{"global": global, "mandanten": tenants, "standard": standard,
			"agent_intervall_s": s.cfg.AgentInterval.Seconds()}, nil
	})
}

// settingsIn: Felder fehlen = unverändert. Schwellen: null = Standard.
type settingsIn struct {
	Netze      *[]string           `json:"netze"`
	Alarmziele *[]string           `json:"alarmziele"`
	Totmann    *string             `json:"totmann"` // "" = aus
	Schwellen  map[string]*float64 `json:"schwellen"`
	Code       string              `json:"code"`
}

func parseNets(in []string) ([]netip.Prefix, error) {
	if len(in) > 64 {
		return nil, badRequest("Höchstens 64 Netze.")
	}
	seen := map[netip.Prefix]bool{}
	out := []netip.Prefix{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			if a, err2 := netip.ParseAddr(raw); err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return nil, badRequest(fmt.Sprintf("„%s“ ist kein Netz (Form 10.10.0.0/16 oder eine einzelne Adresse).", clipRunes(raw, 50)))
			}
		}
		p = p.Masked()
		if p.Addr().Zone() != "" {
			return nil, badRequest("Netze ohne Zone angeben.")
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// parseLimits prüft Schwellen: Prozent 0 (aus) oder 1–100, Warnung unter
// Kritisch, stumm nach 120 s bis 1 Tag und mindestens zwei Meldeintervalle.
// Unbekannte Felder sind ein Fehler.
func (s *Server) parseLimits(in map[string]*float64) (limitRow, error) {
	var l limitRow
	for k := range in {
		known := false
		for _, f := range limitFields {
			known = known || f == k
		}
		if !known {
			return l, badRequest(fmt.Sprintf("Unbekannte Schwelle „%s“.", clipRunes(k, 30)))
		}
	}
	for i, f := range limitFields {
		v := in[f]
		if v == nil {
			continue
		}
		x := *v
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return l, badRequest("Ungültige Zahl.")
		}
		if f == setDiskDays {
			if x != math.Trunc(x) || x < 0 || x > 365 {
				return l, badRequest("„Platte voll in weniger als … Tagen“: 0 (aus) bis 365 Tage.")
			}
		} else if f == setSilent {
			x = math.Round(x)
			if x < 120 || x > 86400 {
				return l, badRequest("„Stumm nach“: 2 Minuten bis 1 Tag.")
			}
			if x < 2*s.cfg.AgentInterval.Seconds() {
				return l, badRequest(fmt.Sprintf("„Stumm nach“: mindestens zwei Meldeintervalle (%s).", 2*s.cfg.AgentInterval))
			}
		} else if x != 0 && (x < 1 || x > 100) {
			return l, badRequest("Schwellen: 0 (aus) oder 1 bis 100 Prozent.")
		}
		l[i] = &x
	}
	for _, p := range [][2]int{{1, 2}, {3, 4}, {5, 6}} {
		w, c := l[p[0]], l[p[1]]
		if w != nil && c != nil && *w > 0 && *c > 0 && *w >= *c {
			return l, badRequest("Die Warnschwelle muss unter der kritischen liegen.")
		}
	}
	return l, nil
}

// confirmCode prüft den frischen 2FA-Code (mit Rate Limit je Adresse).
func (s *Server) confirmCode(r *http.Request, code string) error {
	sess := sessionFrom(r.Context())
	if !sess.TOTPEnabled {
		return s.confirmPassword(r, code)
	}
	if strings.TrimSpace(code) == "" {
		return &apiError{http.StatusForbidden, "Für diese Änderung bitte den aktuellen Code aus der Authenticator-App eingeben."}
	}
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		return &apiError{http.StatusTooManyRequests, "Zu viele Versuche. Bitte kurz warten."}
	}
	src := s.loginSource(r)
	if s.sourceLocked(r.Context(), sess.UserID, src) {
		return errConfirmLocked
	}
	ok, err := s.verifyTOTP(r.Context(), sess.UserID, strings.TrimSpace(code), true)
	if err != nil {
		return err
	}
	if !ok {
		// Fehlversuche zählen wie bei der Anmeldung (Etappe 30, M8).
		s.loginFailed(r.Context(), sess.UserID, src)
		s.auditAuth(r.Context(), sess.UserID, "bestaetigung.fehlgeschlagen", map[string]any{"grund": "zweiter_faktor"}, true)
		return &apiError{http.StatusForbidden, "Der Code stimmt nicht oder wurde schon benutzt. Bitte den nächsten Code eingeben."}
	}
	return nil
}

// confirmPassword: Konten ohne 2FA (wenn die Einstellung das erlaubt)
// bestätigen heikle Änderungen mit ihrem Passwort.
func (s *Server) confirmPassword(r *http.Request, pass string) error {
	ctx := r.Context()
	if pass == "" {
		return &apiError{http.StatusForbidden, "Für diese Änderung bitte das eigene Passwort eingeben."}
	}
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		return &apiError{http.StatusTooManyRequests, "Zu viele Versuche. Bitte kurz warten."}
	}
	wrong := &apiError{http.StatusForbidden, "Das Passwort stimmt nicht."}
	if auth.CheckPasswordInput(pass) != nil {
		return wrong
	}
	userID := sessionFrom(ctx).UserID
	src := s.loginSource(r)
	if s.sourceLocked(ctx, userID, src) {
		return errConfirmLocked
	}
	var hash, dirID, ext *string
	if err := s.withUser(ctx, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash, directory_id::text, external_id FROM openwacht.auth_own_password()`).
			Scan(&hash, &dirID, &ext)
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return wrong
		}
		return err
	}
	if dirID != nil && ext != nil {
		d, err := scanDir(s.pool.QueryRow(ctx, `SELECT `+dirCols+` FROM openwacht.directory_sync_list() d WHERE d.id = $1`, *dirID))
		if errors.Is(err, pgx.ErrNoRows) {
			// OIDC (oder Anbindung aus): kein Passwort, das die Zentrale prüfen könnte
			return &apiError{http.StatusForbidden, "Konten mit Firmen-Login (SSO) bestätigen Änderungen mit der Zwei-Faktor-Anmeldung. Bitte zuerst einrichten (Menü unten links)."}
		}
		if err != nil {
			return err
		}
		cfg, err := s.dirConfig(d)
		if err != nil {
			return err
		}
		switch err := cfg.VerifyByID(ctx, *ext, pass); {
		case err == nil:
			return nil
		case errors.Is(err, verzeichnis.ErrBadPassword), errors.Is(err, verzeichnis.ErrNotFound):
			s.loginFailed(ctx, userID, src)
			s.auditAuth(ctx, userID, "bestaetigung.fehlgeschlagen", nil, true)
			return wrong
		default:
			return &apiError{http.StatusServiceUnavailable, "Der Verzeichnisdienst (AD) ist gerade nicht erreichbar."}
		}
	}
	if hash == nil {
		return wrong
	}
	if !s.acquireHash(ctx) {
		return ctx.Err()
	}
	defer s.releaseHash()
	ok, _, err := auth.VerifyPassword(pass, *hash, *s.cfg.PasswordParams)
	if err != nil || !ok {
		// Fehlversuche zählen wie bei der Anmeldung (Etappe 30, M8).
		s.loginFailed(ctx, userID, src)
		s.auditAuth(ctx, userID, "bestaetigung.fehlgeschlagen", nil, true)
		return wrong
	}
	return nil
}

// errConfirmLocked: Nach fünf Fehlversuchen aus dieser Quelle ist auch die
// Bestätigung gesperrt (wie die Anmeldung).
var errConfirmLocked = &apiError{http.StatusForbidden, "Zu viele Fehlversuche. Bitte später erneut versuchen."}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var in settingsIn
	if !readJSON(w, r, &in) {
		return
	}
	// Erst alles prüfen, dann den Code: ein Tippfehler im Netz kostet keinen Code.
	var nets []netip.Prefix
	var targets *alarm.Targets
	var dead []byte
	var err error
	fail := func(err error) { writeDBError(w, "einstellungen", err) }
	for field, present := range map[string]bool{setNets: in.Netze != nil, setTargets: in.Alarmziele != nil, setDeadMan: in.Totmann != nil} {
		if present && s.pinned(field) {
			fail(&apiError{http.StatusConflict, "Dieser Wert ist per Startoption gesetzt und lässt sich hier nicht ändern."})
			return
		}
	}
	for f := range in.Schwellen {
		if s.pinned(f) {
			fail(&apiError{http.StatusConflict, "Diese Schwelle ist per Startoption gesetzt und lässt sich hier nicht ändern."})
			return
		}
	}
	if in.Netze != nil {
		if nets, err = parseNets(*in.Netze); err != nil {
			fail(err)
			return
		}
	}
	if in.Alarmziele != nil {
		if len(*in.Alarmziele) > 32 {
			fail(badRequest("Höchstens 32 Alarmziele."))
			return
		}
		if targets, err = alarm.ParseTargets(strings.Join(*in.Alarmziele, ",")); err != nil {
			fail(badRequest("Alarmziele: " + err.Error() + "."))
			return
		}
	}
	if in.Totmann != nil {
		raw := strings.TrimSpace(*in.Totmann)
		if raw != "" {
			if _, err := ParseDeadManURL(raw); err != nil {
				fail(badRequest(err.Error() + "."))
				return
			}
		}
		if dead, err = s.sealDeadMan(raw); err != nil {
			fail(err)
			return
		}
	}
	var lim limitRow
	if in.Schwellen != nil {
		if lim, err = s.parseLimits(in.Schwellen); err != nil {
			fail(err)
			return
		}
	}
	if in.Netze == nil && in.Alarmziele == nil && in.Totmann == nil && in.Schwellen == nil {
		fail(badRequest("Nichts zu ändern."))
		return
	}
	// Betreiber vor dem Code prüfen, damit Nicht-Betreiber keine Codes raten.
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	if in.Netze != nil || in.Alarmziele != nil || in.Totmann != nil {
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
	}
	s.handle(w, r, "einstellungen ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		sets, args := []string{}, []any{}
		add := func(col string, v any) {
			args = append(args, v)
			sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
		}
		if in.Netze != nil {
			add("check_nets", nets)
		}
		if targets != nil {
			add("alert_targets", targets.List())
		}
		if in.Totmann != nil {
			add("deadman_enc", dead)
		}
		if in.Schwellen != nil {
			cols := []string{"silent_s", "disk_warn", "disk_crit", "mem_warn", "mem_crit", "cpu_warn", "cpu_crit", "disk_days"}
			for i, f := range limitFields {
				if _, ok := in.Schwellen[f]; !ok {
					continue
				}
				if i == 0 && lim[0] != nil {
					add(cols[i], int32(*lim[0]))
				} else {
					add(cols[i], lim[i])
				}
			}
		}
		if len(sets) == 0 {
			return http.StatusNoContent, nil, nil
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.settings SET `+strings.Join(sets, ", "), args...)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, &apiError{http.StatusForbidden, "Einstellungen ändern darf nur der Betreiber."}
		}
		return http.StatusNoContent, nil, nil
	})
	s.reloadAfterWrite(r.Context())
}

func (s *Server) reloadAfterWrite(ctx context.Context) {
	if err := s.ReloadSettings(context.WithoutCancel(ctx)); err != nil {
		slog.Warn("Einstellungen: nach dem Speichern nicht neu geladen", "fehler", err)
	}
}

// tenantSettingsIn: vollständiger Stand je Mandant; netze null = keine eigene Eingrenzung.
type tenantSettingsIn struct {
	Netze     *[]string           `json:"netze"`
	Schwellen map[string]*float64 `json:"schwellen"`
	Code      string              `json:"code"`
}

func (s *Server) handleTenantSettingsPut(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in tenantSettingsIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "einstellungen mandant", err) }
	var nets []netip.Prefix
	var err error
	if in.Netze != nil {
		if nets, err = parseNets(*in.Netze); err != nil {
			fail(err)
			return
		}
	}
	lim, err := s.parseLimits(in.Schwellen)
	if err != nil {
		fail(err)
		return
	}
	// Ändern sich die Netze? Dann braucht es den Code.
	var oldNets []netip.Prefix
	err = s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		if err := requireOperator(r.Context(), tx); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM openwacht.settings_tenants() WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errNotFound
		}
		err := tx.QueryRow(r.Context(), `SELECT check_nets FROM openwacht.tenant_settings WHERE tenant_id = $1`, id).Scan(&oldNets)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	if !sameNets(oldNets, nets, in.Netze == nil) {
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
	}
	s.handle(w, r, "einstellungen mandant", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		var netsArg any
		if in.Netze != nil {
			netsArg = nets
		}
		if in.Netze == nil && lim.empty() {
			// Aufbewahrung (Etappe 35) bleibt; die Zeile verschwindet nur, wenn nichts mehr gesetzt ist.
			_, err := tx.Exec(ctx, `UPDATE openwacht.tenant_settings SET check_nets = NULL, silent_s = NULL, disk_warn = NULL,
				disk_crit = NULL, mem_warn = NULL, mem_crit = NULL, cpu_warn = NULL, cpu_crit = NULL, disk_days = NULL
				WHERE tenant_id = $1`, id)
			if err == nil {
				err = pruneTenantSettings(ctx, tx, id)
			}
			return http.StatusNoContent, nil, err
		}
		var silent any
		if lim[0] != nil {
			silent = int32(*lim[0])
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.tenant_settings AS ts (tenant_id, check_nets, silent_s, disk_warn, disk_crit,
				mem_warn, mem_crit, cpu_warn, cpu_crit, disk_days) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant_id) DO UPDATE SET check_nets = EXCLUDED.check_nets, silent_s = EXCLUDED.silent_s,
				disk_warn = EXCLUDED.disk_warn, disk_crit = EXCLUDED.disk_crit, mem_warn = EXCLUDED.mem_warn,
				mem_crit = EXCLUDED.mem_crit, cpu_warn = EXCLUDED.cpu_warn, cpu_crit = EXCLUDED.cpu_crit,
				disk_days = EXCLUDED.disk_days`,
			id, netsArg, silent, lim[1], lim[2], lim[3], lim[4], lim[5], lim[6], lim[7])
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23503" {
			return 0, nil, errNotFound
		}
		return http.StatusNoContent, nil, err
	})
	s.reloadAfterWrite(r.Context())
}

// sameNets: unverändert? newNil = keine eigene Eingrenzung.
func sameNets(old, nu []netip.Prefix, newNil bool) bool {
	if (old == nil) != newNil {
		return false
	}
	if len(old) != len(nu) {
		return false
	}
	a, b := prefixStrings(old), prefixStrings(nu)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Schwellen je Gerät ------------------------------------------------------------

func (s *Server) handleDeviceLimitsGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "schwellen gerät", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var inh limitRow
		var tenantName *string
		if err := tx.QueryRow(ctx, `SELECT silent_s::double precision, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit,
				disk_days, tenant_name FROM openwacht.device_limits_inherited($1)`, id).
			Scan(append(inh.dest(), &tenantName)...); err != nil {
			return 0, nil, err
		}
		if tenantName == nil {
			return 0, nil, errNotFound
		}
		var own limitRow
		err := tx.QueryRow(ctx, `SELECT silent_s::double precision, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit,
				disk_days FROM openwacht.device_limits WHERE device_id = $1`, id).Scan(own.dest()...)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, err
		}
		var canEdit bool
		if err := tx.QueryRow(ctx, `SELECT d.tenant_id IN (SELECT openwacht.operator_tenants()) FROM openwacht.devices d WHERE d.id = $1`, id).
			Scan(&canEdit); err != nil {
			return 0, nil, err
		}
		global := s.hostLimits()
		return http.StatusOK, map[string]any{"eigene": own.json(), "mandant": inh.json(), "global": limitsJSON(global),
			"wirksam": limitsJSON(own.apply(inh.apply(global))), "darf_aendern": canEdit}, nil
	})
}

func (s *Server) handleDeviceLimitsPut(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Schwellen map[string]*float64 `json:"schwellen"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	lim, err := s.parseLimits(in.Schwellen)
	if err != nil {
		writeDBError(w, "schwellen gerät", err)
		return
	}
	s.handle(w, r, "schwellen gerät", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name FROM openwacht.devices WHERE id = $1`, id).Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.operator_tenants())`, tenant).Scan(&allowed); err != nil {
			return 0, nil, err
		}
		if !allowed {
			return 0, nil, &apiError{http.StatusForbidden, "Schwellen ändern dürfen nur Admins und Operatoren."}
		}
		if lim.empty() {
			if _, err := tx.Exec(ctx, `DELETE FROM openwacht.device_limits WHERE device_id = $1`, id); err != nil {
				return 0, nil, err
			}
		} else {
			var silent any
			if lim[0] != nil {
				silent = int32(*lim[0])
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.device_limits (device_id, silent_s, disk_warn, disk_crit, mem_warn,
					mem_crit, cpu_warn, cpu_crit, disk_days) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (device_id) DO UPDATE SET silent_s = EXCLUDED.silent_s, disk_warn = EXCLUDED.disk_warn,
					disk_crit = EXCLUDED.disk_crit, mem_warn = EXCLUDED.mem_warn, mem_crit = EXCLUDED.mem_crit,
					cpu_warn = EXCLUDED.cpu_warn, cpu_crit = EXCLUDED.cpu_crit, disk_days = EXCLUDED.disk_days`,
				id, silent, lim[1], lim[2], lim[3], lim[4], lim[5], lim[6], lim[7]); err != nil {
				return 0, nil, err
			}
		}
		if err := audit(ctx, tx, &tenant, "geraet.schwellen", map[string]any{"geraet": id, "name": name,
			"schwellen": lim.json()}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
	s.reloadAfterWrite(r.Context())
}

// CheckNetworks: die wirksamen Netze der Installation (für das Log beim Start).
func (s *Server) CheckNetworks() []string { return prefixStrings(s.guard.Networks()) }

// AlertTargetList: die wirksamen Alarmziele (für das Log beim Start).
func (s *Server) AlertTargetList() []string { return s.alertTargets.List() }

// DeadManOn: Ist der Totmannschalter an?
func (s *Server) DeadManOn() bool { return s.deadMan.Load() != nil }
