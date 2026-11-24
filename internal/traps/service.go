// SPDX-License-Identifier: AGPL-3.0-only

package traps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Config des Trap-Dienstes.
type Config struct {
	Pool *pgxpool.Pool
	Key  []byte         // Trap-Schlüssel (traps.DeriveKey)
	Conn net.PacketConn // UDP-Socket (Port 162, von systemd)

	Reload       time.Duration // Quellen und Regeln neu lesen, Standard 10 s
	Maintain     time.Duration // Aufräumen, Standard 10 min
	Summary      time.Duration // Zusammenfassung im Log, Standard 5 min
	PerSource    float64       // Traps je Sekunde und Absender, Standard 10
	PerSourceMax float64       // Puffer je Absender, Standard 50
	Global       float64       // Traps je Sekunde gesamt, Standard 1000
	Resolver     func(ctx context.Context, host string) ([]netip.Addr, error)
	Now          func() time.Time
}

func (c *Config) defaults() {
	if c.Reload <= 0 {
		c.Reload = 10 * time.Second
	}
	if c.Maintain <= 0 {
		c.Maintain = 10 * time.Minute
	}
	if c.Summary <= 0 {
		c.Summary = 5 * time.Minute
	}
	if c.PerSource <= 0 {
		c.PerSource = 10
	}
	if c.PerSourceMax <= 0 {
		c.PerSourceMax = 50
	}
	if c.Global <= 0 {
		c.Global = 1000
	}
	if c.Resolver == nil {
		c.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// testPanicHook: nur in Tests gesetzt, um eine Panik im Empfang auszulösen.
// Atomar, weil Empfänger aus früheren Tests noch laufen können (Rennen unter -race).
var testPanicHook atomic.Pointer[func(msg []byte)]

// Zähler für die Zusammenfassung im Log.
type counters struct {
	accepted, unknown, community, auth, replay, window, rate, parse, queue, discovery atomic.Int64
}

// snapshot: was der Empfang liest (wird beim Neuladen ersetzt).
type snapshot struct {
	byAddr map[netip.Addr][]*Source
	rules  RuleSet
}

// record: ein Trap auf dem Weg in die Datenbank.
type record struct {
	src      *Source
	n        *Notification
	rule     *Rule
	instance string
}

// Service ist der Trap-Dienst.
type Service struct {
	cfg    Config
	engine localEngine
	snap   atomic.Pointer[snapshot]
	cnt    counters

	mu      sync.Mutex
	buckets map[netip.Addr]*tokenBucket
	global  tokenBucket
	unknown map[netip.Addr]int
	remote  map[string]*remoteState // Quelle|Engine-ID
	replay  *replayCache
	hosts   map[string][]netip.Addr // zuletzt aufgelöste Namen

	queue chan record
	seen  chan engineSeen

	lastBeat time.Time // nur im Hintergrundlauf
}

type engineSeen struct {
	source, engine string
	boots, time    uint32
}

// New bereitet den Dienst vor: eigene Engine starten (snmpEngineBoots + 1),
// Quellen, Regeln und gemerkte Engines laden.
func New(ctx context.Context, cfg Config) (*Service, error) {
	cfg.defaults()
	if len(cfg.Key) != 32 {
		return nil, errors.New("Trap-Schlüssel muss 32 Bytes lang sein")
	}
	s := &Service{cfg: cfg, buckets: map[netip.Addr]*tokenBucket{}, unknown: map[netip.Addr]int{},
		remote: map[string]*remoteState{}, replay: newReplayCache(20000), hosts: map[string][]netip.Addr{},
		queue: make(chan record, 2000), seen: make(chan engineSeen, 1000)}
	var id []byte
	var boots int32
	if err := cfg.Pool.QueryRow(ctx, `SELECT engine_id, engine_boots FROM openwacht.traps_engine_start()`).Scan(&id, &boots); err != nil {
		return nil, fmt.Errorf("Engine starten: %w", err)
	}
	s.engine = localEngine{id: string(id), boots: uint32(boots), start: cfg.Now()}
	rows, err := cfg.Pool.Query(ctx, `SELECT source_id::text, engine_id, boots, engine_time, seen_at FROM openwacht.traps_engines()`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var src string
		var eng []byte
		var b, t int32
		var at time.Time
		if err := rows.Scan(&src, &eng, &b, &t, &at); err != nil {
			rows.Close()
			return nil, err
		}
		s.remote[src+"|"+string(eng)] = &remoteState{boots: uint32(b), time: uint32(t), at: at, saved: at}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// EngineID für Log und Tests.
func (s *Service) EngineID() string { return string(s.engine.id) }

// load liest Quellen und Regeln und ersetzt den Stand atomar.
func (s *Service) load(ctx context.Context) error {
	rows, err := s.cfg.Pool.Query(ctx, `SELECT id::text, tenant_id::text, device_id::text, device_name, version, host, port,
		trap_secret_enc, tenants::text[], groups::text[] FROM openwacht.traps_sources()`)
	if err != nil {
		return err
	}
	var sources []*Source
	for rows.Next() {
		src := &Source{}
		var enc []byte
		if err := rows.Scan(&src.ID, &src.Tenant, &src.Device, &src.DeviceName, &src.Version, &src.Host, &src.Port,
			&enc, &src.Tenants, &src.Groups); err != nil {
			rows.Close()
			return err
		}
		sec, err := Open(s.cfg.Key, enc, src.ID, src.Tenant, src.Host, src.Port, src.Version)
		if err != nil {
			slog.Warn("Traps: Zugangsdaten einer Quelle nicht lesbar", "quelle", src.ID, "fehler", err)
			continue
		}
		src.Secret = sec
		sources = append(sources, src)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rs := RuleSet{}
	rows, err = s.cfg.Pool.Query(ctx, `SELECT id::text, tenant_id::text, pos, name, coalesce(group_id::text, ''),
		coalesce(device_id::text, ''), trap_oid, coalesce(vb_oid, ''), coalesce(vb_op, ''), coalesce(vb_value, ''), action,
		coalesce(key_oid, '') FROM openwacht.traps_rules()`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Tenant, &r.Pos, &r.Name, &r.Group, &r.Device, &r.TrapOID, &r.VbOID, &r.VbOp, &r.VbValue,
			&r.Action, &r.KeyOID); err != nil {
			rows.Close()
			return err
		}
		rs[r.Tenant] = append(rs[r.Tenant], r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	byAddr := map[netip.Addr][]*Source{}
	for _, src := range sources {
		for _, a := range s.resolve(ctx, src.Host) {
			byAddr[a] = append(byAddr[a], src)
		}
	}
	s.snap.Store(&snapshot{byAddr: byAddr, rules: rs})
	return nil
}

// resolve: IP-Adresse direkt, Namen über DNS; scheitert die Auflösung,
// gilt die letzte bekannte Antwort weiter.
func (s *Service) resolve(ctx context.Context, host string) []netip.Addr {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := s.cfg.Resolver(ctx, host)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || len(addrs) == 0 {
		return s.hosts[host]
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	if len(out) > 16 {
		out = out[:16]
	}
	s.hosts[host] = out
	return out
}

// Run empfängt, bis ctx endet.
func (s *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); s.writer(ctx) }()
	go func() { defer wg.Done(); s.engineWriter(ctx) }()
	go func() { defer wg.Done(); s.background(ctx) }()
	go func() { <-ctx.Done(); s.cfg.Conn.SetReadDeadline(time.Now()) }()
	slog.Info("Traps: Dienst bereit", "adresse", s.cfg.Conn.LocalAddr().String(),
		"engine_id", fmt.Sprintf("%x", s.engine.id), "engine_boots", s.engine.boots)
	s.heartbeat(ctx)
	buf := make([]byte, MaxPacket+1)
	var err error
	for {
		n, addr, rerr := s.cfg.Conn.ReadFrom(buf)
		if ctx.Err() != nil {
			break
		}
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				continue
			}
			err = rerr
			break
		}
		if n > MaxPacket {
			s.cnt.parse.Add(1)
			continue
		}
		if safe.Run("traps", func() { s.handle(buf[:n], addr) }) {
			s.cnt.parse.Add(1)
		}
	}
	cancel()
	wg.Wait()
	return err
}

func (s *Service) background(ctx context.Context) {
	reload := time.NewTicker(s.cfg.Reload)
	maintain := time.NewTicker(s.cfg.Maintain)
	summary := time.NewTicker(s.cfg.Summary)
	defer reload.Stop()
	defer maintain.Stop()
	defer summary.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if err := s.load(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("Traps: Quellen und Regeln nicht lesbar, alter Stand gilt weiter", "fehler", err)
			}
			s.heartbeat(ctx)
		case <-maintain.C:
			var n int
			if err := s.cfg.Pool.QueryRow(ctx, `SELECT openwacht.traps_maintain()`).Scan(&n); err != nil && ctx.Err() == nil {
				slog.Warn("Traps: Aufräumen gescheitert", "fehler", err)
			}
		case <-summary.C:
			s.logSummary()
		}
	}
}

// heartbeat: Lebenszeichen für /api/v1/gesund und die Selbstüberwachung
// der Zentrale (höchstens einmal je Minute).
func (s *Service) heartbeat(ctx context.Context) {
	now := s.cfg.Now()
	if now.Sub(s.lastBeat) < time.Minute {
		return
	}
	if _, err := s.cfg.Pool.Exec(ctx, `SELECT openwacht.traps_heartbeat()`); err != nil {
		if ctx.Err() == nil {
			slog.Warn("Traps: Lebenszeichen nicht gespeichert", "fehler", err)
		}
		return
	}
	s.lastBeat = now
}

// logSummary schreibt verworfene Traps und unbekannte Absender ins Log.
func (s *Service) logSummary() {
	s.mu.Lock()
	type kv struct {
		a netip.Addr
		n int
	}
	var unk []kv
	for a, n := range s.unknown {
		unk = append(unk, kv{a, n})
	}
	s.unknown = map[netip.Addr]int{}
	// Rate-Eimer alter Absender aufräumen
	now := s.cfg.Now()
	for a, b := range s.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(s.buckets, a)
		}
	}
	s.mu.Unlock()
	c := &s.cnt
	vals := []any{"angenommen", c.accepted.Swap(0), "unbekannter_absender", c.unknown.Swap(0),
		"community_falsch", c.community.Swap(0), "v3_abgelehnt", c.auth.Swap(0), "wiederholt", c.replay.Swap(0),
		"zeitfenster", c.window.Swap(0), "rate", c.rate.Swap(0), "unlesbar", c.parse.Swap(0),
		"warteschlange_voll", c.queue.Swap(0), "discovery", c.discovery.Swap(0)}
	nonzero := false
	for i := 1; i < len(vals); i += 2 {
		if vals[i].(int64) != 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return
	}
	if len(unk) > 0 {
		sort.Slice(unk, func(i, j int) bool { return unk[i].n > unk[j].n })
		if len(unk) > 10 {
			unk = unk[:10]
		}
		var parts []string
		for _, u := range unk {
			parts = append(parts, fmt.Sprintf("%s (%d)", u.a, u.n))
		}
		vals = append(vals, "unbekannte", strings.Join(parts, ", "))
	}
	slog.Info("Traps: Zusammenfassung", vals...)
}

// handle bearbeitet ein Paket. Fehler zählen nur; Absender erfahren nichts
// außer bei Informs und v3-Discovery bekannter Geräte.
func (s *Service) handle(msg []byte, from net.Addr) {
	if h := testPanicHook.Load(); h != nil {
		(*h)(msg)
	}
	now := s.cfg.Now()
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return
	}
	ip := ua.AddrPort().Addr().Unmap()
	snap := s.snap.Load()
	cands := snap.byAddr[ip]

	s.mu.Lock()
	if !s.global.allow(s.cfg.Global, s.cfg.Global, now) {
		s.mu.Unlock()
		s.cnt.rate.Add(1)
		return
	}
	if len(cands) == 0 {
		if len(s.unknown) < 1000 || s.unknown[ip] > 0 {
			s.unknown[ip]++
		}
		s.mu.Unlock()
		s.cnt.unknown.Add(1)
		return
	}
	b := s.buckets[ip]
	if b == nil {
		b = &tokenBucket{}
		s.buckets[ip] = b
	}
	allowed := b.allow(s.cfg.PerSource, s.cfg.PerSourceMax, now)
	s.mu.Unlock()
	if !allowed {
		s.cnt.rate.Add(1)
		return
	}

	version, err := peekVersion(msg)
	if err != nil {
		s.cnt.parse.Add(1)
		return
	}
	if version == snmp.V3 {
		s.handleV3(msg, ua, cands, snap.rules, now)
		return
	}
	var list []*Source
	var communities []string
	for _, c := range cands {
		if c.Version != snmp.V3 {
			list = append(list, c)
			communities = append(communities, c.Secret.Community)
		}
	}
	if len(list) == 0 {
		s.cnt.auth.Add(1) // v1/v2c an eine v3-Quelle
		return
	}
	n, pkt, idx, err := decodeCommunity(msg, version, communities)
	if err != nil {
		if errors.Is(err, errCommunity) {
			s.cnt.community.Add(1)
		} else {
			s.cnt.parse.Add(1)
		}
		return
	}
	src := list[idx]
	if n.Inform {
		if resp, err := informResponseV2(pkt); err == nil {
			s.cfg.Conn.WriteTo(resp, ua)
		}
	}
	s.accept(src, n, snap.rules)
}

func (s *Service) handleV3(msg []byte, to *net.UDPAddr, cands []*Source, rules RuleSet, now time.Time) {
	var v3 []*Source
	for _, c := range cands {
		if c.Version == snmp.V3 && c.Secret.V3 != nil {
			v3 = append(v3, c)
		}
	}
	if len(v3) == 0 {
		s.cnt.auth.Add(1)
		return
	}
	// Engine-Ermittlung für Informs: eigene Engine-ID melden, nur an bekannte
	// v3-Geräte (sonst ließe sich der Dienst als Reflektor nutzen).
	if req, ok := discoveryProbe(msg); ok {
		s.cnt.discovery.Add(1)
		if resp, err := report(req, &s.engine, s.engine.time(now), oidUnknownEngID, uint32(s.cnt.discovery.Load()), nil); err == nil {
			s.cfg.Conn.WriteTo(resp, to)
		}
		return
	}
	var pkt *gosnmp.SnmpPacket
	var src *Source
	for _, c := range v3 {
		p, err := decodeV3(msg, c.Secret.V3)
		if err == nil {
			pkt, src = p, c
			break
		}
	}
	if pkt == nil {
		s.cnt.auth.Add(1)
		return
	}
	usm := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	n, err := notification(pkt, snmp.V3)
	if err != nil {
		s.cnt.parse.Add(1)
		return
	}
	n.Authentic = true
	if n.Inform {
		// OpenWacht ist maßgeblich: eigene Engine-ID, eigene Zeit.
		if usm.AuthoritativeEngineID != s.engine.id {
			s.cnt.window.Add(1)
			return
		}
		if !s.engine.inWindow(usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, now) {
			s.cnt.window.Add(1)
			// authentifizierter Report, damit der Absender die Zeit übernimmt
			if resp, err := report(pkt, &s.engine, s.engine.time(now), oidNotInTimeWin, uint32(s.cnt.window.Load()), usm); err == nil {
				s.cfg.Conn.WriteTo(resp, to)
			}
			return
		}
	} else {
		// Trap: Der Absender ist maßgeblich, seine Engine-ID darf nicht unsere sein.
		if usm.AuthoritativeEngineID == s.engine.id || len(usm.AuthoritativeEngineID) < 5 || len(usm.AuthoritativeEngineID) > 32 {
			s.cnt.window.Add(1)
			return
		}
		key := src.ID + "|" + usm.AuthoritativeEngineID
		s.mu.Lock()
		next, ok := checkRemote(s.remote[key], usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, now)
		if ok {
			save := next.boots != remoteBoots(s.remote[key]) || now.Sub(next.saved) > time.Minute
			if save {
				next.saved = now
			}
			s.remote[key] = &next
			s.mu.Unlock()
			if save {
				select {
				case s.seen <- engineSeen{src.ID, usm.AuthoritativeEngineID, next.boots, next.time}:
				default:
				}
			}
		} else {
			s.mu.Unlock()
			s.cnt.window.Add(1)
			return
		}
	}
	if !s.replay.first(msg, now) {
		s.cnt.replay.Add(1)
		return
	}
	if n.Inform {
		if resp, err := informResponseV3(pkt, &s.engine, s.engine.time(now)); err == nil {
			s.cfg.Conn.WriteTo(resp, to)
		}
	}
	s.accept(src, n, rules)
}

func remoteBoots(st *remoteState) uint32 {
	if st == nil {
		return maxBoots + 1
	}
	return st.boots
}

func (s *Service) accept(src *Source, n *Notification, rules RuleSet) {
	rule, inst := rules.Match(src, n)
	select {
	case s.queue <- record{src: src, n: n, rule: rule, instance: inst}:
		s.cnt.accepted.Add(1)
	default:
		s.cnt.queue.Add(1)
	}
}

func (s *Service) writer(ctx context.Context) {
	var lastErr time.Time
	for {
		var rec record
		select {
		case <-ctx.Done():
			return
		case rec = <-s.queue:
		}
		vb, err := json.Marshal(rec.n.Varbinds)
		if err != nil || rec.n.Varbinds == nil {
			vb = []byte("[]")
		}
		var rule *string
		if rec.rule != nil {
			rule = &rec.rule.ID
		}
		var res string
		err = s.cfg.Pool.QueryRow(ctx, `SELECT openwacht.traps_record($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			rec.src.ID, rec.n.Version, rec.n.Inform, rec.n.Authentic, rec.n.TrapOID, vb, rule, rec.instance, Message(rec.n)).Scan(&res)
		if err != nil && ctx.Err() == nil && time.Since(lastErr) > time.Minute {
			lastErr = time.Now()
			slog.Warn("Traps: nicht gespeichert", "quelle", rec.src.ID, "fehler", err)
		}
	}
}

func (s *Service) engineWriter(ctx context.Context) {
	for {
		var e engineSeen
		select {
		case <-ctx.Done():
			return
		case e = <-s.seen:
		}
		if _, err := s.cfg.Pool.Exec(ctx, `SELECT openwacht.traps_engine_seen($1, $2, $3, $4)`, e.source, []byte(e.engine),
			int32(e.boots), int32(e.time)); err != nil && ctx.Err() == nil {
			slog.Warn("Traps: Engine-Zeit nicht gespeichert", "quelle", e.source, "fehler", err)
		}
	}
}

// CheckRole prüft, dass der Dienst als Trap-Rolle verbunden ist: Mitglied von
// openwacht_traps, nicht von openwacht_app, kein Superuser, kein BYPASSRLS.
func CheckRole(ctx context.Context, pool *pgxpool.Pool) error {
	var super, bypass, traps, app bool
	err := pool.QueryRow(ctx, `SELECT r.rolsuper, r.rolbypassrls, pg_has_role(current_user, 'openwacht_traps', 'MEMBER'),
		pg_has_role(current_user, 'openwacht_app', 'MEMBER') FROM pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &traps, &app)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("Datenbankrolle nicht gefunden")
	}
	if err != nil {
		return err
	}
	switch {
	case super || bypass:
		return errors.New("der Trap-Dienst darf nicht als Superuser oder mit BYPASSRLS laufen")
	case !traps:
		return errors.New("die Datenbankrolle ist kein Mitglied von openwacht_traps")
	case app:
		return errors.New("die Datenbankrolle des Trap-Dienstes darf kein Mitglied von openwacht_app sein")
	}
	return nil
}
