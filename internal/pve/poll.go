// SPDX-License-Identifier: AGPL-3.0-only

package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Info: was „Verbindung prüfen“ zeigt.
type Info struct {
	Node       string   `json:"knoten"`
	Version    string   `json:"version"`
	UptimeS    uint64   `json:"laufzeit_s"`
	ExtraPrivs []string `json:"zu_viele_rechte"`
}

func (c *Client) budget() time.Duration {
	if c.Budget > 0 {
		return c.Budget
	}
	return 40 * time.Second
}

// Probe liest Knoten, Version und die Rechte des Tokens.
func (c *Client) Probe(ctx context.Context, cfg Config) (_ Info, err error) {
	defer safe.Recover("proxmox", &err)
	ctx, cancel := context.WithTimeout(ctx, c.budget())
	defer cancel()
	s, err := c.open(cfg)
	if err != nil {
		return Info{}, err
	}
	defer s.closer()
	node, err := s.node(ctx)
	if err != nil {
		return Info{}, err
	}
	st, err := s.status(ctx, node)
	if err != nil {
		return Info{}, err
	}
	extra, _ := s.extraPrivs(ctx)
	if extra == nil {
		extra = []string{}
	}
	return Info{Node: node, Version: st.version, UptimeS: st.uptime, ExtraPrivs: extra}, nil
}

var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`)

// node: der Knoten, mit dem die Zentrale spricht (local=1 in /cluster/status;
// ohne Cluster gibt es genau einen).
func (s *session) node(ctx context.Context) (string, error) {
	var cs []struct {
		Type  string  `json:"type"`
		Name  string  `json:"name"`
		Local flexInt `json:"local"`
	}
	if err := s.get(ctx, "/cluster/status", nil, &cs); err != nil {
		return "", err
	}
	var nodes []string
	for _, e := range cs {
		if e.Type != "node" || !nodePattern.MatchString(e.Name) {
			continue
		}
		if e.Local == 1 {
			return e.Name, nil
		}
		nodes = append(nodes, e.Name)
	}
	if len(nodes) == 1 {
		return nodes[0], nil
	}
	return "", errors.New("Knoten nicht erkennbar (Antwort von /cluster/status ohne lokalen Knoten)")
}

type nodeStatus struct {
	version string
	uptime  uint64
}

func (s *session) status(ctx context.Context, node string) (nodeStatus, error) {
	var st struct {
		PVEVersion string  `json:"pveversion"`
		Uptime     flexInt `json:"uptime"`
	}
	if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/status", nil, &st); err != nil {
		return nodeStatus{}, err
	}
	// „pve-manager/9.2.2/abcdef“ → „9.2.2“
	v := st.PVEVersion
	if parts := strings.Split(v, "/"); len(parts) >= 2 && strings.HasPrefix(v, "pve-manager/") {
		v = parts[1]
	}
	return nodeStatus{version: clean(v, 40), uptime: st.Uptime.u64()}, nil
}

// extraPrivs: Rechte des Tokens, die über Lesen (*.Audit) hinausgehen.
func (s *session) extraPrivs(ctx context.Context) ([]string, error) {
	var perms map[string]map[string]flexInt
	if err := s.get(ctx, "/access/permissions", nil, &perms); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	n := 0
	for _, privs := range perms {
		for p, v := range privs {
			if n++; n > 10000 {
				break
			}
			if v == 0 || strings.HasSuffix(p, ".Audit") || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, clean(p, 60))
		}
	}
	sort.Strings(out)
	if len(out) > 32 {
		out = append(out[:32], "…")
	}
	return out, nil
}

// Poll fragt einen Host ab. prev ist der letzte Snapshot (Backups und
// „beim Booten starten“ werden fortgeschrieben).
func (c *Client) Poll(ctx context.Context, cfg Config, prev *snmp.Snapshot) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("proxmox", &err)
	ctx, cancel := context.WithTimeout(ctx, c.budget())
	defer cancel()
	s, err := c.open(cfg)
	if err != nil {
		return nil, err
	}
	defer s.closer()
	now := c.now()
	var pp *snmp.Proxmox
	if prev != nil {
		pp = prev.Proxmox
	}

	node, err := s.node(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.status(ctx, node)
	if err != nil {
		return nil, err
	}
	snap := &snmp.Snapshot{CollectedAt: now, Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{}}
	snap.System = snmp.System{Name: node, Descr: "Proxmox VE " + st.version, UptimeS: st.uptime}
	px := &snmp.Proxmox{Node: node, Version: st.version, Guests: []snmp.Guest{}, Storages: []snmp.Storage{}, ThinPools: []snmp.ThinPool{}}
	snap.Proxmox = px
	partial := func(part string, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrToken) {
			return err
		}
		snap.Partial = append(snap.Partial, part)
		return nil
	}

	if err := s.guests(ctx, node, px, pp, now); err != nil {
		if e := partial("Gäste", err); e != nil {
			return nil, e
		}
		if pp != nil { // Backup-Stand nicht verlieren
			px.Guests = pp.Guests
		}
	}
	if err := s.backupJobs(ctx, px); err != nil {
		if e := partial("Backup-Jobs", err); e != nil {
			return nil, e
		}
	}
	if err := s.storages(ctx, node, snap); err != nil {
		if e := partial("Speicher", err); e != nil {
			return nil, e
		}
	}
	if err := s.thinPools(ctx, node, px); err != nil {
		if e := partial("Thin-Pools", err); e != nil {
			return nil, e
		}
	}
	if err := s.backups(ctx, node, px, pp, now); err != nil {
		if e := partial("Backups", err); e != nil {
			return nil, e
		}
	}
	if extra, err := s.extraPrivs(ctx); err == nil {
		px.ExtraPrivs = extra
	} else if e := partial("Rechte", err); e != nil {
		return nil, e
	}
	return snap, nil
}

func (s *session) guests(ctx context.Context, node string, px, pp *snmp.Proxmox, now time.Time) error {
	old := map[string]snmp.Guest{}
	if pp != nil {
		for _, g := range pp.Guests {
			old[g.Type+"/"+strconv.Itoa(g.VMID)] = g
		}
	}
	type item struct {
		VMID     flexInt `json:"vmid"`
		Name     string  `json:"name"`
		Status   string  `json:"status"`
		Template flexInt `json:"template"`
		Uptime   flexInt `json:"uptime"`
	}
	var list []snmp.Guest
	for _, typ := range []string{"qemu", "lxc"} {
		var items []item
		if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/"+typ, nil, &items); err != nil {
			return err
		}
		for _, it := range items {
			if it.VMID < 100 || it.VMID > 999999999 {
				continue
			}
			if len(list) >= MaxGuests {
				break
			}
			list = append(list, snmp.Guest{VMID: int(it.VMID), Type: typ, Name: clean(it.Name, MaxText),
				Status: clean(it.Status, 30), Template: it.Template == 1, UptimeS: it.Uptime.u64()})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].VMID < list[j].VMID })
	configs := 0
	for i := range list {
		g := &list[i]
		if o, ok := old[g.Type+"/"+strconv.Itoa(g.VMID)]; ok {
			g.OnBoot, g.ConfigAt = o.OnBoot, o.ConfigAt
			g.BackupOK, g.BackupTry, g.BackupError = o.BackupOK, o.BackupTry, o.BackupError
		}
		if g.Template || g.OnBoot != nil && now.Sub(g.ConfigAt) < configEvery && !g.ConfigAt.After(now) {
			continue
		}
		if configs >= maxConfigsPerPoll {
			continue
		}
		configs++
		var cfg struct {
			OnBoot flexInt `json:"onboot"`
		}
		if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/"+g.Type+"/"+strconv.Itoa(g.VMID)+"/config", nil, &cfg); err != nil {
			if ctx.Err() != nil || errors.Is(err, ErrToken) {
				return err
			}
			continue // bleibt beim alten Wert
		}
		on := cfg.OnBoot == 1
		g.OnBoot, g.ConfigAt = &on, now
	}
	px.Guests = list
	if px.Guests == nil {
		px.Guests = []snmp.Guest{}
	}
	return nil
}

// backupJobs: welche Gäste in keinem Backup-Job stehen.
func (s *session) backupJobs(ctx context.Context, px *snmp.Proxmox) error {
	var missing []struct {
		VMID flexInt `json:"vmid"`
	}
	if err := s.get(ctx, "/cluster/backup-info/not-backed-up", nil, &missing); err != nil {
		return err
	}
	not := map[int]bool{}
	for _, m := range missing {
		not[int(m.VMID)] = true
	}
	for i := range px.Guests {
		in := !not[px.Guests[i].VMID]
		px.Guests[i].InJob = &in
	}
	px.BackupInfo = true
	return nil
}

func (s *session) storages(ctx context.Context, node string, snap *snmp.Snapshot) error {
	var items []struct {
		Storage string  `json:"storage"`
		Type    string  `json:"type"`
		Active  flexInt `json:"active"`
		Enabled *int    `json:"enabled"`
		Shared  flexInt `json:"shared"`
		Total   flexInt `json:"total"`
		Used    flexInt `json:"used"`
	}
	if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/storage", nil, &items); err != nil {
		return err
	}
	px := snap.Proxmox
	seen := map[string]bool{}
	for _, it := range items {
		name := clean(it.Storage, 100)
		if name == "" || seen[name] {
			continue
		}
		if len(px.Storages) >= MaxStorages {
			snap.Truncated = append(snap.Truncated, "Speicher")
			break
		}
		seen[name] = true
		st := snmp.Storage{Name: name, Type: clean(it.Type, 30), Active: it.Active == 1,
			Enabled: it.Enabled == nil || *it.Enabled == 1, Shared: it.Shared == 1,
			TotalBytes: it.Total.u64(), UsedBytes: it.Used.u64()}
		px.Storages = append(px.Storages, st)
		if st.Enabled && st.Active && st.TotalBytes > 0 && st.UsedBytes <= st.TotalBytes {
			snap.Disks = append(snap.Disks, snmp.Disk{Mount: st.Name, FSType: st.Type,
				TotalBytes: st.TotalBytes, FreeBytes: st.TotalBytes - st.UsedBytes})
		}
	}
	sort.Slice(px.Storages, func(i, j int) bool { return px.Storages[i].Name < px.Storages[j].Name })
	sort.Slice(snap.Disks, func(i, j int) bool { return snap.Disks[i].Mount < snap.Disks[j].Mount })
	return nil
}

func (s *session) thinPools(ctx context.Context, node string, px *snmp.Proxmox) error {
	var items []struct {
		LV           string  `json:"lv"`
		VG           string  `json:"vg"`
		Size         flexInt `json:"lv_size"`
		Used         flexInt `json:"used"`
		MetadataSize flexInt `json:"metadata_size"`
		MetadataUsed flexInt `json:"metadata_used"`
	}
	if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/disks/lvmthin", nil, &items); err != nil {
		return err
	}
	for _, it := range items {
		if len(px.ThinPools) >= MaxThinPools {
			break
		}
		name := clean(it.VG, 60) + "/" + clean(it.LV, 60)
		if it.LV == "" {
			continue
		}
		px.ThinPools = append(px.ThinPools, snmp.ThinPool{Name: name, SizeBytes: it.Size.u64(), UsedBytes: it.Used.u64(),
			MetaSizeBytes: it.MetadataSize.u64(), MetaUsedBytes: it.MetadataUsed.u64()})
	}
	sort.Slice(px.ThinPools, func(i, j int) bool { return px.ThinPools[i].Name < px.ThinPools[j].Name })
	return nil
}

var (
	finishedRe = regexp.MustCompile(`Finished Backup of VM (\d{3,9})\b`)
	failedRe   = regexp.MustCompile(`Backup of VM (\d{3,9}) failed(?: - (.*))?$`)
)

type task struct {
	UPID    string  `json:"upid"`
	Type    string  `json:"type"`
	ID      string  `json:"id"`
	Status  string  `json:"status"`
	EndTime flexInt `json:"endtime"`
}

// backups wertet neue, beendete vzdump-Aufgaben aus: aus dem Protokoll
// ergibt sich je Gast „fertig“ oder „fehlgeschlagen“. Der Zeitpunkt ist das
// Ende der Aufgabe. Wer die Aufgabe gestartet hat, wird nicht gespeichert.
func (s *session) backups(ctx context.Context, node string, px, pp *snmp.Proxmox, now time.Time) error {
	since := now.Add(-TaskWindow)
	if pp != nil && pp.TasksUntil.After(since) && !pp.TasksUntil.After(now) {
		since = pp.TasksUntil
	}
	px.TasksUntil = since
	var list []task
	q := url.Values{"typefilter": {"vzdump"}, "limit": {"500"}}
	if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks", q, &list); err != nil {
		return err
	}
	var todo []task
	for _, t := range list {
		end := time.Unix(int64(t.EndTime), 0)
		if t.Type != "vzdump" || t.EndTime <= 0 || !end.After(since) || end.After(now.Add(time.Hour)) || len(t.UPID) > 300 {
			continue
		}
		todo = append(todo, t)
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].EndTime < todo[j].EndTime })
	if len(todo) > maxTasksPerPoll {
		todo = todo[:maxTasksPerPoll]
	}
	idx := map[int]int{}
	for i, g := range px.Guests {
		idx[g.VMID] = i
	}
	for _, t := range todo {
		res, err := s.taskResult(ctx, node, t)
		if err != nil {
			return err // nächste Abfrage versucht es ab hier erneut
		}
		end := time.Unix(int64(t.EndTime), 0).UTC()
		for vmid, msg := range res {
			i, ok := idx[vmid]
			if !ok {
				continue
			}
			g := &px.Guests[i]
			e := end
			if g.BackupTry == nil || !g.BackupTry.After(e) {
				g.BackupTry = &e
				g.BackupError = msg
			}
			if msg == "" && (g.BackupOK == nil || g.BackupOK.Before(e)) {
				g.BackupOK = &e
			}
		}
		px.TasksUntil = time.Unix(int64(t.EndTime), 0).UTC()
	}
	return nil
}

// taskResult: VMID → "" (fertig) oder Fehlertext.
func (s *session) taskResult(ctx context.Context, node string, t task) (map[int]string, error) {
	var lines []struct {
		T string `json:"t"`
	}
	q := url.Values{"start": {"0"}, "limit": {strconv.Itoa(maxLogLines)}}
	if err := s.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(t.UPID)+"/log", q, &lines); err != nil {
		return nil, err
	}
	res := map[int]string{}
	for _, l := range lines {
		if m := finishedRe.FindStringSubmatch(l.T); m != nil {
			if id, err := strconv.Atoi(m[1]); err == nil {
				res[id] = ""
			}
		} else if m := failedRe.FindStringSubmatch(l.T); m != nil {
			if id, err := strconv.Atoi(m[1]); err == nil {
				msg := clean(m[2], MaxText)
				if msg == "" {
					msg = "fehlgeschlagen"
				}
				res[id] = msg
			}
		}
	}
	// Einzelner Gast ohne passende Zeile (z. B. gekürztes Protokoll): Status
	// der Aufgabe.
	if id, err := strconv.Atoi(t.ID); err == nil && id >= 100 {
		if _, ok := res[id]; !ok {
			if t.Status == "OK" {
				res[id] = ""
			} else {
				res[id] = clean(fmt.Sprintf("Aufgabe beendet mit %q", t.Status), MaxText)
			}
		}
	}
	return res, nil
}

// Rebooted: Laufzeit des Knotens ist kleiner geworden, und er lief vorher
// lange genug, dass der Neustart gemeldet wird (snmp.MinUptimeForReboot).
func Rebooted(prevUptime, newUptime uint64) bool {
	return snmp.RebootCounts(prevUptime) && newUptime+60 < prevUptime
}
