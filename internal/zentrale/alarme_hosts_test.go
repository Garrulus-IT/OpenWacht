// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

// hostSnapshot: Messwerte mit Arbeitsspeicher- und Plattenbelegung in Prozent.
func hostSnapshot(t *testing.T, mem int, disks map[string]int) string {
	t.Helper()
	var ds []map[string]any
	for mount, pct := range disks {
		ds = append(ds, map[string]any{"einhaengepunkt": mount, "dateisystem": "ext4", "gesamt": 1000, "frei": 1000 - pct*10})
	}
	b, _ := json.Marshal(map[string]any{
		"hostname": "x", "speicher": map[string]any{"gesamt": 1000, "verfuegbar": 1000 - mem*10}, "platten": ds})
	return string(b)
}

func TestHostAlarme(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	server, _ := alarm.NormalizeServer(f.URL)

	tenant := func(name, parent string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2) RETURNING id::text`,
			parent, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ta := tenant("Host A", ids["IT"])
	tb := tenant("Host B", ta)
	tc := tenant("Host C", ids["IT"]) // Geschwister von A
	channel := func(tid, name, topic string, children bool) string {
		id, _ := newUUID()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic, include_children)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, tid, name, server, topic, children); err != nil {
			t.Fatal(err)
		}
		return id
	}
	chA := channel(ta, "A mit Kindern", "ha", true)
	channel(ta, "A allein", "ha2", false)
	channel(tb, "B", "hb", false)
	channel(tc, "C", "hc", false)
	agent := func(tid, host string) string {
		id, _ := newUUID()
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, last_seen, snapshot)
			VALUES ($1, $2, $3, 's1', now() + interval '30 days', now(), $4)`, id, tid, host, hostSnapshot(t, 50, map[string]int{"/": 50})); err != nil {
			t.Fatal(err)
		}
		return id
	}
	agB := agent(tb, "agb")
	agA := agent(ta, "aga")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE tenant_id IN ($1, $2, $3)`, ta, tb, tc)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE tenant_id IN ($1, $2, $3)`, ta, tb, tc)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE tenant_id IN ($1, $2, $3)`, ta, tb, tc)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id IN ($1, $2)`, tb, tc)
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, ta)
	})
	set := func(id, sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE openwacht.agents SET `+sql+` WHERE id = $1`, append([]any{id}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	round := func(what string) map[string][]ntfyMsg {
		t.Helper()
		if _, err := s.alertRoundN(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return f.take()
	}
	// want: Topic → Titel | Nachricht
	expect := func(what string, got map[string][]ntfyMsg, want map[string]string) {
		t.Helper()
		for topic, tm := range want {
			title, msg, _ := strings.Cut(tm, " | ")
			if len(got[topic]) != 1 || got[topic][0].Title != title || msg != "" && got[topic][0].Message != msg {
				t.Errorf("%s: an %s %+v, erwartet „%s“", what, topic, got[topic], tm)
			}
		}
		for topic, msgs := range got {
			if _, ok := want[topic]; !ok {
				t.Errorf("%s: unerwartet an %s: %+v", what, topic, msgs)
			}
		}
	}

	expect("alles gut", round("1"), nil)

	// Platte voll: Warnung an den eigenen Mandanten und an Eltern mit
	// Untermandanten, nie an Geschwister oder Eltern ohne Untermandanten.
	set(agB, `snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 92}))
	expect("Platte 92 %", round("2"), map[string]string{
		"ha": "Host B: 1 Problem | ⚠️ Host B / agb · Platte /: 92 % belegt (Warnung ab 90 %)",
		"hb": "Host B: 1 Problem | ⚠️ agb · Platte /: 92 % belegt (Warnung ab 90 %)"})
	expect("keine Wiederholung", round("3"), nil)
	// Hysterese: 89 % ist noch keine Entwarnung, 87 % schon.
	set(agB, `snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 89}))
	expect("89 %", round("4"), nil)
	set(agB, `snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 87}))
	expect("87 %", round("5"), map[string]string{"ha": "Host B: 1 wieder OK | ✅ Host B / agb · Platte /: 87 % belegt", "hb": "Host B: 1 wieder OK"})
	expect("danach still", round("6"), nil)

	// Stumm: Alarm, Messwerte bleiben unberührt (auch wenn sie veraltet schlecht sind).
	set(agB, `last_seen = now() - interval '5 minutes', snapshot = $2`, hostSnapshot(t, 99, map[string]int{"/": 99}))
	expect("stumm", round("7"), map[string]string{
		"ha": "Host B: 1 Problem | ❌ Host B / agb: meldet sich nicht, seit 5 Min.",
		"hb": "Host B: 1 Problem | ❌ agb: meldet sich nicht, seit 5 Min."})
	expect("stumm, keine Wiederholung", round("8"), nil)
	// Erinnerung nach 12 h.
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	got := round("9")
	expect("Erinnerung", got, map[string]string{"ha": "Host B: 1 Problem", "hb": "Host B: 1 Problem"})
	if m := got["hb"]; len(m) == 1 && !strings.HasSuffix(m[0].Message, "(Erinnerung)") {
		t.Errorf("Erinnerung: %q", m[0].Message)
	}
	s.now = time.Now
	// Meldet sich wieder, mit vollem Arbeitsspeicher: Entwarnung und neues Problem in einer Nachricht.
	set(agB, `last_seen = now(), snapshot = $2`, hostSnapshot(t, 96, map[string]int{"/": 50}))
	expect("wieder da", round("10"), map[string]string{
		"hb": "Host B: 1 Problem, 1 wieder OK | ❌ agb · Arbeitsspeicher: 96 % belegt (kritisch ab 95 %)\n✅ agb: meldet sich wieder",
		"ha": "Host B: 1 Problem, 1 wieder OK"})

	// Schonfrist: Eine frisch gestartete Zentrale meldet stumme Agents erst
	// nach HostSilentAfter, frische Agents aber sofort.
	set(agA, `last_seen = now() - interval '10 minutes'`)
	s.started = time.Now()
	set(agB, `snapshot = $2`, hostSnapshot(t, 50, map[string]int{"/": 50}))
	expect("Schonfrist", round("11"), map[string]string{"ha": "Host B: 1 wieder OK", "hb": "Host B: 1 wieder OK"})
	s.started = time.Now().Add(-time.Hour)
	expect("nach Schonfrist", round("12"), map[string]string{
		"ha": "Host A: 1 Problem | ❌ aga: meldet sich nicht, seit 10 Min.", "ha2": "Host A: 1 Problem"})

	// Check und Host im selben Durchlauf: eine Nachricht, beides vermerkt.
	var cB string
	if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
		INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, 'B-NAS', 'ping', '{"host":"x.lan"}', 60 FROM d RETURNING id::text`, tb).Scan(&cB); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, 'crit', 'keine Antwort', '', NULL)`, cB).Scan(&ok); err != nil || !ok {
			t.Fatalf("check_record: %v %v", ok, err)
		}
	}
	set(agB, `last_seen = now() - interval '4 minutes'`)
	expect("Check und Host", round("13"), map[string]string{
		"hb": "Host B: 2 Probleme | ❌ Testgerät · B-NAS: keine Antwort\n❌ agb: meldet sich nicht, seit 4 Min.",
		"ha": "Host B: 2 Probleme"})
	expect("beides vermerkt", round("14"), nil)

	// Neues Topic: Der Kanal bekommt auch die Host-Probleme neu.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.alert_channels SET topic = 'ha3' WHERE id = $1`, chA); err != nil {
		t.Fatal(err)
	}
	expect("neues Topic", round("15"), map[string]string{"ha3": "Host A: 3 Probleme"})

	// Gesperrt: letzte Entwarnung, danach nie wieder.
	set(agB, `revoked_at = now()`)
	expect("gesperrt", round("16"), map[string]string{
		"hb":  "Host B: 1 wieder OK | ✅ agb: Agent gesperrt, wird nicht mehr überwacht",
		"ha3": "Host B: 1 wieder OK"})
	set(agB, `last_seen = now() - interval '1 day'`)
	expect("gesperrt, still", round("17"), nil)
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alert_host_candidates() WHERE agent_id = $1`, agB).Scan(&n)
	if n != 0 {
		t.Errorf("gesperrter Agent ohne Probleme noch Kandidat: %d", n)
	}

	// Unlesbare Messwerte: Der Durchlauf scheitert nicht, stumm wird weiter bewertet.
	set(agA, `last_seen = now(), snapshot = '{"speicher": "kaputt"}'`)
	expect("kaputte Messwerte", round("18"), map[string]string{"ha3": "Host A: 1 wieder OK", "ha2": "Host A: 1 wieder OK"})
}

// Die Anwendungsrolle kommt an alert_state_agents nur über die Funktionen.
func TestHostAlarmZustandNichtLesbar(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	for _, q := range []string{
		`SELECT count(*) FROM openwacht.alert_state_agents`,
		`DELETE FROM openwacht.alert_state_agents`,
		`INSERT INTO openwacht.alert_state_agents (agent_id, channel_id, tenant_id, subject, alerted, alerted_at)
			VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'stumm', 'crit', now())`,
	} {
		_, err := pool.Exec(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v", q, err)
		}
	}
}

func TestHostSchwellenPruefen(t *testing.T) {
	for _, c := range []struct {
		mod  func(*Config)
		want string
	}{
		{func(c *Config) { c.HostSilentAfter = 90 * time.Second }, "zwei Meldeintervallen"},
		{func(c *Config) { c.DiskWarn, c.DiskCrit = 95, 90 }, "Platte: Die Warnschwelle"},
		{func(c *Config) { c.MemWarn, c.MemCrit = 95, 95 }, "Arbeitsspeicher: Die Warnschwelle"},
		{func(c *Config) { c.DiskCrit = 101 }, "höchstens 100"},
	} {
		cfg := vServer.cfg
		c.mod(&cfg)
		if _, err := New(cfg, pool, testKey); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("erwartet „%s“, bekommen %v", c.want, err)
		}
	}
	// Eine Schwelle aus, die andere an: erlaubt.
	cfg := vServer.cfg
	cfg.DiskWarn, cfg.MemCrit = -1, -1
	if _, err := New(cfg, pool, testKey); err != nil {
		t.Error(err)
	}
}
