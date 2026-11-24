// SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/dbtest"
)

// TestMigrationGeraeteMitAltdaten spielt den Stand 0011 mit Agents, Checks und
// einer Agent-Wartung ein und prüft, wie 0012 sie Geräten zuordnet.
func TestMigrationGeraeteMitAltdaten(t *testing.T) {
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

	migs, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `CREATE SCHEMA openwacht; CREATE TABLE openwacht.schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum bytea NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migs {
		if m.Version > 11 {
			break
		}
		if _, err := owner.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			m.Version, m.Name, m.Checksum[:]); err != nil {
			t.Fatal(err)
		}
	}

	q := func(sql string, args ...any) string {
		t.Helper()
		var s string
		if err := owner.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	it := q(`INSERT INTO openwacht.tenants (parent_id, name) VALUES (NULL, 'IT') RETURNING id::text`)
	fw := q(`INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Fertigung') RETURNING id::text`, it)
	agent := func(tenant, host string, revoked bool, seen string) string {
		id := q(`SELECT gen_random_uuid()::text`)
		q(`INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, last_seen, revoked_at)
			VALUES ($1, $2, $3, 's', now() + interval '30 days', now() - $4::interval,
			        CASE WHEN $5 THEN now() END) RETURNING id::text`, id, tenant, host, seen, revoked)
		return id
	}
	pve1 := agent(it, "pve-1", false, "1 minute")
	pve2alt := agent(it, "pve-2", true, "1 minute") // gesperrt, aber zuletzt gesehen
	pve2 := agent(it, "pve-2", false, "1 hour")
	srv := agent(fw, "srv", false, "1 minute")
	check := func(tenant, name, kind, target string) string {
		return q(`INSERT INTO openwacht.checks (tenant_id, name, kind, target, interval_s)
			VALUES ($1, $2, $3, $4::jsonb, 60) RETURNING id::text`, tenant, name, kind, target)
	}
	cPve1 := check(it, "pve-1 Ping", "ping", `{"host":"pve-1.example.org"}`)
	cPve2 := check(it, "pve-2 SSH", "tcp", `{"host":"PVE-2","port":22}`)
	cDmsWeb := check(it, "DMS Web", "http", `{"url":"https://dms.beispiel.example/login"}`)
	cDmsTLS := check(it, "DMS Zertifikat", "tls", `{"host":"dms.beispiel.example","warnung_tage":21,"kritisch_tage":7}`)
	cIP := check(it, "Zentrale Ping", "ping", `{"host":"172.16.0.36"}`)
	cV6 := check(it, "V6 Web", "http", `{"url":"https://[fd00::1]:8443/x"}`)
	cFW := check(fw, "FW pve-1", "ping", `{"host":"pve-1"}`) // gleicher Name, anderer Mandant
	cSrv := check(fw, "FW srv", "ping", `{"host":"srv.fertigung.lan"}`)
	q(`INSERT INTO openwacht.maintenance (agent_id, ends_at) VALUES ($1, now() + interval '1 hour') RETURNING id::text`, pve1)

	if _, err := Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}

	agentDev := func(a string) string { return q(`SELECT device_id::text FROM openwacht.agents WHERE id = $1`, a) }
	checkDev := func(c string) string { return q(`SELECT device_id::text FROM openwacht.checks WHERE id = $1`, c) }
	devName := func(d string) string {
		return q(`SELECT name || '|' || coalesce(address, '-') || '|' || tenant_id::text FROM openwacht.devices WHERE id = $1`, d)
	}

	if a, b := agentDev(pve2alt), agentDev(pve2); a == b {
		t.Fatal("zwei Agents teilen sich ein Gerät")
	}
	for _, c := range []struct{ name, got, want string }{
		{"pve-1 über erstes Label", checkDev(cPve1), agentDev(pve1)},
		{"pve-2 zum aktiven Agent, groß/klein egal", checkDev(cPve2), agentDev(pve2)},
		{"srv über erstes Label im eigenen Mandanten", checkDev(cSrv), agentDev(srv)},
		{"DMS Web und Zertifikat auf einem Gerät", checkDev(cDmsWeb), checkDev(cDmsTLS)},
	} {
		if c.got != c.want {
			t.Errorf("%s: Gerät %s, erwartet %s", c.name, c.got, c.want)
		}
	}
	for _, c := range []struct{ check, want string }{
		{cDmsWeb, "dms.beispiel.example|dms.beispiel.example|" + it},
		{cIP, "172.16.0.36|172.16.0.36|" + it},
		{cV6, "fd00::1|fd00::1|" + it},
		{cFW, "pve-1|pve-1|" + fw},
		{cPve1, "pve-1|-|" + it},
	} {
		if got := devName(checkDev(c.check)); got != c.want {
			t.Errorf("Gerät von Check: %q, erwartet %q", got, c.want)
		}
	}
	if q(`SELECT count(*)::text FROM openwacht.devices`) != "8" { // 4 Agents + dms, IP, v6, FW pve-1
		t.Errorf("Geräte: %s, erwartet 8", q(`SELECT string_agg(name, ', ' ORDER BY name) FROM openwacht.devices`))
	}
	if got := q(`SELECT device_id::text FROM openwacht.maintenance`); got != agentDev(pve1) {
		t.Errorf("Wartung des Agents nicht auf sein Gerät übertragen: %s", got)
	}
	if q(`SELECT count(*)::text FROM pg_tables WHERE tablename LIKE 'mig_%'`) != "0" {
		t.Error("Hilfstabellen der Migration nicht entfernt")
	}
}
