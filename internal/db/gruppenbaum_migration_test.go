// SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/dbtest"
)

// TestMigrationGruppenbaum spielt den Stand 0015 mit Gruppenpfaden an Geräten
// ein und prüft, wie 0016 daraus den Gruppenbaum baut.
func TestMigrationGruppenbaum(t *testing.T) {
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
	apply := func(from, to int) {
		t.Helper()
		for _, m := range migs {
			if m.Version < from || m.Version > to {
				continue
			}
			if _, err := owner.Exec(ctx, m.SQL); err != nil {
				t.Fatalf("%s: %v", m.Name, err)
			}
		}
	}
	apply(1, 15)

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
	dev := func(tenant, name string, path any) string {
		return q(`INSERT INTO openwacht.devices (tenant_id, name, group_path) VALUES ($1, $2, $3) RETURNING id::text`, tenant, name, path)
	}
	lancom := dev(it, "sw-lancom", "Netzwerk/Switche/Lancom")
	aruba := dev(it, "sw-aruba", "netzwerk/SWITCHE/Aruba") // gleiche Ebenen anders geschrieben
	srv := dev(it, "pve-1", "Server")
	netz := dev(it, "fritzbox", "Netzwerk")
	ohne := dev(it, "drucker", nil)
	fwNetz := dev(fw, "fw-switch", "Netzwerk") // eigener Baum je Mandant
	tief := dev(fw, "fw-tief", "A/B/C/D")

	apply(16, 16)

	if n := q(`SELECT count(*)::text FROM information_schema.columns WHERE table_schema = 'openwacht' AND table_name = 'devices' AND column_name = 'group_path'`); n != "0" {
		t.Error("group_path ist noch da")
	}
	// Pfad je Gerät aus dem Baum (ohne Groß/Klein, die Schreibweise kommt vom ersten Gerät).
	path := func(dev string) string {
		t.Helper()
		return q(`WITH RECURSIVE up(id, parent_id, name, lvl) AS (
				SELECT g.id, g.parent_id, g.name, 0 FROM openwacht.device_groups g JOIN openwacht.devices d ON d.group_id = g.id WHERE d.id = $1
				UNION ALL
				SELECT g.id, g.parent_id, g.name, u.lvl + 1 FROM openwacht.device_groups g JOIN up u ON g.id = u.parent_id)
			SELECT coalesce(lower(string_agg(name, '/' ORDER BY lvl DESC)), '') FROM up`, dev)
	}
	for dev, want := range map[string]string{
		lancom: "netzwerk/switche/lancom", aruba: "netzwerk/switche/aruba", srv: "server", netz: "netzwerk",
		ohne: "", fwNetz: "netzwerk", tief: "a/b/c/d",
	} {
		if got := path(dev); got != want {
			t.Errorf("Pfad %s: %q, erwartet %q", dev, got, want)
		}
	}
	if n := q(`SELECT count(*)::text FROM openwacht.device_groups WHERE tenant_id = $1`, it); n != "5" {
		t.Errorf("Gruppen IT: %s, erwartet 5 (Netzwerk, Switche, Lancom, Aruba, Server)", n)
	}
	if n := q(`SELECT count(*)::text FROM openwacht.device_groups WHERE tenant_id = $1`, fw); n != "5" {
		t.Errorf("Gruppen Fertigung: %s, erwartet 5", n)
	}
	// Fritzbox und Switche hängen an derselben Gruppe „Netzwerk“.
	if q(`SELECT g.parent_id::text FROM openwacht.device_groups g JOIN openwacht.devices d ON d.group_id = g.id WHERE d.id = $1`, lancom) !=
		q(`SELECT g.id::text FROM openwacht.device_groups g WHERE g.parent_id = (SELECT group_id FROM openwacht.devices WHERE id = $1)`, netz) {
		t.Error("Switche hängt nicht unter derselben Gruppe Netzwerk wie die Fritzbox")
	}
	// Reihenfolge anfangs alphabetisch.
	order := func(tenant string, parent any) string {
		return q(`SELECT string_agg(lower(name), ',' ORDER BY position) FROM openwacht.device_groups
			WHERE tenant_id = $1 AND parent_id IS NOT DISTINCT FROM $2::uuid`, tenant, parent)
	}
	if got := order(it, nil); got != "netzwerk,server" {
		t.Errorf("oberste Ebene: %s", got)
	}
	sw := q(`SELECT parent_id::text FROM openwacht.device_groups g JOIN openwacht.devices d ON d.group_id = g.id WHERE d.id = $1`, aruba)
	if got := order(it, sw); got != "aruba,lancom" {
		t.Errorf("unter Switche: %s", got)
	}
	if got := q(`SELECT string_agg(position::text, ',' ORDER BY position) FROM openwacht.device_groups WHERE tenant_id = $1 AND parent_id = $2`, it, sw); got != "0,1" {
		t.Errorf("Positionen: %s", got)
	}
	// Nach der Übernahme gelten die Regeln des Baums.
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.device_groups (tenant_id, parent_id, name)
		SELECT tenant_id, group_id, 'E' FROM openwacht.devices WHERE id = $1`, tief); err == nil || !strings.Contains(err.Error(), "4 Ebenen") {
		t.Errorf("fünfte Ebene: %v", err)
	}
}
