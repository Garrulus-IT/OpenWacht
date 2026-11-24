// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAgentLoeschen(t *testing.T) {
	_, aid, op := wartungZiele(t, "AL")
	ctx := context.Background()
	del := func(user string) response { return as(t, user).do("DELETE", "/api/v1/agents/"+aid, nil) }
	count := func(sql string) int {
		var n int
		owner.QueryRow(ctx, sql, aid).Scan(&n)
		return n
	}
	// Verlauf, Wartung und ein Eintrag im Alarmprotokoll.
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
		VALUES ($1, $2, now(), 'cpu', 5)`, ids["Lager Nord"], aid); err != nil {
		t.Fatal(err)
	}
	dev := agentDevice(t, aid)
	owner.Exec(ctx, `INSERT INTO openwacht.maintenance (device_id, ends_at) VALUES ($1, now() + interval '1 hour')`, dev)
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, agent_id, subject, name, status, worst, started_at, changed_at, ended_at)
		VALUES ($1, $2, 'stumm', 'al-host', 'crit', 'crit', now() - interval '1 hour', now(), now())`, ids["Lager Nord"], aid); err != nil {
		t.Fatal(err)
	}

	expectStatus(t, "ungültige ID", as(t, op).do("DELETE", "/api/v1/agents/kein-uuid", nil), 400)
	expectStatus(t, "Geschwister löscht", del("v_oa"), 404)
	expectStatus(t, "aktiver Agent", del(op), 409)
	// Auch direkt in SQL nicht, selbst als Admin darüber.
	var n int64 = -1
	vServer.withUser(ctx, ids["v_fw"], func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, aid)
		n = tag.RowsAffected()
		return err
	})
	if n != 0 {
		t.Errorf("aktiver Agent über SQL gelöscht: %d", n)
	}

	expectStatus(t, "Operator sperrt", as(t, op).do("POST", "/api/v1/agents/"+aid+"/sperren", nil), 204)
	expectStatus(t, "Leser löscht", del("v_lz"), 403)
	expectStatus(t, "Geschwister löscht gesperrten", del("v_oa"), 404)
	expectStatus(t, "Operator löscht", del(op), 204)
	expectStatus(t, "nochmal löschen", del(op), 404)

	if c := count(`SELECT count(*) FROM openwacht.agents WHERE id = $1`); c != 0 {
		t.Errorf("Agent noch da: %d", c)
	}
	if c := count(`SELECT count(*) FROM openwacht.metrics_host_raw WHERE agent_id = $1`); c != 0 {
		t.Errorf("Verlauf noch da: %d", c)
	}
	// Das Gerät war danach leer und ging mit, samt Wartung.
	var devs, maint int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.devices WHERE id = $1`, dev).Scan(&devs)
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.maintenance WHERE device_id = $1`, dev).Scan(&maint)
	if devs != 0 || maint != 0 {
		t.Errorf("Gerät %d, Wartung %d noch da", devs, maint)
	}
	var left int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.alarms WHERE name = 'al-host' AND agent_id IS NULL`).Scan(&left)
	if left != 1 {
		t.Errorf("Alarmprotokoll: %d Einträge ohne Agent, erwartet 1", left)
	}
	owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = 'al-host'`)
	if c := count(`SELECT count(*) FROM openwacht.audit_log WHERE action = 'agent.geloescht' AND details ->> 'agent' = $1`); c != 1 {
		t.Errorf("Audit: %d", c)
	}
}
