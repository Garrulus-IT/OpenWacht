// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6: Konten löschen (von Hand und 90 Tage nach dem Sperren).

import (
	"context"
	"strings"
	"testing"
)

func userExists(t *testing.T, id string) bool {
	t.Helper()
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.users WHERE id = $1`, id).Scan(&n)
	return n == 1
}

func TestKontoLoeschenVonHand(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	id := kontoMitRollen(t, "del_lager", "Lager Nord", map[string]string{"Lager Nord": "leser"}, false, false)
	fremd := kontoMitRollen(t, "del_beide", "Lager Nord", map[string]string{"Lager Nord": "leser", "Organisation": "leser"}, false, false)
	del := func(user, target string) response {
		return as(t, user).do("DELETE", "/api/v1/benutzer/"+target, nil)
	}
	expectStatus(t, "nicht gesperrt", del("v_fw", id), 409)
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id IN ($1, $2)`, id, fremd)
	var at *string
	owner.QueryRow(ctx, `SELECT disabled_at::text FROM openwacht.users WHERE id = $1`, id).Scan(&at)
	if at == nil {
		t.Fatal("Zeitpunkt der Sperre fehlt")
	}
	expectStatus(t, "Geschwister", del("v_oa", id), 404)
	expectStatus(t, "Leser", del("v_lz", id), 404)
	expectStatus(t, "Konto mit fremder Rolle", del("v_fw", fremd), 403)
	expectStatus(t, "sich selbst", del("v_fw", ids["v_fw"]), 400)
	expectStatus(t, "Admin löscht", del("v_fw", id), 204)
	if userExists(t, id) {
		t.Fatal("Konto noch da")
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'benutzer.geloescht' AND details->>'id' = $1
		AND details->>'quelle' = 'hand'`, id).Scan(&n)
	if n != 1 {
		t.Errorf("Audit: %d", n)
	}
	// Entsperren setzt den Zeitpunkt zurück.
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = false WHERE id = $1`, fremd)
	owner.QueryRow(ctx, `SELECT disabled_at::text FROM openwacht.users WHERE id = $1`, fremd).Scan(&at)
	if at != nil {
		t.Error("Zeitpunkt nach Entsperren geblieben")
	}
}

func TestKontoLoeschenNachFrist(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	alt := kontoMitRollen(t, "del_alt", "Lager Nord", map[string]string{"Lager Nord": "leser"}, false, false)
	jung := kontoMitRollen(t, "del_jung", "Lager Nord", map[string]string{"Lager Nord": "leser"}, false, false)
	betr := kontoMitRollen(t, "del_betr", "IT", map[string]string{"IT": "admin"}, false, false)
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id IN ($1, $2, $3)`, alt, jung, betr)
	owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true WHERE id = $1`, betr)
	t.Cleanup(func() { owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = false WHERE id = $1`, betr) })
	// Den Zeitpunkt kann nur der Trigger setzen; hier für den Test zurückdatieren.
	owner.Exec(ctx, `ALTER TABLE openwacht.users DISABLE TRIGGER users_disabled_at`)
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled_at = now() - interval '91 days' WHERE id IN ($1, $2)`, alt, betr)
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled_at = now() - interval '89 days' WHERE id = $1`, jung)
	owner.Exec(ctx, `ALTER TABLE openwacht.users ENABLE TRIGGER users_disabled_at`)
	vServer.purgeUsers(ctx)
	if userExists(t, alt) || !userExists(t, jung) || !userExists(t, betr) {
		t.Fatalf("nach Frist: alt %v, jung %v, Betreiber %v", userExists(t, alt), userExists(t, jung), userExists(t, betr))
	}
	r := as(t, "v_fw").do("GET", "/api/v1/benutzer", nil)
	if r.status != 200 || !strings.Contains(r.raw, `"loescht_am"`) {
		t.Errorf("Liste ohne Löschdatum: %s", r.raw)
	}
}
