// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestAutoFenster(t *testing.T) {
	berlin, _ := time.LoadLocation("Europe/Berlin")
	mo22 := time.Date(2026, 11, 23, 22, 30, 0, 0, berlin) // Montag
	di03 := time.Date(2026, 11, 24, 3, 0, 0, 0, berlin)   // Dienstag
	alle := 127
	nurMo := 1
	for name, c := range map[string]struct {
		k    autoCandidate
		t    time.Time
		want bool
	}{
		"ganzer Tag":                  {autoCandidate{Days: alle}, mo22, true},
		"falscher Tag":                {autoCandidate{Days: 2}, mo22, false},
		"im Fenster":                  {autoCandidate{Days: alle, HourFrom: 22, HourTo: 23}, mo22, true},
		"vor dem Fenster":             {autoCandidate{Days: alle, HourFrom: 23, HourTo: 24 % 24}, mo22, false},
		"über Mitternacht, abends":    {autoCandidate{Days: nurMo, HourFrom: 22, HourTo: 5}, mo22, true},
		"über Mitternacht, morgens":   {autoCandidate{Days: nurMo, HourFrom: 22, HourTo: 5}, di03, true},
		"über Mitternacht, Tag fehlt": {autoCandidate{Days: 2, HourFrom: 22, HourTo: 5}, di03, false},
		"über Mitternacht, nach Ende": {autoCandidate{Days: alle, HourFrom: 22, HourTo: 2}, di03, false},
	} {
		if got := c.k.inWindow(c.t); got != c.want {
			t.Errorf("%s: %v, erwartet %v", name, got, c.want)
		}
	}
}

func TestAutoGrund(t *testing.T) {
	now := time.Now()
	base := autoCandidate{Version: "1.0.4", Uploaded: now.Add(-2 * time.Hour), WaitHours: 24, Days: 127}
	for name, c := range map[string]struct {
		k    autoCandidate
		ver  string
		want string
	}{
		"schon aktuell":               {base, "1.0.4", "aktuell"},
		"neuer als Paket":             {base, "1.0.5", "aktuell"},
		"Pilot sofort":                {func() autoCandidate { k := base; k.Pilot = true; return k }(), "1.0.3", ""},
		"Wartezeit":                   {base, "1.0.3", "Wartezeit läuft"},
		"Pilot mit Fehler":            {func() autoCandidate { k := base; k.WaitHours = 0; k.Pilots, k.PilotsError = 2, 1; return k }(), "1.0.3", "angehalten: ein Pilot meldet einen Fehler"},
		"Piloten noch nicht dran":     {func() autoCandidate { k := base; k.WaitHours = 0; k.Pilots = 2; return k }(), "1.0.3", "wartet auf die Piloten"},
		"Piloten fertig":              {func() autoCandidate { k := base; k.WaitHours = 0; k.Pilots, k.PilotsOK = 2, 1; return k }(), "1.0.3", ""},
		"ohne Piloten nach Wartezeit": {func() autoCandidate { k := base; k.WaitHours = 1; return k }(), "1.0.3", ""},
	} {
		if got := c.k.autoReason(c.ver, now); got != c.want {
			t.Errorf("%s: %q, erwartet %q", name, got, c.want)
		}
	}
}

func TestAgentUpdateAutomatik(t *testing.T) {
	agentServer(t)
	resetSettings(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys = ""
		owner.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
		owner.Exec(ctx, `DELETE FROM openwacht.agent_update_auto`)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'auto-%'`)
		owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE hostname LIKE 'auto-%' AND revoked_at IS NULL`)
		owner.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE name IN ('Auto Pilot', 'Auto Pilot Org')`)
		resetSettings(t)
	})
	vServer.cfg.UpdateKeys = keyLine(pub, "")
	setOperator(t, "v_it", true)
	bin := []byte("agent-1.0.4")
	expectStatus(t, "hochladen", uploadUpdate(t, as(t, "v_it"), signedPackage(t, priv, "1.0.4", "linux/amd64", bin), bin), 201)

	var pilotGroup, orgGroup string
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'Auto Pilot') RETURNING id::text`, ids["Fertigung"]).Scan(&pilotGroup)
	owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, name) VALUES ($1, 'Auto Pilot Org') RETURNING id::text`, ids["Organisation"]).Scan(&orgGroup)

	// --- Regel: Mandantentrennung ---
	path := "/api/v1/mandanten/" + ids["Fertigung"] + "/agent-updates/automatik"
	regel := map[string]any{"aktiv": true, "pilotgruppe": pilotGroup, "wartezeit_stunden": 24, "tage": []int{1, 2, 3, 4, 5, 6, 7}, "von": 0, "bis": 0}
	expectStatus(t, "Geschwister", as(t, "v_oa").do("PUT", path, regel), 404)
	expectStatus(t, "Leser", as(t, "v_lz").do("PUT", path, regel), 404)
	expectStatus(t, "Kind setzt bei Eltern", as(t, "v_fw").do("PUT", "/api/v1/mandanten/"+ids["IT"]+"/agent-updates/automatik", regel), 404)
	fremd := map[string]any{"aktiv": true, "pilotgruppe": orgGroup, "wartezeit_stunden": 24, "tage": []int{1}, "von": 0, "bis": 0}
	expectStatus(t, "Pilotgruppe eines anderen Mandanten", as(t, "v_fw").do("PUT", path, fremd), 400)
	for name, body := range map[string]map[string]any{
		"Wartezeit zu groß": {"aktiv": true, "wartezeit_stunden": 721, "tage": []int{1}, "von": 0, "bis": 0},
		"Tag 8":             {"aktiv": true, "wartezeit_stunden": 1, "tage": []int{8}, "von": 0, "bis": 0},
		"ohne Tage":         {"aktiv": true, "wartezeit_stunden": 1, "tage": []int{}, "von": 0, "bis": 0},
		"Stunde 24":         {"aktiv": true, "wartezeit_stunden": 1, "tage": []int{1}, "von": 0, "bis": 24},
	} {
		expectStatus(t, name, as(t, "v_fw").do("PUT", path, body), 400)
	}
	expectStatus(t, "Eltern setzen beim Kind", as(t, "v_it").do("PUT", path, regel), 200)
	expectStatus(t, "Admin setzt", as(t, "v_fw").do("PUT", path, regel), 200)
	if l := as(t, "v_oa").do("GET", "/api/v1/agent-updates/automatik", nil); strings.Contains(l.raw, ids["Fertigung"]) {
		t.Errorf("Geschwister sieht Regel: %s", l.raw)
	}
	if l := as(t, "v_it").do("GET", "/api/v1/agent-updates/automatik", nil); !strings.Contains(l.raw, ids["Fertigung"]) || !strings.Contains(l.raw, pilotGroup) {
		t.Errorf("Eltern sehen Regel nicht: %s", l.raw)
	}
	// Datenbank allein: Geschwister schreibt nicht.
	if err := vServer.withUser(ctx, ids["v_oa"], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.agent_update_auto SET enabled = false WHERE tenant_id = $1`, ids["Fertigung"])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var an bool
	owner.QueryRow(ctx, `SELECT enabled FROM openwacht.agent_update_auto WHERE tenant_id = $1`, ids["Fertigung"]).Scan(&an)
	if !an {
		t.Error("Geschwister hat die Regel per SQL geändert")
	}

	// --- Ablauf: Pilot zuerst, dann die übrigen ---
	agent := func(host string, pilot bool) *testAgent {
		tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
		a, st, body := register(t, tok, host)
		if st != 200 {
			t.Fatalf("Registrierung %s: %d %s", host, st, body)
		}
		if pilot {
			owner.Exec(ctx, `UPDATE openwacht.devices SET group_id = $2 WHERE id = (SELECT device_id FROM openwacht.agents WHERE id = $1)`, a.id, pilotGroup)
		}
		return a
	}
	pil := agent("auto-pilot", true)
	rest := agent("auto-rest", false)
	angebot := func(a *testAgent, host, ver string) string {
		if r := a.reportAs(host, ver, "linux/amd64"); r.Update != nil {
			return r.Update.Version
		}
		return ""
	}
	if v := angebot(rest, "auto-rest", "1.0.3"); v != "" {
		t.Errorf("übriger Agent sofort: %s", v)
	}
	if v := angebot(pil, "auto-pilot", "1.0.3"); v != "1.0.4" {
		t.Fatalf("Pilot bekommt nichts: %q", v)
	}
	var auto bool
	owner.QueryRow(ctx, `SELECT auto FROM openwacht.agent_update_releases WHERE agent_id = $1`, pil.id).Scan(&auto)
	if !auto {
		t.Error("Freigabe nicht als automatisch markiert")
	}
	// Wartezeit vorbei, aber Pilot noch nicht auf 1.0.4: die übrigen warten.
	owner.Exec(ctx, `UPDATE openwacht.agent_updates SET uploaded_at = now() - interval '25 hours'`)
	if v := angebot(rest, "auto-rest", "1.0.3"); v != "" {
		t.Errorf("übriger Agent vor den Piloten: %s", v)
	}
	// Pilot meldet einen Fehler: angehalten.
	owner.Exec(ctx, `UPDATE openwacht.agents SET snapshot = jsonb_set(snapshot, '{update_fehler}', '"Signatur falsch"') WHERE id = $1`, pil.id)
	owner.Exec(ctx, `UPDATE openwacht.agents SET snapshot = jsonb_set(snapshot, '{agent}', '"1.0.3"') WHERE id = $1`, pil.id)
	if v := angebot(rest, "auto-rest", "1.0.3"); v != "" {
		t.Errorf("trotz Fehler beim Piloten: %s", v)
	}
	// Pilot läuft mit 1.0.4: jetzt die übrigen.
	pil.reportAs("auto-pilot", "1.0.4", "linux/amd64")
	if v := angebot(rest, "auto-rest", "1.0.3"); v != "1.0.4" {
		t.Errorf("übriger Agent nach den Piloten: %q", v)
	}
	// Freigabe von Hand geht vor: die Automatik überschreibt sie nicht.
	hand := agent("auto-hand", false)
	owner.Exec(ctx, `INSERT INTO openwacht.agent_updates (version, os, arch, sha256, size, signature, data, key_id)
		SELECT '1.0.3', os, arch, sha256, size, signature, data, key_id FROM openwacht.agent_updates WHERE version = '1.0.4'`)
	expectStatus(t, "von Hand", as(t, "v_fw").do("PUT", "/api/v1/agents/"+hand.id+"/update", map[string]any{"version": "1.0.3"}), 200)
	if v := angebot(hand, "auto-hand", "1.0.2"); v != "1.0.3" {
		t.Errorf("Freigabe von Hand überschrieben: %q", v)
	}
	// Außerhalb des Zeitfensters: nichts Neues.
	loc, _ := vServer.zone()
	h := time.Now().In(loc).Hour()
	regel["von"], regel["bis"] = (h+2)%24, (h+3)%24
	expectStatus(t, "Fenster", as(t, "v_fw").do("PUT", path, regel), 200)
	spaet := agent("auto-spaet", true)
	if v := angebot(spaet, "auto-spaet", "1.0.3"); v != "" {
		t.Errorf("außerhalb des Fensters: %q", v)
	}
	// Automatik aus: auch für Piloten nichts.
	regel["von"], regel["bis"], regel["aktiv"] = 0, 0, false
	expectStatus(t, "aus", as(t, "v_fw").do("PUT", path, regel), 200)
	if v := angebot(spaet, "auto-spaet", "1.0.3"); v != "" {
		t.Errorf("Automatik aus: %q", v)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'agent_update.automatik' AND tenant_id = $1`, ids["Fertigung"]).Scan(&n)
	if n < 4 {
		t.Errorf("Audit: %d", n)
	}
}
