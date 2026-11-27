// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/citrix"
	"github.com/garrulus-it/openwacht/internal/citrix/citrixtest"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

func ctxBody(addr string, extra map[string]any) map[string]any {
	b := map[string]any{"adresse": addr, "benutzer": citrixtest.User, "passwort": citrixtest.Password, "fingerabdruck": xsPin}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestCitrixMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newDevice(t, "v_fw", "Fertigung", "CTX ddc-1", "ddc-01.lan")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/citrix"

	expectStatus(t, "Geschwister legt an", as(t, "v_oa").do("PUT", path, ctxBody("ddc-01.lan", nil)), 404)
	expectStatus(t, "Leser legt an", as(t, "v_lz").do("PUT", path, ctxBody("ddc-01.lan", nil)), 404)
	expectStatus(t, "ohne Fingerabdruck", as(t, "v_fw").do("PUT", path, ctxBody("ddc-01.lan", map[string]any{"fingerabdruck": ""})), 400)
	expectStatus(t, "Benutzer ohne Domäne", as(t, "v_fw").do("PUT", path, ctxBody("ddc-01.lan", map[string]any{"benutzer": "svc"})), 400)
	r = as(t, "v_fw").do("PUT", path, ctxBody("ddc-01.lan", nil))
	expectStatus(t, "Fertigung legt an", r, 201)
	id := r.body["id"].(string)
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if _, got := snmpEntry(t, user, id); got != want {
			t.Errorf("%s sieht Citrix: %v, erwartet %v", user, got, want)
		}
	}
	e, _ := snmpEntry(t, "v_it", id)
	if e["version"] != "citrix" || e["port"] != 443.0 || e["hat_community"] != true {
		t.Errorf("Eintrag: %+v", e)
	}
	if list := as(t, "v_it").do("GET", "/api/v1/snmp", nil); strings.Contains(list.raw, citrixtest.Password) {
		t.Error("Passwort in der Liste")
	}
	expectStatus(t, "SNMP auf Citrix-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/snmp", snmpBody("ddc-01.lan", nil)), 409)
	expectStatus(t, "XenServer auf Citrix-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/xenserver", xsBody("ddc-01.lan", nil)), 409)
	expectStatus(t, "Proxmox auf Citrix-Gerät", as(t, "v_fw").do("PUT", "/api/v1/geraete/"+dev+"/proxmox", pveBody("ddc-01.lan", nil)), 409)
	// Ändern ohne Passwort nur bei gleichem Ziel, Benutzer und Fingerabdruck.
	expectStatus(t, "Intervall", as(t, "v_fw").do("PUT", path, map[string]any{"adresse": "ddc-01.lan", "benutzer": citrixtest.User, "intervall_sekunden": 600}), 200)
	expectStatus(t, "neue Adresse ohne Passwort", as(t, "v_fw").do("PUT", path,
		map[string]any{"adresse": "ddc-02.lan", "benutzer": citrixtest.User, "fingerabdruck": xsPin}), 400)
}

func TestCitrixPruefenUndAbfrage(t *testing.T) {
	verwaltungSetup(t)
	allowLoopback(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	ctx := context.Background()
	srv := citrixtest.Start(t)
	r := newDevice(t, "v_fw", "Fertigung", "CTX Site", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	path := "/api/v1/geraete/" + dev + "/citrix"
	t.Cleanup(func() { as(t, "v_fw").do("DELETE", path, nil) })
	probe := func(b map[string]any) response {
		t.Helper()
		resetProbeLimit()
		return as(t, "v_fw").do("POST", path+"/pruefen", b)
	}
	// Ohne Fingerabdruck: nur der Fingerabdruck, keine Anfrage, kein Passwort.
	r = probe(map[string]any{"adresse": "127.0.0.1", "port": srv.Port, "benutzer": citrixtest.User, "passwort": citrixtest.Password})
	if r.body["ok"] != false || r.body["fingerabdruck_neu"] != citrix.FormatPin(srv.Pin) || len(srv.Methods) != 0 {
		t.Fatalf("Fingerabdruck: %s", r.raw)
	}
	body := ctxBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": citrix.FormatPin(srv.Pin)})
	r = probe(body)
	info, _ := r.body["citrix"].(map[string]any)
	if r.body["ok"] != true || info["vdas"] != 3.0 || info["nicht_registriert"] != 1.0 || info["fehler_gesamt"] != 3.0 {
		t.Fatalf("prüfen: %s", r.raw)
	}
	r = probe(ctxBody("127.0.0.1", map[string]any{"port": srv.Port, "fingerabdruck": srv.Pin, "passwort": "falsch-999-xyz"}))
	if r.body["ok"] != false || strings.Contains(r.raw, "falsch-999") || !strings.Contains(r.raw, "Anmeldung abgelehnt") {
		t.Fatalf("falsches Passwort: %s", r.raw)
	}
	r = as(t, "v_fw").do("PUT", path, body)
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)

	// Abfrage über den Planer, dann Alarme
	cfg := vServer.cfg
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.started = time.Now().Add(-time.Hour)
	owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, id)
	due, err := s.claimSNMP(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range due {
		if c.id == id {
			s.pollSNMP(ctx, c)
		} else {
			owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = $1`, c.id)
		}
	}
	var lastErr *string
	var raw []byte
	owner.QueryRow(ctx, `SELECT last_error, snapshot FROM openwacht.snmp_sources WHERE id = $1`, id).Scan(&lastErr, &raw)
	if lastErr != nil || raw == nil {
		t.Fatalf("Abfrage: %v", lastErr)
	}
	var snap snmp.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Citrix == nil || snap.Citrix.Unregistered != 1 {
		t.Fatalf("Snapshot: %v %s", err, raw)
	}
	if strings.Contains(string(raw), "beispiel.example") && !strings.Contains(string(raw), "VDA-02") {
		t.Errorf("Snapshot: %s", raw)
	}
	// Alarmgegenstände gültig, Bewertung wie erwartet
	var ok1, ok2 bool
	owner.QueryRow(ctx, `SELECT openwacht.valid_snmp_subject('citrixvda'), openwacht.valid_snmp_subject('citrixfehler')`).Scan(&ok1, &ok2)
	if !ok1 || !ok2 {
		t.Error("Gegenstände ungültig")
	}
	found := map[string]string{}
	for _, f := range alarm.EvaluateSNMP(alarm.SNMPInput{Name: "CTX Site", Snapshot: &snap, Citrix: true, Interval: 5 * time.Minute}, nil, alarm.HostLimits{}) {
		found[f.Subject] = f.Status + " " + f.Message
	}
	if !strings.HasPrefix(found["citrixvda"], "warn 1 von 3 VDAs nicht registriert: BEISPIEL\\VDA-02") ||
		!strings.HasPrefix(found["citrixfehler"], "ok 3 fehlgeschlagene") {
		t.Errorf("Bewertung: %v", found)
	}
	// Die Datenbank nimmt Citrix nicht mit Traps oder Sammler.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.snmp_sources SET traps = true WHERE id = $1`, id); err == nil {
		t.Error("Traps für Citrix angenommen")
	}
	// Schlüsselwechsel und Verschieben kennen die Art (AAD).
	if string(snmpSourceAAD([]string{id, "t", "citrix", "h", "443", ""})) != string(citrixAAD(id, "t", "h", 443)) {
		t.Error("snmpSourceAAD kennt citrix nicht")
	}
}
