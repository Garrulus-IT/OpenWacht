// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm/smtptest"
	"github.com/garrulus-it/openwacht/internal/auth"
)

func TestAusfallzeit(t *testing.T) {
	b := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	h := func(n int) time.Time { return b.Add(time.Duration(n) * time.Hour) }
	d, n := downtime([]span{{h(1), h(3)}, {h(2), h(4)}, {h(10), h(11)}, {h(-5), h(-4)}, {h(-1), h(1)}}, b, h(24))
	if d != 5*time.Hour || n != 4 {
		t.Errorf("%v %d", d, n)
	}
	if d, _ := downtime(nil, b, h(24)); d != 0 {
		t.Error("leer")
	}
	if _, err := parseMonth("2026-13", time.UTC); err == nil {
		t.Error("Monat 13")
	}
}

func TestBerichte(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	loc := vServer.mailZone()
	month := time.Date(time.Now().In(loc).Year(), time.Now().In(loc).Month(), 1, 0, 0, 0, 0, loc).AddDate(0, -1, 0)
	monat := month.Format("2006-01")
	monthLen := month.AddDate(0, 1, 0).Sub(month)
	// Geräte in Fertigung und Lager Nord, eins im Organisation
	dev := func(tenant, name string) (string, string) {
		var d, c string
		if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name, created_at) VALUES ($1, $2, $3) RETURNING id)
			INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, 'Ping', 'ping', '{"host":"x.lan"}', 60 FROM d
			RETURNING device_id::text, id::text`, ids[tenant], name, month.AddDate(0, -1, 0)).Scan(&d, &c); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE openwacht.devices SET created_at = $2 WHERE id = $1`, d, month.AddDate(0, -1, 0)); err != nil {
			t.Fatal(err)
		}
		return d, c
	}
	_, cFw := dev("Fertigung", "ber-fw-router")
	dev("Lager Nord", "ber-lz-nas")
	_, cOa := dev("Organisation", "ber-oa-server")
	alarmAt := func(check, tenant string, from, to time.Duration, worst string) {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alarms (tenant_id, check_id, subject, name, status, worst, started_at, changed_at, ended_at)
			VALUES ($1, $2, 'check', 'Ping ber', $5, $5, $3, $3, $4)`, ids[tenant], check, month.Add(from), month.Add(to), worst); err != nil {
			t.Fatal(err)
		}
	}
	alarmAt(cFw, "Fertigung", 10*time.Hour, 12*time.Hour, "crit")
	alarmAt(cFw, "Fertigung", 11*time.Hour, 13*time.Hour, "crit") // überlappend: zusammen 3 h
	alarmAt(cFw, "Fertigung", 20*time.Hour, 30*time.Hour, "warn") // Warnung zählt nicht als Ausfall
	alarmAt(cOa, "Organisation", time.Hour, 2*time.Hour, "crit")
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alarms WHERE name = 'Ping ber'`)
		owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE device_id IN (SELECT id FROM openwacht.devices WHERE name LIKE 'ber-%')`)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'ber-%'`)
		owner.Exec(ctx, `UPDATE openwacht.tenants SET sla_target = NULL`)
	})

	fw := as(t, "v_fw")
	r := fw.do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat, nil)
	expectStatus(t, "Bericht Fertigung", r, 200)
	if strings.Contains(r.raw, "ber-oa") {
		t.Error("Geschwister im Bericht")
	}
	var router map[string]any
	for _, g := range r.body["geraete"].([]any) {
		if g.(map[string]any)["name"] == "ber-fw-router" {
			router = g.(map[string]any)
		}
	}
	want := 100 * (1 - 3*time.Hour.Seconds()/monthLen.Seconds())
	if router == nil || math.Abs(router["verfuegbarkeit"].(float64)-want) > 0.001 || router["ausfall_minuten"].(float64) != 180 ||
		router["ausfaelle"].(float64) != 2 || router["erfuellt"] != true {
		t.Errorf("Router: %v (erwartet %.3f)", router, want)
	}
	if !strings.Contains(r.raw, "ber-lz-nas") {
		t.Error("Untermandant fehlt")
	}
	if r := fw.do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat+"&untermandanten=0", nil); strings.Contains(r.raw, "ber-lz-nas") {
		t.Error("ohne Untermandanten trotzdem enthalten")
	}
	if r.body["alarme"].(float64) != 3 || r.body["kritisch"].(float64) != 2 {
		t.Errorf("Alarme: %v %v", r.body["alarme"], r.body["kritisch"])
	}
	// Trennung
	expectStatus(t, "Organisation liest Fertigung", as(t, "v_oa").do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat, nil), 404)
	expectStatus(t, "Leser LZ liest Fertigung", as(t, "v_lz").do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat, nil), 404)
	if r := as(t, "v_lz").do("GET", "/api/v1/berichte?mandant="+ids["Lager Nord"]+"&monat="+monat, nil); r.status != 200 || strings.Contains(r.raw, "ber-fw") {
		t.Errorf("Leser LZ: %d", r.status)
	}
	for _, bad := range []string{"&monat=2026-13", "&monat=2999-01", "&monat=x"} {
		expectStatus(t, "Monat "+bad, fw.do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+bad, nil), 400)
	}
	// SLA: Ziel setzen (Admin), erben, Grenzen
	expectStatus(t, "SLA zu klein", fw.do("PUT", "/api/v1/mandanten/"+ids["Fertigung"]+"/sla", map[string]any{"ziel": 10}), 400)
	expectStatus(t, "SLA Leser", as(t, "v_lz").do("PUT", "/api/v1/mandanten/"+ids["Lager Nord"]+"/sla", map[string]any{"ziel": 99}), 404)
	expectStatus(t, "SLA Geschwister", as(t, "v_oa").do("PUT", "/api/v1/mandanten/"+ids["Fertigung"]+"/sla", map[string]any{"ziel": 99}), 404)
	expectStatus(t, "SLA Fertigung", fw.do("PUT", "/api/v1/mandanten/"+ids["Fertigung"]+"/sla", map[string]any{"ziel": 99}), 200)
	r = fw.do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat, nil)
	for _, m := range r.body["mandanten"].([]any) {
		mm := m.(map[string]any)
		if mm["ziel"].(float64) != 99 {
			t.Errorf("SLA geerbt: %v", mm)
		}
	}
	expectStatus(t, "SLA hoch", fw.do("PUT", "/api/v1/mandanten/"+ids["Fertigung"]+"/sla", map[string]any{"ziel": 99.9}), 200)
	r = fw.do("GET", "/api/v1/berichte?mandant="+ids["Fertigung"]+"&monat="+monat, nil)
	for _, g := range r.body["geraete"].([]any) {
		if gg := g.(map[string]any); gg["name"] == "ber-fw-router" && gg["erfuellt"] != false {
			t.Errorf("SLA verfehlt nicht erkannt: %v", gg)
		}
	}
	// PDF
	resp, raw := fw.raw("GET", "/api/v1/berichte/pdf?mandant="+ids["Fertigung"]+"&monat="+monat, nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(raw, "%PDF-1.4") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "OpenWacht-Bericht-Fertigung-"+monat+".pdf") {
		t.Errorf("PDF: %d %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(raw, "ber-fw-router") {
		t.Error("PDF ohne Gerät")
	}
}

func TestMonatsberichtPerMail(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	smtp := smtptest.Start(t, false, "relay", "relay-pass")
	s, err := New(vServer.cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := auth.Seal(s.smtpKey(), []byte("relay-pass"), smtpAAD("127.0.0.1", "relay"))
	if _, err := owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = '127.0.0.1', smtp_port = $1, smtp_tls = 'starttls',
		smtp_from = 'openwacht@test.invalid', smtp_user = 'relay', smtp_pass_enc = $2, smtp_ca = $3`, smtp.Port, enc, smtp.CAPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	var ch string
	owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, kind, all_users) VALUES ($1, 'Bericht FW', 'mail', true)
		RETURNING id::text`, ids["Fertigung"]).Scan(&ch)
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, ch)
		owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL, smtp_from = NULL,
			smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
	})
	fw := as(t, "v_fw")
	expectStatus(t, "Monatsbericht für ntfy-Kanal", fw.do("PUT", "/api/v1/alarm-kanaele/"+ch+"/zustellung",
		map[string]any{"monatsbericht": true}), 200)
	loc := s.mailZone()
	s.now = func() time.Time { return time.Date(2026, 12, 2, 8, 0, 0, 0, loc) }
	if n, err := s.sendMonthlyReports(ctx); err != nil || n == 0 {
		t.Fatalf("Versand: %d %v", n, err)
	}
	msgs := smtp.Messages()
	if len(msgs) == 0 || !strings.Contains(msgs[0].Data, "application/pdf") || !strings.Contains(msgs[0].Data, "OpenWacht-Bericht-Fertigung-2026-11.pdf") {
		t.Fatalf("Mail: %+v", msgs)
	}
	found := false
	for _, m := range msgs {
		found = found || m.To[0] == "v_fw@test.invalid"
		if strings.HasPrefix(m.To[0], "v_oa") || strings.HasPrefix(m.To[0], "v_it") {
			t.Errorf("Empfänger ohne Rolle in Fertigung: %v", m.To)
		}
	}
	if !found {
		t.Error("v_fw bekam keinen Bericht")
	}
	if n, _ := s.sendMonthlyReports(ctx); n != 0 {
		t.Error("doppelt verschickt")
	}
	s.now = func() time.Time { return time.Date(2026, 12, 9, 8, 0, 0, 0, loc) }
	owner.Exec(ctx, `DELETE FROM openwacht.report_runs WHERE channel_id = $1`, ch)
	if n, _ := s.sendMonthlyReports(ctx); n != 0 {
		t.Error("nach dem 7. verschickt")
	}
	// ntfy-Kanal: kein Monatsbericht
	var nt string
	owner.QueryRow(ctx, `INSERT INTO openwacht.alert_channels (tenant_id, name, server, topic) VALUES ($1, 'Bericht ntfy', 'https://ntfy.test', 'x')
		RETURNING id::text`, ids["Fertigung"]).Scan(&nt)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, nt) })
	expectStatus(t, "ntfy mit Bericht", fw.do("PUT", "/api/v1/alarm-kanaele/"+nt+"/zustellung", map[string]any{"monatsbericht": true}), 400)
}
