// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

var testDevices = map[string]string{}

// testDevice liefert ein Gerät im Mandanten (als Eigentümer angelegt, einmal je Mandant).
func testDevice(t *testing.T, tenant string) string {
	t.Helper()
	if id, ok := testDevices[tenant]; ok {
		return id
	}
	var id string
	if err := owner.QueryRow(context.Background(), `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2)
		RETURNING id::text`, ids[tenant], "Gerät "+tenant).Scan(&id); err != nil {
		t.Fatal(err)
	}
	testDevices[tenant] = id
	return id
}

func newCheck(t *testing.T, user, tenant, name string) response {
	t.Helper()
	return as(t, user).do("POST", "/api/v1/geraete/"+testDevice(t, tenant)+"/checks", map[string]any{
		"name": name, "typ": "tcp", "ziel": map[string]any{"host": "nas.lan", "port": 5001}, "intervall_sekunden": 60})
}

func checkNames(t *testing.T, user string) string {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/checks", nil)
	expectStatus(t, "Checks "+user, r, 200)
	var names []string
	for _, x := range r.body["checks"].([]any) {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	return strings.Join(names, ",")
}

func TestChecksMandantentrennung(t *testing.T) {
	verwaltungSetup(t)
	r := newCheck(t, "v_fw", "Fertigung", "FW NAS")
	expectStatus(t, "Fertigung legt Check an", r, 201)
	id := r.body["id"].(string)

	// Sehen: eigener Mandant und Eltern ja, Geschwister und Kinder nein.
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if got := strings.Contains(checkNames(t, user), "FW NAS"); got != want {
			t.Errorf("%s sieht Check: %v, erwartet %v", user, got, want)
		}
	}
	// Anlegen: nur als Admin/Operator im eigenen Teilbaum.
	expectStatus(t, "Leser legt an", newCheck(t, "v_lz", "Lager Nord", "LZ"), 403)
	// Fremde Geräte sind unsichtbar: 404 wie bei jedem anderen fremden Datensatz.
	expectStatus(t, "Organisation legt bei Fertigung an", newCheck(t, "v_oa", "Fertigung", "fremd"), 404)
	expectStatus(t, "Fertigung legt bei IT an", newCheck(t, "v_fw", "IT", "nach oben"), 404)
	r = newCheck(t, "v_fw", "Lager Nord", "LZ NAS")
	expectStatus(t, "Fertigung legt beim Lager an", r, 201)
	lz := r.body["id"].(string)
	// Ein Leser sieht die Checks seines Mandanten, darf sie aber nicht ändern.
	if !strings.Contains(checkNames(t, "v_lz"), "LZ NAS") {
		t.Error("Leser sieht Check im eigenen Mandanten nicht")
	}
	lzUpd := map[string]any{"name": "LZ geändert", "typ": "ping", "ziel": map[string]any{"host": "nas.lan"}}
	expectStatus(t, "Leser ändert", as(t, "v_lz").do("PUT", "/api/v1/checks/"+lz, lzUpd), 404)
	expectStatus(t, "Leser löscht", as(t, "v_lz").do("DELETE", "/api/v1/checks/"+lz, nil), 404)
	expectStatus(t, "Leser jetzt", as(t, "v_lz").do("POST", "/api/v1/checks/"+lz+"/jetzt", nil), 404)
	expectStatus(t, "IT legt bei Fertigung an", newCheck(t, "v_it", "Fertigung", "IT für FW"), 201)

	upd := map[string]any{"name": "FW NAS neu", "typ": "tcp", "ziel": map[string]any{"host": "nas.lan", "port": 5000}}
	// Ändern, löschen, jetzt prüfen: Fremde bekommen 404 (sie sehen den Check nicht).
	for _, u := range []string{"v_oa", "v_lz"} {
		expectStatus(t, u+" ändert", as(t, u).do("PUT", "/api/v1/checks/"+id, upd), 404)
		expectStatus(t, u+" löscht", as(t, u).do("DELETE", "/api/v1/checks/"+id, nil), 404)
		expectStatus(t, u+" jetzt", as(t, u).do("POST", "/api/v1/checks/"+id+"/jetzt", nil), 404)
	}
	// Gerät wechseln: nur innerhalb des Mandanten, nur sichtbare Geräte.
	moveTo := func(user, device string) response {
		m := map[string]any{"geraet_id": device}
		for k, v := range upd {
			m[k] = v
		}
		return as(t, user).do("PUT", "/api/v1/checks/"+id, m)
	}
	expectStatus(t, "zu Gerät im Kind", moveTo("v_fw", testDevice(t, "Lager Nord")), 409)
	expectStatus(t, "zu Gerät der Eltern", moveTo("v_fw", testDevice(t, "IT")), 404)
	var other string
	owner.QueryRow(context.Background(), `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'FW zweites') RETURNING id::text`,
		ids["Fertigung"]).Scan(&other)
	expectStatus(t, "zu zweitem Gerät", moveTo("v_fw", other), 204)
	var dev string
	owner.QueryRow(context.Background(), `SELECT device_id::text FROM openwacht.checks WHERE id = $1`, id).Scan(&dev)
	if dev != other {
		t.Errorf("Gerät nach Wechsel: %s, erwartet %s", dev, other)
	}
	expectStatus(t, "IT ändert", as(t, "v_it").do("PUT", "/api/v1/checks/"+id, upd), 204)
	if !strings.Contains(checkNames(t, "v_fw"), "FW NAS neu") {
		t.Error("Änderung nicht sichtbar")
	}
	expectStatus(t, "Fertigung jetzt", as(t, "v_fw").do("POST", "/api/v1/checks/"+id+"/jetzt", nil), 202)
	expectStatus(t, "Fertigung löscht", as(t, "v_fw").do("DELETE", "/api/v1/checks/"+id, nil), 204)
	expectStatus(t, "doppelt löschen", as(t, "v_fw").do("DELETE", "/api/v1/checks/"+id, nil), 404)

	// Audit beim richtigen Mandanten.
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id = $1
		AND action IN ('check.angelegt', 'check.geaendert', 'check.geloescht') AND details->>'id' = $2`, ids["Fertigung"], id).Scan(&n)
	if n != 4 {
		t.Errorf("Audit: %d Einträge, erwartet 4", n)
	}
}

func TestChecksEingabe(t *testing.T) {
	verwaltungSetup(t)
	post := func(body map[string]any) response {
		return as(t, "v_fw").do("POST", "/api/v1/geraete/"+testDevice(t, "Fertigung")+"/checks", body)
	}
	for name, body := range map[string]map[string]any{
		"unbekannter Typ":   {"name": "a", "typ": "dns", "ziel": map[string]any{"host": "x"}},
		"file-URL":          {"name": "a", "typ": "http", "ziel": map[string]any{"url": "file:///etc/passwd"}},
		"Zugangsdaten":      {"name": "a", "typ": "http", "ziel": map[string]any{"url": "https://u:p@nas.lan/"}},
		"Intervall zu kurz": {"name": "a", "typ": "ping", "ziel": map[string]any{"host": "nas.lan"}, "intervall_sekunden": 5},
		"fremdes Feld":      {"name": "a", "typ": "ping", "ziel": map[string]any{"host": "nas.lan", "url": "http://x/"}},
		// Der Testserver gibt keine Netze frei: IP-Adressen werden sofort abgelehnt.
		"IP nicht freigegeben": {"name": "a", "typ": "ping", "ziel": map[string]any{"host": "192.168.1.10"}},
		"Loopback":             {"name": "a", "typ": "http", "ziel": map[string]any{"url": "http://127.0.0.1:5432/"}},
	} {
		if r := post(body); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	r := post(map[string]any{"name": "a", "typ": "ping", "ziel": map[string]any{"host": "10.1.2.3"}})
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "nicht freigegeben") {
		t.Errorf("Meldung zur Freigabe: %q", r.raw)
	}
	expectStatus(t, "gültig", post(map[string]any{"name": "Doppelt", "typ": "ping", "ziel": map[string]any{"host": "nas.lan"}}), 201)
	expectStatus(t, "doppelter Name", post(map[string]any{"name": "doppelt", "typ": "ping", "ziel": map[string]any{"host": "nas.lan"}}), 409)
}

// Planer: echter Check gegen einen lokalen Port, Zustand landet in der Datenbank.
func TestChecksPlaner(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	cfg := vServer.cfg
	cfg.CheckNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	cfg.CheckPoll = 50 * time.Millisecond
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(name, kind, target string) string {
		var id string
		if err := owner.QueryRow(ctx, `WITH d AS (INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'Testgerät') RETURNING id)
			INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s) SELECT d.id, $2, $3, $4, 30 FROM d RETURNING id::text`, ids["Organisation"], name, kind, target).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	open := insert("Planer offen", "tcp", fmt.Sprintf(`{"host":"127.0.0.1","port":%d}`, port))
	// Ein Ziel, das an der API vorbei in die Datenbank kam, wird trotzdem geprüft.
	bad := insert("Planer ungültig", "http", `{"url":"file:///etc/passwd"}`)
	blocked := insert("Planer gesperrt", "tcp", `{"host":"127.0.0.2","port":5432}`)

	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.RunChecks(rctx); close(done) }()
	state := func(id string) (status, msg string, fails int) {
		owner.QueryRow(ctx, `SELECT coalesce(status, ''), coalesce(message, ''), fails FROM openwacht.checks WHERE id = $1`, id).
			Scan(&status, &msg, &fails)
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a, _, _ := state(open)
		b, _, _ := state(bad)
		c, _, _ := state(blocked)
		if a != "" && b != "" && c != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if st, msg, _ := state(open); st != "ok" || !strings.Contains(msg, fmt.Sprintf("Port %d offen", port)) {
		t.Errorf("offener Port: %s %q", st, msg)
	}
	if st, msg, _ := state(bad); st != "unknown" || !strings.Contains(msg, "Ziel ungültig") {
		t.Errorf("ungültiges Ziel: %s %q", st, msg)
	}
	if st, msg, fails := state(blocked); st != "unknown" || !strings.Contains(msg, "nicht freigegeben") || fails != 1 {
		t.Errorf("gesperrtes Ziel: %s %q %d", st, msg, fails)
	}
	var next time.Time
	owner.QueryRow(ctx, `SELECT next_run FROM openwacht.checks WHERE id = $1`, open).Scan(&next)
	if d := time.Until(next); d < 20*time.Second || d > 31*time.Second {
		t.Errorf("nächster Lauf in %v, erwartet etwa 30 s", d)
	}
}

// Zustand und Revision: Ein neues Ziel verwirft den alten Zustand und
// Ergebnisse, die noch zum alten Ziel gehören.
func TestChecksRevision(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newCheck(t, "v_oa", "Organisation", "Revision")
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)
	record := func(rev int, status string) bool {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.check_record($1, $2, $3, 'Meldung', '', NULL)`, id, rev, status).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	first, second := record(1, "crit"), record(1, "crit")
	if !first || !second {
		t.Fatal("Ergebnis zu Revision 1 verworfen")
	}
	var fails int
	var since1, since2 time.Time
	owner.QueryRow(ctx, `SELECT fails, since FROM openwacht.checks WHERE id = $1`, id).Scan(&fails, &since1)
	if fails != 2 {
		t.Errorf("Fehler in Folge: %d", fails)
	}
	record(1, "ok")
	owner.QueryRow(ctx, `SELECT fails, since FROM openwacht.checks WHERE id = $1`, id).Scan(&fails, &since2)
	if fails != 0 || !since2.After(since1) {
		t.Errorf("nach OK: fails %d, seit %v → %v", fails, since1, since2)
	}
	// Nur der Name ändert sich: Zustand bleibt.
	expectStatus(t, "umbenennen", as(t, "v_oa").do("PUT", "/api/v1/checks/"+id, map[string]any{
		"name": "Revision 2", "typ": "tcp", "ziel": map[string]any{"host": "nas.lan", "port": 5001}, "intervall_sekunden": 60}), 204)
	var status *string
	owner.QueryRow(ctx, `SELECT status FROM openwacht.checks WHERE id = $1`, id).Scan(&status)
	if status == nil || *status != "ok" {
		t.Errorf("Zustand nach Umbenennen: %v", status)
	}
	// Neues Ziel: Zustand weg, altes Ergebnis wird verworfen.
	expectStatus(t, "Ziel ändern", as(t, "v_oa").do("PUT", "/api/v1/checks/"+id, map[string]any{
		"name": "Revision 2", "typ": "tcp", "ziel": map[string]any{"host": "nas.lan", "port": 22}, "intervall_sekunden": 60}), 204)
	owner.QueryRow(ctx, `SELECT status FROM openwacht.checks WHERE id = $1`, id).Scan(&status)
	if status != nil {
		t.Errorf("Zustand nach Zieländerung: %v", *status)
	}
	if record(1, "ok") {
		t.Error("Ergebnis zum alten Ziel übernommen")
	}
	if !record(2, "ok") {
		t.Error("Ergebnis zum neuen Ziel verworfen")
	}
	// „Jetzt prüfen“ direkt nach einem Lauf: zu früh.
	expectStatus(t, "jetzt, zu früh", as(t, "v_oa").do("POST", "/api/v1/checks/"+id+"/jetzt", nil), 429)
}

// Schichten einzeln: Die Datenbank allein verhindert Zugriffe über Mandanten
// hinweg, auch wenn die API-Prüfung fehlte.
func TestChecksPruefungJeSchicht(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	r := newCheck(t, "v_fw", "Fertigung", "Schicht")
	expectStatus(t, "anlegen", r, 201)
	id := r.body["id"].(string)

	tryAs := func(user string, sql string, args ...any) int64 {
		var n int64
		err := vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return -1
		}
		return n
	}
	if n := tryAs("v_oa", `UPDATE openwacht.checks SET name = 'übernommen' WHERE id = $1`, id); n != 0 {
		t.Errorf("Organisation ändert über SQL: %d", n)
	}
	if n := tryAs("v_lz", `DELETE FROM openwacht.checks WHERE id = $1`, id); n != 0 {
		t.Errorf("Leser im Kind löscht über SQL: %d", n)
	}
	if n := tryAs("v_oa", `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s)
		VALUES ($1, 'fremd', 'ping', '{"host":"x"}', 60)`, testDevice(t, "Fertigung")); n != -1 {
		t.Errorf("Organisation legt über SQL bei Fertigung an: %d", n)
	}
	if n := tryAs("v_oa", `INSERT INTO openwacht.checks (tenant_id, device_id, name, kind, target, interval_s)
		VALUES ($1, $2, 'fremd2', 'ping', '{"host":"x"}', 60)`, ids["Fertigung"], testDevice(t, "Organisation")); n != -1 {
		t.Errorf("Mandant beim Anlegen über SQL vorgegeben: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.checks SET device_id = $2 WHERE id = $1`, id, testDevice(t, "Lager Nord")); n != -1 {
		t.Errorf("Check über SQL an Gerät eines anderen Mandanten gehängt: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.checks SET tenant_id = $2 WHERE id = $1`, id, ids["Lager Nord"]); n != -1 {
		t.Errorf("Mandant eines Checks geändert: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.checks SET next_run = now() + interval '30 days' WHERE id = $1`, id); n != -1 {
		t.Errorf("next_run weit in die Zukunft geschoben: %d", n)
	}
	if n := tryAs("v_fw", `UPDATE openwacht.checks SET status = 'ok' WHERE id = $1`, id); n != -1 {
		t.Errorf("Zustand von außen gesetzt: %d", n)
	}
	var visible int
	vServer.withUser(ctx, ids["v_oa"], func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE id = $1`, id).Scan(&visible)
	})
	if visible != 0 {
		t.Error("Organisation sieht Check der Fertigung über SQL")
	}
}
