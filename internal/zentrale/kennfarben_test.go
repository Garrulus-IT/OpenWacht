// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestKennfarbeKontrast(t *testing.T) {
	for in, want := range map[string]string{
		"#c0307a": "#c0307a", // Pink
		"#C0307A": "#c0307a",
		"#00838a": "#00838a", // Türkis
		"#e05a00": "#e05a00", // Orange
		"#7b5cd6": "#7b5cd6",
	} {
		got, err := cleanKennfarbe(in)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", in, got, err)
		}
	}
	for in, msg := range map[string]string{
		"pink":     "Format",
		"#fff":     "Format",
		"#c0307a;": "Format",
		"#ffff00":  "hellem Grund", // Zitronengelb
		"#f2f2f2":  "hellem Grund",
		"#102238":  "dunklem Grund", // Nachtblau
		"#000000":  "dunklem Grund",
	} {
		_, err := cleanKennfarbe(in)
		if err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, erwartet %q", in, err, msg)
		}
	}
	// Gegenprobe mit bekannten Werten aus docs/design/README.md
	if r := contrastRatio([3]uint8{0x2c, 0x7a, 0x57}, kennfarbeHell); r < 5.1 || r > 5.3 {
		t.Errorf("Kontrast OK auf Weiß: %.2f, erwartet 5,2", r)
	}
}

func TestSensorSchluessel(t *testing.T) {
	u := "0b6a8a00-1111-4222-8333-444455556666"
	for key, want := range map[string]string{
		"c:" + u:                  "check|" + u + "|",
		"h:" + u + "/speicher":    "host|" + u + "|speicher",
		"s:" + u + "/if:3":        "snmp|" + u + "|if:3",
		"s:" + u + "/trap:" + u:   "snmp|" + u + "|trap:" + u,
		"h:" + u + "/platte:/a/b": "host|" + u + "|platte:/a/b",
	} {
		art, id, sub, err := parseSensorKey(key)
		if got := art + "|" + id + "|" + sub; err != nil || got != want {
			t.Errorf("%s: %s, %v", key, got, err)
		}
	}
	for _, key := range []string{"", "c:", "c:x", "x:" + u, "h:" + u, "h:" + u + "/", "h:nope/speicher", "s:" + u + "/a\nb",
		"h:" + u + "/" + strings.Repeat("x", 301)} {
		if _, _, _, err := parseSensorKey(key); err == nil {
			t.Errorf("%q angenommen", key)
		}
	}
}

// Rot gewinnt immer: Bei gleicher Schwere verdeckt eine Kennfarbe nie den
// Zustand ohne Kennfarbe; eine schlimmere Schwere gewinnt trotz Kennfarbe.
func TestAnzeigeKennfarbeRotGewinnt(t *testing.T) {
	pink := &kennfarbeRef{ID: "k", Name: "Neustart verpasst", Farbe: "#c0307a"}
	dev := func(name, st string, k *kennfarbeRef) *anzeigeKnoten {
		d := &anzeigeKnoten{Name: name, Art: "geraet", Status: st}
		d.setzeKennfarbe(k)
		return d
	}
	for name, tc := range map[string]struct {
		kinder          []*anzeigeKnoten
		status, kennfrb string
	}{
		"gleich, rot zuerst":       {[]*anzeigeKnoten{dev("a", dispCrit, nil), dev("b", dispCrit, pink)}, dispCrit, ""},
		"gleich, pink zuerst":      {[]*anzeigeKnoten{dev("a", dispCrit, pink), dev("b", dispCrit, nil)}, dispCrit, ""},
		"pink kritisch vor gelb":   {[]*anzeigeKnoten{dev("a", dispWarn, nil), dev("b", dispCrit, pink)}, dispCrit, "#c0307a"},
		"rot vor pink warnung":     {[]*anzeigeKnoten{dev("a", dispWarn, pink), dev("b", dispCrit, nil)}, dispCrit, ""},
		"nur pink":                 {[]*anzeigeKnoten{dev("a", dispOK, nil), dev("b", dispWarn, pink)}, dispWarn, "#c0307a"},
		"OK ohne Kennfarbe":        {[]*anzeigeKnoten{dev("a", dispOK, pink)}, dispOK, ""},
		"unbekannt ohne Kennfarbe": {[]*anzeigeKnoten{dev("a", dispUnknown, pink)}, dispUnknown, ""},
		"bestätigt mit Kennfarbe":  {[]*anzeigeKnoten{dev("a", dispAcked, pink)}, dispAcked, "#c0307a"},
	} {
		g := &anzeigeKnoten{Name: "G", Art: "gruppe", Kinder: tc.kinder}
		root := &anzeigeKnoten{Name: "M", Art: "mandant", Kinder: []*anzeigeKnoten{g}}
		if st := root.worst(); st != tc.status || root.Farbe != tc.kennfrb || g.Farbe != tc.kennfrb {
			t.Errorf("%s: %s %q (Gruppe %q), erwartet %s %q", name, st, root.Farbe, g.Farbe, tc.status, tc.kennfrb)
		}
	}
}

func kennfarbenVon(t *testing.T, user string) map[string]map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/kennfarben", nil)
	expectStatus(t, "Kennfarben "+user, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.body["kennfarben"].([]any) {
		m := x.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

func sensorKennfarbe(t *testing.T, user, key string) map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/sensoren", nil)
	expectStatus(t, "Sensoren "+user, r, 200)
	for _, x := range r.body["sensoren"].([]any) {
		m := x.(map[string]any)
		if m["schluessel"] == key {
			k, _ := m["kennfarbe"].(map[string]any)
			return k
		}
	}
	t.Fatalf("%s sieht Sensor %s nicht", user, key)
	return nil
}

func TestKennfarbenMandanten(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.kennfarben WHERE name LIKE 'KF %'`)
	})
	body := func(name, farbe string) map[string]any { return map[string]any{"name": name, "farbe": farbe} }
	url := func(tenant string) string { return "/api/v1/mandanten/" + ids[tenant] + "/kennfarben" }

	// Anlegen: Leser nein, Geschwister nein, Admin des Mandanten ja
	expectStatus(t, "Leser", as(t, "v_lz").do("POST", url("Lager Nord"), body("KF Leser", "#c0307a")), 403)
	expectStatus(t, "Geschwister", as(t, "v_oa").do("POST", url("Fertigung"), body("KF Fremd", "#c0307a")), 403)
	r := as(t, "v_it").do("POST", url("IT"), body("KF Neustart", "#C0307A"))
	expectStatus(t, "IT legt an", r, 201)
	itID := r.body["id"].(string)
	r = as(t, "v_fw").do("POST", url("Fertigung"), body("KF Fertigung", "#00838a"))
	expectStatus(t, "Fertigung legt an", r, 201)
	fwID := r.body["id"].(string)
	r = as(t, "v_oa").do("POST", url("Organisation"), body("KF Orga", "#7b5cd6"))
	expectStatus(t, "Organisation legt an", r, 201)
	oaID := r.body["id"].(string)
	expectStatus(t, "doppelt", as(t, "v_fw").do("POST", url("Fertigung"), body("kf fertigung", "#00838a")), 409)
	r = as(t, "v_fw").do("POST", url("Fertigung"), body("KF Gelb", "#ffff00"))
	expectStatus(t, "zu blass", r, 400)
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "hellem Grund") {
		t.Errorf("Meldung: %q", msg)
	}

	// Sehen: eigener Mandant, Kinder und Vorfahren; Geschwister nicht
	for user, want := range map[string][]string{
		"v_it": {"KF Neustart", "KF Fertigung", "KF Orga"},
		"v_fw": {"KF Neustart", "KF Fertigung"},
		"v_lz": {"KF Neustart", "KF Fertigung"},
		"v_oa": {"KF Neustart", "KF Orga"},
	} {
		got := kennfarbenVon(t, user)
		n := 0
		for name := range got {
			if strings.HasPrefix(name, "KF ") {
				n++
			}
		}
		for _, w := range want {
			if got[w] == nil {
				t.Errorf("%s sieht %s nicht", user, w)
			}
		}
		if n != len(want) {
			t.Errorf("%s sieht %d Kennfarben, erwartet %d", user, n, len(want))
		}
	}
	if f := kennfarbenVon(t, "v_fw")["KF Neustart"]["farbe"]; f != "#c0307a" {
		t.Errorf("Farbe nicht normalisiert: %v", f)
	}

	// Ändern: Kind nicht an der Farbe der Eltern, Eltern an der des Kinds
	expectStatus(t, "Kind ändert Eltern", as(t, "v_fw").do("PUT", "/api/v1/kennfarben/"+itID, body("KF Neustart", "#00838a")), 404)
	expectStatus(t, "Eltern ändert Kind", as(t, "v_it").do("PUT", "/api/v1/kennfarben/"+fwID, body("KF Fertigung", "#00838a")), 204)

	// Zuordnen an einen Sensor der Fertigung
	r = newCheck(t, "v_fw", "Fertigung", "KF Sensor")
	expectStatus(t, "Sensor", r, 201)
	check := r.body["id"].(string)
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.checks WHERE id = $1`, check) })
	key := "c:" + check
	set := func(user, key string, k any) response {
		return as(t, user).do("PUT", "/api/v1/sensoren/kennfarbe", map[string]any{"schluessel": key, "kennfarbe_id": k})
	}
	expectStatus(t, "Leser setzt", set("v_lz", key, itID), 404)
	expectStatus(t, "Geschwister setzt", set("v_oa", key, oaID), 404)
	r = set("v_fw", key, oaID) // Kennfarbe eines Geschwisters
	expectStatus(t, "fremde Kennfarbe", r, 400)
	expectStatus(t, "Kennfarbe der IT", set("v_fw", key, itID), 204)
	if k := sensorKennfarbe(t, "v_fw", key); k == nil || k["name"] != "KF Neustart" {
		t.Errorf("Sensor zeigt %v", k)
	}
	if k := sensorKennfarbe(t, "v_it", key); k == nil || k["farbe"] != "#c0307a" {
		t.Errorf("IT sieht %v", k)
	}
	expectStatus(t, "entfernen", set("v_fw", key, nil), 204)
	if k := sensorKennfarbe(t, "v_fw", key); k != nil {
		t.Errorf("nach Entfernen: %v", k)
	}

	// Eingebaute Gegenstände eines Agents in der Fertigung
	var dev string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'KF Server') RETURNING id::text`,
		ids["Fertigung"]).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	agent, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.agents (id, tenant_id, device_id, hostname, cert_serial, cert_not_after, last_seen)
		VALUES ($1, $2, $3, 'kf-server', 'kf', now() + interval '30 days', now())`, agent, ids["Fertigung"], dev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, agent)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, dev)
	})
	hkey := "h:" + agent + "/" + "stumm"
	expectStatus(t, "Geschwister am Agent", set("v_oa", hkey, oaID), 404)
	expectStatus(t, "Leser am Agent", set("v_lz", hkey, itID), 404)
	expectStatus(t, "Agent", set("v_fw", hkey, fwID), 204)
	expectStatus(t, "Agent ändern", set("v_it", hkey, itID), 204)
	if k := sensorKennfarbe(t, "v_fw", hkey); k == nil || k["name"] != "KF Neustart" {
		t.Errorf("Erreichbarkeit zeigt %v", k)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.sensor_kennfarben WHERE agent_id = $1`, agent).Scan(&n)
	if n != 1 {
		t.Errorf("Zuordnungen: %d", n)
	}

	// Liste zählt die Verwendung; Löschen nimmt die Kennfarbe von Sensoren
	expectStatus(t, "Sensor erneut", set("v_fw", key, itID), 204)
	if v := kennfarbenVon(t, "v_it")["KF Neustart"]["verwendet"]; v != float64(2) {
		t.Errorf("verwendet: %v", v)
	}
	expectStatus(t, "Kind löscht Eltern", as(t, "v_fw").do("DELETE", "/api/v1/kennfarben/"+itID, nil), 404)
	expectStatus(t, "löschen", as(t, "v_it").do("DELETE", "/api/v1/kennfarben/"+itID, nil), 204)
	if k := sensorKennfarbe(t, "v_fw", key); k != nil {
		t.Errorf("nach Löschen: %v", k)
	}
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.sensor_kennfarben WHERE agent_id = $1`, agent).Scan(&n)
	if n != 0 {
		t.Errorf("Zuordnungen nach Löschen: %d", n)
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action LIKE 'kennfarbe.%' OR action = 'sensor.kennfarbe'`).Scan(&audits)
	if audits < 8 {
		t.Errorf("Audit-Einträge: %d", audits)
	}
}

// Wandanzeige: Kennfarbe am Gerät und im Mandanten darüber, Rot gewinnt an
// der Wurzel, Legende mit Kennfarben von oben, ohne die eines Geschwisters.
func TestAnzeigeKennfarben(t *testing.T) {
	wandSetup(t)
	ctx := context.Background()
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.kennfarben WHERE name LIKE 'KFA %'`) })
	r := as(t, "v_it").do("POST", "/api/v1/mandanten/"+ids["IT"]+"/kennfarben", map[string]any{"name": "KFA Neustart", "farbe": "#c0307a"})
	expectStatus(t, "IT", r, 201)
	pink := r.body["id"].(string)
	var wb string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.kennfarben (tenant_id, name, color) VALUES ($1, 'KFA Geschwister', '#00838a')
		RETURNING id::text`, ids["Wand B"]).Scan(&wb); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.checks SET kennfarbe_id = $1 WHERE name = 'WA1 Ping'`, pink); err != nil {
		t.Fatal(err)
	}
	r = newDisplay(t, "v_it", "Wand A", map[string]any{"name": "KFA Wand", "mit_untermandanten": true})
	expectStatus(t, "Anzeige", r, 201)
	wall := newClient(t, vSrv)
	expectStatus(t, "anmelden", wall.do("POST", "/api/v1/anzeige/anmelden", map[string]string{"schluessel": displayKey(t, r)}), 200)
	d := wall.do("GET", "/api/v1/anzeige/daten", nil)
	expectStatus(t, "Daten", d, 200)
	var out struct {
		Baum struct {
			Status string `json:"status"`
			Farbe  string `json:"farbe"`
			Kinder []struct {
				Name      string `json:"name"`
				Status    string `json:"status"`
				Farbe     string `json:"farbe"`
				Kennfarbe string `json:"kennfarbe"`
				Kinder    []struct {
					Name  string `json:"name"`
					Farbe string `json:"farbe"`
				} `json:"kinder"`
			} `json:"kinder"`
		} `json:"baum"`
		Kennfarben []anzeigeKennfarbe `json:"kennfarben"`
	}
	if err := json.Unmarshal([]byte(d.raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Baum.Status != "crit" || out.Baum.Farbe != "" {
		t.Errorf("Wurzel: %s %q (Rot gewinnt)", out.Baum.Status, out.Baum.Farbe)
	}
	found := false
	for _, k := range out.Baum.Kinder {
		if k.Name == "Wand A1" {
			found = true
			if k.Status != "warn" || k.Farbe != "#c0307a" || k.Kennfarbe != "KFA Neustart" || len(k.Kinder) != 1 || k.Kinder[0].Farbe != "#c0307a" {
				t.Errorf("Wand A1: %+v", k)
			}
		}
	}
	if !found {
		t.Fatal("Wand A1 fehlt")
	}
	var legende []string
	for _, k := range out.Kennfarben {
		if strings.HasPrefix(k.Name, "KFA ") {
			legende = append(legende, k.Name+"="+itoa(k.Geraete))
		}
	}
	if strings.Join(legende, ",") != "KFA Neustart=1" {
		t.Errorf("Legende: %v", legende)
	}
	if strings.Contains(d.raw, "geheime Meldung") || strings.Contains(d.raw, wb) {
		t.Error("Anzeige verrät mehr als Namen und Farben")
	}
}

// Trap-Regeln: Kennfarbe nur aus dem eigenen Mandanten oder darüber.
func TestTrapRegelKennfarbe(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.snmp_trap_rules WHERE name LIKE 'KFT %'`)
		owner.Exec(ctx, `DELETE FROM openwacht.kennfarben WHERE name LIKE 'KFT %'`)
	})
	kf := func(user, tenant, name string) string {
		r := as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/kennfarben", map[string]any{"name": name, "farbe": "#c0307a"})
		expectStatus(t, name, r, 201)
		return r.body["id"].(string)
	}
	itKF, oaKF := kf("v_it", "IT", "KFT IT"), kf("v_oa", "Organisation", "KFT Orga")
	regel := func(k string) response {
		return as(t, "v_fw").do("POST", "/api/v1/trapregeln", map[string]any{"mandant_id": ids["Fertigung"], "name": "KFT " + k[:8],
			"trap_oid": "1.3.6.1.6.3.1.1.5.3", "wirkung": "crit", "kennfarbe_id": k})
	}
	expectStatus(t, "Geschwister", regel(oaKF), 400)
	r := regel(itKF)
	expectStatus(t, "IT", r, 201)
	id := r.body["id"].(string)
	var got *string
	owner.QueryRow(ctx, `SELECT kennfarbe_id::text FROM openwacht.snmp_trap_rules WHERE id = $1`, id).Scan(&got)
	if got == nil || *got != itKF {
		t.Errorf("Kennfarbe der Regel: %v", got)
	}
	// Zustand der Regel erbt die Kennfarbe, aber nur für Benutzer, die die Regel sehen
	zustand := func(user string) *kennfarbeRef {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var k []byte
		if err := tx.QueryRow(ctx, `SELECT set_config('app.user_id', $2, true),
				openwacht.kennfarbe_json(openwacht.kennfarbe_of(NULL, NULL, gen_random_uuid(), 'trap:' || $1::text))`, id, ids[user]).
			Scan(new(string), &k); err != nil {
			t.Fatal(err)
		}
		return parseKennfarbeRef(k)
	}
	if ref := zustand("v_fw"); ref == nil || ref.ID != itKF {
		t.Errorf("Trap-Zustand Fertigung: %v", ref)
	}
	if ref := zustand("v_oa"); ref != nil {
		t.Errorf("Geschwister sieht Kennfarbe der Regel: %v", ref)
	}
}

// Eingaben von Benutzern: nie Panik, angenommene Farben sind normalisiert,
// angenommene Schlüssel haben eine bekannte Art.
func FuzzKennfarbe(f *testing.F) {
	for _, s := range []string{"#c0307a", "#FFFF00", "pink", "", "c:" + strings.Repeat("0", 36), "h:x/y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if c, err := cleanKennfarbe(s); err == nil && !kennfarbePattern.MatchString(c) || err == nil && c != strings.ToLower(c) {
			t.Fatalf("%q → %q", s, c)
		}
		if art, _, sub, err := parseSensorKey(s); err == nil {
			if art != "check" && art != "host" && art != "snmp" || art != "check" && sub == "" {
				t.Fatalf("%q → %s %q", s, art, sub)
			}
		}
	})
}
