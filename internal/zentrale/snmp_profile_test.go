// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Etappe 27: SNMP-Zugangsprofile. Baum wie in verwaltung_test.go:
//
//	IT ─┬─ Fertigung ── Lager Nord
//	    └─ Organisation

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/traps"
)

const profCommunity = "profil-gemeinschaft"

var lzAdminOnce sync.Once

// lzAdmin: Admin des Lagers Nord (Untermandant der Fertigung), mit TOTP.
func lzAdmin(t *testing.T) string {
	t.Helper()
	verwaltungSetup(t)
	lzAdminOnce.Do(func() {
		ctx := context.Background()
		hash, _ := auth.HashPassword(testPassword, testParams)
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
			VALUES ($1, 'v_lzchef@test.invalid', 'v_lzchef', $2) RETURNING id::text`, ids["Lager Nord"], hash).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`,
			id, ids["Lager Nord"]); err != nil {
			t.Fatal(err)
		}
		secret, _ := auth.GenerateTOTPSecret()
		enc, _ := auth.Seal(deriveKey(testKey, "openwacht secretbox v1"), secret, []byte(id))
		if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2, totp_enabled = true WHERE id = $1`, id, enc); err != nil {
			t.Fatal(err)
		}
		vMu.Lock()
		ids["v_lzchef"], vSecrets["v_lzchef"] = id, secret
		vMu.Unlock()
	})
	return "v_lzchef"
}

func newProfile(t *testing.T, user, tenant, name string, body map[string]any) response {
	t.Helper()
	b := map[string]any{"name": name, "version": "2c", "community": profCommunity}
	for k, v := range body {
		b[k] = v
	}
	return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/snmp-profile", b)
}

func profileEntry(t *testing.T, user, id string) (map[string]any, bool) {
	t.Helper()
	return listEntry(t, user, "/api/v1/snmp-profile", "profile", id)
}

// sourceSecret entschlüsselt die Kopie an einer Quelle (als Eigentümer).
func sourceSecret(t *testing.T, id string) (snmpSecret, map[string]any) {
	t.Helper()
	var tenant, host, version string
	var port, revision int
	var enc, trapEnc []byte
	var profile *string
	if err := owner.QueryRow(context.Background(), `SELECT tenant_id::text, host, port, version, secret_enc, trap_secret_enc,
		profile_id::text, revision FROM openwacht.snmp_sources WHERE id = $1`, id).
		Scan(&tenant, &host, &port, &version, &enc, &trapEnc, &profile, &revision); err != nil {
		t.Fatal(err)
	}
	info := map[string]any{"version": version, "revision": revision, "profil": profile, "trap": nil}
	if trapEnc != nil {
		ts, err := traps.Open(vServer.trapKey, trapEnc, id, tenant, host, port, version)
		if err != nil {
			t.Fatalf("Trap-Zugangsdaten: %v", err)
		}
		info["trap"] = ts
	}
	if enc == nil {
		return snmpSecret{}, info
	}
	sec, err := vServer.openSNMP(id, tenant, host, port, version, enc)
	if err != nil {
		t.Fatalf("Kopie an der Quelle: %v", err)
	}
	return sec, info
}

func TestSNMPProfilMandantentrennung(t *testing.T) {
	lz := lzAdmin(t)
	ctx := context.Background()
	r := newProfile(t, "v_it", "IT", "PM IT-Switches", nil)
	expectStatus(t, "IT legt an", r, 201)
	itProf := r.body["id"].(string)
	r = newProfile(t, "v_fw", "Fertigung", "PM FW-Switches", nil)
	expectStatus(t, "Fertigung legt an", r, 201)
	fwProf := r.body["id"].(string)
	if strings.Contains(r.raw, profCommunity) {
		t.Error("Community in der Antwort")
	}

	// Anlegen: nur Admins des Mandanten oder darüber.
	expectStatus(t, "Kind legt bei Eltern an", newProfile(t, "v_fw", "IT", "x", nil), 403)
	expectStatus(t, "Geschwister legt an", newProfile(t, "v_oa", "Fertigung", "x", nil), 403)
	expectStatus(t, "Leser legt an", newProfile(t, "v_lz", "Lager Nord", "x", nil), 403)
	expectStatus(t, "Untermandant legt bei Eltern an", newProfile(t, lz, "Fertigung", "x", nil), 403)
	expectStatus(t, "Name doppelt", newProfile(t, "v_it", "Fertigung", "pm fw-switches", nil), 409)
	r = newProfile(t, "v_it", "Fertigung", "PM von oben", nil)
	expectStatus(t, "Eltern legt bei Kind an", r, 201)
	fromAbove := r.body["id"].(string)

	// Sehen: nur Admins, Eltern sehen Kinder, nie Geschwister oder Eltern.
	for _, c := range []struct {
		user string
		id   string
		want bool
	}{
		{"v_it", itProf, true}, {"v_it", fwProf, true}, {"v_fw", fwProf, true}, {"v_fw", fromAbove, true},
		{"v_fw", itProf, false}, {"v_oa", fwProf, false}, {"v_oa", itProf, false},
		{lz, fwProf, false}, {lz, itProf, false}, {"v_lz", fwProf, false}, {"leser", fwProf, false},
	} {
		if _, got := profileEntry(t, c.user, c.id); got != c.want {
			t.Errorf("%s sieht %s: %v, erwartet %v", c.user, c.id, got, c.want)
		}
	}
	list := as(t, "v_it").do("GET", "/api/v1/snmp-profile", nil)
	if strings.Contains(list.raw, profCommunity) {
		t.Error("Community in der Liste")
	}

	// Ändern und Löschen fremder Profile: nicht sichtbar → 404.
	upd := map[string]any{"name": "neu", "version": "2c"}
	expectStatus(t, "Kind ändert Eltern", as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+itProf, upd), 404)
	expectStatus(t, "Geschwister ändert", as(t, "v_oa").do("PUT", "/api/v1/snmp-profile/"+fwProf, upd), 404)
	expectStatus(t, "Untermandant ändert", as(t, lz).do("PUT", "/api/v1/snmp-profile/"+fwProf, upd), 404)
	expectStatus(t, "Geschwister löscht", as(t, "v_oa").do("DELETE", "/api/v1/snmp-profile/"+fwProf, nil), 404)
	expectStatus(t, "Kind löscht Eltern", as(t, "v_fw").do("DELETE", "/api/v1/snmp-profile/"+itProf, nil), 404)
	expectStatus(t, "Eltern benennt Kind um", as(t, "v_it").do("PUT", "/api/v1/snmp-profile/"+fromAbove,
		map[string]any{"name": "PM von oben 2", "version": "2c"}), 200)

	// Die App-Rolle liest secret_enc nie direkt, auch nicht als Admin.
	if n := tryAsUser("v_it", `SELECT secret_enc FROM openwacht.snmp_profiles`); n != -1 {
		t.Error("secret_enc per SELECT lesbar")
	}
	// Zugangsdaten über die Funktion: nur mit Gerät im Teilbaum und als Admin beider.
	var oaDev, fwDev string
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'PM OA') RETURNING id::text`, ids["Organisation"]).Scan(&oaDev)
	owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, 'PM FW') RETURNING id::text`, ids["Fertigung"]).Scan(&fwDev)
	count := func(user, profile, device string) int {
		var n int
		vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.snmp_profile_secret($1, $2)`, profile, device).Scan(&n)
		})
		return n
	}
	for _, c := range []struct {
		user, profile, device string
		want                  int
	}{
		{"v_fw", fwProf, fwDev, 1}, {"v_it", itProf, fwDev, 1}, {"v_it", itProf, oaDev, 1},
		{"v_fw", itProf, fwDev, 0},    // Profil der Eltern: kein Admin dort
		{"v_it", fwProf, oaDev, 0},    // Profil eines Geschwisters des Geräts
		{"v_oa", itProf, oaDev, 0},    // Admin des Geräts, nicht des Profils
		{"v_lz", fwProf, fwDev, 0},    // Leser
		{"v_oa", fwProf, fwDev, 0},    // Geschwister
		{"v_fw", fwProf, oaDev, 0},    // Gerät nicht sichtbar
		{"leser", fwProf, fwDev, 0},   // Leser der Fertigung
		{"v_lz", fromAbove, fwDev, 0}, // Leser
	} {
		if got := count(c.user, c.profile, c.device); got != c.want {
			t.Errorf("snmp_profile_secret als %s: %d, erwartet %d", c.user, got, c.want)
		}
	}
	if n := count("v_it", fwProf, fwDev); n != 1 {
		t.Errorf("Eltern-Admin liest Profil des Kindes: %d", n)
	}
	var none *int
	vServer.withUser(ctx, ids["v_fw"], func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT openwacht.snmp_profile_use_count($1)`, itProf).Scan(&none)
	})
	if none != nil {
		t.Error("Nutzungszahl eines fremden Profils lesbar")
	}

	// Negativfälle beim Anlegen.
	for name, body := range map[string]map[string]any{
		"ohne Community": {"community": ""},
		"v3 ohne Daten":  {"version": "3", "community": ""},
		"v3 mit MD5": {"version": "3", "community": "", "v3": map[string]any{"benutzer": "u", "auth": "MD5", "auth_passwort": v3AuthPass,
			"priv": "AES", "priv_passwort": v3PrivPass}},
		"Steuerzeichen": {"community": "a\nb"},
		"Version 4":     {"version": "4"},
	} {
		expectStatus(t, name, newProfile(t, "v_it", "IT", "PM "+name, body), 400)
	}
	expectStatus(t, "leerer Name", newProfile(t, "v_it", "IT", " ", nil), 400)
}

func TestSNMPProfilAnGeraeten(t *testing.T) {
	lz := lzAdmin(t)
	ctx := context.Background()
	r := newProfile(t, "v_fw", "Fertigung", "PA FW", nil)
	expectStatus(t, "Profil FW", r, 201)
	fwProf := r.body["id"].(string)
	r = newProfile(t, "v_it", "IT", "PA IT", nil)
	expectStatus(t, "Profil IT", r, 201)
	itProf := r.body["id"].(string)

	dev := func(user, tenant, name string) string {
		r := newDevice(t, user, tenant, name, "")
		expectStatus(t, "Gerät "+name, r, 201)
		return r.body["id"].(string)
	}
	fw1, fw2 := dev("v_fw", "Fertigung", "PA Switch 1"), dev("v_fw", "Fertigung", "PA Switch 2")
	lzDev := dev("v_it", "Lager Nord", "PA LZ")
	oaDev := dev("v_oa", "Organisation", "PA OA")
	put := func(user, device string, body map[string]any) response {
		return as(t, user).do("PUT", "/api/v1/geraete/"+device+"/snmp", body)
	}
	withProfile := func(host, profile string, extra map[string]any) map[string]any {
		b := map[string]any{"version": "2c", "adresse": host, "profil": profile}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}

	// Zuordnen: nur Profile des eigenen Mandanten oder darüber, nur als Admin beider.
	expectStatus(t, "Kind nimmt Profil der Eltern", put("v_fw", fw1, withProfile("sw1.lan", itProf, nil)), 400)
	expectStatus(t, "Profil eines Geschwisters", put("v_it", oaDev, withProfile("oa.lan", fwProf, nil)), 400)
	expectStatus(t, "Untermandant nimmt Profil der Eltern", put(lz, lzDev, withProfile("lz.lan", fwProf, nil)), 400)
	expectStatus(t, "Geschwister", put("v_oa", fw1, withProfile("sw1.lan", fwProf, nil)), 404)
	expectStatus(t, "Leser", put("v_lz", lzDev, withProfile("lz.lan", fwProf, nil)), 400) // Profil für Leser nicht lesbar
	expectStatus(t, "Profil und eigene Community", put("v_fw", fw1, withProfile("sw1.lan", fwProf, map[string]any{"community": "x"})), 400)
	expectStatus(t, "ungültige ID", put("v_fw", fw1, withProfile("sw1.lan", "kein-uuid", nil)), 400)

	r = put("v_fw", fw1, withProfile("sw1.lan", fwProf, map[string]any{"traps": true}))
	expectStatus(t, "FW-Profil an FW-Gerät", r, 201)
	src1 := r.body["id"].(string)
	r = put("v_it", fw2, withProfile("sw2.lan", itProf, map[string]any{"version": "3"}))
	expectStatus(t, "IT-Profil an FW-Gerät (Eltern)", r, 201)
	src2 := r.body["id"].(string)
	r = put("v_it", lzDev, withProfile("lz.lan", fwProf, nil))
	expectStatus(t, "FW-Profil an LZ-Gerät (Eltern)", r, 201)
	srcLZ := r.body["id"].(string)

	sec, info := sourceSecret(t, src1)
	if sec.Community != profCommunity || info["profil"] == nil || *info["profil"].(*string) != fwProf || info["version"] != "2c" {
		t.Fatalf("Quelle 1: %+v %+v", sec, info)
	}
	if ts, _ := info["trap"].(traps.Secret); ts.Community != profCommunity {
		t.Errorf("Trap-Kopie: %+v", info["trap"])
	}
	if sec, info := sourceSecret(t, src2); sec.Community != profCommunity || info["version"] != "2c" {
		t.Errorf("Version kommt aus dem Profil: %+v %+v", sec, info)
	}
	e, _ := snmpEntry(t, "v_fw", src1)
	if e["profil_id"] != fwProf || e["profil_name"] != "PA FW" || e["hat_community"] != true {
		t.Errorf("Liste: %+v", e)
	}
	e, _ = snmpEntry(t, "v_fw", src2)
	if e["profil_id"] != itProf || e["profil_name"] != nil {
		t.Errorf("Name des Eltern-Profils sichtbar: %+v", e)
	}

	// Direkt in der Datenbank: dieselben Regeln (Trigger).
	if n := tryAsUser("v_fw", `UPDATE openwacht.snmp_sources SET profile_id = $2 WHERE id = $1`, src1, itProf); n != -1 {
		t.Error("Kind setzt Profil der Eltern per SQL")
	}
	if n := tryAsUser("v_it", `UPDATE openwacht.snmp_sources SET version = '1' WHERE id = $1`, src1); n != -1 {
		t.Error("Version weicht vom Profil ab")
	}
	r = put("v_oa", oaDev, map[string]any{"version": "2c", "adresse": "oa.lan", "community": testCommunity})
	expectStatus(t, "OA eigene Community", r, 201)
	if n := tryAsUser("v_it", `UPDATE openwacht.snmp_sources SET profile_id = $2 WHERE id = $1`, r.body["id"], fwProf); n != -1 {
		t.Error("Profil eines Geschwisters per SQL zugeordnet")
	}
	if n := tryAsUser("v_it", `UPDATE openwacht.snmp_sources SET profile_id = $2 WHERE id = $1`, r.body["id"], itProf); n != 1 {
		t.Errorf("Profil der Eltern per SQL: %d", n)
	}
	owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, r.body["id"])
	if n := tryAsUser(lz, `UPDATE openwacht.snmp_sources SET profile_id = $2 WHERE id = $1`, srcLZ, fwProf); n != 1 {
		t.Errorf("unverändertes Profil darf bleiben: %d", n)
	}

	// Untermandant ändert sein Gerät mit Eltern-Profil: Intervall ja, Adresse nicht (Profil nicht lesbar).
	expectStatus(t, "LZ ändert Intervall", put(lz, lzDev, map[string]any{"version": "2c", "adresse": "lz.lan", "intervall_sekunden": 120}), 200)
	if _, info := sourceSecret(t, srcLZ); info["profil"] == nil {
		t.Error("Profil nach Intervall weg")
	}
	expectStatus(t, "LZ ändert Adresse", put(lz, lzDev, map[string]any{"version": "2c", "adresse": "lz2.lan"}), 400)

	// Neue Adresse mit Profil: neue Kopie, an die neue Adresse gebunden.
	expectStatus(t, "Adresse ändern", put("v_fw", fw1, map[string]any{"version": "2c", "adresse": "sw1-neu.lan"}), 200)
	if sec, info := sourceSecret(t, src1); sec.Community != profCommunity || info["profil"] == nil {
		t.Errorf("nach Adresswechsel: %+v %+v", sec, info)
	}

	// Profil ändern: alle Quellen neu verschlüsselt, auch Trap-Kopie.
	_, before := sourceSecret(t, src1)
	r = as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW", "version": "2c", "community": "neue-gemeinschaft"})
	expectStatus(t, "Community ändern", r, 200)
	if r.body["neu_verschluesselt"] != 2.0 {
		t.Errorf("neu verschlüsselt: %v", r.body["neu_verschluesselt"])
	}
	sec, after := sourceSecret(t, src1)
	if sec.Community != "neue-gemeinschaft" || after["revision"].(int) <= before["revision"].(int) {
		t.Errorf("Quelle 1 nach Änderung: %+v %+v", sec, after)
	}
	if ts, _ := after["trap"].(traps.Secret); ts.Community != "neue-gemeinschaft" {
		t.Errorf("Trap-Kopie nach Änderung: %+v", after["trap"])
	}
	if sec, _ := sourceSecret(t, srcLZ); sec.Community != "neue-gemeinschaft" {
		t.Errorf("LZ-Quelle nach Änderung: %+v", sec)
	}
	if sec, _ := sourceSecret(t, src2); sec.Community != profCommunity {
		t.Error("Quelle mit anderem Profil verändert")
	}
	// Nur Name: nichts neu verschlüsselt.
	r = as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW 2", "version": "2c"})
	expectStatus(t, "Name ändern", r, 200)
	if r.body["neu_verschluesselt"] != 0.0 {
		t.Errorf("Name ändern verschlüsselt neu: %v", r.body)
	}
	// Versionswechsel ohne Zugangsdaten: abgelehnt.
	expectStatus(t, "auf v3 ohne Daten", as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW 2", "version": "3"}), 400)
	expectStatus(t, "auf 1 ohne Community", as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW 2", "version": "1"}), 400)
	// Auf v3: Quellen bekommen Version und Verfahren.
	r = as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW 2", "version": "3",
		"v3": map[string]any{"benutzer": "wtest", "auth": "SHA-256", "auth_passwort": v3AuthPass, "priv": "AES-128", "priv_passwort": v3PrivPass}})
	expectStatus(t, "auf v3", r, 200)
	sec, info = sourceSecret(t, src1)
	if sec.V3 == nil || sec.V3.User != "wtest" || info["version"] != "3" {
		t.Errorf("Quelle nach v3: %+v %+v", sec, info)
	}
	if ts, _ := info["trap"].(traps.Secret); ts.V3 == nil {
		t.Errorf("Trap-Kopie nach v3: %+v", info["trap"])
	}
	e, _ = snmpEntry(t, "v_fw", src1)
	if e["v3_auth"] != snmp.AuthSHA256 || e["v3_priv"] != snmp.PrivAES {
		t.Errorf("Verfahren an der Quelle: %+v", e)
	}
	// Eigene Community ohne Feld „profil“: Profil gelöst.
	expectStatus(t, "eigene Community", put("v_fw", fw1, map[string]any{"version": "2c", "adresse": "sw1-neu.lan", "community": testCommunity}), 200)
	if sec, info := sourceSecret(t, src1); sec.Community != testCommunity || info["profil"] != (*string)(nil) {
		t.Errorf("nach eigener Community: %+v %+v", sec, info)
	}

	// Ein Gerät, das der Profil-Admin nicht ändern darf, gibt es nicht; die
	// Zählung muss trotzdem stimmen: als Eigentümer eine zweite Zuordnung an
	// einem Organisation-Gerät vortäuschen (umgeht den Trigger nicht, daher
	// Trigger kurz aus), dann muss das Ändern scheitern und nichts ändern.
	if _, err := owner.Exec(ctx, `ALTER TABLE openwacht.snmp_sources DISABLE TRIGGER snmp_sources_zz_profile`); err != nil {
		t.Fatal(err)
	}
	var oaSrc string
	err := owner.QueryRow(ctx, `INSERT INTO openwacht.snmp_sources (id, device_id, version, host, secret_enc, profile_id, v3_auth, v3_priv)
		VALUES (gen_random_uuid(), $1, '3', 'oa.lan', $2, $3, 'sha256', 'aes') RETURNING id::text`,
		oaDev, make([]byte, 40), fwProf).Scan(&oaSrc)
	owner.Exec(ctx, `ALTER TABLE openwacht.snmp_sources ENABLE TRIGGER snmp_sources_zz_profile`)
	if err != nil {
		t.Fatal(err)
	}
	r = as(t, "v_fw").do("PUT", "/api/v1/snmp-profile/"+fwProf, map[string]any{"name": "PA FW 2", "version": "2c", "community": "dritte"})
	expectStatus(t, "Profil mit unerreichbarer Quelle", r, 409)
	if sec, _ := sourceSecret(t, srcLZ); sec.V3 == nil {
		t.Error("Quelle trotz Abbruch geändert")
	}
	owner.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, oaSrc)

	// Löschen: Quellen behalten die Kopie, ohne Profil.
	expectStatus(t, "Profil löschen", as(t, "v_it").do("DELETE", "/api/v1/snmp-profile/"+fwProf, nil), 204)
	if sec, info := sourceSecret(t, srcLZ); sec.V3 == nil || info["profil"] != (*string)(nil) {
		t.Errorf("nach Löschen: %+v %+v", sec, info)
	}
	expectStatus(t, "gelöschtes Profil zuordnen", put("v_fw", fw1, withProfile("sw1-neu.lan", fwProf, nil)), 400)
}

// Ende zu Ende: „Verbindung prüfen“ mit einem Profil gegen snmpd.
func TestSNMPProfilGegenSnmpd(t *testing.T) {
	host, port := snmpdTarget(t)
	allowLoopbackSNMP(t)
	resetProbeLimit()
	t.Cleanup(resetProbeLimit)
	r := newProfile(t, "v_fw", "Fertigung", "PS snmpd", map[string]any{"community": "geheim-test"})
	expectStatus(t, "Profil", r, 201)
	prof := r.body["id"].(string)
	r = newDevice(t, "v_fw", "Fertigung", "PS Gerät", "")
	expectStatus(t, "Gerät", r, 201)
	dev := r.body["id"].(string)
	r = as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev+"/snmp/pruefen", map[string]any{"version": "2c", "adresse": host, "port": port, "profil": prof})
	expectStatus(t, "prüfen", r, 200)
	if r.body["ok"] != true {
		t.Fatalf("prüfen mit Profil: %s", r.raw)
	}
	resetProbeLimit()
	r = as(t, "v_oa").do("POST", "/api/v1/geraete/"+dev+"/snmp/pruefen", map[string]any{"version": "2c", "adresse": host, "port": port, "profil": prof})
	expectStatus(t, "Geschwister prüft", r, 404)
}
