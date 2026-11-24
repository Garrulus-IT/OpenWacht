// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/version"
)

func cleanupRequests(t *testing.T) {
	t.Cleanup(func() {
		ctx := context.Background()
		owner.Exec(ctx, `DELETE FROM openwacht.tenant_requests`)
		// Angelegte Mandanten wieder entfernen (ihr Audit steht am Elternknoten).
		owner.Exec(ctx, `DELETE FROM openwacht.tenants WHERE name IN ('LZ Ost', 'Gruppe Eins', 'Direkt')`)
	})
}

func requestList(t *testing.T, user string) []map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/mandanten-antraege", nil)
	if r.status != 200 {
		t.Fatalf("%s Liste: %d %s", user, r.status, r.raw)
	}
	out := []map[string]any{}
	for _, x := range r.body["antraege"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func TestMandantenAntraege(t *testing.T) {
	verwaltungSetup(t)
	cleanupRequests(t)
	req := func(user, tenant, name string) response {
		return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/antraege", map[string]string{"name": name, "begruendung": "neue Halle"})
	}
	r := req("v_fw", "Fertigung", "LZ Ost")
	expectStatus(t, "v_fw beantragt unter Fertigung", r, 201)
	first, _ := r.body["id"].(string)
	r = req("v_fw", "Lager Nord", "Gruppe Eins")
	expectStatus(t, "v_fw beantragt im Kind", r, 201)
	second, _ := r.body["id"].(string)
	expectStatus(t, "Geschwister beantragt unter Fertigung", req("v_oa", "Fertigung", "X1"), 403)
	expectStatus(t, "Leser beantragt", req("v_lz", "Lager Nord", "X2"), 403)
	expectStatus(t, "Hauptmandant beantragt", req("v_it", "Fertigung", "X3"), 400)
	expectStatus(t, "doppelter offener Antrag", req("v_fw", "Fertigung", "lz ost"), 409)
	expectStatus(t, "Name existiert", req("v_fw", "Fertigung", "Lager Nord"), 409)
	expectStatus(t, "leerer Name", req("v_fw", "Fertigung", " "), 400)
	expectStatus(t, "Begründung mit Umbruch", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/antraege",
		map[string]string{"name": "Y", "begruendung": "a\nb"}), 400)
	expectStatus(t, "ungültige ID", as(t, "v_fw").do("POST", "/api/v1/mandanten/x/antraege", map[string]string{"name": "Y"}), 400)

	// Sichtbarkeit: Antragsteller-Ast und Hauptmandant; Geschwister und Kinder nicht.
	if l := requestList(t, "v_fw"); len(l) != 2 || l[0]["darf_entscheiden"] != false || l[0]["beantragt_von"] != "v_fw" {
		t.Errorf("v_fw sieht %v", l)
	}
	if l := requestList(t, "v_oa"); len(l) != 0 {
		t.Errorf("Geschwister sieht %v", l)
	}
	if l := requestList(t, "v_lz"); len(l) != 0 {
		t.Errorf("Kind sieht %v", l)
	}
	if l := requestList(t, "v_it"); len(l) != 2 || l[0]["darf_entscheiden"] != true {
		t.Errorf("Hauptmandant sieht %v", l)
	}

	// Entscheiden nur der Hauptmandant.
	approve := func(user, id string) response {
		return as(t, user).do("POST", "/api/v1/mandanten-antraege/"+id+"/freigeben", map[string]string{"notiz": "ok"})
	}
	expectStatus(t, "Antragsteller gibt frei", approve("v_fw", first), 403)
	expectStatus(t, "Geschwister gibt frei", approve("v_oa", first), 403)
	r = approve("v_it", first)
	expectStatus(t, "Hauptmandant gibt frei", r, 200)
	newID, _ := r.body["mandant_id"].(string)
	if names := tenantNames(t, as(t, "v_fw")); names["LZ Ost"] != "admin" {
		t.Errorf("neuer Mandant für v_fw: %v", names)
	}
	var parent string
	owner.QueryRow(context.Background(), `SELECT parent_id::text FROM openwacht.tenants WHERE id = $1`, newID).Scan(&parent)
	if parent != ids["Fertigung"] {
		t.Errorf("neuer Mandant hängt unter %s", parent)
	}
	expectStatus(t, "zweimal freigeben", approve("v_it", first), 404)
	expectStatus(t, "Ablehnen durch Antragsteller", as(t, "v_fw").do("POST", "/api/v1/mandanten-antraege/"+second+"/ablehnen", nil), 403)
	expectStatus(t, "Hauptmandant lehnt ab", as(t, "v_it").do("POST", "/api/v1/mandanten-antraege/"+second+"/ablehnen",
		map[string]string{"notiz": "bitte über die Wehrführung"}), 204)
	l := requestList(t, "v_fw")
	states := map[string]string{}
	for _, x := range l {
		states[x["name"].(string)] = x["zustand"].(string)
		if x["name"] == "Gruppe Eins" && (x["notiz"] != "bitte über die Wehrführung" || x["entschieden_von"] != "v_it") {
			t.Errorf("Ablehnung: %v", x)
		}
	}
	if states["LZ Ost"] != "freigegeben" || states["Gruppe Eins"] != "abgelehnt" {
		t.Errorf("Zustände %v", states)
	}
	// Nach der Ablehnung ist derselbe Name wieder beantragbar.
	expectStatus(t, "erneut beantragen", req("v_fw", "Lager Nord", "Gruppe Eins"), 201)

	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action IN
		('mandant.beantragt', 'mandant.antrag_freigegeben', 'mandant.antrag_abgelehnt') AND at > now() - interval '5 minutes'`).Scan(&n)
	if n != 5 {
		t.Errorf("%d Audit-Einträge, erwartet 5", n)
	}

	// Datenbank: direkte Änderungen an Anträgen sind gesperrt.
	ctx := context.Background()
	var open string
	owner.QueryRow(ctx, `SELECT id::text FROM openwacht.tenant_requests WHERE state = 'beantragt'`).Scan(&open)
	if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE openwacht.tenant_requests SET state = 'abgelehnt' WHERE id = $1`, open)
		if err == nil && tag.RowsAffected() != 0 {
			t.Error("Antragsteller entscheidet per SQL")
		}
		return err
	}); err != nil {
		t.Errorf("v_fw UPDATE: %v", err)
	}
	if err := asDB(t, "v_it", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.tenant_requests SET state = 'freigegeben' WHERE id = $1`, open)
		return err
	}); !isCode(err, "23514") {
		t.Errorf("freigegeben ohne Mandant: %v", err)
	}
	if err := asDB(t, "v_it", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.tenant_requests SET name = 'Direkt' WHERE id = $1`, open)
		return err
	}); !isDenied(err) {
		t.Errorf("Name ändern: %v", err)
	}
	if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.tenant_requests (tenant_id, name) VALUES ($1, 'Fremd')`, ids["Organisation"])
		return err
	}); !isDenied(err) {
		t.Errorf("Antrag im Geschwister per SQL: %v", err)
	}
	if err := asDB(t, "v_it", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.tenant_requests (tenant_id, name) VALUES ($1, 'Vom Hauptmandanten')`, ids["Fertigung"])
		return err
	}); !isDenied(err) {
		t.Errorf("Hauptmandant beantragt per SQL: %v", err)
	}
	// Hauptmandant legt weiter direkt an; Untermandanten nicht.
	expectStatus(t, "v_fw legt direkt an", as(t, "v_fw").do("POST", "/api/v1/mandanten",
		map[string]string{"uebergeordnet_id": ids["Fertigung"], "name": "Direkt"}), 403)
}

func TestRezertifizierung(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	// Konto mit Formel im Namen (aus AD denkbar) und Rolle in der Fertigung,
	// Heimat außerhalb (Organisation).
	kontoMitRollen(t, "rz_formel", "Organisation", map[string]string{"Fertigung": "operator"}, false, false)
	owner.Exec(ctx, `UPDATE openwacht.users SET display_name = '=HYPERLINK("x")' WHERE id = $1`, ids["rz_formel"])
	as(t, "v_fw") // Anmeldung setzt die letzte Anmeldung

	get := func(user, tenant, format string) response {
		return as(t, user).do("GET", "/api/v1/mandanten/"+ids[tenant]+"/rezertifizierung?format="+format, nil)
	}
	r := get("v_fw", "Fertigung", "csv")
	if r.status != 200 || !strings.HasPrefix(r.raw, "\uFEFF") || !strings.Contains(r.header.Get("Content-Disposition"), "Rezertifizierung-Fertigung") {
		t.Fatalf("CSV: %d %v %.200s", r.status, r.header, r.raw)
	}
	rd := csv.NewReader(strings.NewReader(strings.TrimPrefix(r.raw, "\uFEFF")))
	rd.Comma = ';'
	recs, err := rd.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	byMail := map[string][]string{}
	for _, rec := range recs[1:] {
		byMail[rec[3]+"|"+rec[0]] = rec
		if strings.HasPrefix(rec[0], "IT") {
			t.Errorf("Pfad über dem Mandanten: %v", rec)
		}
	}
	fw := byMail["v_fw@test.invalid|Fertigung"]
	if fw == nil || fw[1] != "admin" || fw[8] != "ja" || fw[10] == "" {
		t.Errorf("v_fw: %v", fw)
	}
	if lz := byMail["v_lz@test.invalid|Fertigung / Lager Nord"]; lz == nil || lz[1] != "leser" || lz[8] != "nein" {
		t.Errorf("v_lz: %v (%v)", lz, keysOf(byMail))
	}
	f := byMail["rz_formel@test.invalid|Fertigung"]
	if f == nil || f[4] != `'=HYPERLINK("x")` || f[6] != "(außerhalb)" || f[10] != "" {
		t.Errorf("Formel-Konto: %v", f)
	}
	for k := range byMail {
		if strings.HasPrefix(k, "v_oa") || strings.HasPrefix(k, "v_it") {
			t.Errorf("fremdes Konto im Bericht: %s", k)
		}
	}
	// PDF
	r = get("v_fw", "Lager Nord", "pdf")
	if r.status != 200 || !strings.HasPrefix(r.raw, "%PDF") || r.header.Get("Content-Type") != "application/pdf" {
		t.Errorf("PDF: %d %.40s", r.status, r.raw)
	}
	// Mandantentrennung: Geschwister, Kind (Leser) und Eltern-Sicht
	expectStatus(t, "Geschwister", get("v_oa", "Fertigung", "csv"), 404)
	expectStatus(t, "Leser", get("v_lz", "Lager Nord", "csv"), 404)
	expectStatus(t, "Kind fragt Eltern", get("v_fw", "IT", "csv"), 404)
	r = get("v_it", "IT", "csv")
	if r.status != 200 || !strings.Contains(r.raw, "v_oa@test.invalid") || !strings.Contains(r.raw, "v_fw@test.invalid") {
		t.Errorf("Hauptmandant: %d", r.status)
	}
	expectStatus(t, "ohne Format", as(t, "v_fw").do("GET", "/api/v1/mandanten/"+ids["Fertigung"]+"/rezertifizierung", nil), 400)
	if err := asDB(t, "v_lz", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.recert_report($1)`, ids["Lager Nord"])
		return err
	}); !isDenied(err) {
		t.Errorf("Leser ruft Funktion direkt: %v", err)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'rezertifizierung.abgerufen' AND at > now() - interval '5 minutes'`).Scan(&n)
	if n < 3 {
		t.Errorf("Audit: %d", n)
	}
	var last *time.Time
	owner.QueryRow(ctx, `SELECT last_login_at FROM openwacht.users WHERE id = $1`, ids["v_lz2"]).Scan(&last)
	_ = last
}

func keysOf(m map[string][]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSecurityTxt(t *testing.T) {
	_, srv := newTestServer(t, func(c *Config) {
		c.SecurityContacts = []string{"mailto:it-sicherheit@example.com", "https://example.com/melden"}
	})
	r := newClient(t, srv).do("GET", "/.well-known/security.txt", nil)
	if r.status != 200 || !strings.Contains(r.raw, "Contact: mailto:it-sicherheit@example.com\nContact: https://example.com/melden\n") ||
		!strings.Contains(r.raw, "Canonical: "+srv.URL+"/.well-known/security.txt") || !strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Fatalf("security.txt: %d %s", r.status, r.raw)
	}
	for _, line := range strings.Split(r.raw, "\n") {
		if v, ok := strings.CutPrefix(line, "Expires: "); ok {
			exp, err := time.Parse(time.RFC3339, v)
			if err != nil || exp.Before(time.Now().Add(24*time.Hour)) || exp.After(time.Now().Add(366*24*time.Hour)) {
				t.Errorf("Expires %q", v)
			}
		}
	}
	_, off := newTestServer(t, func(c *Config) {
		c.SecurityContacts = []string{"mailto:it-sicherheit@example.com"}
		c.SecurityTxtOff = true
	})
	expectStatus(t, "abgeschaltet", newClient(t, off).do("GET", "/.well-known/security.txt", nil), 404)
	// Ohne eigenen Kontakt des Betreibers: nur der Meldeweg des Herstellers (im Build, seit 0.99.3)
	_, none := newTestServer(t, nil)
	r = newClient(t, none).do("GET", "/.well-known/security.txt", nil)
	if want := version.SecurityContact(); want == "" {
		expectStatus(t, "ohne Kontakt", r, 404)
	} else if r.status != 200 || !strings.Contains(r.raw, "Contact: "+want+"\n") || strings.Count(r.raw, "Contact: ") != 1 {
		t.Errorf("nur Hersteller: %d %s", r.status, r.raw)
	}

	for _, bad := range []string{"http://example.com", "mailto:keine-adresse", "mailto:a@b c", "ftp://x", "https://", "mailto:a@b\nContact: x",
		strings.Repeat("a", 201)} {
		if _, err := ParseSecurityContacts(bad); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	if c, err := ParseSecurityContacts(" mailto:a@example.com , https://example.com/s "); err != nil || len(c) != 2 {
		t.Errorf("gültig: %v %v", c, err)
	}
}
