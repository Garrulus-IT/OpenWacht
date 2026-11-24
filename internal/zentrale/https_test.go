// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// httpsServer: Server mit HTTPS aus der Datenbank (eigene CA für
// openwacht.example.com), Betreiber v_it.
func httpsServer(t *testing.T) (*Server, *client) {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	names := []string{"openwacht.example.com"}
	ca, err := pki.NewHTTPSCA(names, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ca.HTTPSLeaf(names, time.Now())
	sm, err := sealMaterial(testKey, "eigene-ca", m, ca, names)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, cert_pem = EXCLUDED.cert_pem,
		key_enc = EXCLUDED.key_enc, ca_cert_pem = EXCLUDED.ca_cert_pem, ca_key_enc = EXCLUDED.ca_key_enc, names = EXCLUDED.names`,
		sm.kind, sm.cert, sm.key, sm.caCert, sm.caKey, sm.names); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(context.Background(), `DELETE FROM openwacht.https_material`) })
	h, err := LoadHTTPS(ctx, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	resetSettings(t)
	t.Cleanup(func() { resetSettings(t) })
	s, srv := settingsServer(t, Config{HTTPS: h})
	setOperator(t, "v_it", true)
	return s, loginOn(t, srv, "v_it")
}

func TestHTTPSEinstellungen(t *testing.T) {
	s, c := httpsServer(t)
	r := c.do("GET", "/api/v1/einstellungen/https", nil)
	expectStatus(t, "lesen", r, 200)
	caFP := r.body["ca_fingerabdruck"]
	leafFP := r.body["fingerabdruck"]
	if r.body["art"] != "eigene-ca" || caFP == nil {
		t.Fatalf("%v", r.body)
	}
	// Wurzel öffentlich ladbar
	anon := &client{t: t, base: c.base, cookies: map[string]*http.Cookie{}}
	r = anon.do("GET", "/openwacht-wurzel.crt", nil)
	expectStatus(t, "Wurzel", r, 200)
	if b, _ := pem.Decode([]byte(r.raw)); b == nil || b.Type != "CERTIFICATE" {
		t.Fatal("Wurzel kein PEM")
	}

	// Erneuern ohne Code
	expectStatus(t, "erneuern", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "erneuern"}), 200)
	r = c.do("GET", "/api/v1/einstellungen/https", nil)
	if r.body["fingerabdruck"] == leafFP || r.body["ca_fingerabdruck"] != caFP {
		t.Fatal("Erneuern: neues Serverzertifikat mit alter CA erwartet")
	}
	// Neue CA und Hochladen nur mit Code
	expectStatus(t, "neue CA ohne Code", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "eigene-ca"}), 403)
	expectStatus(t, "neue CA", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "eigene-ca", "code": freshCode(t, "v_it")}), 200)
	if s.https.info()["ca_fingerabdruck"] == caFP {
		t.Fatal("keine neue CA")
	}
	other, _ := pki.SelfSigned([]string{"anders.example.com"}, time.Now())
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: other.KeyDER})
	expectStatus(t, "falscher Name", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "hochgeladen",
		"zertifikat": string(other.CertPEM), "schluessel": string(keyPEM), "code": freshCode(t, "v_it")}), 400)
	good, _ := pki.SelfSigned([]string{"openwacht.example.com"}, time.Now())
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: good.KeyDER})
	body := map[string]any{"art": "hochgeladen", "zertifikat": string(good.CertPEM), "schluessel": string(keyPEM)}
	expectStatus(t, "hochladen ohne Code", c.do("PUT", "/api/v1/einstellungen/https", body), 403)
	body["code"] = freshCode(t, "v_it")
	expectStatus(t, "hochladen", c.do("PUT", "/api/v1/einstellungen/https", body), 200)
	if s.https.info()["art"] != "hochgeladen" || s.https.caPEM() != nil {
		t.Fatal("hochgeladenes Zertifikat nicht aktiv")
	}
	expectStatus(t, "erneuern ohne CA", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "erneuern"}), 400)

	// Kein Betreiber: kein Zugriff
	setOperator(t, "v_it", false)
	expectStatus(t, "ohne Betreiber lesen", c.do("GET", "/api/v1/einstellungen/https", nil), 403)
	expectStatus(t, "ohne Betreiber erneuern", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "erneuern"}), 403)
}

func TestInstallationEinstellungen(t *testing.T) {
	s, c := httpsServer(t)
	t.Cleanup(func() {
		owner.Exec(context.Background(), `UPDATE openwacht.settings SET timezone = NULL, backup_hour = NULL, backup_days = NULL`)
	})
	r := c.do("GET", "/api/v1/einstellungen/installation", nil)
	expectStatus(t, "lesen", r, 200)
	if r.body["zeitzone"] != DefaultZoneName {
		t.Fatalf("%v", r.body)
	}
	expectStatus(t, "falsche Zone", c.do("PUT", "/api/v1/einstellungen/installation",
		map[string]any{"zeitzone": "Mond/Krater", "sicherung": map[string]int{"uhr": 1, "tage": 7}}), 400)
	expectStatus(t, "falsche Uhrzeit", c.do("PUT", "/api/v1/einstellungen/installation",
		map[string]any{"zeitzone": "UTC", "sicherung": map[string]int{"uhr": 24, "tage": 7}}), 400)
	expectStatus(t, "speichern", c.do("PUT", "/api/v1/einstellungen/installation",
		map[string]any{"zeitzone": "America/New_York", "sicherung": map[string]int{"uhr": 3, "tage": 30}}), 200)
	if s.zoneName() != "America/New_York" {
		t.Fatalf("Zeitzone nicht übernommen: %s", s.zoneName())
	}
	setOperator(t, "v_it", false)
	expectStatus(t, "ohne Betreiber", c.do("PUT", "/api/v1/einstellungen/installation",
		map[string]any{"zeitzone": "UTC", "sicherung": map[string]int{"uhr": 1, "tage": 7}}), 403)
}

func TestAdresseAendern(t *testing.T) {
	s, c := httpsServer(t)
	t.Cleanup(func() {
		owner.Exec(context.Background(), `UPDATE openwacht.settings SET base_url = NULL, names = NULL`)
	})
	restarted := make(chan struct{}, 1)
	s.cfg.Restart = func() { restarted <- struct{}{} }
	oldCA := s.https.info()["ca_fingerabdruck"]
	body := map[string]any{"adressen": []string{"neu.example.com", "10.10.0.9"}}
	expectStatus(t, "ohne Code", c.do("PUT", "/api/v1/einstellungen/adresse", body), 403)
	expectStatus(t, "falsche Adresse", c.do("PUT", "/api/v1/einstellungen/adresse", map[string]any{"adressen": []string{"*.x"}, "code": freshCode(t, "v_it")}), 400)
	body["code"] = freshCode(t, "v_it")
	r := c.do("PUT", "/api/v1/einstellungen/adresse", body)
	expectStatus(t, "ändern", r, 200)
	if r.body["adresse"] != "https://neu.example.com" || r.body["neustart"] != true {
		t.Fatalf("%v", r.body)
	}
	select {
	case <-restarted:
	case <-time.After(3 * time.Second):
		t.Fatal("kein Neustart angefordert")
	}
	info := s.https.info()
	if info["ca_fingerabdruck"] == oldCA || strings.Join(info["namen"].([]string), ",") != "neu.example.com,10.10.0.9" {
		t.Fatalf("keine neue Wurzel für die neuen Namen: %v", info)
	}
	var base string
	var audit int
	owner.QueryRow(context.Background(), `SELECT base_url FROM openwacht.settings`).Scan(&base)
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'installation.adresse'`).Scan(&audit)
	if base != "https://neu.example.com" || audit == 0 {
		t.Fatalf("DB: %s %d", base, audit)
	}
	// Mit hochgeladenem Zertifikat muss eines für die neuen Namen mitkommen.
	good, _ := pki.SelfSigned([]string{"neu.example.com"}, time.Now())
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: good.KeyDER})
	expectStatus(t, "hochladen", c.do("PUT", "/api/v1/einstellungen/https", map[string]any{"art": "hochgeladen",
		"zertifikat": string(good.CertPEM), "schluessel": string(keyPEM), "code": freshCode(t, "v_it")}), 200)
	expectStatus(t, "hochgeladen ohne neues Zertifikat", c.do("PUT", "/api/v1/einstellungen/adresse",
		map[string]any{"adressen": []string{"anders.example.com"}, "code": freshCode(t, "v_it")}), 400)
	setOperator(t, "v_it", false)
	expectStatus(t, "ohne Betreiber", c.do("PUT", "/api/v1/einstellungen/adresse", map[string]any{"adressen": []string{"x.example.com"}}), 403)
	if _, err := pool.Exec(context.Background(), `SELECT openwacht.install_set_address('https://x', '{x}', 'eigene-ca', 'c', '\x00', NULL, NULL)`); !isCode(err, "42501") {
		t.Fatalf("DB ohne Betreiber: %v", err)
	}
}

func TestSicherungenListe(t *testing.T) {
	_, c := httpsServer(t)
	ctx := context.Background()
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.backup_log`) })
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok) VALUES (now() - interval '1 day', 'openwacht-20261121T000500Z.dump', 1234, true);
		INSERT INTO openwacht.backup_log (started_at, ok, message) VALUES (now(), false, 'pg_dump: kaputt')`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok) VALUES (now(), '../etc/passwd', 1, true)`); err == nil {
		t.Fatal("Dateiname ohne Muster angenommen")
	}
	r := c.do("GET", "/api/v1/einstellungen/sicherungen", nil)
	expectStatus(t, "Liste", r, 200)
	list := r.body["sicherungen"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["ok"] != false || list[1].(map[string]any)["groesse"].(float64) != 1234 {
		t.Fatalf("%v", list)
	}
	setOperator(t, "v_it", false)
	expectStatus(t, "ohne Betreiber", c.do("GET", "/api/v1/einstellungen/sicherungen", nil), 403)
	for _, q := range []string{`SELECT * FROM openwacht.backup_log`, `SELECT * FROM openwacht.backup_list(10)`} {
		if _, err := pool.Exec(ctx, q); !isCode(err, "42501") {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestAgentCASchluesselPruefen(t *testing.T) {
	sealed, err := auth.Seal(deriveKey(testKey, "openwacht agent-ca v1"), []byte("geheim"), []byte("agent-ca"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAgentCAKey(testKey, sealed); err != nil {
		t.Fatal(err)
	}
	if err := CheckAgentCAKey(make([]byte, auth.KeySize), sealed); err == nil {
		t.Fatal("falscher Schlüssel angenommen")
	}
	if err := CheckAgentCAKey(testKey, nil); err != nil {
		t.Fatal("Sicherung ohne Agent-CA abgelehnt")
	}
}
