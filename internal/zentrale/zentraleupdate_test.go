// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/garrulus-it/openwacht/internal/update"
)

func uploadZentrale(t *testing.T, c *client, datei string, paket, summen, sig []byte, code string) response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if code != "" {
		f, _ := mw.CreateFormField("code")
		f.Write([]byte(code))
	}
	if summen != nil {
		f, _ := mw.CreateFormFile("summen", "SHA256SUMS")
		f.Write(summen)
	}
	if sig != nil {
		f, _ := mw.CreateFormFile("signatur", "SHA256SUMS.sig")
		f.Write(sig)
	}
	if paket != nil {
		f, _ := mw.CreateFormFile("paket", datei)
		f.Write(paket)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", c.base+"/api/v1/zentrale-update", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", c.csrf)
	req.Header.Set("Origin", c.origin)
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := response{status: resp.StatusCode, raw: string(raw)}
	json.Unmarshal(raw, &r.body)
	return r
}

func TestZentraleUpdateUpload(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, fremd, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	vServer.cfg.UpdateKeys = keyLine(pub, "")
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys = ""
		vServer.cfg.ZentraleUpdateDir = ""
		resetSettings(t)
	})
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		t.Skip("Plattform ohne Paket")
	}
	datei := "openwacht-zentrale_9.0.0_" + arch + ".deb"
	paket := []byte("debian-paket 9.0.0")
	h := sha256.Sum256(paket)
	summen := []byte(hex.EncodeToString(h[:]) + "  " + datei + "\n")
	sig, _ := update.SignSums(priv, summen)
	fremdSig, _ := update.SignSums(fremd, summen)

	it := as(t, "v_it")
	// Ohne Ablage (kein Debian-Paket): aus.
	vServer.cfg.ZentraleUpdateDir = ""
	setOperator(t, "v_it", true)
	expectStatus(t, "nicht eingerichtet", uploadZentrale(t, it, datei, paket, summen, sig, "x"), 409)
	vServer.cfg.ZentraleUpdateDir = dir
	if r := it.do("GET", "/api/v1/zentrale-update", nil); r.body["eingerichtet"] != true || r.body["laeuft"] != false {
		t.Errorf("Stand: %s", r.raw)
	}
	// Nur der Betreiber.
	setOperator(t, "v_it", false)
	expectStatus(t, "kein Betreiber", uploadZentrale(t, it, datei, paket, summen, sig, "x"), 403)
	expectStatus(t, "Stand kein Betreiber", it.do("GET", "/api/v1/zentrale-update", nil), 403)
	expectStatus(t, "Admin Fertigung", uploadZentrale(t, as(t, "v_fw"), datei, paket, summen, sig, "x"), 403)
	setOperator(t, "v_it", true)
	// Zweitfaktor
	expectStatus(t, "ohne Code", uploadZentrale(t, it, datei, paket, summen, sig, ""), 403)
	expectStatus(t, "falscher Code", uploadZentrale(t, it, datei, paket, summen, sig, "000000"), 403)
	// Prüfung
	fremdDatei := "openwacht-zentrale_9.0.0_arm64.deb"
	if arch == "arm64" {
		fremdDatei = "openwacht-zentrale_9.0.0_amd64.deb"
	}
	for name, c := range map[string]struct {
		datei              string
		paket, summen, sig []byte
	}{
		"fremder Schlüssel": {datei, paket, summen, fremdSig},
		"Paket verändert":   {datei, append([]byte("x"), paket...), summen, sig},
		"falscher Name":     {"zentrale.deb", paket, summen, sig},
		"andere Plattform":  {fremdDatei, paket, summen, sig},
		"ohne Signatur":     {datei, paket, summen, nil},
		"ohne Summen":       {datei, paket, nil, sig},
		"ohne Paket":        {datei, nil, summen, sig},
	} {
		if r := uploadZentrale(t, it, c.datei, c.paket, c.summen, c.sig, freshCode(t, "v_it")); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "auftrag")); err == nil {
		t.Fatal("Auftrag trotz Ablehnung")
	}
	// Gültig: Auftrag liegt bereit, Dateien wie hochgeladen.
	r := uploadZentrale(t, it, datei, paket, summen, sig, freshCode(t, "v_it"))
	expectStatus(t, "gültig", r, 202)
	var a ZentraleAuftrag
	b, _ := os.ReadFile(filepath.Join(dir, "auftrag"))
	if json.Unmarshal(b, &a) != nil || a.Version != "9.0.0" || a.Datei != datei || a.SHA256 != hex.EncodeToString(h[:]) {
		t.Errorf("Auftrag: %s", b)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "paket.deb")); !bytes.Equal(got, paket) {
		t.Error("Paket nicht abgelegt")
	}
	if r := it.do("GET", "/api/v1/zentrale-update", nil); r.body["laeuft"] != true {
		t.Errorf("Stand während des Updates: %s", r.raw)
	}
	expectStatus(t, "zweites Update", uploadZentrale(t, it, datei, paket, summen, sig, freshCode(t, "v_it")), 409)
	// Ergebnis des Installationsdienstes erscheint im Stand.
	os.Remove(filepath.Join(dir, "auftrag"))
	os.WriteFile(filepath.Join(dir, "ergebnis.json"), []byte(`{"zeit":"2026-11-25T20:00:00Z","version":"9.0.0","ok":true,"meldung":"installiert"}`), 0o644)
	if r := it.do("GET", "/api/v1/zentrale-update", nil); r.body["ergebnis"] == nil {
		t.Errorf("Ergebnis fehlt: %s", r.raw)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'zentrale.update_abgelehnt'`).Scan(&n)
	if n < 3 {
		t.Errorf("Audit abgelehnt: %d", n)
	}
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'zentrale.update_hochgeladen'`).Scan(&n)
	if n != 1 {
		t.Errorf("Audit hochgeladen: %d", n)
	}
}
