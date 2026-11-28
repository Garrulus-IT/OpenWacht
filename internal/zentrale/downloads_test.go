// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// downloadOrdner legt einen Ordner wie im Paket der Zentrale an.
func downloadOrdner(t *testing.T, files map[string]string, falsch ...string) string {
	t.Helper()
	dir := t.TempDir()
	sums := map[string]*strings.Builder{}
	for name, content := range files {
		o, n, _ := strings.Cut(name, "/")
		os.MkdirAll(filepath.Join(dir, o), 0o755)
		if err := os.WriteFile(filepath.Join(dir, o, n), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(content))
		for _, f := range falsch {
			if f == name {
				h = sha256.Sum256([]byte("anders"))
			}
		}
		if sums[o] == nil {
			sums[o] = &strings.Builder{}
		}
		fmt.Fprintf(sums[o], "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	for o, b := range sums {
		if err := os.WriteFile(filepath.Join(dir, o, "SHA256SUMS"), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDownloadListe(t *testing.T) {
	dir := downloadOrdner(t, map[string]string{
		"windows/openwacht-agent_1.0.14_amd64.msi":    "msi",
		"windows/openwacht-desktop_windows_arm64.exe": "desktop",
		"linux/openwacht-agent_linux_amd64":           "agent",
		"linux/openwacht-agent_linux_amd64.sig":       "sig",
		"linux/openwacht-agent-1.0.14-1.aarch64.rpm":  "rpm",
		"linux/openwacht-agent_linux_arm64":           "manipuliert",
		"darwin/openwacht-agent_darwin_arm64":         "mac",
	}, "linux/openwacht-agent_linux_arm64")
	// Eintrag in SHA256SUMS ohne Datei, und ein fremder Name
	f, _ := os.OpenFile(filepath.Join(dir, "linux", "SHA256SUMS"), os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintf(f, "%064d  openwacht-agent_fehlt\n%064d  ../geheim\n", 0, 0)
	f.Close()

	s := &Server{cfg: Config{Downloads: dir}}
	liste := s.downloadListe()
	var got []string
	for _, sys := range liste {
		for _, d := range sys.Dateien {
			got = append(got, fmt.Sprintf("%s/%s %s %s sig=%s", sys.OS, d.Name, d.Art, d.Arch, d.Signatur))
		}
	}
	want := []string{
		"windows/openwacht-agent_1.0.14_amd64.msi msi amd64 sig=",
		"windows/openwacht-desktop_windows_arm64.exe desktop arm64 sig=",
		"linux/openwacht-agent-1.0.14-1.aarch64.rpm rpm arm64 sig=",
		"linux/openwacht-agent_linux_amd64 agent amd64 sig=openwacht-agent_linux_amd64.sig",
		"darwin/openwacht-agent_darwin_arm64 agent arm64 sig=",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Liste:\n%s", strings.Join(got, "\n"))
	}
	if (&Server{}).downloadListe() != nil {
		t.Error("ohne Ordner keine Liste")
	}
}

func TestDownloadDatei(t *testing.T) {
	dir := downloadOrdner(t, map[string]string{
		"windows/openwacht-agent_1.0.14_amd64.msi": "msi-inhalt",
		"linux/openwacht-agent_linux_arm64":        "manipuliert",
	}, "linux/openwacht-agent_linux_arm64")
	os.WriteFile(filepath.Join(dir, "windows", "openwacht-agent_nicht_gelistet.exe"), []byte("x"), 0o644)
	s := &Server{cfg: Config{Downloads: dir}}
	get := func(o, name string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/downloads/"+o+"/"+name, nil)
		r.SetPathValue("os", o)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		s.handleDownloadFile(w, r)
		return w
	}
	w := get("windows", "openwacht-agent_1.0.14_amd64.msi")
	if w.Code != 200 || w.Body.String() != "msi-inhalt" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), `filename="openwacht-agent_1.0.14_amd64.msi"`) {
		t.Fatalf("MSI: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	for _, c := range [][2]string{
		{"linux", "openwacht-agent_linux_arm64"},              // Prüfsumme passt nicht
		{"windows", "openwacht-agent_nicht_gelistet.exe"},     // nicht in SHA256SUMS
		{"windows", "SHA256SUMS"},                             // kein Download
		{"etc", "openwacht-agent_1.0.14_amd64.msi"},           // kein System
		{"windows", "openwacht-agent_..%2f..%2fetc%2fpasswd"}, // Pfad
	} {
		if w := get(c[0], c[1]); w.Code != 404 {
			t.Errorf("%s/%s: %d", c[0], c[1], w.Code)
		}
	}
}

func TestMitgelieferteAgentUpdates(t *testing.T) {
	agentServer(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, fremd, _ := ed25519.GenerateKey(rand.Reader)
	bin := "agent-0.50.0-linux"
	winBin := "agent-0.50.0-windows"
	armBin := "agent-0.50.0-arm"
	dir := downloadOrdner(t, map[string]string{
		"linux/openwacht-agent_linux_amd64":         bin,
		"linux/openwacht-agent_linux_amd64.sig":     string(signedPackage(t, priv, "0.50.0", "linux/amd64", []byte(bin))),
		"linux/openwacht-agent_linux_arm64":         armBin,
		"linux/openwacht-agent_linux_arm64.sig":     string(signedPackage(t, fremd, "0.50.0", "linux/arm64", []byte(armBin))),
		"windows/openwacht-agent_windows_amd64.exe": winBin,
		// Signatur für eine andere Plattform
		"windows/openwacht-agent_windows_amd64.exe.sig": string(signedPackage(t, priv, "0.50.0", "linux/amd64", []byte(winBin))),
	})
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys, vServer.cfg.Downloads = "", ""
		owner.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
	})
	vServer.cfg.Downloads = dir

	vServer.cfg.UpdateKeys = noUpdateKeys
	if n, err := vServer.MitgelieferteAgentUpdates(ctx); err != nil || n != 0 {
		t.Fatalf("ohne Schlüssel: %d %v", n, err)
	}
	vServer.cfg.UpdateKeys = keyLine(pub, "")
	if n, err := vServer.MitgelieferteAgentUpdates(ctx); err != nil || n != 1 {
		t.Fatalf("erster Start: %d %v", n, err)
	}
	if n, err := vServer.MitgelieferteAgentUpdates(ctx); err != nil || n != 0 {
		t.Fatalf("zweiter Start: %d %v", n, err)
	}
	var plattformen []string
	rows, _ := owner.Query(ctx, `SELECT os || '/' || arch || ' ' || version || ' ' || (uploaded_by IS NULL)::text FROM openwacht.agent_updates ORDER BY 1`)
	for rows.Next() {
		var p string
		rows.Scan(&p)
		plattformen = append(plattformen, p)
	}
	rows.Close()
	if strings.Join(plattformen, ",") != "linux/amd64 0.50.0 true" {
		t.Fatalf("abgelegt: %v", plattformen)
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'agent_update.mitgeliefert' AND details->>'version' = '0.50.0'`).Scan(&audits)
	if audits != 1 {
		t.Errorf("Audit: %d", audits)
	}
}
