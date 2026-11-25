// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

type updateFall struct {
	dir, tmp string
	keys     *update.Keyring
	priv     ed25519.PrivateKey
	paket    []byte
	datei    string
}

func neuerUpdateFall(t *testing.T) *updateFall {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &updateFall{dir: t.TempDir(), tmp: t.TempDir(), keys: update.SingleKey(pub), priv: priv,
		paket: []byte("debian-paket 1.0.4"), datei: "openwacht-zentrale_1.0.4_amd64.deb"}
	f.ablegen(t, f.paket, f.datei)
	return f
}

func (f *updateFall) ablegen(t *testing.T, paket []byte, datei string) {
	t.Helper()
	h := sha256.Sum256(paket)
	sum := hex.EncodeToString(h[:])
	sums := []byte(sum + "  " + datei + "\n")
	sig, _ := update.SignSums(f.priv, sums)
	a, _ := json.Marshal(zentrale.ZentraleAuftrag{ZentralePaket: update.ZentralePaket{Datei: datei, Version: "1.0.4", Arch: "amd64", SHA256: sum},
		Zeit: time.Now()})
	for n, b := range map[string][]byte{"paket.deb": paket, "SHA256SUMS": sums, "SHA256SUMS.sig": sig, "auftrag": a} {
		if err := os.WriteFile(filepath.Join(f.dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *updateFall) lauf(t *testing.T, current string) (zentrale.ZentraleErgebnis, []string) {
	t.Helper()
	var aufrufe []string
	alt := aptInstall
	aptInstall = func(_ context.Context, deb string) ([]byte, error) {
		got, _ := os.ReadFile(deb)
		aufrufe = append(aufrufe, filepath.Base(deb)+"|"+string(got))
		return []byte("Entpacken von openwacht-zentrale (1.0.4) ...\n"), nil
	}
	t.Cleanup(func() { aptInstall = alt })
	e := zentraleUpdateRun(context.Background(), f.dir, f.keys, current, "amd64", f.tmp)
	return e, aufrufe
}

func TestZentraleUpdateInstallieren(t *testing.T) {
	f := neuerUpdateFall(t)
	e, apt := f.lauf(t, "1.0.3")
	if !e.OK || e.Version != "1.0.4" || len(apt) != 1 || apt[0] != f.datei+"|"+string(f.paket) {
		t.Fatalf("gültiges Update: %+v %v", e, apt)
	}
	// Aufgeräumt, Ergebnis lesbar, nichts im Arbeitsordner übrig
	for _, n := range []string{"auftrag", "in-arbeit", "paket.deb", "SHA256SUMS", "SHA256SUMS.sig"} {
		if _, err := os.Lstat(filepath.Join(f.dir, n)); err == nil {
			t.Errorf("%s liegt noch da", n)
		}
	}
	var got zentrale.ZentraleErgebnis
	b, _ := os.ReadFile(filepath.Join(f.dir, "ergebnis.json"))
	if json.Unmarshal(b, &got) != nil || !got.OK {
		t.Errorf("Ergebnis: %s", b)
	}
	if rest, _ := os.ReadDir(f.tmp); len(rest) != 0 {
		t.Errorf("Arbeitsordner nicht aufgeräumt: %v", rest)
	}
	// Ohne Auftrag nichts
	if e, apt := f.lauf(t, "1.0.3"); e.OK || len(apt) != 0 {
		t.Errorf("ohne Auftrag: %+v", e)
	}
}

func TestZentraleUpdateAbgelehnt(t *testing.T) {
	for name, vorbereiten := range map[string]func(t *testing.T, f *updateFall){
		"Paket nach der Prüfung getauscht": func(t *testing.T, f *updateFall) {
			os.WriteFile(filepath.Join(f.dir, "paket.deb"), []byte("boese"), 0o600)
		},
		"Paket als Symlink": func(t *testing.T, f *updateFall) {
			os.Remove(filepath.Join(f.dir, "paket.deb"))
			os.WriteFile(filepath.Join(f.tmp, "ziel"), f.paket, 0o600)
			os.Symlink(filepath.Join(f.tmp, "ziel"), filepath.Join(f.dir, "paket.deb"))
		},
		"Summen als Symlink": func(t *testing.T, f *updateFall) {
			os.Remove(filepath.Join(f.dir, "SHA256SUMS"))
			os.Symlink("/etc/passwd", filepath.Join(f.dir, "SHA256SUMS"))
		},
		"fremder Schlüssel": func(t *testing.T, f *updateFall) {
			_, fremd, _ := ed25519.GenerateKey(rand.Reader)
			f.priv = fremd
			f.ablegen(t, f.paket, f.datei)
		},
		"Dateiname mit Pfad": func(t *testing.T, f *updateFall) {
			b, _ := os.ReadFile(filepath.Join(f.dir, "auftrag"))
			os.WriteFile(filepath.Join(f.dir, "auftrag"), []byte(strings.Replace(string(b), f.datei, "../../etc/x.deb", 1)), 0o600)
		},
		"Paket ist ein Ordner": func(t *testing.T, f *updateFall) {
			os.Remove(filepath.Join(f.dir, "paket.deb"))
			os.Mkdir(filepath.Join(f.dir, "paket.deb"), 0o700)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := neuerUpdateFall(t)
			vorbereiten(t, f)
			e, apt := f.lauf(t, "1.0.3")
			if e.OK || len(apt) != 0 {
				t.Errorf("angenommen: %+v %v", e, apt)
			}
			if _, err := os.Lstat(filepath.Join(f.dir, "ergebnis.json")); err != nil {
				t.Error("kein Ergebnis")
			}
			if _, err := os.Lstat(filepath.Join(f.dir, "in-arbeit")); err == nil {
				t.Error("in-arbeit bleibt liegen")
			}
		})
	}
	// Gleiche oder ältere Version: keine Rückstufung
	f := neuerUpdateFall(t)
	if e, apt := f.lauf(t, "1.0.4"); e.OK || len(apt) != 0 {
		t.Errorf("gleiche Version: %+v", e)
	}
}

// Ein Symlink namens ergebnis.json wird ersetzt, nicht verfolgt.
func TestZentraleUpdateErgebnisOhneSymlink(t *testing.T) {
	f := neuerUpdateFall(t)
	opfer := filepath.Join(f.tmp, "opfer")
	os.WriteFile(opfer, []byte("unverändert"), 0o600)
	os.Symlink(opfer, filepath.Join(f.dir, "ergebnis.json"))
	f.lauf(t, "1.0.3")
	if b, _ := os.ReadFile(opfer); string(b) != "unverändert" {
		t.Error("Ergebnis durch einen Symlink geschrieben")
	}
	if st, err := os.Lstat(filepath.Join(f.dir, "ergebnis.json")); err != nil || st.Mode()&os.ModeSymlink != 0 {
		t.Errorf("ergebnis.json: %v %v", st, err)
	}
}

// apt scheitert: Ergebnis mit Fehler, alles aufgeräumt.
func TestZentraleUpdateAptScheitert(t *testing.T) {
	f := neuerUpdateFall(t)
	alt := aptInstall
	aptInstall = func(context.Context, string) ([]byte, error) {
		return []byte("E: kaputt"), errors.New("exit status 100")
	}
	defer func() { aptInstall = alt }()
	e := zentraleUpdateRun(context.Background(), f.dir, f.keys, "1.0.3", "amd64", f.tmp)
	if e.OK || !strings.Contains(e.Ausgabe, "E: kaputt") || !strings.Contains(e.Meldung, "bisherige Version läuft weiter") {
		t.Errorf("Ergebnis: %+v", e)
	}
}
