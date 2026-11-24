// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/garrulus-it/openwacht/internal/agentproto"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/update"
)

type fakeInstall struct {
	dir, exe string
	restarts int
	written  []byte
}

func prepare(t *testing.T, priv ed25519.PrivateKey, ver, platform string, bin []byte) *fakeInstall {
	t.Helper()
	f := &fakeInstall{dir: t.TempDir()}
	f.exe = filepath.Join(t.TempDir(), "openwacht-agent")
	os.WriteFile(f.exe, []byte("alt"), 0o755)
	goos, arch, _ := strings.Cut(platform, "/")
	s, err := update.Sign(priv, update.ManifestFor(ver, goos, arch, bin))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	ud := filepath.Join(f.dir, updateDir)
	os.MkdirAll(ud, 0o755)
	os.WriteFile(filepath.Join(ud, updateSig), raw, 0o644)
	os.WriteFile(filepath.Join(ud, updateBin), bin, 0o644)
	os.WriteFile(filepath.Join(ud, updateReady), []byte(ver), 0o644)
	return f
}

// ring: Schlüsselbund mit einem Schlüssel (nil = Updates aus).
func ring(pub ed25519.PublicKey) *update.Keyring {
	if pub == nil {
		return nil
	}
	return update.SingleKey(pub)
}

func (f *fakeInstall) installer(pub ed25519.PublicKey, cur string) Installer {
	return f.installerKeys(ring(pub), cur)
}

func (f *fakeInstall) installerKeys(k *update.Keyring, cur string) Installer {
	return Installer{Dir: f.dir, Key: k, Current: cur, Exe: f.exe,
		Replace: func(exe string, bin []byte) error { f.written = bin; return replaceFile(exe, bin) },
		Restart: func() error { f.restarts++; return nil }}
}

func (f *fakeInstall) leftovers(t *testing.T) {
	t.Helper()
	for _, n := range []string{updateReady, updateBin, updateSig} {
		if _, err := os.Lstat(filepath.Join(f.dir, updateDir, n)); err == nil {
			t.Errorf("%s nicht entfernt", n)
		}
	}
}

func TestUpdateInstallieren(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	plat := runtime.GOOS + "/" + runtime.GOARCH
	bin := []byte("neues binary")
	f := prepare(t, priv, "0.23.0", plat, bin)
	if err := f.installer(pub, "0.22.1").Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.exe)
	if string(got) != string(bin) || f.restarts != 1 {
		t.Fatalf("nicht installiert: %q %d", got, f.restarts)
	}
	if fi, _ := os.Stat(f.exe); fi.Mode().Perm() != 0o755 {
		t.Errorf("Rechte %v", fi.Mode().Perm())
	}
	f.leftovers(t)
	// Nichts bereit
	if err := f.installer(pub, "0.23.0").Run(); !errors.Is(err, ErrNothing) {
		t.Errorf("ohne Marke: %v", err)
	}
	// Negativfälle: nichts ersetzt, Fehler steht in update/fehler
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		priv     ed25519.PrivateKey
		ver, cur string
		plat     string
		mod      func(f *fakeInstall)
		key      ed25519.PublicKey
	}{
		"fremder Schlüssel": {priv: other, ver: "0.23.0", cur: "0.22.1", plat: plat, key: pub},
		"ohne Schlüssel":    {priv: priv, ver: "0.23.0", cur: "0.22.1", plat: plat, key: nil},
		"Rückstufung":       {priv: priv, ver: "0.22.0", cur: "0.22.1", plat: plat, key: pub},
		"gleiche Version":   {priv: priv, ver: "0.22.1", cur: "0.22.1", plat: plat, key: pub},
		"andere Plattform":  {priv: priv, ver: "0.23.0", cur: "0.22.1", plat: "windows/arm64", key: pub},
		"Binary vertauscht": {priv: priv, ver: "0.23.0", cur: "0.22.1", plat: plat, key: pub, mod: func(f *fakeInstall) {
			os.WriteFile(filepath.Join(f.dir, updateDir, updateBin), []byte("boese!!!!!!!"), 0o644)
		}},
		"Signatur als Verknüpfung nach außen": {priv: priv, ver: "0.23.0", cur: "0.22.1", plat: plat, key: pub, mod: func(f *fakeInstall) {
			outside := filepath.Join(t.TempDir(), "sig")
			b, _ := os.ReadFile(filepath.Join(f.dir, updateDir, updateSig))
			os.WriteFile(outside, b, 0o644)
			os.Remove(filepath.Join(f.dir, updateDir, updateSig))
			os.Symlink(outside, filepath.Join(f.dir, updateDir, updateSig))
		}},
	} {
		if c.plat == "windows/arm64" && runtime.GOOS == "windows" {
			continue
		}
		var f *fakeInstall
		if c.plat == "windows/arm64" {
			f = prepare(t, c.priv, c.ver, "linux/arm64", bin)
			if runtime.GOARCH == "arm64" {
				f = prepare(t, c.priv, c.ver, "linux/amd64", bin)
			}
		} else {
			f = prepare(t, c.priv, c.ver, c.plat, bin)
		}
		if c.mod != nil {
			c.mod(f)
		}
		if err := f.installer(c.key, c.cur).Run(); err == nil || errors.Is(err, ErrNothing) {
			t.Errorf("%s: angenommen (%v)", name, err)
		}
		if got, _ := os.ReadFile(f.exe); string(got) != "alt" || f.restarts != 0 {
			t.Errorf("%s: Binary ersetzt", name)
		}
		f.leftovers(t)
		if msg := readUpdateError(f.dir); msg == "" {
			t.Errorf("%s: kein Fehler vermerkt", name)
		}
	}
	// Update-Verzeichnis als Verknüpfung nach außen: os.Root lehnt ab, außen bleibt alles
	f = prepare(t, priv, "0.23.0", plat, bin)
	outside := t.TempDir()
	os.Rename(filepath.Join(f.dir, updateDir), filepath.Join(outside, "u"))
	os.Symlink(filepath.Join(outside, "u"), filepath.Join(f.dir, updateDir))
	if err := f.installer(pub, "0.22.1").Run(); err == nil || errors.Is(err, ErrNothing) {
		t.Errorf("Verzeichnis-Verknüpfung: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "u", updateReady)); err != nil {
		t.Error("außerhalb gelöscht")
	}
	if _, err := os.Stat(filepath.Join(outside, "u", updateFailed)); err == nil {
		t.Error("außerhalb geschrieben")
	}
}

func TestUpdateMeldungBereinigt(t *testing.T) {
	if got := cleanMessage("a\nb\x00c"); got != "a b c" {
		t.Errorf("%q", got)
	}
	if got := cleanMessage(strings.Repeat("ä", 400)); len([]rune(got)) != 291 {
		t.Errorf("Länge %d", len([]rune(got)))
	}
}

func TestUpdateLaden(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("binary-0.99.0")
	goos, arch := runtime.GOOS, runtime.GOARCH
	s, _ := update.Sign(priv, update.ManifestFor("0.99.0", goos, arch, bin))
	sigRaw, _ := json.Marshal(s)
	serveBin := bin
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+agentproto.PathUpdateSignature, func(w http.ResponseWriter, r *http.Request) { w.Write(sigRaw) })
	mux.HandleFunc("POST "+agentproto.PathUpdateBinary, func(w http.ResponseWriter, r *http.Request) { w.Write(serveBin) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	newRunner := func(key ed25519.PublicKey) *Runner {
		return &Runner{dir: t.TempDir(), zentrale: u, client: srv.Client(), now: time.Now,
			upd: updateState{key: ring(key), tried: map[string]time.Time{}}}
	}
	offer := &agentproto.UpdateOffer{Version: "0.99.0", SHA256: s.SHA256}
	r := newRunner(pub)
	r.upd.offer = offer
	r.maybeUpdate(context.Background())
	if b, err := os.ReadFile(filepath.Join(r.dir, updateDir, updateBin)); err != nil || string(b) != string(bin) {
		t.Fatalf("nicht bereitgelegt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, updateDir, updateReady)); err != nil {
		t.Fatal("Marke fehlt")
	}
	// Ein zweites Angebot derselben Version wird erst nach 6 Stunden erneut versucht
	os.RemoveAll(filepath.Join(r.dir, updateDir))
	r.upd.offer = offer
	r.maybeUpdate(context.Background())
	if _, err := os.Stat(filepath.Join(r.dir, updateDir)); err == nil {
		t.Error("sofort erneut geladen")
	}
	// Negativfälle: nichts bereitgelegt
	for name, prep := range map[string]func() *Runner{
		"fremder Schlüssel": func() *Runner { other, _, _ := ed25519.GenerateKey(rand.Reader); return newRunner(other) },
		"ohne Schlüssel":    func() *Runner { return newRunner(nil) },
		"Binary vertauscht": func() *Runner { serveBin = []byte("boese-0.99.0!"); return newRunner(pub) },
	} {
		serveBin = bin
		r := prep()
		r.upd.offer = offer
		r.maybeUpdate(context.Background())
		if _, err := os.Stat(filepath.Join(r.dir, updateDir, updateReady)); err == nil {
			t.Errorf("%s: bereitgelegt", name)
		}
	}
	serveBin = bin
	r = newRunner(pub)
	r.upd.offer = &agentproto.UpdateOffer{Version: "0.99.0", SHA256: strings.Repeat("0", 64)}
	r.maybeUpdate(context.Background())
	if _, err := os.Stat(filepath.Join(r.dir, updateDir, updateReady)); err == nil {
		t.Error("anderer Hash im Angebot: bereitgelegt")
	}
}

// Etappe 32: Ein Update, signiert mit der Reserve, widerruft den aktiven
// Schlüssel. Der Installationsdienst merkt sich das neben dem Binary und
// nimmt danach nichts mehr an, was mit dem widerrufenen Schlüssel signiert ist.
func TestUpdateWiderrufImInstaller(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	keys := func() *update.Keyring {
		k, err := update.ParseKeyring("ed25519:" + b64(pubA) + " aktiv\ned25519:" + b64(pubB) + " reserve\n")
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	plat := runtime.GOOS + "/" + runtime.GOARCH
	goos, arch, _ := strings.Cut(plat, "/")
	f := &fakeInstall{dir: t.TempDir()}
	f.exe = filepath.Join(t.TempDir(), "openwacht-agent")
	os.WriteFile(f.exe, []byte("alt"), 0o755)
	put := func(priv ed25519.PrivateKey, ver string, bin []byte, revoke ...string) {
		s, err := update.Sign(priv, update.ManifestFor(ver, goos, arch, bin), revoke...)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s)
		ud := filepath.Join(f.dir, updateDir)
		os.MkdirAll(ud, 0o755)
		os.WriteFile(filepath.Join(ud, updateSig), raw, 0o644)
		os.WriteFile(filepath.Join(ud, updateBin), bin, 0o644)
		os.WriteFile(filepath.Join(ud, updateReady), []byte(ver), 0o644)
	}
	// Der Widerruf wird auch gespeichert, wenn das Ersetzen danach scheitert.
	put(privB, "0.23.0", []byte("bin-0.23.0"), update.KeyID(pubA))
	in := f.installerKeys(keys(), "0.22.1")
	in.Replace = func(string, []byte) error { return errors.New("Platte voll") }
	if err := in.Run(); err == nil {
		t.Fatal("Ersetzen gescheitert, aber kein Fehler")
	}
	if b, err := os.ReadFile(RevokedFile(f.exe)); err != nil || strings.TrimSpace(string(b)) != update.KeyID(pubA) {
		t.Fatalf("Widerruf nicht gespeichert: %q %v", b, err)
	}
	put(privB, "0.23.0", []byte("bin-0.23.0"), update.KeyID(pubA))
	if err := f.installerKeys(keys(), "0.22.1").Run(); err != nil {
		t.Fatal(err)
	}
	// Danach: A abgelehnt, auch mit frischem Schlüsselbund (aus der Datei).
	put(privA, "0.24.0", []byte("bin-0.24.0"))
	if err := f.installerKeys(keys(), "0.23.0").Run(); !errors.Is(err, update.ErrRevoked) {
		t.Fatalf("A nach Widerruf: %v", err)
	}
	if got, _ := os.ReadFile(f.exe); string(got) != "bin-0.23.0" {
		t.Errorf("Binary danach: %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, updateDir, updateFailed)); !strings.Contains(string(b), "widerrufen") {
		t.Errorf("Fehlermeldung: %q", b)
	}
	// B gilt weiter.
	put(privB, "0.24.0", []byte("bin-0.24.0"))
	if err := f.installerKeys(keys(), "0.23.0").Run(); err != nil {
		t.Fatal(err)
	}
	// Der Agent-Dienst liest die Widerrufe ebenso (nur lesend).
	k := keys()
	if err := loadRevoked(k, f.exe); err != nil || !k.IsRevoked(update.KeyID(pubA)) || k.IsRevoked(update.KeyID(pubB)) {
		t.Errorf("loadRevoked: %v", err)
	}
	// Ohne Datei: nichts widerrufen, kein Fehler.
	k = keys()
	if err := loadRevoked(k, filepath.Join(t.TempDir(), "x")); err != nil || len(k.Revoked()) != 0 {
		t.Errorf("ohne Datei: %v", err)
	}
}

func b64(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// Das Update-Verzeichnis gehört dem Agent-Benutzer. Legt er „fehler“ als
// harten Link auf eine fremde Datei an, darf der Installationsdienst (root
// bzw. SYSTEM) diese Datei nicht überschreiben, wenn er eine Meldung ablegt.
func TestInstallerUeberschreibtKeineFremdeDateiUeberHartenLink(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := prepare(t, priv, "9.9.9", Platform(), []byte("neues binary"))
	victim := filepath.Join(t.TempDir(), "fremd.conf")
	if err := os.WriteFile(victim, []byte("wichtiger inhalt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, updateDir, updateFailed)
	if err := os.Link(victim, link); err != nil {
		t.Skipf("harte Links hier nicht möglich: %v", err)
	}
	// Binary verfälschen: Die Installation schlägt fehl und schreibt „fehler“.
	os.WriteFile(filepath.Join(f.dir, updateDir, updateBin), []byte("verfälscht!!"), 0o644)
	if err := f.installer(pub, "1.0.0").Run(); err == nil {
		t.Fatal("verfälschtes Binary installiert")
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "wichtiger inhalt\n" {
		t.Errorf("fremde Datei über den harten Link verändert: %q (%v)", got, err)
	}
	// Die Meldung steht trotzdem da, in einer neuen Datei.
	if msg := readUpdateError(f.dir); msg == "" {
		t.Error("Fehlermeldung fehlt")
	}
}
