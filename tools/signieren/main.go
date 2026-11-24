// SPDX-License-Identifier: AGPL-3.0-only

// signieren: Agent-Updates offline signieren (Etappe 23).
//
// Nur auf einem Rechner ohne Verbindung zur Zentrale ausführen. Der private
// Schlüssel liegt nie auf der Zentrale oder im Repository.
//
//	go run ./tools/signieren -neu -schluessel /pfad/update.key
//	    erzeugt ein Schlüsselpaar; die Zeile „ed25519:…“ kommt nach
//	    internal/update/schluessel.pub.
//	go run ./tools/signieren -schluessel /pfad/update.key -version 0.23.0 dist/openwacht-agent_linux_amd64 …
//	    schreibt je Datei <datei>.sig. OS und Architektur aus dem Dateinamen.
//	go run ./tools/signieren -schluessel /pfad/reserve.key -version 0.40.0 -widerrufen <kennung> dist/openwacht-agent_…
//	    wie oben; die Signaturen erklären den Schlüssel <kennung> für widerrufen
//	    (nur mit dem Reserve-Schlüssel, oder mit dem aktiven gegen einen auslaufenden).
//	go run ./tools/signieren -zeigen -schluessel /pfad/update.key
//	    zeigt nur den öffentlichen Teil und die Kennung (z. B. um eine
//	    Sicherungskopie zu prüfen); der private Schlüssel wird nie ausgegeben.
//	go run ./tools/signieren -schluessel /pfad/update.key -summen dist/SHA256SUMS
//	    signiert die Prüfsummen eines Releases bzw. Offline-Pakets (dist/SHA256SUMS.sig).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garrulus-it/openwacht/internal/update"
)

var nameRe = regexp.MustCompile(`openwacht-agent_(linux|windows)_(amd64|arm64)(\.exe)?$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("signieren", flag.ContinueOnError)
	neu := fs.Bool("neu", false, "neues Schlüsselpaar erzeugen")
	keyFile := fs.String("schluessel", "", "Datei mit dem privaten Schlüssel")
	ver := fs.String("version", "", "Version der Binarys (x.y.z)")
	revoke := fs.String("widerrufen", "", "Kennungen von Update-Schlüsseln, die die Signaturen für widerrufen erklären (Komma)")
	sums := fs.String("summen", "", "SHA256SUMS signieren (schreibt <datei>.sig)")
	show := fs.Bool("zeigen", false, "nur öffentlichen Schlüssel und Kennung aus der Schlüsseldatei zeigen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-schluessel fehlt")
	}
	if *neu {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("Schlüsseldatei anlegen (wird nie überschrieben): %w", err)
		}
		if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("Privater Schlüssel: %s (sicher und offline aufbewahren, Sicherungskopie!)\n", *keyFile)
		fmt.Printf("Zeile für internal/update/schluessel.pub (Zustand aktiv oder reserve anhängen):\ned25519:%s aktiv\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("Kennung (Fingerabdruck, getrennt veröffentlichen): %s\n", update.KeyID(pub))
		return nil
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("Schlüsseldatei unlesbar")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if *show {
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("Zeile für internal/update/schluessel.pub:\ned25519:%s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("Kennung: %s\n", update.KeyID(pub))
		return nil
	}
	if *sums != "" {
		if fs.NArg() > 0 || *ver != "" || *revoke != "" {
			return errors.New("-summen allein angeben (ohne Binarys, -version, -widerrufen)")
		}
		content, err := os.ReadFile(*sums)
		if err != nil {
			return err
		}
		sig, err := update.SignSums(priv, content)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*sums+".sig", sig, 0o644); err != nil {
			return err
		}
		fmt.Printf("%s.sig (Schlüssel %s)\n", *sums, update.KeyID(priv.Public().(ed25519.PublicKey)))
		return nil
	}
	var revoked []string
	if *revoke != "" {
		revoked = strings.Split(*revoke, ",")
	}
	if fs.NArg() == 0 {
		return errors.New("keine Binarys angegeben")
	}
	for _, p := range fs.Args() {
		m := nameRe.FindStringSubmatch(filepath.Base(p))
		if m == nil {
			return fmt.Errorf("%s: Name passt nicht (openwacht-agent_<os>_<arch>[.exe])", p)
		}
		bin, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s, err := update.Sign(priv, update.ManifestFor(*ver, m[1], m[2], bin), revoked...)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(p+".sig", append(out, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s.sig (%s %s/%s, Schlüssel %s)\n", p, s.Version, s.OS, s.Arch, s.KeyID)
		if len(s.Revoked) > 0 {
			fmt.Printf("  widerruft: %s\n", strings.Join(s.Revoked, ", "))
		}
	}
	return nil
}
