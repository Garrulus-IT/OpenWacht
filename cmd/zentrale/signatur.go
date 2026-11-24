// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/garrulus-it/openwacht/internal/update"
)

// exitNoKey: Rückgabewert von pruefe-signatur, wenn dieses Binary keinen
// Update-Schlüssel enthält (installieren.sh weicht dann auf openssl aus).
const exitNoKey = 3

// cmdVerifySums prüft die Signatur einer Prüfsummendatei (Etappe 32, M7).
// Ohne -schluessel-datei gelten die in dieses Binary eingebetteten
// Schlüssel: Ein schon installiertes, früher geprüftes Binary prüft so das
// nächste Paket. Mit -schluessel-datei (aus einem Paket, also nicht
// vertrauenswürdig) nur zusammen mit -abdruck aus einer zweiten Quelle.
func cmdVerifySums(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pruefe-signatur", flag.ContinueOnError)
	sums := fs.String("summen", "", "Datei SHA256SUMS (Pflicht)")
	sigFile := fs.String("signatur", "", "Signaturdatei (Standard: <summen>.sig)")
	pin := fs.String("abdruck", "", "Kennung des erwarteten Schlüssels (16 Hexziffern, aus einer zweiten Quelle)")
	keyFile := fs.String("schluessel-datei", "", "Schlüssel aus dieser Datei statt der eingebetteten (nur mit -abdruck)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sums == "" {
		return errors.New("-summen ist Pflicht")
	}
	if *sigFile == "" {
		*sigFile = *sums + ".sig"
	}
	var keys *update.Keyring
	var err error
	if *keyFile != "" {
		if *pin == "" {
			return errors.New("-schluessel-datei nur mit -abdruck: Die Datei kommt aus dem Paket und beweist allein nichts")
		}
		b, err := readLimited(*keyFile, 4096)
		if err != nil {
			return err
		}
		if keys, err = update.ParseKeyring(string(b)); err != nil {
			return err
		}
	} else if keys, err = update.Keys(); err != nil {
		return err
	}
	if *pin != "" {
		if keys, err = keys.Pin(*pin); err != nil {
			return err
		}
	}
	content, err := readLimited(*sums, update.MaxSums)
	if err != nil {
		return err
	}
	raw, err := readLimited(*sigFile, 512)
	if err != nil {
		return err
	}
	sig, err := update.ParseSumsSig(raw)
	if err != nil {
		return err
	}
	if err := keys.VerifySums(content, sig); err != nil {
		return fmt.Errorf("%s: %w", *sums, err)
	}
	fmt.Fprintf(out, "Signatur in Ordnung (Schlüssel %s).\n", sig.KeyID)
	return nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s ist zu groß", path)
	}
	return b, nil
}
