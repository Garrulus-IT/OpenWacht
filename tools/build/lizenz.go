// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Urheber und Lizenz für die Copyright-Dateien der Pakete.
const (
	copyrightHolder = "Philipp-Maximilian Heller"
	licenseSPDX     = "AGPL-3.0-only"
)

var (
	licenseOnce sync.Once
	licenseText []byte
	licenseErr  error
)

// copyrightFile: Inhalt von /usr/share/doc/<paket>/copyright. Die AGPL steht
// nicht in /usr/share/common-licenses, deshalb mit dem vollen Lizenztext aus
// LICENSE in der Wurzel des Repositorys (tools/build läuft dort, die Tests im
// Paketordner).
func copyrightFile(pkg string) []byte {
	licenseOnce.Do(func() {
		for _, p := range []string{"LICENSE", filepath.Join("..", "..", "LICENSE")} {
			if licenseText, licenseErr = os.ReadFile(p); licenseErr == nil {
				return
			}
		}
	})
	if licenseErr != nil {
		fmt.Fprintln(os.Stderr, "LICENSE:", licenseErr)
		os.Exit(1)
	}
	head := fmt.Sprintf("OpenWacht (%s)\nCopyright (C) 2026 %s\nLizenz: %s (GNU Affero General Public License, Version 3)\nQuellcode: https://github.com/garrulus-it/openwacht\n\n", pkg, copyrightHolder, licenseSPDX)
	return append([]byte(head), licenseText...)
}
