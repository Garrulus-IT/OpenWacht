// SPDX-License-Identifier: AGPL-3.0-only

// Package webui bettet die gebaute Web-Oberfläche (web/ → dist/) in die
// Zentrale ein. Ohne vorherigen Build enthält dist/ nur LIESMICH.txt; die
// Zentrale meldet dann, dass die Oberfläche fehlt, und die API funktioniert.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS liefert den Inhalt von dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
