// SPDX-License-Identifier: AGPL-3.0-only

// Package version liefert die Versionsangaben, die beim Bauen per -ldflags
// eingesetzt werden. Ohne Build-Werkzeug (z. B. bei "go run") steht hier "dev".
package version

import (
	"fmt"
	"runtime"
)

// Diese Werte setzt tools/build über -ldflags "-X ...". Sie bleiben Variablen,
// damit der Linker sie überschreiben kann; geändert werden sie zur Laufzeit nie.
var (
	Version = "dev"     // z. B. "0.1.0"
	Commit  = "unknown" // Git-Commit, aus dem gebaut wurde
)

// String gibt eine einzeilige Beschreibung aus, z. B.
// "openwacht-agent 0.1.0 (Commit 1a2b3c4, linux/amd64, go1.27.4)".
func String(program string) string {
	return fmt.Sprintf("%s %s (Commit %s, %s/%s, %s)",
		program, Version, Commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
