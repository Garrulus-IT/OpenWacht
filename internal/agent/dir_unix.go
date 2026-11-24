// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package agent

import "os"

// prepareDir legt das Agent-Verzeichnis an, nur für den Eigentümer zugänglich.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
