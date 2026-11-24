// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"os"
	"os/exec"
)

// renameOver: unter Linux ersetzt rename atomar, auch während das Binary läuft.
func renameOver(tmp, exe string) error { return os.Rename(tmp, exe) }

// RestartService startet den Agent-Dienst neu (ohne zu warten).
func RestartService() error {
	if out, err := exec.Command("systemctl", "restart", "--no-block", "openwacht-agent.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, out)
	}
	return nil
}

// ReplaceBinary ersetzt das installierte Binary.
func ReplaceBinary(exe string, bin []byte) error {
	if err := CheckBinary(exe); err != nil {
		return err
	}
	return replaceFile(exe, bin)
}
