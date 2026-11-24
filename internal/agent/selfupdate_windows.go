// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// renameOver: Ein laufendes Programm lässt sich unter Windows nicht
// überschreiben, aber umbenennen. Das alte Binary wird zu .alt (beim
// nächsten Update gelöscht), dann kommt das neue an seinen Platz.
func renameOver(tmp, exe string) error {
	old := exe + ".alt"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		return err
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

// RestartService stoppt den Agent-Dienst und startet ihn neu.
func RestartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("Dienst anhalten: %w", err)
		}
		for range 60 {
			time.Sleep(500 * time.Millisecond)
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				break
			}
		}
	}
	return s.Start()
}
