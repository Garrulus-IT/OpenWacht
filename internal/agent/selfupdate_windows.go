// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
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
		angehalten := false
		for range 60 {
			time.Sleep(500 * time.Millisecond)
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				angehalten = true
				break
			}
		}
		if !angehalten {
			return errors.New("Dienst hält nach 30 s nicht an; Start-Service bzw. Neustart des Rechners holt das Update nach")
		}
	}
	if err := s.Start(); err != nil {
		return err
	}
	return waitRunning(s)
}

// waitRunning: bis zu 10 s warten, bis der Dienst läuft. Der Agent meldet
// „läuft“ sofort und beendet sich bei einem Fehler erst danach; so fällt
// ein Dienst auf, der gleich wieder stehen bleibt.
func waitRunning(s *mgr.Service) error {
	for range 20 {
		time.Sleep(500 * time.Millisecond)
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			// kurz nachsehen, ob er dabei bleibt
			time.Sleep(time.Second)
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				return fmt.Errorf("Dienst beendet sich gleich nach dem Start (Code %d); Ursache in der Ereignisanzeige, Quelle %s",
					st.ServiceSpecificExitCode, ServiceName)
			}
			return nil
		case svc.Stopped:
			return fmt.Errorf("Dienst beendet sich gleich nach dem Start (Code %d); Ursache in der Ereignisanzeige, Quelle %s",
				st.ServiceSpecificExitCode, ServiceName)
		}
	}
	return errors.New("Dienst meldet nach 10 s noch nicht „läuft“")
}
