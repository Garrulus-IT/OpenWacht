// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoOff schaltet die Anzeige der Eingabe ab, wenn f ein Terminal ist, und
// liefert die Funktion zum Wiederherstellen. Kein Terminal (Pipe, Datei):
// ok = false, es ändert sich nichts.
func echoOff(f *os.File) (restore func(), ok bool) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, false
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return nil, false
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, true
}
