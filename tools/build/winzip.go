// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// windowsZentraleTargets: Zentrale für Windows Server (1.0.14), als ZIP mit
// den Downloads, ohne Installer (Handbuch Kapitel 1, Windows Server).
var windowsZentraleTargets = []target{{"windows", "amd64", ""}}

// zentraleLiesmich: Kurzanleitung im ZIP (ausführlich im Handbuch).
const zentraleLiesmich = `OpenWacht-Zentrale für Windows Server
======================================

Ausführlich: Handbuch, Kapitel 1, Abschnitt „Windows Server“.

1. PostgreSQL 16 oder neuer installieren. Rollen und Datenbank anlegen
   (als postgres, z. B. in psql):

     CREATE ROLE openwacht_app NOLOGIN;
     CREATE ROLE openwacht_owner LOGIN PASSWORD '<Passwort 1>';
     CREATE ROLE openwacht_zentrale LOGIN PASSWORD '<Passwort 2>' IN ROLE openwacht_app;
     CREATE ROLE openwacht_traps NOLOGIN;
     CREATE DATABASE openwacht OWNER openwacht_owner ENCODING 'UTF8' TEMPLATE template0;
     REVOKE ALL ON DATABASE openwacht FROM PUBLIC;
     GRANT CONNECT ON DATABASE openwacht TO openwacht_owner, openwacht_zentrale;

2. Diesen Ordner nach C:\Program Files\OpenWacht kopieren (mit dem
   Unterordner downloads).

3. C:\ProgramData\OpenWacht\zentrale.env anlegen (Vorlage: zentrale.env.beispiel)
   und die beiden Verbindungen eintragen.

4. In einer PowerShell als Administrator:

     & "C:\Program Files\OpenWacht\openwacht-zentrale.exe" dienst-einrichten
     Start-Service OpenWacht-Zentrale

5. Den Link zum Einrichtungsassistenten zeigt
   C:\ProgramData\OpenWacht\zentrale.log (oder: openwacht-zentrale.exe einrichtungslink).

Der Hauptschlüssel liegt in C:\ProgramData\OpenWacht\schluessel. Ohne ihn ist
eine Sicherung der Datenbank unlesbar: mit der Sicherung aufbewahren.
`

const zentraleEnvBeispiel = `# Einstellungen der Zentrale unter Windows (C:\ProgramData\OpenWacht\zentrale.env).
# Was schon in der Umgebung des Dienstes steht, gilt vorrangig.
OPENWACHT_DB_EIGENTUEMER=host=127.0.0.1 user=openwacht_owner password=<Passwort 1> dbname=openwacht
OPENWACHT_DB=host=127.0.0.1 user=openwacht_zentrale password=<Passwort 2> dbname=openwacht
`

// buildWindowsZip baut openwacht-zentrale_<version>_windows_<arch>.zip aus
// der (signierten) Zentrale im Ordner dir und den Downloads unter root.
func buildWindowsZip(dir, exeName, goarch, ver string, mtime time.Time, root string) (string, error) {
	exe, err := os.ReadFile(filepath.Join(dir, exeName))
	if err != nil {
		return "", err
	}
	files := map[string][]byte{
		"OpenWacht/openwacht-zentrale.exe": exe,
		"OpenWacht/LIESMICH.txt":           crlf(zentraleLiesmich),
		"OpenWacht/zentrale.env.beispiel":  crlf(zentraleEnvBeispiel),
		"OpenWacht/LICENSE.txt":            copyrightFile("openwacht-zentrale"),
	}
	dl, err := downloadFiles(root, "OpenWacht/downloads")
	if err != nil {
		return "", err
	}
	for _, f := range dl {
		files[f.path] = f.data
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate, Modified: mtime.UTC()}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return "", err
		}
		if _, err := w.Write(files[n]); err != nil {
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	name := fmt.Sprintf("openwacht-zentrale_%s_windows_%s.zip", ver, goarch)
	fmt.Printf("baue %-40s (ZIP für Windows Server)\n", name)
	return name, os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644)
}

func crlf(s string) []byte {
	return bytes.ReplaceAll([]byte(s), []byte("\n"), []byte("\r\n"))
}
