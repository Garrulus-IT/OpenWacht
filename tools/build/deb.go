// SPDX-License-Identifier: AGPL-3.0-only

package main

// Debian-Paket der Zentrale, nur mit der Standardbibliothek (CONTRIBUTING.md:
// keine neue Abhängigkeit wie nFPM). Ein .deb ist ein ar-Archiv mit drei
// Teilen: debian-binary ("2.0"), control.tar.gz und data.tar.gz. Alle Zeiten
// sind die Commit-Zeit, Eigentümer root, Reihenfolge fest: Der Build bleibt
// reproduzierbar.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	deploylinux "github.com/garrulus-it/openwacht/deploy/linux"
)

const debPostinst = `#!/bin/sh
# OpenWacht: nach dem Auspacken alles einrichten bzw. aktualisieren.
# openwacht-zentrale installieren ist mehrfach ausführbar.
set -e
case "$1" in
    configure)
        /usr/bin/openwacht-zentrale installieren -paket
        ;;
esac
exit 0
`

const debPrerm = `#!/bin/sh
# OpenWacht: Beim Entfernen Dienste anhalten. Bei einem Update laufen sie
# weiter, postinst startet sie danach neu.
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now openwacht-zentrale.socket openwacht-zentrale.service \
        openwacht-traps.socket openwacht-traps.service openwacht-sicherung.timer \
        openwacht-zentrale-update.path >/dev/null 2>&1 || true
fi
exit 0
`

const debPostrm = `#!/bin/sh
# OpenWacht: Datenbank, Schlüssel (/etc/openwacht) und Sicherungen
# (/var/backups/openwacht) bleiben auch bei purge erhalten: Sie sind die Daten.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = purge ]; then
    echo "OpenWacht: Datenbank openwacht, /etc/openwacht und /var/backups/openwacht bleiben erhalten."
fi
exit 0
`

type debFile struct {
	path string // ohne führendes "/"
	data []byte
	mode int64
}

// commitTime: Zeit des Commits (reproduzierbar), sonst 0.
func commitTime() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	out, err := exec.Command("git", "log", "-1", "--format=%ct").Output()
	if err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

// debVersion: Debian-Version aus der Versionsnummer (- ist dort Trenner der
// Paketrevision, deshalb ~ für Vorabstände wie 0.21.0-dev).
func debVersion(v string) string {
	return strings.ReplaceAll(strings.TrimPrefix(v, "v"), "-", "~")
}

// tarGz schreibt Dateien samt aller Elternordner sortiert als tar.gz.
func tarGz(files []debFile, mtime time.Time) ([]byte, error) {
	dirs := map[string]bool{}
	for _, f := range files {
		for d := path.Dir(f.path); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	type entry struct {
		name string
		dir  bool
		f    debFile
	}
	var entries []entry
	for d := range dirs {
		entries = append(entries, entry{name: d, dir: true})
	}
	for _, f := range files {
		entries = append(entries, entry{name: f.path, f: f})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755, ModTime: mtime,
		Uname: "root", Gname: "root", Format: tar.FormatGNU}); err != nil {
		return nil, err
	}
	for _, e := range entries {
		h := &tar.Header{Name: "./" + e.name, ModTime: mtime, Uname: "root", Gname: "root", Format: tar.FormatGNU}
		if e.dir {
			h.Typeflag, h.Name, h.Mode = tar.TypeDir, h.Name+"/", 0o755
		} else {
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, e.f.mode, int64(len(e.f.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if !e.dir {
			if _, err := tw.Write(e.f.data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// arArchive schreibt das ar-Format, wie dpkg es erwartet.
func arArchive(members []debFile, mtime time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", m.path, mtime.Unix(), 0, 0, 0o100644, len(m.data))
		b.Write(m.data)
		if len(m.data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// pkgSpec beschreibt ein Paket (für .deb und .rpm gleich).
type pkgSpec struct {
	name, version, summary, description string
	depends                             []string // nur .deb
	files                               []debFile
	postinst, prerm, postrm             string // .deb-Skripte
}

// buildDeb baut openwacht-zentrale_<version>_<arch>.deb aus dem gebauten
// Binary binName im Ordner out. Rückgabe: Dateiname.
func buildDeb(out, binName, goarch, ver string, mtime time.Time) (string, error) {
	bin, err := os.ReadFile(filepath.Join(out, binName))
	if err != nil {
		return "", err
	}
	data := []debFile{
		{"usr/bin/openwacht-zentrale", bin, 0o755},
		{"usr/share/doc/openwacht-zentrale/copyright", copyrightFile("openwacht-zentrale"), 0o644},
	}
	for _, n := range deploylinux.UnitNames {
		u, err := deploylinux.Unit(n)
		if err != nil {
			return "", err
		}
		data = append(data, debFile{"usr/lib/systemd/system/" + n, u, 0o644})
	}
	return writeDeb(out, goarch, mtime, pkgSpec{
		name: "openwacht-zentrale", version: ver,
		summary: "OpenWacht-Zentrale (Monitoring, mandantenfähig)",
		description: `Zentrale von OpenWacht mit Web-Oberfläche (HTTPS auf Port 443), Agent-Port,
aktiven Checks, SNMP, Alarmen und Trap-Dienst. Nach der Installation führt
ein Assistent im Browser durch die Einrichtung (Link in der Ausgabe von apt).`,
		depends: []string{"postgresql", "passwd"},
		files:   data, postinst: debPostinst, prerm: debPrerm, postrm: debPostrm,
	})
}

// writeDeb schreibt <name>_<version>_<arch>.deb.
func writeDeb(out, goarch string, mtime time.Time, p pkgSpec) (string, error) {
	data := slices.Clone(p.files)
	var size int64
	var sums strings.Builder
	sort.Slice(data, func(i, j int) bool { return data[i].path < data[j].path })
	for _, f := range data {
		size += int64(len(f.data))
		s := md5.Sum(f.data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), f.path)
	}
	dv := debVersion(p.version)
	var desc strings.Builder
	for _, l := range strings.Split(strings.TrimSpace(p.description), "\n") {
		if l = strings.TrimSpace(l); l == "" {
			l = "."
		}
		desc.WriteString(" " + l + "\n")
	}
	control := fmt.Sprintf(`Package: %s
Version: %s
Architecture: %s
Maintainer: Philipp-Maximilian Heller <info@garrulus.de>
Installed-Size: %d
Depends: %s
Section: admin
Priority: optional
Homepage: https://github.com/garrulus-it/openwacht
Description: %s
%s`, p.name, dv, goarch, (size+1023)/1024, strings.Join(p.depends, ", "), p.summary, desc.String())
	ctrl, err := tarGz([]debFile{
		{"control", []byte(control), 0o644},
		{"md5sums", []byte(sums.String()), 0o644},
		{"postinst", []byte(p.postinst), 0o755},
		{"postrm", []byte(p.postrm), 0o755},
		{"prerm", []byte(p.prerm), 0o755},
	}, mtime)
	if err != nil {
		return "", err
	}
	dat, err := tarGz(data, mtime)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s_%s.deb", p.name, dv, goarch)
	deb := arArchive([]debFile{{"debian-binary", []byte("2.0\n"), 0}, {"control.tar.gz", ctrl, 0}, {"data.tar.gz", dat, 0}}, mtime)
	fmt.Printf("baue %-40s (Debian-Paket)\n", name)
	return name, os.WriteFile(filepath.Join(out, name), deb, 0o644)
}
