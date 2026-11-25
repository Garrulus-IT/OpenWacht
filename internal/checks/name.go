// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Automatische Namen (Etappe 18c): Bleibt der Name beim Anlegen leer, bildet
// die Zentrale ihn aus Art und Ziel, z. B. „Ping“, „TCP 53“, „HTTP 443“ oder
// „DNS heise.de“. Die Oberfläche zeigt denselben Vorschlag (web/src/Checks.tsx,
// vorschlagName); beide Fassungen müssen gleich bleiben.

// MaxName: höchstens so viele Zeichen hat ein Name (wie in der Datenbank).
const MaxName = 100

// DefaultName bildet den Namen aus Art und bereinigtem Ziel.
func DefaultName(kind string, s Spec) string {
	n := ""
	switch kind {
	case "ping":
		n = "Ping"
	case "tcp":
		n = "TCP " + strconv.Itoa(s.Port)
	case "http":
		n = "HTTP " + urlPort(s.URL)
	case "tls":
		n = "Zertifikat " + s.Host
	case "dns":
		n = "DNS " + s.Name
	case "http_json":
		n = "JSON " + s.JSONPath
	case "tcp_banner":
		n = "Banner " + strconv.Itoa(s.Port)
	case "ntp":
		n = "NTP"
	case "snmp_oid":
		n = "OID " + s.OID
		if s.Aggregate != "" {
			n = "Spalte " + s.OID + " " + s.Aggregate
		}
	case "dienst":
		n = "Dienst " + s.Name
	case "prozess":
		n = "Prozess " + s.Name
	case "datei":
		if s.Folder {
			n = "Ordner " + baseName(s.Path)
		} else {
			n = "Datei " + baseName(s.Path)
		}
	case "docker":
		n = "Container " + s.Name
	case "hyperv":
		n = "Hyper-V-VM " + s.Name
	case "leistungsindikator":
		n = s.Object + " " + s.Counter
	case "autodienste":
		n = "Automatische Dienste"
	default:
		n = "Sensor"
	}
	return clipName(strings.TrimSpace(n))
}

// NumberedName: „Ping“, „Ping 2“, „Ping 3“ … (n ≥ 2), gekürzt auf MaxName.
func NumberedName(base string, n int) string {
	if n < 2 {
		return clipName(base)
	}
	suffix := " " + strconv.Itoa(n)
	return clipName(base, utf8.RuneCountInString(suffix)) + suffix
}

func clipName(s string, reserve ...int) string {
	limit := MaxName
	if len(reserve) > 0 {
		limit -= reserve[0]
	}
	if utf8.RuneCountInString(s) > limit {
		s = strings.TrimSpace(string([]rune(s)[:limit]))
	}
	return s
}

func urlPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func baseName(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}
