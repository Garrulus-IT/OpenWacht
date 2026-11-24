// SPDX-License-Identifier: AGPL-3.0-only

package checks

// Fuzz-Ziel für die Parameter von Checks und Sensoren (Befund M3). Ziele
// kommen von Mandanten-Admins, Vorlagen und der Zentrale (für den Agent).
// Ein angenommenes Ziel muss sich nach dem Speichern wieder lesen lassen.

import (
	"encoding/json"
	"testing"
)

func FuzzParse(f *testing.F) {
	seeds := map[string]string{
		"ping": `{"host":"10.10.0.1","anzahl":5}`, "tcp": `{"host":"srv-file01","port":445}`,
		"http":      `{"url":"https://srv-web01.example.com/","erwarte_status":200,"enthaelt":"OK"}`,
		"tls":       `{"host":"srv-web01.example.com","port":443,"warnung_tage":20}`,
		"dns":       `{"name":"example.com","server":"10.10.0.53","eintrag":"A"}`,
		"http_json": `{"url":"https://10.10.0.5/status","json_pfad":"a.b[0]","warnung_ueber":5}`,
		"ntp":       `{"host":"10.10.0.123"}`, "snmp_oid": `{"oid":"1.3.6.1.2.1.1.3.0","rate":true}`,
		"dienst": `{"name":"nginx.service"}`, "prozess": `{"name":"postgres","mindestens":1}`,
		"datei": `{"pfad":"/srv/backup/db.dump","warnung_stunden":26}`, "docker": `{"name":"webapp"}`,
		"leistungsindikator": `{"objekt":"Swyx Trunk","indikator":"% Channels used","instanz":"*","zusammenfassung":"maximum","warnung_ueber":80}`,
	}
	kinds := append(append([]string{}, Kinds...), AgentKinds...)
	for i, k := range kinds {
		if s, ok := seeds[k]; ok {
			f.Add(uint8(i), []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, k uint8, raw []byte) {
		kind := kinds[int(k)%len(kinds)]
		s, err := Parse(kind, raw)
		if err != nil {
			return
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("angenommenes Ziel nicht speicherbar: %v", err)
		}
		if _, err := Parse(kind, b); err != nil {
			t.Fatalf("gespeichertes Ziel (%s) wird abgelehnt: %v\n%s", kind, err, b)
		}
	})
}
