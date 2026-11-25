// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSensorenGueltig(t *testing.T) {
	for kind, raw := range map[string]string{
		"ping":      `{"host":"127.0.0.1","anzahl":5,"verlust_warnung":20,"verlust_kritisch":60,"antwort_warnung_ms":50}`,
		"dns":       `{"name":"nas.example.org","server":"127.0.0.1","eintrag":"a","erwartet":["127.0.0.5"]}`,
		"http_json": `{"url":"http://127.0.0.1/status","json_pfad":"werte.0.temp","warnung_ueber":0,"kritisch_ueber":70}`,
		"dienst":    `{"name":"nginx.service"}`,
		"prozess":   `{"name":"postgres","hoechstens":20}`,
		"datei":     `{"pfad":"/var/backups/db.dump","warnung_stunden":26,"kritisch_stunden":50,"mindestgroesse":1024}`,
	} {
		s, err := Parse(kind, []byte(raw))
		if err != nil {
			t.Errorf("%s %s: %v", kind, raw, err)
		}
		if kind == "dns" && (s.Record != "A" || s.TimeoutSec != 5) {
			t.Errorf("dns: Standardwerte %+v", s)
		}
		if kind == "prozess" && s.Min != 1 {
			t.Errorf("prozess: mindestens %d, erwartet 1", s.Min)
		}
	}
	// Windows-Pfad und Ordner
	if _, err := Parse("datei", []byte(`{"pfad":"D:\\Backup\\Nacht","ordner":true,"kritisch_stunden":30}`)); err != nil {
		t.Error(err)
	}
	// alter Ping ohne neue Felder: 3 Pakete wie bisher
	if s, err := Parse("ping", []byte(`{"host":"10.0.0.1"}`)); err != nil || s.Count != 3 {
		t.Errorf("Ping alt: %+v %v", s, err)
	}
}

func TestParseSensorenUngueltig(t *testing.T) {
	for _, tc := range []struct{ kind, raw, want string }{
		{"ping", `{"host":"x","anzahl":21}`, "Anzahl Pakete"},
		{"ping", `{"host":"x","anzahl":20,"timeout_s":4}`, "höchstens 60"},
		{"ping", `{"host":"x","verlust_warnung":60,"verlust_kritisch":20}`, "Warnung kleiner"},
		{"ping", `{"host":"x","verlust_warnung":101}`, "0 bis 100"},
		{"dns", `{"name":"10.0.0.1"}`, "keine IP"},
		{"dns", `{"name":"nas","server":"nas.example.org"}`, "DNS-Server"},
		{"dns", `{"name":"nas","eintrag":"MX"}`, "Eintrag"},
		{"dns", `{"name":"nas","eintrag":"A","erwartet":["::1"]}`, "passen nicht"},
		{"dns", `{"name":"nas","host":"x"}`, "passt nicht zum Typ"},
		{"http_json", `{"url":"http://x/","json_pfad":"a..b"}`, "JSON-Pfad"},
		{"http_json", `{"url":"http://x/","json_pfad":"a","gleich":"ok","warnung_ueber":1}`, "nicht beides"},
		{"http_json", `{"url":"http://x/","json_pfad":"a","warnung_ueber":5,"kritisch_ueber":5}`, "Warnung kleiner"},
		{"http_json", `{"url":"http://x/","json_pfad":"a","warnung_unter":1,"kritisch_unter":5}`, "Warnung größer"},
		{"dienst", `{"name":"-H evil"}`, "Dienst"},
		{"dienst", `{"name":"a;b"}`, "Dienst"},
		{"dienst", `{"name":"nginx","timeout_s":5}`, "passt nicht zum Typ"},
		{"prozess", `{"name":"x","mindestens":5,"hoechstens":2}`, "Anzahl"},
		{"prozess", `{"name":"../x"}`, "Prozess"},
		{"datei", `{"pfad":"relativ/x","kritisch_stunden":1}`, "absolut"},
		{"datei", `{"pfad":"/var/../etc/shadow","kritisch_stunden":1}`, "ohne"},
		{"datei", `{"pfad":"/var/backups/","kritisch_stunden":1}`, "ohne"},
		{"datei", `{"pfad":"C:\\a\\..\\b","kritisch_stunden":1}`, "ohne"},
		{"datei", `{"pfad":"C:\\a/b","kritisch_stunden":1}`, "Trenner"},
		{"datei", `{"pfad":"/var/x"}`, "Alter oder Mindestgröße"},
		{"datei", `{"pfad":"/var/x","ordner":true,"mindestgroesse":5}`, "nur für Dateien"},
		{"datei", `{"pfad":"/var/x","warnung_stunden":50,"kritisch_stunden":26}`, "Warnung kleiner"},
	} {
		_, err := Parse(tc.kind, []byte(tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: %v (erwartet %q)", tc.kind, tc.raw, err, tc.want)
		}
	}
}

func TestPingResult(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		spec          Spec
		count         int
		rtts          []time.Duration
		status, inMsg string
	}{
		{Spec{}, 3, nil, Crit, "keine Antwort"},
		{Spec{}, 3, []time.Duration{ms, 2 * ms, ms}, OK, "erreichbar"},
		{Spec{}, 4, []time.Duration{ms, ms, ms}, OK, "25 % Verlust"},
		{Spec{LossWarn: 20, LossCrit: 50}, 4, []time.Duration{ms, ms, ms}, Warn, "Warnung ab 20"},
		{Spec{LossWarn: 20, LossCrit: 50}, 4, []time.Duration{ms, ms}, Crit, "kritisch ab 50"},
		{Spec{RTTWarn: 10, RTTCrit: 100}, 2, []time.Duration{20 * ms, 20 * ms}, Warn, "über 10 ms"},
		{Spec{RTTWarn: 10, RTTCrit: 100}, 2, []time.Duration{200 * ms, 200 * ms}, Crit, "über 100 ms"},
	} {
		got := pingResult(tc.spec, tc.count, tc.rtts)
		if got.Status != tc.status || !strings.Contains(got.Message, tc.inMsg) {
			t.Errorf("%+v %d %v: %+v", tc.spec, tc.count, tc.rtts, got)
		}
	}
	got := pingResult(Spec{}, 3, []time.Duration{ms, 3 * ms, ms})
	if got.Metric != "Ø 1,7 ms, Jitter 2,0 ms" {
		t.Errorf("Messwert %q", got.Metric)
	}
}

func TestHTTPJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kaputt":
			w.Write([]byte("<html>"))
		case "/fehler":
			w.WriteHeader(500)
		default:
			w.Write([]byte(`{"status":"geheimer Text","werte":[{"temp":42.5}],"an":true,"leer":null,"obj":{}}`))
		}
	}))
	defer srv.Close()
	r := runner()
	j := func(rest string) string { return `{"url":"` + srv.URL + `/` + `",` + rest + `}` }
	for _, tc := range []struct {
		raw, status, msg, metric string
	}{
		{j(`"json_pfad":"werte.0.temp"`), OK, "Wert vorhanden", "42,5"},
		{j(`"json_pfad":"werte.0.temp","warnung_ueber":40,"kritisch_ueber":50`), Warn, "über 40", "42,5"},
		{j(`"json_pfad":"werte.0.temp","warnung_ueber":30,"kritisch_ueber":40`), Crit, "über 40 (kritisch)", "42,5"},
		{j(`"json_pfad":"werte.0.temp","warnung_unter":50,"kritisch_unter":0`), Warn, "unter 50", "42,5"},
		{j(`"json_pfad":"werte.0.temp","warnung_ueber":50`), OK, "im Rahmen", "42,5"},
		{j(`"json_pfad":"status","warnung_ueber":1`), Unknown, "keine Zahl", ""},
		{j(`"json_pfad":"status","gleich":"geheimer Text"`), OK, "wie erwartet", ""},
		{j(`"json_pfad":"status","gleich":"anders"`), Crit, "weicht", ""},
		{j(`"json_pfad":"an","gleich":"true"`), OK, "wie erwartet", ""},
		{j(`"json_pfad":"leer","gleich":"null"`), OK, "wie erwartet", ""},
		{j(`"json_pfad":"obj","gleich":"x"`), Crit, "Objekt", ""},
		{j(`"json_pfad":"werte.5.temp"`), Crit, "nicht gefunden", ""},
		{j(`"json_pfad":"fehlt"`), Crit, "nicht gefunden", ""},
		{`{"url":"` + srv.URL + `/kaputt","json_pfad":"a"}`, Crit, "kein JSON", ""},
		{`{"url":"` + srv.URL + `/fehler","json_pfad":"a"}`, Crit, "HTTP 500", ""},
	} {
		got := run(t, r, "http_json", tc.raw)
		if got.Status != tc.status || !strings.Contains(got.Message, tc.msg) || (tc.metric != "" && got.Metric != tc.metric) {
			t.Errorf("%s: %+v", tc.raw, got)
		}
		// Texte aus der Antwort erscheinen nie in Meldung oder Messwert.
		if strings.Contains(got.Message+got.Metric, "geheim") {
			t.Errorf("Inhalt in der Meldung: %+v", got)
		}
	}
	// außerhalb der Freigabe
	blocked := &Runner{Guard: NewGuard(nil)}
	expect(t, "gesperrt", run(t, blocked, "http_json", j(`"json_pfad":"a"`)), Unknown, "nicht freigegeben")
}

// fakeDNS beantwortet jede Frage nach A mit den angegebenen Adressen, sonst
// NXDOMAIN für „fehlt.test.“.
func fakeDNS(t *testing.T, answers ...[4]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 12 {
				continue
			}
			// Frage bis zum Ende von QNAME + QTYPE + QCLASS
			i := 12
			for i < n && q[i] != 0 {
				i += int(q[i]) + 1
			}
			end := i + 5
			if end > n {
				continue
			}
			qname := string(q[12:i])
			qtype := binary.BigEndian.Uint16(q[i+1:])
			resp := append([]byte{}, q[:2]...)
			rcode := byte(0)
			an := answers
			if strings.Contains(qname, "fehlt") {
				rcode, an = 3, nil
			}
			if qtype != 1 {
				an = nil
			}
			resp = append(resp, 0x81, 0x80|rcode, 0, 1, 0, byte(len(an)), 0, 0, 0, 0)
			resp = append(resp, q[12:end]...)
			for _, a := range an {
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, a[:]...)
			}
			pc.WriteTo(resp, from)
		}
	}()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	return port
}

func TestDNS(t *testing.T) {
	port := fakeDNS(t, [4]byte{127, 0, 0, 5}, [4]byte{192, 0, 2, 7})
	r := &Runner{Guard: NewGuard(prefixes("127.0.0.0/8")), DNSPort: port}
	expect(t, "auflösen", run(t, r, "dns", `{"name":"nas.test","server":"127.0.0.1","eintrag":"A"}`),
		OK, "löst auf: 127.0.0.5 und 1 weitere")
	got := run(t, r, "dns", `{"name":"nas.test","server":"127.0.0.1","eintrag":"A"}`)
	if strings.Contains(got.Message, "192.0.2.7") {
		t.Errorf("Adresse außerhalb der Freigabe in der Meldung: %q", got.Message)
	}
	expect(t, "erwartet", run(t, r, "dns", `{"name":"nas.test","server":"127.0.0.1","eintrag":"A","erwartet":["127.0.0.5"]}`),
		OK, "erwartete Adresse")
	expect(t, "abweichend", run(t, r, "dns", `{"name":"nas.test","server":"127.0.0.1","eintrag":"A","erwartet":["127.0.0.9"]}`),
		Crit, "ohne erwartete Adresse 127.0.0.9")
	expect(t, "NXDOMAIN", run(t, r, "dns", `{"name":"fehlt.test","server":"127.0.0.1","eintrag":"A"}`),
		Crit, "nicht gefunden")
	// Server nicht freigegeben: kein Paket geht raus
	blocked := &Runner{Guard: NewGuard(prefixes("10.0.0.0/8")), DNSPort: port}
	expect(t, "gesperrt", run(t, blocked, "dns", `{"name":"nas.test","server":"127.0.0.1"}`), Unknown, "nicht freigegeben")
	// Zeitüberschreitung: Port ohne Antwort
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	_, silent, _ := net.SplitHostPort(pc.LocalAddr().String())
	slow := &Runner{Guard: loopback, DNSPort: silent}
	ctx := context.Background()
	s, _ := Parse("dns", []byte(`{"name":"nas.test","server":"127.0.0.1","timeout_s":1}`))
	if got := slow.Run(ctx, "dns", s); got.Status != Crit {
		t.Errorf("ohne Antwort: %+v", got)
	}
}

func TestVorlagen(t *testing.T) {
	raw, err := ParseTemplate("http", []byte(`{"url":"https://{adresse}:5001/","erwarte_status":[200]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !UsesPlaceholder(raw) {
		t.Fatalf("Platzhalter verloren: %s", raw)
	}
	s, err := Parse("http", Substitute(raw, "172.16.0.20"))
	if err != nil || s.URL != "https://172.16.0.20:5001/" {
		t.Errorf("eingesetzt: %+v %v", s, err)
	}
	s, err = Parse("http", Substitute(raw, "fd00::1"))
	if err != nil || s.URL != "https://[fd00::1]:5001/" {
		t.Errorf("IPv6: %+v %v", s, err)
	}
	// ungültige Adresse wird nicht eingesetzt (kein Ausbruch aus dem JSON)
	if got := Substitute(raw, `x","ca_pem":"`); string(got) != string(raw) {
		t.Errorf("ungeprüft eingesetzt: %s", got)
	}
	for _, tc := range []struct{ kind, raw, want string }{
		{"datei", `{"pfad":"/srv/{adresse}","kritisch_stunden":1}`, "nur in Host"},
		{"tcp", `{"host":"{adresse}"}`, "Port"},
		{"tcp", `{"host":"{adresse}","port":22,"x":1}`, "unknown field"},
	} {
		if _, err := ParseTemplate(tc.kind, []byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.raw, err)
		}
	}
	if raw, err := ParseTemplate("dienst", []byte(`{"name":"sshd"}`)); err != nil || UsesPlaceholder(raw) {
		t.Errorf("dienst: %s %v", raw, err)
	}
}

// Benannte SQL-Instanzen heißen MSSQL$NAME, Anzeigenamen enthalten Klammern
// (0.99.0 lehnte beides ab). Shell-Zeichen bleiben verboten.
func TestDienstnameSQLInstanz(t *testing.T) {
	for _, ok := range []string{`MSSQL$BEISPIELSQL`, `SQLAgent$NAME`, `SQL Server (BEISPIELSQL)`, `nginx.service`, `getty@tty1.service`} {
		if _, err := Parse("dienst", []byte(`{"name":`+strconv.Quote(ok)+`}`)); err != nil {
			t.Errorf("%q abgelehnt: %v", ok, err)
		}
	}
	for _, bad := range []string{"-x", "a;b", "a|b", "a`b", "a/b", "$x", "(x)"} {
		if _, err := Parse("dienst", []byte(`{"name":`+strconv.Quote(bad)+`}`)); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
}

// Benannte SQL-Instanz: Objekt MSSQL$NAME:… (0.99.2), am Server gesehen.
func TestLeistungsindikatorSQLInstanz(t *testing.T) {
	ok := `{"objekt":"MSSQL$BEISPIELSQL:General Statistics","indikator":"Processes blocked"}`
	if _, err := Parse("leistungsindikator", []byte(ok)); err != nil {
		t.Errorf("benannte Instanz abgelehnt: %v", err)
	}
	if !ValidPerfName("MSSQL$BEISPIELSQL:Databases") {
		t.Error("ValidPerfName lehnt MSSQL$… ab")
	}
	for _, bad := range []string{"$x", `a\b`, "a(b)", "a*b", "a?b"} {
		if ValidPerfName(bad) {
			t.Errorf("%q angenommen", bad)
		}
	}
}

func TestDurationText(t *testing.T) {
	for sec, want := range map[float64]string{
		30: "30 s", 59.6: "60 s", 60: "1 Min.", 7140: "119 Min.", 7200: "2 Std.", 93600: "26 Std.", 93660: "26 Std. 1 Min.",
		172800: "2 Tage", 86400 * 3.5: "3 Tage 12 Std.", 86400 * 400: "400 Tage", -1: "-1 s",
	} {
		if got := DurationText(sec); got != want {
			t.Errorf("%v: %q, erwartet %q", sec, got, want)
		}
	}
	lim := 93600.0
	r := JudgeSeconds(Spec{CritAbove: &lim}, 100000, "1 Tag 3 Std.")
	if r.Status != Crit || r.Message != "Laufzeit über 26 Std. (kritisch)" {
		t.Errorf("%+v", r)
	}
}

func TestAutodiensteSpec(t *testing.T) {
	s, err := Parse("autodienste", []byte(`{"ausnahmen":[" gupdate ","GUPDATE","edge*","MSSQL$SQLEXPRESS"]}`))
	if err != nil || len(s.Exceptions) != 3 || s.Exceptions[0] != "gupdate" {
		t.Fatalf("%v %q", err, s.Exceptions)
	}
	if _, err := Parse("autodienste", []byte(`{}`)); err != nil {
		t.Errorf("ohne Ausnahmen: %v", err)
	}
	if DefaultName("autodienste", s) != "Automatische Dienste" {
		t.Errorf("Name %q", DefaultName("autodienste", s))
	}
	for _, bad := range []string{`{"ausnahmen":["*"]}`, `{"ausnahmen":["a*b"]}`, `{"ausnahmen":["a\nb"]}`, `{"ausnahmen":[""]}`, `{"name":"x"}`} {
		if _, err := Parse("autodienste", []byte(bad)); err == nil {
			t.Errorf("angenommen: %s", bad)
		}
	}
	many := `{"ausnahmen":["a0"`
	for i := 1; i <= MaxExceptions; i++ {
		many += `,"a` + strconv.Itoa(i) + `"`
	}
	if _, err := Parse("autodienste", []byte(many+`]}`)); err == nil {
		t.Error("zu viele Ausnahmen angenommen")
	}
	if !ExceptionMatch([]string{"Edge*"}, "edgeupdatem", "") || ExceptionMatch([]string{"edge"}, "edgeupdate", "") ||
		!ExceptionMatch([]string{"druckwarteschlange"}, "Spooler", "Druckwarteschlange") {
		t.Error("ExceptionMatch")
	}
}
