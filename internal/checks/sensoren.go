// SPDX-License-Identifier: AGPL-3.0-only

package checks

// Prüfung der Sensorarten aus Etappe 18 (Ping-Schwellen, DNS, HTTP-JSON und
// die Arten auf dem Agent) sowie der Vorlagen.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxPingCount = 20
	maxExpect    = 8
	maxPathLen   = 500
	maxEquals    = 200
)

// Namen von Diensten (systemd-Unit oder Windows-Dienst) und Prozessen. Kein
// führendes „-“, damit ein Name nie als Option gelesen werden kann.
var (
	// $ für benannte SQL-Instanzen (MSSQL$NAME), Klammern für Anzeigenamen
	// („SQL Server (NAME)“). Gefahrlos: Der Name geht ohne Shell an systemctl
	// (nach „--“) bzw. an OpenService.
	serviceName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@$() \-]{0,199}$`)
	processName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+:@\-]{0,99}$`)
	containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$`)
	// Hyper-V erlaubt fast alles; der Name wird nur am Agent verglichen.
	vmName = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._()+,:@#&'\-]{0,99}$`)
	// Leistungsindikatoren (0.44.0): Objekt, Indikator und Instanz ohne
	// \ ( ) * ?, damit der Agent den Pfad eindeutig zusammensetzt und keine
	// Platzhalter von der Zentrale kommen (nur „*“ als ganze Instanz).
	// „$“ ab 0.99.2: benannte SQL-Instanzen heißen MSSQL$NAME:General Statistics.
	perfName = regexp.MustCompile(`^[\p{L}\p{N}%_][\p{L}\p{N} %!._,:+&'/#$\-]{0,127}$`)
	// Indikatoren dürfen Klammern enthalten (Exchange: „Internal Aggregate
	// Delivery Queue Length (All Internal Queues)“); sie stehen im Pfad hinter dem letzten „\“
	// und sind dort eindeutig. Objekt und Instanz bleiben ohne Klammern.
	perfCounterName = regexp.MustCompile(`^[\p{L}\p{N}%_][\p{L}\p{N} %!._,:+&'/#()\-]{0,127}$`)
	jsonPath        = regexp.MustCompile(`^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*$`)
	winAbs          = regexp.MustCompile(`^[A-Za-z]:\\`)
)

func (s *Spec) normalizePing() error {
	if s.Count == 0 {
		s.Count = 3
	}
	if s.Count < 1 || s.Count > maxPingCount {
		return fmt.Errorf("Anzahl Pakete: 1 bis %d", maxPingCount)
	}
	if s.Count*s.TimeoutSec > 60 {
		return errors.New("Anzahl Pakete mal Zeitlimit: höchstens 60 Sekunden")
	}
	if s.LossWarn < 0 || s.LossWarn > 100 || s.LossCrit < 0 || s.LossCrit > 100 {
		return errors.New("Verlust: 0 bis 100 Prozent")
	}
	if s.LossWarn > 0 && s.LossCrit > 0 && s.LossWarn >= s.LossCrit {
		return errors.New("Verlust: Warnung kleiner als kritisch")
	}
	if s.RTTWarn < 0 || s.RTTCrit < 0 || s.RTTWarn > 60000 || s.RTTCrit > 60000 {
		return errors.New("Antwortzeit: 0 bis 60000 ms")
	}
	if s.RTTWarn > 0 && s.RTTCrit > 0 && s.RTTWarn >= s.RTTCrit {
		return errors.New("Antwortzeit: Warnung kleiner als kritisch")
	}
	return nil
}

func (s *Spec) normalizeDNS() error {
	if !validHost(s.Name) {
		return errors.New("Name: Hostname angeben, der aufgelöst werden soll")
	}
	if _, err := netip.ParseAddr(s.Name); err == nil {
		return errors.New("Name: einen Namen angeben, keine IP-Adresse")
	}
	if s.Server != "" {
		a, err := netip.ParseAddr(s.Server)
		if err != nil || a.Zone() != "" {
			return errors.New("DNS-Server: IP-Adresse angeben (leer = Resolver der Zentrale)")
		}
		s.Server = a.Unmap().String()
	}
	s.Record = strings.ToUpper(strings.TrimSpace(s.Record))
	if s.Record != "" && s.Record != "A" && s.Record != "AAAA" {
		return errors.New("Eintrag: A, AAAA oder leer (beide)")
	}
	if len(s.Expect) > maxExpect {
		return fmt.Errorf("Erwartete Adressen: höchstens %d", maxExpect)
	}
	for i, e := range s.Expect {
		a, err := netip.ParseAddr(strings.TrimSpace(e))
		if err != nil || a.Zone() != "" {
			return errors.New("Erwartete Adressen: nur IP-Adressen")
		}
		a = a.Unmap()
		if s.Record == "A" && !a.Is4() || s.Record == "AAAA" && !a.Is6() {
			return errors.New("Erwartete Adressen passen nicht zum Eintrag")
		}
		s.Expect[i] = a.String()
	}
	return nil
}

func (s *Spec) normalizeJSON() error {
	if len(s.ExpectStatus) > maxStatus {
		return fmt.Errorf("Erwartete Status-Codes: höchstens %d", maxStatus)
	}
	for _, c := range s.ExpectStatus {
		if c < 100 || c > 599 {
			return errors.New("Erwartete Status-Codes: 100 bis 599")
		}
	}
	if len(s.JSONPath) > 200 || strings.Count(s.JSONPath, ".") > 19 || !jsonPath.MatchString(s.JSONPath) {
		return errors.New("JSON-Pfad: Schlüssel mit Punkt getrennt, z. B. status.cpu oder werte.0.temp")
	}
	return s.normalizeValue()
}

// ValidOID: numerische OID ohne führenden Punkt, 2 bis 64 Teile.
func ValidOID(o string) bool {
	if o == "" || len(o) > 200 {
		return false
	}
	parts := strings.Split(o, ".")
	if len(parts) < 2 || len(parts) > 64 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 10 || strings.Trim(p, "0123456789") != "" || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return parts[0] == "0" || parts[0] == "1" || parts[0] == "2"
}

func (s *Spec) normalizeOID() error {
	s.OID = strings.TrimPrefix(strings.TrimSpace(s.OID), ".")
	if !ValidOID(s.OID) {
		return errors.New("OID: Zahlen mit Punkt getrennt, z. B. 1.3.6.1.2.1.1.3.0")
	}
	if s.Rate && s.Equals != nil {
		return errors.New("Rate nur für Zähler mit Schwellen, nicht mit erwartetem Text")
	}
	s.Aggregate = strings.ToLower(strings.TrimSpace(s.Aggregate))
	if s.Aggregate != "" {
		// Spalte einer Tabelle (0.47.0): eine Kennzahl über alle Zeilen
		if !slices.Contains(ColumnAggregates, s.Aggregate) {
			return errors.New("Zusammenfassung der Spalte: " + strings.Join(ColumnAggregates, ", "))
		}
		if s.Rate || s.Equals != nil {
			return errors.New("Spalte: nur mit Schwellen, ohne Rate und ohne erwarteten Text")
		}
	}
	counting := s.Aggregate == "anzahl_gleich" || s.Aggregate == "anzahl_ungleich"
	if counting != (s.Compare != nil) {
		return errors.New("Vergleichswert nur und immer bei anzahl_gleich und anzahl_ungleich")
	}
	if s.Compare != nil && (*s.Compare < math.MinInt32 || *s.Compare > math.MaxInt32) {
		return errors.New("Vergleichswert: ganze Zahl im 32-Bit-Bereich")
	}
	if err := s.normalizeTextNumber(); err != nil {
		return err
	}
	if f := math.Abs(s.Factor); s.Factor != 0 && (math.IsNaN(f) || f < 1e-9 || f > 1e9) {
		return errors.New("Faktor: nicht 0, Betrag zwischen 0,000000001 und 1000000000")
	}
	if s.Factor == 1 {
		s.Factor = 0
	}
	s.Unit = strings.TrimSpace(s.Unit)
	if s.Unit != "" && !slices.Contains(Units, s.Unit) {
		return errors.New("Einheit: " + strings.Join(Units, ", "))
	}
	return s.normalizeValue()
}

// Units: Einheiten für eigene SNMP-Werte (feste Liste, nur Anzeige).
var Units = []string{"°C", "%", "W", "V", "A", "RPM", "MB", "GB", "s", "ms", "bit/s", "dBm"}

// TextNumberModes: Arten, eine Zahl aus einem Text zu lesen.
var TextNumberModes = []string{"erste", "nte", "nach"}

const (
	// MaxTextIndex: höchstens die so vielte Zahl im Text.
	MaxTextIndex = 16
	// MaxTextAfter: Länge des Texts, hinter dem die Zahl steht.
	MaxTextAfter = 40
)

func (s *Spec) normalizeTextNumber() error {
	s.TextNumber = strings.ToLower(strings.TrimSpace(s.TextNumber))
	switch s.TextNumber {
	case "":
		if s.TextIndex != 0 || s.TextAfter != "" {
			return errors.New("Zahl aus Text: Nummer und „nach Text“ nur zusammen mit der Art")
		}
		return nil
	case "erste":
		if s.TextIndex != 0 || s.TextAfter != "" {
			return errors.New("Zahl aus Text „erste“: ohne Nummer und ohne „nach Text“")
		}
	case "nte":
		if s.TextIndex < 1 || s.TextIndex > MaxTextIndex || s.TextAfter != "" {
			return fmt.Errorf("Zahl aus Text „nte“: Nummer 1 bis %d", MaxTextIndex)
		}
	case "nach":
		// Der Text vergleicht genau, auch mit Leerzeichen am Rand („10s: “).
		if s.TextIndex != 0 || s.TextAfter == "" || utf8.RuneCountInString(s.TextAfter) > MaxTextAfter || !utf8.ValidString(s.TextAfter) ||
			strings.ContainsFunc(s.TextAfter, unicode.IsControl) {
			return fmt.Errorf("Zahl aus Text „nach“: Text mit 1 bis %d Zeichen", MaxTextAfter)
		}
	default:
		return errors.New("Zahl aus Text: " + strings.Join(TextNumberModes, ", "))
	}
	if s.Aggregate != "" || s.Rate || s.Equals != nil {
		return errors.New("Zahl aus Text: nur mit Schwellen, nicht mit Spalte, Rate oder erwartetem Text")
	}
	return nil
}

// NumberFromText liest eine Zahl aus einem Text: die n-te (ab 1), oder, wenn
// after gesetzt ist, die erste hinter dem ersten Vorkommen von after. Zahlen
// sind Ziffernfolgen mit höchstens einem Punkt oder Komma als Dezimaltrenner;
// ein Minus direkt davor zählt als Vorzeichen, wenn davor kein Buchstabe und
// keine Ziffer steht („-5“, aber nicht „a-5“ oder „1-5“).
func NumberFromText(text string, n int, after string) (float64, bool) {
	if after != "" {
		i := strings.Index(text, after)
		if i < 0 {
			return 0, false
		}
		text, n = text[i+len(after):], 1
	}
	if n < 1 {
		return 0, false
	}
	b := []byte(text)
	digit := func(i int) bool { return i >= 0 && i < len(b) && b[i] >= '0' && b[i] <= '9' }
	for i := 0; i < len(b); i++ {
		if !digit(i) {
			continue
		}
		start := i
		for digit(i) {
			i++
		}
		if i < len(b) && (b[i] == '.' || b[i] == ',') && digit(i+1) {
			i++
			for digit(i) {
				i++
			}
		}
		n--
		if n > 0 {
			i--
			continue
		}
		num := strings.Replace(string(b[start:i]), ",", ".", 1)
		if len(num) > 40 {
			return 0, false
		}
		if start > 0 && b[start-1] == '-' {
			vor := rune(' ')
			if start > 1 {
				vor, _ = utf8.DecodeLastRune(b[:start-1])
			}
			if !unicode.IsLetter(vor) && !unicode.IsDigit(vor) {
				num = "-" + num
			}
		}
		f, err := strconv.ParseFloat(num, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func (s *Spec) normalizeNTP() error {
	if s.Port == 0 {
		s.Port = 123
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("Port: 1 bis 65535")
	}
	if s.OffsetWarnMS == 0 {
		s.OffsetWarnMS = 100
	}
	if s.OffsetCritMS == 0 {
		s.OffsetCritMS = 1000
	}
	if s.OffsetWarnMS < 0 || s.OffsetCritMS > 3600000 || s.OffsetWarnMS >= s.OffsetCritMS {
		return errors.New("Abweichung: Warnung kleiner als kritisch, höchstens 3600000 ms")
	}
	return nil
}

// normalizeValue: Schwellen oder erwarteter Wert (HTTP-JSON, SNMP-OID).
func (s *Spec) normalizeValue() error {
	numeric := s.WarnAbove != nil || s.CritAbove != nil || s.WarnBelow != nil || s.CritBelow != nil
	if numeric && s.Equals != nil {
		return errors.New("Entweder Schwellen oder ein erwarteter Wert, nicht beides")
	}
	if s.WarnAbove != nil && s.CritAbove != nil && *s.WarnAbove >= *s.CritAbove {
		return errors.New("Schwellen „über“: Warnung kleiner als kritisch")
	}
	if s.WarnBelow != nil && s.CritBelow != nil && *s.WarnBelow <= *s.CritBelow {
		return errors.New("Schwellen „unter“: Warnung größer als kritisch")
	}
	if s.Equals != nil && (utf8.RuneCountInString(*s.Equals) > maxEquals || hasControl(*s.Equals)) {
		return fmt.Errorf("Erwarteter Wert: höchstens %d Zeichen, keine Steuerzeichen", maxEquals)
	}
	return nil
}

func (s *Spec) normalizeAgent(kind string) error {
	switch kind {
	case "dienst":
		if !serviceName.MatchString(s.Name) {
			return errors.New("Dienst: Name der systemd-Unit oder des Windows-Dienstes (Buchstaben, Ziffern, Leerzeichen, : _ . @ $ ( ) -)")
		}
	case "prozess":
		if !processName.MatchString(s.Name) {
			return errors.New("Prozess: Name des Programms, z. B. nginx oder nginx.exe")
		}
		if s.Min == 0 {
			s.Min = 1
		}
		if s.Min < 0 || s.Min > 10000 || s.Max < 0 || s.Max > 10000 || (s.Max > 0 && s.Max < s.Min) {
			return errors.New("Anzahl: mindestens 0 bis 10000, höchstens nicht kleiner als mindestens (0 = egal)")
		}
	case "docker":
		if !containerName.MatchString(s.Name) {
			return errors.New("Container: Name wie bei docker ps (Buchstaben, Ziffern, _ . -)")
		}
	case "hyperv":
		if !vmName.MatchString(s.Name) || strings.HasSuffix(s.Name, " ") {
			return errors.New("VM: Name wie im Hyper-V-Manager (höchstens 100 Zeichen; Buchstaben, Ziffern, Leerzeichen, . _ ( ) + , : @ # & ' -)")
		}
	case "leistungsindikator":
		return s.normalizePerf()
	case "autodienste":
		return s.normalizeExceptions()
	case "datei":
		p, err := CleanPath(s.Path)
		if err != nil {
			return err
		}
		s.Path = p
		if s.WarnHours < 0 || s.CritHours < 0 || s.WarnHours > 24*366 || s.CritHours > 24*366 {
			return errors.New("Alter: 0 bis 8784 Stunden")
		}
		if s.WarnHours > 0 && s.CritHours > 0 && s.WarnHours >= s.CritHours {
			return errors.New("Alter: Warnung kleiner als kritisch")
		}
		if s.WarnHours == 0 && s.CritHours == 0 && s.MinBytes == 0 {
			return errors.New("Datei: Alter oder Mindestgröße angeben")
		}
		if s.MinBytes < 0 || s.MinBytes > 1<<50 {
			return errors.New("Mindestgröße: 0 bis 1 PiB")
		}
		if s.Folder && s.MinBytes != 0 {
			return errors.New("Mindestgröße gilt nur für Dateien, nicht für Ordner")
		}
	}
	return nil
}

// ColumnAggregates: Zusammenfassung einer SNMP-Spalte über alle Zeilen.
var ColumnAggregates = []string{"minimum", "maximum", "summe", "anzahl", "anzahl_gleich", "anzahl_ungleich"}

// PerfAggregates: Zusammenfassung über alle Instanzen (Instanz „*“).
var PerfAggregates = []string{"summe", "minimum", "maximum", "anzahl"}

// ValidPerfName: Name eines Leistungsindikator-Objekts oder einer Instanz
// (ohne Platzhalter und Klammern).
func ValidPerfName(n string) bool { return perfName.MatchString(n) && !strings.HasSuffix(n, " ") }

// ValidPerfCounter: Name eines Indikators (ohne Platzhalter, Klammern erlaubt).
func ValidPerfCounter(n string) bool {
	return perfCounterName.MatchString(n) && !strings.HasSuffix(n, " ")
}

func (s *Spec) normalizePerf() error {
	s.Object, s.Counter = strings.TrimSpace(s.Object), strings.TrimSpace(s.Counter)
	s.Instance, s.Relative = strings.TrimSpace(s.Instance), strings.TrimSpace(s.Relative)
	s.Aggregate = strings.ToLower(strings.TrimSpace(s.Aggregate))
	if !ValidPerfName(s.Object) {
		return errors.New("Objekt: Name wie in der Leistungsüberwachung, z. B. SwyxServer (höchstens 128 Zeichen, ohne \\ ( ) * ?)")
	}
	if !ValidPerfCounter(s.Counter) {
		return errors.New("Indikator: Name wie in der Leistungsüberwachung, z. B. Active Calls (ohne \\ * ?)")
	}
	if s.Instance != "" && s.Instance != "*" && !ValidPerfName(s.Instance) {
		return errors.New("Instanz: Name, „*“ für alle oder leer (ohne \\ ( ) ?)")
	}
	if s.Relative != "" && (!ValidPerfCounter(s.Relative) || strings.EqualFold(s.Relative, s.Counter)) {
		return errors.New("Bezug: ein anderer Indikator desselben Objekts, z. B. Licensed users")
	}
	switch {
	case s.Instance == "*" && s.Aggregate == "":
		s.Aggregate = "summe"
	case s.Instance != "*" && s.Aggregate != "":
		return errors.New("Zusammenfassung nur mit Instanz „*“ (alle)")
	}
	if s.Aggregate != "" && !slices.Contains(PerfAggregates, s.Aggregate) {
		return errors.New("Zusammenfassung: summe, minimum, maximum oder anzahl")
	}
	if s.Relative != "" && s.Aggregate != "" && s.Aggregate != "summe" {
		return errors.New("Bezug nur für eine Instanz oder mit Zusammenfassung summe")
	}
	return s.normalizeValue()
}

// PerfPath: Pfad für die englischen Namen (PdhAddEnglishCounter).
func PerfPath(object, instance, counter string) string {
	if instance == "" {
		return `\` + object + `\` + counter
	}
	return `\` + object + "(" + instance + `)\` + counter
}

// JudgeNumber bewertet einen Zahlenwert mit den Schwellen des Sensors.
func JudgeNumber(s Spec, x float64, metric string) Result {
	return judge(s, x, metric, "Wert", germanNum)
}

// JudgeSeconds bewertet eine Dauer in Sekunden (z. B. „System Up Time“) und
// nennt Schwellen in Minuten, Stunden und Tagen statt in Sekunden (0.99.2).
func JudgeSeconds(s Spec, x float64, metric string) Result {
	return judge(s, x, metric, "Laufzeit", func(v float64) string { return DurationText(v) })
}

// DurationText: Sekunden als „45 Min.“, „26 Std.“, „3 Tage 4 Std.“.
func DurationText(sec float64) string {
	if math.IsNaN(sec) || sec < 0 {
		return germanNum(sec) + " s"
	}
	m := int64(sec / 60)
	switch {
	case sec < 60:
		return germanNum(math.Round(sec)) + " s"
	case m < 120:
		return fmt.Sprintf("%d Min.", m)
	case m < 48*60:
		if m%60 == 0 {
			return fmt.Sprintf("%d Std.", m/60)
		}
		return fmt.Sprintf("%d Std. %d Min.", m/60, m%60)
	}
	d, h := m/(24*60), (m%(24*60))/60
	tage := "Tage"
	if d == 1 {
		tage = "Tag"
	}
	if h == 0 {
		return fmt.Sprintf("%d %s", d, tage)
	}
	return fmt.Sprintf("%d %s %d Std.", d, tage, h)
}

func judge(s Spec, x float64, metric, label string, num func(float64) string) Result {
	switch {
	case s.CritAbove != nil && x > *s.CritAbove:
		return Result{Status: Crit, Message: label + " über " + num(*s.CritAbove) + " (kritisch)", Metric: metric}
	case s.CritBelow != nil && x < *s.CritBelow:
		return Result{Status: Crit, Message: label + " unter " + num(*s.CritBelow) + " (kritisch)", Metric: metric}
	case s.WarnAbove != nil && x > *s.WarnAbove:
		return Result{Status: Warn, Message: label + " über " + num(*s.WarnAbove) + " (Warnung)", Metric: metric}
	case s.WarnBelow != nil && x < *s.WarnBelow:
		return Result{Status: Warn, Message: label + " unter " + num(*s.WarnBelow) + " (Warnung)", Metric: metric}
	}
	if s.WarnAbove == nil && s.CritAbove == nil && s.WarnBelow == nil && s.CritBelow == nil {
		return Result{Status: OK, Message: "Wert gelesen", Metric: metric}
	}
	return Result{Status: OK, Message: "Wert im Rahmen", Metric: metric}
}

// GermanNumber: Zahl mit Komma, höchstens zwei Nachkommastellen.
func GermanNumber(v float64) string {
	return germanNum(math.Round(v*100) / 100)
}

// CleanPath prüft einen absoluten Pfad (Linux „/…“ oder Windows „C:\…“) ohne
// Zentrale und Agent vom Betriebssystem abhängig zu machen: keine
// Steuerzeichen, keine Teile „.“ oder „..“, nichts doppelt. Die Prüfung, ob
// der Pfad unter einem freigegebenen Ordner liegt, macht der Agent selbst.
func CleanPath(p string) (string, error) {
	if p == "" || utf8.RuneCountInString(p) > maxPathLen || hasControl(p) || !utf8.ValidString(p) {
		return "", fmt.Errorf("Pfad: absolut, höchstens %d Zeichen", maxPathLen)
	}
	var parts []string
	switch {
	case strings.HasPrefix(p, "/"):
		if path.Clean(p) != p {
			return "", errors.New("Pfad: ohne „.“, „..“, doppelte oder abschließende „/“")
		}
		return p, nil
	case winAbs.MatchString(p):
		if strings.Contains(p, "/") {
			return "", errors.New(`Pfad: unter Windows nur „\“ als Trenner`)
		}
		parts = strings.Split(p[3:], `\`)
	default:
		return "", errors.New(`Pfad: absolut angeben, z. B. /var/backups/db.dump oder D:\Backup`)
	}
	if len(parts) == 1 && parts[0] == "" {
		return p, nil // Laufwerk selbst
	}
	for _, x := range parts {
		if x == "" || x == "." || x == ".." || strings.ContainsAny(x, `:*?"<>|`) {
			return "", errors.New(`Pfad: ohne „.“, „..“, doppelte oder abschließende „\“ und ohne : * ? " < > |`)
		}
	}
	return p, nil
}

// --- Vorlagen ----------------------------------------------------------------

// Placeholder steht in Vorlagen für die Adresse des Geräts.
const Placeholder = "{adresse}"

// placeholderHost: gültiger Name, mit dem eine Vorlage geprüft wird.
const placeholderHost = "adresse.invalid"

// UsesPlaceholder: Das Ziel der Vorlage braucht die Adresse eines Geräts.
func UsesPlaceholder(raw []byte) bool { return bytes.Contains(raw, []byte(Placeholder)) }

// ParseTemplate prüft das Ziel einer Vorlage. {adresse} ist in Host, URL und
// DNS-Namen erlaubt; geprüft wird mit einem Platzhalternamen. Gespeichert
// wird das Ziel mit {adresse}, ohne Standardwerte (die setzt das Anlegen).
func ParseTemplate(kind string, raw []byte) ([]byte, error) {
	var s Spec
	if len(raw) > 32<<10 {
		return nil, errors.New("Ziel zu groß")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("Ziel ist kein gültiges JSON für einen Sensor: %v", err)
	}
	if dec.More() {
		return nil, errors.New("Ziel enthält mehr als ein JSON-Objekt")
	}
	stored, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	for _, f := range []string{s.Connect, s.Server, s.Path, s.JSONPath, s.Contains} {
		if strings.Contains(f, Placeholder) {
			return nil, errors.New("{adresse} ist nur in Host, URL und DNS-Namen erlaubt")
		}
	}
	if _, err := Parse(kind, Substitute(stored, placeholderHost)); err != nil {
		return nil, err
	}
	return stored, nil
}

// Substitute setzt die Adresse eines Geräts für {adresse} ein. Die Adresse
// ist geprüft (Name oder IP ohne Zone); als JSON-Text ersetzt, damit keine
// Anführungszeichen das Ziel aufbrechen können.
func Substitute(raw []byte, addr string) []byte {
	if !validHost(addr) {
		return raw
	}
	host := addr
	if a, err := netip.ParseAddr(addr); err == nil && a.Is6() {
		// in einer URL in Klammern, als Host ohne
		raw = bytes.ReplaceAll(raw, []byte("://"+Placeholder), []byte("://["+addr+"]"))
	}
	return bytes.ReplaceAll(raw, []byte(Placeholder), []byte(host))
}

// MaxExceptions: so viele Ausnahmen hat ein Sensor „automatische Dienste“.
const MaxExceptions = 100

// normalizeExceptions prüft die Ausnahmen (Dienst- oder Anzeigename, am Ende
// optional „*“) und entfernt Doppelte ohne Rücksicht auf Groß/Klein.
func (s *Spec) normalizeExceptions() error {
	if len(s.Exceptions) > MaxExceptions {
		return fmt.Errorf("Ausnahmen: höchstens %d", MaxExceptions)
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range s.Exceptions {
		e = strings.TrimSpace(e)
		if !serviceName.MatchString(strings.TrimSuffix(e, "*")) {
			return errors.New("Ausnahme: Name eines Windows-Dienstes (Buchstaben, Ziffern, Leerzeichen, : _ . @ $ ( ) -), am Ende optional *")
		}
		if k := strings.ToLower(e); !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	s.Exceptions = out
	return nil
}

// ExceptionMatch meldet, ob ein Dienst unter eine Ausnahme fällt.
func ExceptionMatch(exceptions []string, name, display string) bool {
	n, d := strings.ToLower(name), strings.ToLower(display)
	for _, e := range exceptions {
		e = strings.ToLower(e)
		if p, ok := strings.CutSuffix(e, "*"); ok {
			if strings.HasPrefix(n, p) || (d != "" && strings.HasPrefix(d, p)) {
				return true
			}
		} else if n == e || (d != "" && d == e) {
			return true
		}
	}
	return false
}
