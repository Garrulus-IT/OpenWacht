// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Felder des Sensor-Dialogs je Typ. Die Schlüssel sind die JSON-Namen im Ziel
// eines Checks (internal/checks.Spec); ein Test prüft, dass jeder Typ genau
// die Felder anbietet, die die Zentrale annimmt. Geprüft wird alles Übrige
// (Bereiche, Pflichtfelder, Netze) von der Zentrale, deren Meldung der Dialog
// zeigt.

// FeldArt bestimmt Eingabe und Umwandlung.
type FeldArt int

const (
	FeldText       FeldArt = iota
	FeldGanzzahl           // int
	FeldZahl               // float, Komma oder Punkt
	FeldJaNein             // bool
	FeldListe              // Strings, durch Komma getrennt
	FeldZahlListe          // Ganzzahlen, durch Komma getrennt
	FeldMehrzeilig         // langer Text (PEM)
	FeldAuswahl            // einer aus Optionen ("" = keine Angabe)
	FeldMehrfach           // mehrere aus Optionen (Werte durch Komma getrennt; nur in der App)
)

// Feld: eine Zeile im Dialog.
type Feld struct {
	Schluessel   string
	Beschriftung string
	Art          FeldArt
	Optionen     []string // FeldAuswahl
	Hinweis      string   // grau unter dem Feld bzw. als Platzhalter
	Adresse      bool     // beim Anlegen mit der Adresse des Geräts vorbelegt
}

// Typ: ein Sensortyp für die Auswahl im Dialog.
type Typ struct {
	Schluessel string
	Name       string
	AmAgent    bool
	Felder     []Feld
}

var (
	fTimeout = Feld{Schluessel: "timeout_s", Beschriftung: "Zeitlimit (Sekunden)", Art: FeldGanzzahl, Hinweis: "leer = Standard"}
	fCA      = Feld{Schluessel: "ca_pem", Beschriftung: "Eigene Root-CA (PEM)", Art: FeldMehrzeilig, Hinweis: "nur für ein Zertifikat einer eigenen CA"}
	fHost    = Feld{Schluessel: "host", Beschriftung: "Adresse", Art: FeldText, Hinweis: "Name oder IP", Adresse: true}
	fPort    = Feld{Schluessel: "port", Beschriftung: "Port", Art: FeldGanzzahl}
	fStatus  = Feld{Schluessel: "erwarte_status", Beschriftung: "Erwartete Statuscodes", Art: FeldZahlListe, Hinweis: "z. B. 200, 204; leer = 200–399"}
	fGrenzen = []Feld{
		{Schluessel: "warnung_ueber", Beschriftung: "Warnung über", Art: FeldZahl},
		{Schluessel: "kritisch_ueber", Beschriftung: "Kritisch über", Art: FeldZahl},
		{Schluessel: "warnung_unter", Beschriftung: "Warnung unter", Art: FeldZahl},
		{Schluessel: "kritisch_unter", Beschriftung: "Kritisch unter", Art: FeldZahl},
	}
	fGleich = Feld{Schluessel: "gleich", Beschriftung: "Erwarteter Wert (gleich)", Art: FeldText, Hinweis: "statt Grenzen"}
)

func felder(f ...any) []Feld {
	var out []Feld
	for _, x := range f {
		switch v := x.(type) {
		case Feld:
			out = append(out, v)
		case []Feld:
			out = append(out, v...)
		}
	}
	return out
}

// Typen in der Reihenfolge der Auswahl: erst die der Zentrale, dann die des Agents.
var Typen = []Typ{
	{Schluessel: "ping", Name: "Ping", Felder: felder(fHost,
		Feld{Schluessel: "anzahl", Beschriftung: "Pakete", Art: FeldGanzzahl, Hinweis: "leer = 3"},
		Feld{Schluessel: "verlust_warnung", Beschriftung: "Verlust Warnung ab (%)", Art: FeldZahl},
		Feld{Schluessel: "verlust_kritisch", Beschriftung: "Verlust kritisch ab (%)", Art: FeldZahl},
		Feld{Schluessel: "antwort_warnung_ms", Beschriftung: "Antwortzeit Warnung ab (ms)", Art: FeldZahl},
		Feld{Schluessel: "antwort_kritisch_ms", Beschriftung: "Antwortzeit kritisch ab (ms)", Art: FeldZahl},
		fTimeout)},
	{Schluessel: "tcp", Name: "TCP-Port", Felder: felder(fHost, fPort, fTimeout)},
	{Schluessel: "http", Name: "HTTP(S)", Felder: felder(
		Feld{Schluessel: "url", Beschriftung: "URL", Art: FeldText, Hinweis: "https://…", Adresse: true},
		fStatus,
		Feld{Schluessel: "enthaelt", Beschriftung: "Antwort enthält", Art: FeldText},
		fTimeout, fCA)},
	{Schluessel: "tls", Name: "TLS-Zertifikat", Felder: felder(fHost,
		Feld{Schluessel: "port", Beschriftung: "Port", Art: FeldGanzzahl, Hinweis: "leer = 443"},
		Feld{Schluessel: "verbinde", Beschriftung: "Verbinden mit", Art: FeldText, Hinweis: "andere Adresse, Name per SNI; leer = wie oben"},
		Feld{Schluessel: "warnung_tage", Beschriftung: "Warnung ab (Tage vor Ablauf)", Art: FeldZahl},
		Feld{Schluessel: "kritisch_tage", Beschriftung: "Kritisch ab (Tage vor Ablauf)", Art: FeldZahl},
		fTimeout, fCA)},
	{Schluessel: "dns", Name: "DNS-Auflösung", Felder: felder(
		Feld{Schluessel: "name", Beschriftung: "DNS-Name", Art: FeldText, Adresse: true},
		Feld{Schluessel: "server", Beschriftung: "DNS-Server", Art: FeldText, Hinweis: "IP; leer = Resolver der Zentrale"},
		Feld{Schluessel: "eintrag", Beschriftung: "Eintrag", Art: FeldAuswahl, Optionen: []string{"", "A", "AAAA"}, Hinweis: "leer = beide"},
		Feld{Schluessel: "erwartet", Beschriftung: "Erwartete Adressen", Art: FeldListe, Hinweis: "durch Komma getrennt; leer = beliebig"},
		fTimeout)},
	{Schluessel: "http_json", Name: "HTTP-JSON-Wert", Felder: felder(
		Feld{Schluessel: "url", Beschriftung: "URL", Art: FeldText, Hinweis: "https://…", Adresse: true},
		fStatus,
		Feld{Schluessel: "json_pfad", Beschriftung: "JSON-Pfad", Art: FeldText, Hinweis: "z. B. daten.wert"},
		fGrenzen, fGleich, fTimeout, fCA)},
	{Schluessel: "tcp_banner", Name: "TCP-Banner", Felder: felder(fHost, fPort,
		Feld{Schluessel: "tls", Beschriftung: "Mit TLS verbinden", Art: FeldJaNein},
		Feld{Schluessel: "enthaelt", Beschriftung: "Begrüßung enthält", Art: FeldText},
		fTimeout, fCA)},
	{Schluessel: "ntp", Name: "Zeitserver (NTP)", Felder: felder(fHost,
		Feld{Schluessel: "port", Beschriftung: "Port", Art: FeldGanzzahl, Hinweis: "leer = 123"},
		Feld{Schluessel: "abweichung_warnung_ms", Beschriftung: "Abweichung Warnung ab (ms)", Art: FeldZahl},
		Feld{Schluessel: "abweichung_kritisch_ms", Beschriftung: "Abweichung kritisch ab (ms)", Art: FeldZahl},
		fTimeout)},
	{Schluessel: "snmp_oid", Name: "SNMP eigene OID", Felder: felder(
		Feld{Schluessel: "oid", Beschriftung: "OID", Art: FeldText, Hinweis: "z. B. 1.3.6.1.2.1.1.3.0; braucht die SNMP-Abfrage des Geräts"},
		Feld{Schluessel: "rate", Beschriftung: "Als Rate je Sekunde (Zähler)", Art: FeldJaNein},
		Feld{Schluessel: "zusammenfassung", Beschriftung: "Tabellenspalte zusammenfassen", Art: FeldAuswahl,
			Optionen: []string{"", "minimum", "maximum", "summe", "anzahl", "anzahl_gleich", "anzahl_ungleich"}, Hinweis: "leer = einzelner Wert"},
		Feld{Schluessel: "vergleichswert", Beschriftung: "Vergleichswert (Zeilen gleich/ungleich)", Art: FeldGanzzahl},
		// 1.0.8: Zahl aus einem Text des Geräts, Faktor und Einheit
		Feld{Schluessel: "zahl_aus_text", Beschriftung: "Zahl aus Text", Art: FeldAuswahl, Optionen: []string{"", "erste", "nte", "nach"},
			Hinweis: "leer = nein; erste Zahl, n-te Zahl oder Zahl nach einem Text (z. B. „1500RPM“ → 1500)"},
		Feld{Schluessel: "zahl_nr", Beschriftung: "Die wievielte Zahl (bei „nte“)", Art: FeldGanzzahl, Hinweis: "1 bis 16"},
		Feld{Schluessel: "zahl_nach", Beschriftung: "Text vor der Zahl (bei „nach“)", Art: FeldText, Hinweis: "z. B. 10s:"},
		Feld{Schluessel: "faktor", Beschriftung: "Faktor", Art: FeldZahl, Hinweis: "leer = 1, z. B. 0,1"},
		Feld{Schluessel: "einheit", Beschriftung: "Einheit", Art: FeldAuswahl,
			Optionen: []string{"", "°C", "%", "W", "V", "A", "RPM", "MB", "GB", "s", "ms", "bit/s", "dBm"}},
		fGrenzen, fGleich)},
	{Schluessel: "dienst", Name: "Dienst läuft", AmAgent: true, Felder: felder(
		Feld{Schluessel: "name", Beschriftung: "Dienstname", Art: FeldText, Hinweis: "Windows-Dienst oder systemd-Unit"})},
	{Schluessel: "prozess", Name: "Prozess läuft", AmAgent: true, Felder: felder(
		Feld{Schluessel: "name", Beschriftung: "Prozessname", Art: FeldText},
		Feld{Schluessel: "mindestens", Beschriftung: "Mindestens (Anzahl)", Art: FeldGanzzahl, Hinweis: "leer = 1"},
		Feld{Schluessel: "hoechstens", Beschriftung: "Höchstens (Anzahl)", Art: FeldGanzzahl})},
	{Schluessel: "datei", Name: "Datei- oder Ordneralter", AmAgent: true, Felder: felder(
		Feld{Schluessel: "pfad", Beschriftung: "Pfad", Art: FeldText},
		Feld{Schluessel: "ordner", Beschriftung: "Ist ein Ordner (neueste Datei zählt)", Art: FeldJaNein},
		Feld{Schluessel: "warnung_stunden", Beschriftung: "Warnung älter als (Stunden)", Art: FeldZahl},
		Feld{Schluessel: "kritisch_stunden", Beschriftung: "Kritisch älter als (Stunden)", Art: FeldZahl},
		Feld{Schluessel: "mindestgroesse", Beschriftung: "Mindestgröße (Bytes)", Art: FeldGanzzahl})},
	{Schluessel: "docker", Name: "Docker-Container läuft", AmAgent: true, Felder: felder(
		Feld{Schluessel: "name", Beschriftung: "Container", Art: FeldText})},
	{Schluessel: "hyperv", Name: "Hyper-V-VM läuft", AmAgent: true, Felder: felder(
		Feld{Schluessel: "name", Beschriftung: "VM", Art: FeldText})},
	{Schluessel: "leistungsindikator", Name: "Windows-Leistungsindikator", AmAgent: true, Felder: felder(
		Feld{Schluessel: "objekt", Beschriftung: "Objekt", Art: FeldText, Hinweis: "z. B. Processor"},
		Feld{Schluessel: "indikator", Beschriftung: "Indikator", Art: FeldText, Hinweis: "z. B. % Processor Time"},
		Feld{Schluessel: "instanz", Beschriftung: "Instanz", Art: FeldText, Hinweis: "z. B. _Total; * = alle"},
		Feld{Schluessel: "zusammenfassung", Beschriftung: "Instanzen zusammenfassen", Art: FeldAuswahl,
			Optionen: []string{"", "summe", "minimum", "maximum", "anzahl"}, Hinweis: "nur bei Instanz *"},
		Feld{Schluessel: "bezug", Beschriftung: "Im Verhältnis zu Indikator", Art: FeldText, Hinweis: "Ergebnis in Prozent"},
		fGrenzen)},
	{Schluessel: "autodienste", Name: "Automatische Windows-Dienste laufen", AmAgent: true, Felder: felder(
		Feld{Schluessel: "ausnahmen", Beschriftung: "Ausnahmen", Art: FeldListe, Hinweis: "Dienstnamen, durch Komma getrennt"})},
}

// TypNach liefert den Typ zum Schlüssel.
func TypNach(schluessel string) (Typ, bool) {
	for _, t := range Typen {
		if t.Schluessel == schluessel {
			return t, true
		}
	}
	return Typ{}, false
}

// TypName: Anzeigename eines Typs (unbekannt: der Schlüssel).
func TypName(schluessel string) string {
	if t, ok := TypNach(schluessel); ok {
		return t.Name
	}
	return schluessel
}

// WerteAusZiel: die Felder eines gespeicherten Ziels als Text für den Dialog.
func WerteAusZiel(t Typ, ziel json.RawMessage) map[string]string {
	out := map[string]string{}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(ziel))
	d.UseNumber()
	if len(ziel) == 0 || d.Decode(&m) != nil {
		return out
	}
	for _, f := range t.Felder {
		v, ok := m[f.Schluessel]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case string:
			out[f.Schluessel] = x
		case json.Number:
			out[f.Schluessel] = strings.Replace(x.String(), ".", ",", 1)
		case bool:
			if x {
				out[f.Schluessel] = "ja"
			}
		case []any:
			var teile []string
			for _, e := range x {
				teile = append(teile, strings.Replace(fmt.Sprint(e), ".", ",", 1))
			}
			out[f.Schluessel] = strings.Join(teile, ", ")
		}
	}
	return out
}

// ZielAusWerten baut aus den Eingaben das Ziel. Leere Felder fehlen im Ziel
// (die Zentrale setzt dann ihren Standard). Fehler nennen das Feld.
func ZielAusWerten(t Typ, werte map[string]string) (json.RawMessage, error) {
	m := map[string]any{}
	for _, f := range t.Felder {
		v := strings.TrimSpace(werte[f.Schluessel])
		if f.Art == FeldMehrzeilig {
			v = strings.TrimSpace(strings.ReplaceAll(werte[f.Schluessel], "\r\n", "\n"))
		}
		if v == "" {
			continue
		}
		switch f.Art {
		case FeldText, FeldMehrzeilig, FeldAuswahl:
			m[f.Schluessel] = v
		case FeldGanzzahl:
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: bitte eine ganze Zahl", f.Beschriftung)
			}
			m[f.Schluessel] = n
		case FeldZahl:
			n, err := strconv.ParseFloat(strings.Replace(v, ",", ".", 1), 64)
			if err != nil {
				return nil, fmt.Errorf("%s: bitte eine Zahl", f.Beschriftung)
			}
			m[f.Schluessel] = n
		case FeldJaNein:
			if v == "ja" {
				m[f.Schluessel] = true
			}
		case FeldListe:
			var l []string
			for _, e := range strings.Split(v, ",") {
				if e = strings.TrimSpace(e); e != "" {
					l = append(l, e)
				}
			}
			if len(l) > 0 {
				m[f.Schluessel] = l
			}
		case FeldZahlListe:
			var l []int
			for _, e := range strings.Split(v, ",") {
				if e = strings.TrimSpace(e); e == "" {
					continue
				}
				n, err := strconv.Atoi(e)
				if err != nil {
					return nil, fmt.Errorf("%s: bitte ganze Zahlen, durch Komma getrennt", f.Beschriftung)
				}
				l = append(l, n)
			}
			if len(l) > 0 {
				m[f.Schluessel] = l
			}
		}
	}
	b, err := json.Marshal(m)
	return b, err
}

// Intervalle zur Auswahl im Dialog (Sekunden, Text).
var Intervalle = []struct {
	Sekunden int
	Text     string
}{
	{30, "30 Sekunden"}, {60, "1 Minute"}, {120, "2 Minuten"}, {300, "5 Minuten"}, {600, "10 Minuten"},
	{900, "15 Minuten"}, {1800, "30 Minuten"}, {3600, "1 Stunde"}, {21600, "6 Stunden"}, {86400, "1 Tag"},
}

// StandardFehlversuche: Fehlschläge in Folge bis zum Alarm, wenn ein Sensor
// nichts Eigenes hat (Standard der Zentrale seit 1.0.6).
const StandardFehlversuche = 3

// FehlversucheAuswahl: Texte und Werte für „Alarm nach“ (0 = Standard).
func FehlversucheAuswahl() (texte, werte []string) {
	texte = append(texte, "Standard ("+strconv.Itoa(StandardFehlversuche)+" Fehlschläge)")
	werte = append(werte, "0")
	for n := 1; n <= 10; n++ {
		texte, werte = append(texte, FehlversucheText(n)), append(werte, strconv.Itoa(n))
	}
	return texte, werte
}

// FehlversucheText: „1 Fehlschlag (sofort)“, „5 Fehlschlägen in Folge“.
func FehlversucheText(n int) string {
	if n == 1 {
		return "1 Fehlschlag (sofort)"
	}
	return strconv.Itoa(n) + " Fehlschlägen in Folge"
}

// IntervallText: „5 Minuten“ bzw. „450 s“ für Werte außerhalb der Liste.
func IntervallText(s int) string {
	for _, i := range Intervalle {
		if i.Sekunden == s {
			return i.Text
		}
	}
	return strconv.Itoa(s) + " s"
}

// ZielText: kurze Zusammenfassung des Ziels für Liste und Details.
func ZielText(typ string, ziel json.RawMessage) string {
	t, ok := TypNach(typ)
	if !ok {
		return string(ziel)
	}
	w := WerteAusZiel(t, ziel)
	var teile []string
	for _, f := range t.Felder {
		v := w[f.Schluessel]
		if v == "" || f.Art == FeldMehrzeilig {
			continue
		}
		if f.Art == FeldJaNein {
			v = "ja"
		}
		teile = append(teile, f.Beschriftung+": "+v)
	}
	return strings.Join(teile, " · ")
}
