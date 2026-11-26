// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Farben der Desktop-App aus den Design-Tokens (web/src/tokens.css, Namen
// nach docs/design/tokens.css). Ein Test vergleicht jeden Wert mit der Datei,
// damit App und Weboberfläche nie auseinanderlaufen.

// RGB: Farbe als 0xRRGGBB.
type RGB uint32

// Farben: die Tokens, die die App braucht (Name im Tag).
type Farben struct {
	Marke       RGB `token:"marke"`
	MarkeTief   RGB `token:"marke-tief"`
	MarkeHauch  RGB `token:"marke-hauch"`
	AufMarke    RGB `token:"auf-marke"`
	Nacht       RGB `token:"nacht"`
	NachtTinte  RGB `token:"nacht-tinte"`
	NachtLeise  RGB `token:"nacht-leise"`
	Grund       RGB `token:"grund"`
	Flaeche     RGB `token:"flaeche"`
	Zart        RGB `token:"zart"`
	Tinte       RGB `token:"tinte"`
	Leise       RGB `token:"leise"`
	Linie       RGB `token:"linie"`
	LinieZart   RGB `token:"linie-zart"`
	OK          RGB `token:"ok"`
	OKHauch     RGB `token:"ok-hauch"`
	TextOK      RGB `token:"text-ok"`
	Warn        RGB `token:"warn"`
	WarnHauch   RGB `token:"warn-hauch"`
	TextWarn    RGB `token:"text-warn"`
	AufWarn     RGB `token:"auf-warn"`
	Krit        RGB `token:"krit"`
	KritHauch   RGB `token:"krit-hauch"`
	TextKrit    RGB `token:"text-krit"`
	AufKrit     RGB `token:"auf-krit"`
	Unbek       RGB `token:"unbek"`
	UnbekHauch  RGB `token:"unbek-hauch"`
	Wartung     RGB `token:"wartung"`
	WartHauch   RGB `token:"wartung-hauch"`
	TextWartung RGB `token:"text-wartung"`
	AufWartung  RGB `token:"auf-wartung"`
}

// Hell und Dunkel: die beiden Spalten der Tokens.
var (
	Hell = Farben{
		Marke: 0x0b6a8a, MarkeTief: 0x0a4f68, MarkeHauch: 0xdcedf3, AufMarke: 0xffffff,
		Nacht: 0x102238, NachtTinte: 0xe4edf6, NachtLeise: 0x8ea3ba,
		Grund: 0xeef2f6, Flaeche: 0xffffff, Zart: 0xf5f8fa, Tinte: 0x14202e, Leise: 0x526172, Linie: 0xc9d3de, LinieZart: 0xe1e7ee,
		OK: 0x2c7a57, OKHauch: 0xe1f1e9, TextOK: 0x1f6446,
		Warn: 0xb07c12, WarnHauch: 0xf8efd9, TextWarn: 0x7d5600, AufWarn: 0x0a121c,
		Krit: 0xb3362f, KritHauch: 0xf7e2e0, TextKrit: 0x9c2a24, AufKrit: 0xffffff,
		Unbek: 0x7b8590, UnbekHauch: 0xeceef1,
		Wartung: 0x6b4f8f, WartHauch: 0xece6f4, TextWartung: 0x5b3f7f, AufWartung: 0xffffff,
	}
	Dunkel = Farben{
		Marke: 0x45c3e6, MarkeTief: 0x86d9f0, MarkeHauch: 0x123447, AufMarke: 0x04161e,
		Nacht: 0x060c14, NachtTinte: 0xdfe8f2, NachtLeise: 0x7d92a9,
		Grund: 0x0a121c, Flaeche: 0x111c29, Zart: 0x172435, Tinte: 0xdfe8f2, Leise: 0x94a6ba, Linie: 0x2a3a4d, LinieZart: 0x1d2b3b,
		OK: 0x5cb88b, OKHauch: 0x173126, TextOK: 0x7fd0a6,
		Warn: 0xdba843, WarnHauch: 0x33291a, TextWarn: 0xe6b85c, AufWarn: 0x1a1406,
		Krit: 0xe8685d, KritHauch: 0x3a201e, TextKrit: 0xf08a80, AufKrit: 0x1a0b0a,
		Unbek: 0x8a95a1, UnbekHauch: 0x252b32,
		Wartung: 0xb49ad8, WartHauch: 0x2c2440, TextWartung: 0xcbb7ea, AufWartung: 0x1a1226,
	}
)

// Form einer Zustandsanzeige (docs/design/README.md §6).
type Form int

const (
	FormKreis        Form = iota // OK
	FormDreieck                  // Warnung
	FormAchteck                  // kritisch
	FormAchteckHaken             // bestätigt
	FormQuadrat                  // unbekannt (gestrichelt)
	FormRaute                    // Wartung, pausiert
	FormRing                     // ohne Wertung: neu, kein Sensor
)

// Anzeige: Form, Farbe der Form und Farben für Text und Marke eines Status.
type Anzeige struct {
	Form     Form
	Farbe    RGB // Form, Fläche der Marke
	Text     RGB // Wort in Tabellen
	Hauch    RGB // Fläche hinter Meldungen
	AufFarbe RGB // Text auf der gefüllten Marke
	Gefuellt bool
	Wort     string
}

// AnzeigeFuer: wie ein Status (ok, warn, crit, unknown, pause, neu, wartung,
// bestaetigt, "") in Farbe und Form erscheint.
func (f Farben) AnzeigeFuer(status string) Anzeige {
	switch status {
	case "ok":
		return Anzeige{FormKreis, f.OK, f.TextOK, f.OKHauch, f.OK, false, "OK"}
	case "warn":
		return Anzeige{FormDreieck, f.Warn, f.TextWarn, f.WarnHauch, f.AufWarn, true, "Warnung"}
	case "crit":
		return Anzeige{FormAchteck, f.Krit, f.TextKrit, f.KritHauch, f.AufKrit, true, "Kritisch"}
	case "bestaetigt":
		return Anzeige{FormAchteckHaken, f.Krit, f.TextKrit, f.KritHauch, f.TextKrit, false, "Bestätigt"}
	case "unknown":
		return Anzeige{FormQuadrat, f.Unbek, f.Leise, f.UnbekHauch, f.Leise, false, "Unbekannt"}
	case "pause":
		return Anzeige{FormRaute, f.Wartung, f.TextWartung, f.WartHauch, f.TextWartung, false, "Pausiert"}
	case "wartung":
		return Anzeige{FormRaute, f.Wartung, f.TextWartung, f.WartHauch, f.TextWartung, false, "Wartung"}
	case "neu":
		return Anzeige{FormRing, f.Leise, f.Leise, f.Zart, f.Leise, false, "Neu"}
	}
	return Anzeige{FormRing, f.Leise, f.Leise, f.Zart, f.Leise, false, ""}
}
