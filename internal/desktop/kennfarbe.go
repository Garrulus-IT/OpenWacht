// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Kennfarben (0.99.2) wie web/src/kennfarbe.tsx und die Sonne der
// Wandanzeige (internal/zentrale/wandanzeige.go): Ein Sensor mit Kennfarbe
// erscheint bei Warnung, Kritisch und Bestätigt in dieser Farbe statt in Gelb
// bzw. Rot. Bei gleicher Schwere gewinnt der Zustand ohne Kennfarbe („Rot
// gewinnt immer“), damit eine Kennfarbe nie ein echtes Rot oder Gelb verdeckt.

import (
	"math"
	"regexp"
	"strconv"
)

// Kennfarbe eines Sensors, wie die Zentrale sie liefert (Farbe „#rrggbb“, geprüft).
type Kennfarbe struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Farbe string `json:"farbe"`
}

var hexFarbe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// RGB der Kennfarbe; false bei fehlender oder unbrauchbarer Farbe.
func (k *Kennfarbe) RGB() (RGB, bool) {
	if k == nil || !hexFarbe.MatchString(k.Farbe) {
		return 0, false
	}
	n, _ := strconv.ParseUint(k.Farbe[1:], 16, 32)
	return RGB(n), true
}

// KennGilt: Bei diesen Zuständen der Sonne ersetzt die Kennfarbe Gelb bzw. Rot.
func KennGilt(status string) bool {
	return status == "warn" || status == "crit" || status == "quittiert"
}

// wandGrund: --wand-grund, mit dem die Sonne bestätigte Kennfarben abdunkelt.
const wandGrund RGB = 0x060c14

// SegmentFarbe: Fläche und Schrift eines Segments mit Kennfarbe (styles.css
// .sonne-seg.kenn): Fläche in der Kennfarbe, bei Bestätigt zu 55 % auf dem
// Grund; Schrift nach Kontrast, bei Bestätigt weiß.
func SegmentFarbe(status string, k *Kennfarbe) (fill, text RGB) {
	c, ok := k.RGB()
	if !ok || !KennGilt(status) {
		return SonnenFarbe(status)
	}
	if status == "quittiert" {
		return Mischen(c, wandGrund, 55), Wand.AufSignal
	}
	return c, SchriftAuf(c)
}

// Mischen: p % von a, Rest b (color-mix in srgb).
func Mischen(a, b RGB, p int) RGB {
	m := func(s uint) RGB {
		x, y := int(a>>s&0xff), int(b>>s&0xff)
		return RGB((x*p + y*(100-p) + 50) / 100)
	}
	return m(16)<<16 | m(8)<<8 | m(0)
}

func leuchtdichte(c RGB) float64 {
	kanal := func(v RGB) float64 {
		x := float64(v) / 255
		if x <= 0.04045 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*kanal(c>>16&0xff) + 0.7152*kanal(c>>8&0xff) + 0.0722*kanal(c&0xff)
}

// Kontrast nach WCAG.
func Kontrast(a, b RGB) float64 {
	x, y := leuchtdichte(a), leuchtdichte(b)
	return (math.Max(x, y) + 0.05) / (math.Min(x, y) + 0.05)
}

// SchriftAuf: weiß oder dunkel, je nachdem, was auf c mehr Kontrast hat.
func SchriftAuf(c RGB) RGB {
	if Kontrast(c, 0xffffff) >= Kontrast(c, 0x0a121c) {
		return 0xffffff
	}
	return 0x0a121c
}

// sensorSonne: Zustand eines Sensors in den Worten der Sonne (wie Zaehlen).
func sensorSonne(s Sensor) string {
	if Problem(s.Status) && s.Alarm != nil && s.Alarm.Ende == nil && s.Alarm.Bestaetigt != nil {
		return "quittiert"
	}
	switch s.Status {
	case "crit", "warn", "unknown", "ok":
		return s.Status
	}
	return "wartung"
}

// kennSetzen: Kennfarbe je Knoten. Ein Gerät nimmt die Kennfarbe der Sensoren
// im schlimmsten Zustand, Gruppen und Mandanten die der Kinder; hat einer im
// gleichen Zustand keine Kennfarbe, gilt keine.
func kennSetzen(k *Knoten, sensoren map[string][]Sensor) {
	k.Kenn = nil
	st := SonnenStatus(k)
	var erste *Kennfarbe
	ohne := false
	nimm := func(s string, kenn *Kennfarbe) {
		if s != st {
			return
		}
		if _, ok := kenn.RGB(); !ok {
			ohne = true
		} else if erste == nil {
			erste = kenn
		}
	}
	if k.Art == KnotenGeraet {
		for _, s := range sensoren[k.ID] {
			nimm(sensorSonne(s), s.Kennfarbe)
		}
	} else {
		for _, c := range k.Kinder {
			kennSetzen(c, sensoren)
			nimm(SonnenStatus(c), c.Kenn)
		}
	}
	if KennGilt(st) && !ohne {
		k.Kenn = erste
	}
}

// SonnenWort: Anzeige-Status der Liste („bestaetigt“) in den Worten der Sonne.
func SonnenWort(anzeige string) string {
	if anzeige == "bestaetigt" {
		return "quittiert"
	}
	return anzeige
}
