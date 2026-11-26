// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Sonnendiagramm wie im Dashboard und auf der Wandanzeige (web/src/Sonne.tsx):
// innen der gewählte Knoten, nach außen Untermandanten, Gruppen und Geräte.
// Jedes Gerät ist gleich breit, endet am Außenrand und tritt mit Problem
// hervor; jeder Ring trägt den schlimmsten Zustand darunter. Koordinaten wie
// im Web: −500 … 500, Winkel ab 12 Uhr im Uhrzeigersinn.

import (
	"image"
	"image/color"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	sonneR      = 492.0
	sonneVor    = 34.0
	sonneAussen = sonneR - sonneVor
	sonneLoch   = 0.27 * sonneR
	sonneFuge   = 7.0
)

// Wand: die kräftigen Zustandsfarben des Sonnendiagramms (.wand/.sonne in
// web/src/tokens.css), in hell und dunkel gleich.
var Wand = struct {
	OK, Warn, Krit, Best, Unbek, Wartung RGB
	TextDunkel, AufSignal                RGB
}{0x3fae78, 0xe0b041, 0xe5534b, 0xa8615c, 0x6c7682, 0x9a7fd0, 0x0a121c, 0xffffff}

// SonnenStatus: ok, warn, crit, quittiert, unknown, wartung (wie im Web).
func SonnenStatus(k *Knoten) string {
	if k.Art == KnotenGeraet && k.Geraet != nil && k.Geraet.Wartung != nil {
		return "wartung"
	}
	switch k.Zustand() {
	case "crit":
		return "crit"
	case "warn":
		return "warn"
	case "unknown", "":
		return "unknown"
	case "bestaetigt":
		return "quittiert"
	case "pause":
		return "wartung"
	}
	return "ok"
}

// SonnenFarbe: Fläche und Schrift eines Segments.
func SonnenFarbe(status string) (fill, text RGB) {
	switch status {
	case "crit":
		return Wand.Krit, Wand.TextDunkel
	case "warn":
		return Wand.Warn, Wand.TextDunkel
	case "quittiert":
		return Wand.Best, Wand.AufSignal
	case "unknown":
		return Wand.Unbek, Wand.AufSignal
	case "wartung":
		return Wand.Wartung, Wand.TextDunkel
	}
	return Wand.OK, Wand.TextDunkel
}

// Segment der Sonne.
type Segment struct {
	Knoten *Knoten
	Pfad   []string
	Tiefe  int
	A0, A1 float64
	R0, R1 float64 // mit Fugen
	Blatt  bool
	Status string
}

func blaetter(k *Knoten) int {
	if len(k.Kinder) == 0 {
		return 1
	}
	n := 0
	for _, c := range k.Kinder {
		n += blaetter(c)
	}
	return n
}

// Sonne zerlegt den Baum unter wurzel in Segmente (ohne die Wurzel selbst,
// deren Ring ist Ring 0). Liefert auch die Radien der Ringe.
func Sonne(wurzel *Knoten) (segmente []Segment, ringe []float64) {
	tiefe := 0
	var gehe func(k *Knoten, pfad []string, t int, a0, a1 float64)
	gehe = func(k *Knoten, pfad []string, t int, a0, a1 float64) {
		tiefe = max(tiefe, t)
		if t > 0 {
			segmente = append(segmente, Segment{Knoten: k, Pfad: pfad, Tiefe: t, A0: a0, A1: a1,
				Blatt: len(k.Kinder) == 0, Status: SonnenStatus(k)})
		}
		gesamt := float64(blaetter(k))
		a := a0
		for _, c := range k.Kinder {
			b := a + (a1-a0)*float64(blaetter(c))/gesamt
			gehe(c, append(append([]string(nil), pfad...), c.Name), t+1, a, b)
			a = b
		}
	}
	gehe(wurzel, []string{wurzel.Name}, 0, 0, 2*math.Pi)
	ringe = sonnenRadien(tiefe)
	for i := range segmente {
		s := &segmente[i]
		r0, r1 := ringe[s.Tiefe], ringe[s.Tiefe+1]
		if s.Blatt {
			r1 = sonneAussen
			if s.Status != "ok" && s.Status != "wartung" {
				r1 = sonneR
			}
		}
		s.R0, s.R1 = r0+sonneFuge/2, r1-sonneFuge/2
	}
	return segmente, ringe
}

// sonnenRadien: Ring 0 schmal, der äußerste breiter für die Gerätenamen.
func sonnenRadien(tiefe int) []float64 {
	gewicht := func(t int) float64 {
		switch {
		case t == 0:
			return 0.45
		case t == tiefe && tiefe >= 2:
			return 1.6
		}
		return 1
	}
	summe := 0.0
	for t := 0; t <= tiefe; t++ {
		summe += gewicht(t)
	}
	r := []float64{sonneLoch}
	innen := sonneLoch
	for t := 0; t <= tiefe; t++ {
		innen += (sonneAussen - sonneLoch) * gewicht(t) / summe
		r = append(r, innen)
	}
	return r
}

// winkel: Winkel eines Punkts ab 12 Uhr im Uhrzeigersinn (0 … 2π).
func winkel(x, y float64) float64 {
	a := math.Atan2(x, -y)
	if a < 0 {
		a += 2 * math.Pi
	}
	return a
}

// SonnenTreffer: Segment an (x, y) in Sonnenkoordinaten; -1 = Ring 0
// (Wurzel), -2 = nichts.
func SonnenTreffer(seg []Segment, ringe []float64, x, y float64) int {
	r := math.Hypot(x, y)
	a := winkel(x, y)
	for i := len(seg) - 1; i >= 0; i-- {
		s := seg[i]
		if r >= s.R0 && r <= s.R1 && a >= s.A0 && a < s.A1 {
			return i
		}
	}
	if len(ringe) > 1 && r >= ringe[0]+sonneFuge/2 && r <= ringe[1]-sonneFuge/2 {
		return -1
	}
	return -2
}

// SonnenBild zeichnet die Sonne n×n Pixel groß auf grund. Wie das Widget
// im Dashboard: Fugen und Scheibe in der Farbe des Grunds, jedes Segment mit
// einem Rand von 1 px in derselben Farbe (stroke 1, non-scaling-stroke).
func SonnenBild(seg []Segment, ringe []float64, wurzelStatus string, n int, grund RGB) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	skala := 1000.0 / float64(n)
	rand := 0.5 * skala // halber Strich innen am Segment
	const ss = 3
	farbe := func(x, y float64) (RGB, bool) {
		r := math.Hypot(x, y)
		if r > sonneR+rand {
			return 0, false
		}
		a := winkel(x, y)
		for i := len(seg) - 1; i >= 0; i-- {
			s := seg[i]
			if r >= s.R0-rand && r <= s.R1+rand && a >= s.A0 && a < s.A1 {
				if r < s.R0+rand || r > s.R1-rand || (a-s.A0)*r < rand || (s.A1-a)*r < rand {
					return grund, true
				}
				f, _ := SonnenFarbe(s.Status)
				return f, true
			}
		}
		if len(ringe) > 1 {
			r0, r1 := ringe[0]+sonneFuge/2, ringe[1]-sonneFuge/2
			if r >= r0+rand && r <= r1-rand {
				f, _ := SonnenFarbe(wurzelStatus)
				return f, true
			}
		}
		return grund, r <= sonneAussen+sonneFuge
	}
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			var rs, gs, bs, deck int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px)+(float64(sx)+0.5)/ss)*skala - 500
					y := (float64(py)+(float64(sy)+0.5)/ss)*skala - 500
					c, ok := farbe(x, y)
					if !ok {
						continue
					}
					deck++
					rs += int(c >> 16 & 0xff)
					gs += int(c >> 8 & 0xff)
					bs += int(c & 0xff)
				}
			}
			if deck > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(rs / deck), uint8(gs / deck), uint8(bs / deck), uint8(255 * deck / (ss * ss))})
			}
		}
	}
	return img
}

// Beschriftung eines Segments: radial (entlang des Strahls) oder
// tangential (entlang des Bogens), wie im Web.
type Beschriftung struct {
	Radial  bool
	Text    string
	Schrift float64 // in Sonnenkoordinaten
}

// SonnenBeschriftung: was vom Namen lesbar hineinpasst (nil = nichts),
// Schrift wie im Web zwischen 6,5 und 19 Einheiten.
func SonnenBeschriftung(name string, r0, r1, a0, a1 float64) *Beschriftung {
	return SonnenBeschriftungIn(name, r0, r1, a0, a1, 6.5, 19)
}

// SonnenBeschriftungIn: wie SonnenBeschriftung mit eigener Untergrenze (die
// Desktop-App hebt sie an, damit nichts unter 9 px gesetzt wird).
func SonnenBeschriftungIn(name string, r0, r1, a0, a1, minS, maxS float64) *Beschriftung {
	const zeichen = 0.56
	kuerzen := func(platz, s float64) string {
		n := int(platz / (s * zeichen))
		if n >= utf8.RuneCountInString(name) {
			return name
		}
		if n < 3 {
			return ""
		}
		return strings.TrimSpace(string([]rune(name)[:n-1])) + "…"
	}
	dicke := r1 - r0
	spanne := math.Min(a1-a0, math.Pi)
	bogen := (r0 + r1) / 2 * spanne
	var beste *Beschriftung
	sichtbar := func(b *Beschriftung) float64 {
		n := float64(utf8.RuneCountInString(b.Text))
		if strings.HasSuffix(b.Text, "…") {
			return n - 1
		}
		return n + 0.5
	}
	nimm := func(b *Beschriftung) {
		if b.Text == "" {
			return
		}
		if beste == nil || sichtbar(b) > sichtbar(beste) || (sichtbar(b) == sichtbar(beste) && b.Schrift > beste.Schrift) {
			beste = b
		}
	}
	// tangential (entlang des Bogens): Schrifthöhe durch die Ringdicke begrenzt
	if s := math.Min(maxS, dicke*0.5); s >= minS {
		nimm(&Beschriftung{false, kuerzen(bogen*0.88, s), s})
	}
	// radial: Schrifthöhe durch die Bogenbreite am Innenrand begrenzt
	if s := math.Min(maxS, r0*spanne*0.8); s >= minS {
		nimm(&Beschriftung{true, kuerzen(dicke*0.9, s), s})
	}
	return beste
}
