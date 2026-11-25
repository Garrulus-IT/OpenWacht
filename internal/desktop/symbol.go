// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"math"
)

// Symbol im Infobereich: Zustand als Form und Farbe wie in der Oberfläche
// (nie nur Farbe): Kreis = OK, Dreieck = Warnung, Achteck = Kritisch,
// gestricheltes Quadrat = Unbekannt, leerer Ring = keine Verbindung.

var farben = map[Zustand]color.NRGBA{
	ZustandOK:        {0x2c, 0x7a, 0x57, 0xff},
	ZustandWarn:      {0xe0, 0xb0, 0x41, 0xff},
	ZustandKrit:      {0xd2, 0x3f, 0x37, 0xff},
	ZustandUnbekannt: {0x8a, 0x96, 0xa3, 0xff},
	ZustandStoerung:  {0x8a, 0x96, 0xa3, 0xff},
}

// Bild zeichnet das Symbol in Größe n×n (16, 24 oder 32) mit Kantenglättung.
func Bild(z Zustand, n int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	c, ok := farben[z]
	if !ok {
		c = farben[ZustandUnbekannt]
	}
	const ss = 4 // Unterabtastung je Richtung
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			hit := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					// Punkt im Einheitsquadrat −1 … 1
					px := (float64(x)+(float64(sx)+0.5)/ss)/float64(n)*2 - 1
					py := (float64(y)+(float64(sy)+0.5)/ss)/float64(n)*2 - 1
					if innen(z, px, py) {
						hit++
					}
				}
			}
			if hit > 0 {
				a := uint8(int(c.A) * hit / (ss * ss))
				img.SetNRGBA(x, y, color.NRGBA{c.R, c.G, c.B, a})
			}
		}
	}
	return img
}

func innen(z Zustand, x, y float64) bool {
	r := math.Hypot(x, y)
	switch z {
	case ZustandOK:
		return r <= 0.88
	case ZustandWarn:
		// Dreieck mit Spitze oben: y von −0.9 bis 0.85
		if y < -0.9 || y > 0.85 {
			return false
		}
		half := (y + 0.9) / 1.75 * 0.98
		return math.Abs(x) <= half
	case ZustandKrit:
		// Achteck: |x|, |y| ≤ a und |x|+|y| ≤ b
		const a, b = 0.88, 1.24
		return math.Abs(x) <= a && math.Abs(y) <= a && math.Abs(x)+math.Abs(y) <= b
	case ZustandUnbekannt:
		// gestricheltes Quadrat, Rand 0.2 breit
		if math.Abs(x) > 0.85 || math.Abs(y) > 0.85 || (math.Abs(x) < 0.6 && math.Abs(y) < 0.6) {
			return false
		}
		t := x + y // Striche: abwechselnd an und aus entlang der Diagonale
		return math.Mod(math.Abs(t)*2.5, 1) < 0.6
	default: // Störung: Ring
		return r <= 0.85 && r >= 0.6
	}
}

// IconRessource: ein Bild als Icon-Ressource (BITMAPINFOHEADER, 32 bit BGRA
// von unten nach oben, dahinter die leere UND-Maske), wie sie
// CreateIconFromResourceEx erwartet.
func IconRessource(img *image.NRGBA) []byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	var b bytes.Buffer
	hdr := struct {
		Size                   uint32
		Width, Height          int32
		Planes, BitCount       uint16
		Compression, SizeImage uint32
		XPels, YPels           int32
		ClrUsed, ClrImportant  uint32
	}{40, int32(w), int32(2 * h), 1, 32, 0, 0, 0, 0, 0, 0}
	binary.Write(&b, binary.LittleEndian, hdr)
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			// vormultipliziertes Alpha ist für Icons nicht nötig; BGRA
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	maskRow := ((w + 31) / 32) * 4
	b.Write(make([]byte, maskRow*h))
	return b.Bytes()
}
