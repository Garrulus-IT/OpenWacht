// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"math"
)

// Zustandsformen nach docs/design/README.md §6 (Raster 16 wie
// web/public/formen/*.svg): Kreis = OK, Dreieck = Warnung, Achteck =
// kritisch, Achteck-Umriss mit Haken = bestätigt, gestricheltes Quadrat =
// unbekannt, Raute = Wartung und pausiert, Kreisring = ohne Wertung.
//
// Das Symbol im Infobereich nutzt dieselben Formen; seine Farben sind die
// kräftigeren der Wandanzeige (--wand-*), weil die Taskleiste meist dunkel ist.

var farben = map[Zustand]RGB{
	ZustandOK:        0x3fae78,
	ZustandWarn:      0xe0b041,
	ZustandKrit:      0xe5534b,
	ZustandUnbekannt: 0x8a95a1,
	ZustandStoerung:  0x8a95a1,
}

var formVon = map[Zustand]Form{
	ZustandOK: FormKreis, ZustandWarn: FormDreieck, ZustandKrit: FormAchteck,
	ZustandUnbekannt: FormQuadrat, ZustandStoerung: FormRing,
}

// Bild zeichnet das Symbol für den Infobereich in Größe n×n.
func Bild(z Zustand, n int) *image.NRGBA {
	c, ok := farben[z]
	if !ok {
		c = farben[ZustandUnbekannt]
	}
	f, ok := formVon[z]
	if !ok {
		f = FormRing
	}
	return FormBild(f, c, n)
}

// FormBild zeichnet eine Zustandsform in Farbe c, n×n Pixel, kantengeglättet.
func FormBild(f Form, c RGB, n int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	r, g, b := uint8(c>>16), uint8(c>>8), uint8(c)
	const ss = 4 // Unterabtastung je Richtung
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			hit := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					// Punkt im Raster 16 (0 … 16)
					px := (float64(x) + (float64(sx)+0.5)/ss) / float64(n) * 16
					py := (float64(y) + (float64(sy)+0.5)/ss) / float64(n) * 16
					if innen(f, px, py) {
						hit++
					}
				}
			}
			if hit > 0 {
				img.SetNRGBA(x, y, color.NRGBA{r, g, b, uint8(255 * hit / (ss * ss))})
			}
		}
	}
	return img
}

// abstandStrecke: Abstand des Punkts (x, y) zur Strecke a–b.
func abstandStrecke(x, y, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((x-ax)*dx + (y-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(x-(ax+t*dx), y-(ay+t*dy))
}

func innen(f Form, x, y float64) bool {
	cx, cy := x-8, y-8
	ax, ay := math.Abs(cx), math.Abs(cy)
	r := math.Hypot(cx, cy)
	switch f {
	case FormKreis: // circle r 7
		return r <= 7
	case FormDreieck: // M8 1 15.5 14.5H.5z
		if y < 1 || y > 14.5 {
			return false
		}
		return ax <= (y-1)/13.5*7.5
	case FormAchteck: // M5.1 1h5.8L15 5.1v5.8L10.9 15H5.1L1 10.9V5.1z
		return ax <= 7 && ay <= 7 && ax+ay <= 9.9
	case FormAchteckHaken:
		// Umriss: M5.5 2h5L14 5.5v5L10.5 14h-5L2 10.5v-5z, Strich 1,6
		aussen := ax <= 6.8 && ay <= 6.8 && ax+ay <= 8.5+0.8*math.Sqrt2
		innenF := ax <= 5.2 && ay <= 5.2 && ax+ay <= 8.5-0.8*math.Sqrt2
		if aussen && !innenF {
			return true
		}
		// Haken: m5 8.2 2 2 4-4.2, Strich 1,8
		return abstandStrecke(x, y, 5, 8.2, 7, 10.2) <= 0.9 || abstandStrecke(x, y, 7, 10.2, 11, 6) <= 0.9
	case FormQuadrat: // M2 2h12v12H2z, Strich 2, Striche 3 an, 2 aus
		if ax > 7 || ay > 7 || (ax < 5 && ay < 5) {
			return false
		}
		// Weg entlang des Umfangs ab der Ecke links oben
		var s float64
		switch {
		case cy < -5:
			s = cx + 6
		case cx > 5:
			s = 12 + cy + 6
		case cy > 5:
			s = 24 + 6 - cx
		default:
			s = 36 + 6 - cy
		}
		return math.Mod(s+0.5, 5) < 3
	case FormRaute: // M8 .5 15.5 8 8 15.5.5 8z
		return ax+ay <= 7.5
	default: // FormRing: circle r 6, Strich 2
		return r >= 5 && r <= 7
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
