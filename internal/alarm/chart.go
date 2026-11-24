// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// Graph für Alarm-Mails: ein kleines PNG ohne Schrift, gezeichnet nur mit der
// Standardbibliothek. Mail-Programme (Outlook) zeigen kein SVG; Achsenwerte
// und Legende stehen deshalb als Text in der Mail, nicht im Bild.

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"time"
)

// ChartPoint: ein Wert zu einer Zeit.
type ChartPoint struct {
	T time.Time
	V float64
}

// Chart: eine Reihe mit optionalen Schwellen (0 = keine).
type Chart struct {
	Title   string // z. B. „Platte /var“
	Unit    string // „%“ oder „ms“
	Percent bool   // feste Achse 0–100
	Points  []ChartPoint
	Warn    float64
	Crit    float64
	From    time.Time
	To      time.Time
}

// Größe des Bildes in Pixeln (doppelt so groß wie angezeigt, für scharfe
// Darstellung auf hochauflösenden Bildschirmen).
const (
	ChartWidth  = 1200
	ChartHeight = 320
	chartPad    = 12
	maxPoints   = 2000
)

var (
	chartBG = color.RGBA{0xff, 0xff, 0xff, 0xff}
	// Farben nach docs/design/tokens.css (hell): Linie --marke, Fläche
	// --marke-hauch, Schwellen --warn und --krit, Raster zurückhaltend.
	chartGrid  = color.RGBA{0xe1, 0xe7, 0xee, 0xff}
	chartLine  = color.RGBA{0x0b, 0x6a, 0x8a, 0xff}
	chartFill  = color.RGBA{0xdc, 0xed, 0xf3, 0xff}
	chartWarn  = color.RGBA{0xb0, 0x7c, 0x12, 0xff}
	chartCrit  = color.RGBA{0xb3, 0x36, 0x2f, 0xff}
	chartColor = color.Palette{chartBG, chartGrid, chartLine, chartFill, chartWarn, chartCrit}
)

// Range liefert Minimum, Maximum und letzten Wert (ok = mindestens ein Punkt).
func (c Chart) Range() (lo, hi, last float64, ok bool) {
	lo, hi = math.Inf(1), math.Inf(-1)
	for _, p := range c.Points {
		if math.IsNaN(p.V) || math.IsInf(p.V, 0) {
			continue
		}
		lo, hi, last, ok = math.Min(lo, p.V), math.Max(hi, p.V), p.V, true
	}
	return
}

// axis: unterer und oberer Rand der y-Achse.
func (c Chart) axis() (float64, float64) {
	if c.Percent {
		return 0, 100
	}
	_, hi, _, _ := c.Range()
	hi = math.Max(hi, math.Max(c.Warn, c.Crit))
	if !(hi > 0) {
		hi = 1
	}
	return 0, hi * 1.1
}

// PNG zeichnet den Graphen. Ohne Punkte: nil.
func (c Chart) PNG() []byte {
	if _, _, _, ok := c.Range(); !ok || len(c.Points) > maxPoints || !c.To.After(c.From) {
		return nil
	}
	img := image.NewPaletted(image.Rect(0, 0, ChartWidth, ChartHeight), chartColor)
	// Hintergrund ist Index 0 (weiß).
	x0, x1 := chartPad, ChartWidth-chartPad
	y0, y1 := chartPad, ChartHeight-chartPad
	lo, hi := c.axis()
	ys := func(v float64) int {
		f := (v - lo) / (hi - lo)
		f = math.Max(0, math.Min(1, f))
		return y1 - int(math.Round(f*float64(y1-y0)))
	}
	xs := func(t time.Time) int {
		f := float64(t.Sub(c.From)) / float64(c.To.Sub(c.From))
		f = math.Max(0, math.Min(1, f))
		return x0 + int(math.Round(f*float64(x1-x0)))
	}
	// Raster: vier waagerechte Linien, senkrecht alle 6 Stunden ab From.
	for i := 0; i <= 4; i++ {
		y := y1 - i*(y1-y0)/4
		hline(img, x0, x1, y, 1, false)
	}
	for t := c.From.Add(6 * time.Hour); t.Before(c.To); t = t.Add(6 * time.Hour) {
		vline(img, xs(t), y0, y1, 1)
	}
	// Fläche unter der Linie, dann die Linie selbst.
	var clean []ChartPoint
	for _, p := range c.Points {
		if !math.IsNaN(p.V) && !math.IsInf(p.V, 0) {
			clean = append(clean, p)
		}
	}
	pts := make([]image.Point, len(clean))
	for i, p := range clean {
		pts[i] = image.Pt(xs(p.T), ys(p.V))
	}
	for i := 1; i < len(pts); i++ {
		// Lücke über 30 min: nicht verbinden (Agent war weg).
		if clean[i].T.Sub(clean[i-1].T) > 30*time.Minute {
			continue
		}
		fillUnder(img, pts[i-1], pts[i], y1)
	}
	if c.Warn > 0 {
		hline(img, x0, x1, ys(c.Warn), 4, true)
	}
	if c.Crit > 0 {
		hline(img, x0, x1, ys(c.Crit), 5, true)
	}
	for i, p := range pts {
		dot(img, p, 2)
		if i > 0 && clean[i].T.Sub(clean[i-1].T) <= 30*time.Minute {
			line(img, pts[i-1], p)
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}

func hline(img *image.Paletted, x0, x1, y int, idx uint8, dashed bool) {
	for x := x0; x <= x1; x++ {
		if dashed && (x/12)%2 == 1 {
			continue
		}
		img.SetColorIndex(x, y, idx)
		if idx > 1 { // Schwellen etwas kräftiger
			img.SetColorIndex(x, y+1, idx)
		}
	}
}

func vline(img *image.Paletted, x, y0, y1 int, idx uint8) {
	for y := y0; y <= y1; y++ {
		img.SetColorIndex(x, y, idx)
	}
}

// fillUnder füllt die Fläche zwischen der Strecke a–b und der Grundlinie.
func fillUnder(img *image.Paletted, a, b image.Point, base int) {
	if b.X < a.X {
		a, b = b, a
	}
	for x := a.X; x <= b.X; x++ {
		y := a.Y
		if b.X != a.X {
			y = a.Y + (b.Y-a.Y)*(x-a.X)/(b.X-a.X)
		}
		for yy := y; yy <= base; yy++ {
			if img.ColorIndexAt(x, yy) <= 1 {
				img.SetColorIndex(x, yy, 3)
			}
		}
	}
}

// line: Bresenham mit einem Pinsel von 5 Pixeln (2,5 px in der Anzeige).
func line(img *image.Paletted, a, b image.Point) {
	dx, dy := abs(b.X-a.X), -abs(b.Y-a.Y)
	sx, sy := 1, 1
	if a.X > b.X {
		sx = -1
	}
	if a.Y > b.Y {
		sy = -1
	}
	e := dx + dy
	for {
		dot(img, a, 2)
		if a == b {
			return
		}
		e2 := 2 * e
		if e2 >= dy {
			e += dy
			a.X += sx
		}
		if e2 <= dx {
			e += dx
			a.Y += sy
		}
	}
}

func dot(img *image.Paletted, p image.Point, r int) {
	for y := -r; y <= r; y++ {
		for x := -r; x <= r; x++ {
			if x*x+y*y <= r*r+1 && image.Pt(p.X+x, p.Y+y).In(img.Rect) {
				img.SetColorIndex(p.X+x, p.Y+y, 2)
			}
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
