// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Piktogramme der Seitenleiste wie im Web (web/src/Oberflaeche.tsx,
// symbolPfad): Raster 24, Strich 2, eckige Enden. Die Pfade stehen hier
// noch einmal, ein Test vergleicht sie mit der Datei. Gerastert wird ohne
// Bibliothek: Pfad in Strecken zerlegen (Bögen angenähert), dann je Pixel
// mit 4×4 Abtastpunkten prüfen, ob der Punkt im Strich liegt.

import (
	"image"
	"image/color"
	"math"
	"strconv"
	"strings"
)

// Piktogramme: Name wie im Web → SVG-Pfad (viewBox 0 0 24 24).
var Piktogramme = map[string]string{
	"dashboard":     "M3 3h7v8H3zM13 3h8v5h-8zM13 11h8v10h-8zM3 14h7v7H3z",
	"hosts":         "M3 4h18v6H3zM3 14h18v6H3zM6 7h3M6 17h3",
	"topologie":     "M9 3h6v5H9zM3 16h6v5H3zM15 16h6v5h-6zM12 8v4M6 12h12M6 12v4M18 12v4",
	"zertifikate":   "M4 4h16v11H4zM8 8h8M8 11h5M15 15v6l2-1.5 2 1.5v-6",
	"alarme":        "M6 17v-6a6 6 0 0 1 12 0v6l2 2H4zM10 21h4",
	"berichte":      "M5 3h10l4 4v14H5zM15 3v4h4M8 12h8M8 16h8",
	"vorlagen":      "M4 4h16v4H4zM4 10h10v4H4zM4 16h16v4H4z",
	"snmpprofile":   "M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 12h9M17 12v4M20 12v3",
	"anzeigen":      "M3 4h18v12H3zM8 20h8M12 16v4",
	"wartung":       "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l4 4",
	"verwaltung":    "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3a4 4 0 0 1 0 8M17 14a7 7 0 0 1 5 7",
	"einstellungen": "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9 7 7M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1",
	// Kopf und Fuß der Leiste (Oberflaeche.tsx: Person, Suche)
	"person": "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
	"suche":  "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-4.35-4.35",
	// Pfeil „öffnet im Browser“ (eigene Linien im selben Raster)
	"extern": "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
}

type punkt2 struct{ x, y float64 }

// pfadZerlegen: Teilpfade als Punktfolgen; geschlossen = letzter Punkt gleich dem ersten.
func pfadZerlegen(d string) [][]punkt2 {
	var toks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case strings.IndexByte("MmLlHhVvZzAa", c) >= 0:
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == ',':
			flush()
		case c == '-' && b.Len() > 0 && !strings.HasSuffix(b.String(), "e"):
			flush()
			b.WriteByte(c)
		case c == '.' && strings.Contains(b.String(), "."):
			flush()
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	flush()
	var teile [][]punkt2
	var akt []punkt2
	var cx, cy, sx, sy float64
	cmd := ""
	i := 0
	num := func() float64 {
		if i >= len(toks) {
			return 0
		}
		v, _ := strconv.ParseFloat(toks[i], 64)
		i++
		return v
	}
	istZahl := func() bool {
		if i >= len(toks) {
			return false
		}
		_, err := strconv.ParseFloat(toks[i], 64)
		return err == nil
	}
	neu := func() {
		if len(akt) > 1 {
			teile = append(teile, akt)
		}
		akt = nil
	}
	for i < len(toks) {
		if !istZahl() {
			cmd = toks[i]
			i++
		}
		rel := cmd == strings.ToLower(cmd)
		switch strings.ToUpper(cmd) {
		case "M":
			x, y := num(), num()
			if rel {
				x, y = cx+x, cy+y
			}
			neu()
			cx, cy, sx, sy = x, y, x, y
			akt = []punkt2{{x, y}}
			if rel {
				cmd = "l"
			} else {
				cmd = "L"
			}
		case "L":
			x, y := num(), num()
			if rel {
				x, y = cx+x, cy+y
			}
			cx, cy = x, y
			akt = append(akt, punkt2{x, y})
		case "H":
			x := num()
			if rel {
				x += cx
			}
			cx = x
			akt = append(akt, punkt2{cx, cy})
		case "V":
			y := num()
			if rel {
				y += cy
			}
			cy = y
			akt = append(akt, punkt2{cx, cy})
		case "Z":
			akt = append(akt, punkt2{sx, sy})
			cx, cy = sx, sy
			neu()
			akt = []punkt2{{sx, sy}}
		case "A":
			rx, ry, rot, gross, uhr, x, y := num(), num(), num(), num(), num(), num(), num()
			if rel {
				x, y = cx+x, cy+y
			}
			akt = append(akt, bogenPunkte(cx, cy, rx, ry, rot, gross != 0, uhr != 0, x, y)...)
			cx, cy = x, y
		default:
			i++ // unbekannt: überspringen
		}
	}
	neu()
	return teile
}

// bogenPunkte: elliptischer Bogen nach SVG (Endpunkt-Form) als Punkte ohne den Startpunkt.
func bogenPunkte(x1, y1, rx, ry, rotGrad float64, gross, uhr bool, x2, y2 float64) []punkt2 {
	if rx == 0 || ry == 0 {
		return []punkt2{{x2, y2}}
	}
	phi := rotGrad * math.Pi / 180
	cp, sp := math.Cos(phi), math.Sin(phi)
	dx, dy := (x1-x2)/2, (y1-y2)/2
	x1p := cp*dx + sp*dy
	y1p := -sp*dx + cp*dy
	rx, ry = math.Abs(rx), math.Abs(ry)
	if l := x1p*x1p/(rx*rx) + y1p*y1p/(ry*ry); l > 1 {
		rx, ry = rx*math.Sqrt(l), ry*math.Sqrt(l)
	}
	z := (rx*rx*ry*ry - rx*rx*y1p*y1p - ry*ry*x1p*x1p) / (rx*rx*y1p*y1p + ry*ry*x1p*x1p)
	f := math.Sqrt(math.Max(z, 0))
	if gross == uhr {
		f = -f
	}
	cxp, cyp := f*rx*y1p/ry, -f*ry*x1p/rx
	mx, my := cp*cxp-sp*cyp+(x1+x2)/2, sp*cxp+cp*cyp+(y1+y2)/2
	winkel := func(ux, uy, vx, vy float64) float64 {
		a := math.Atan2(ux*vy-uy*vx, ux*vx+uy*vy)
		return a
	}
	t1 := winkel(1, 0, (x1p-cxp)/rx, (y1p-cyp)/ry)
	dt := winkel((x1p-cxp)/rx, (y1p-cyp)/ry, (-x1p-cxp)/rx, (-y1p-cyp)/ry)
	if !uhr && dt > 0 {
		dt -= 2 * math.Pi
	} else if uhr && dt < 0 {
		dt += 2 * math.Pi
	}
	n := max(int(math.Abs(dt)/(math.Pi/24)), 4)
	out := make([]punkt2, 0, n)
	for k := 1; k <= n; k++ {
		t := t1 + dt*float64(k)/float64(n)
		x := rx * math.Cos(t)
		y := ry * math.Sin(t)
		out = append(out, punkt2{cp*x - sp*y + mx, sp*x + cp*y + my})
	}
	out[len(out)-1] = punkt2{x2, y2}
	return out
}

// imStrich: liegt (px, py) im Strich der Breite w? Enden eckig (butt),
// Ecken innerer Punkte gefüllt.
func imStrich(teile [][]punkt2, px, py, w float64) bool {
	h := w / 2
	for _, t := range teile {
		zu := len(t) > 2 && t[0] == t[len(t)-1]
		for j := 0; j+1 < len(t); j++ {
			a, b := t[j], t[j+1]
			dx, dy := b.x-a.x, b.y-a.y
			l2 := dx*dx + dy*dy
			if l2 == 0 {
				continue
			}
			u := ((px-a.x)*dx + (py-a.y)*dy) / l2
			if u >= 0 && u <= 1 {
				qx, qy := a.x+u*dx-px, a.y+u*dy-py
				if qx*qx+qy*qy <= h*h {
					return true
				}
			}
			// Ecke: an inneren Punkten (und allen Punkten geschlossener Pfade) quadratisch
			if j > 0 || zu {
				if math.Abs(px-a.x) <= h && math.Abs(py-a.y) <= h {
					return true
				}
			}
		}
	}
	return false
}

// PiktogrammBild: Piktogramm name n×n Pixel in Farbe c (transparent drumherum).
func PiktogrammBild(name string, c RGB, n int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	teile := pfadZerlegen(Piktogramme[name])
	if len(teile) == 0 || n <= 0 {
		return img
	}
	k := 24 / float64(n)
	const ss = 4
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			treffer := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					if imStrich(teile, (float64(x)+(float64(sx)+0.5)/ss)*k, (float64(y)+(float64(sy)+0.5)/ss)*k, 2) {
						treffer++
					}
				}
			}
			if treffer > 0 {
				img.SetNRGBA(x, y, color.NRGBA{uint8(c >> 16), uint8(c >> 8), uint8(c), uint8(255 * treffer / (ss * ss))})
			}
		}
	}
	return img
}
