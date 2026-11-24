// SPDX-License-Identifier: AGPL-3.0-only

// Package pdf schreibt einfache PDF-Dokumente (Etappe 25, Berichte): A4,
// Standardschriften Helvetica und Helvetica-Bold mit WinAnsiEncoding (deutsche
// Umlaute), Text, Linien und gefüllte Rechtecke. Keine Abhängigkeiten, keine
// eingebetteten Schriften, keine Bilder.
package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// A4 in Punkt (1/72 Zoll).
const (
	Width  = 595.28
	Height = 841.89
)

// Color als RGB 0..1.
type Color struct{ R, G, B float64 }

var (
	Black = Color{0.11, 0.15, 0.20}
	Gray  = Color{0.36, 0.41, 0.47}
	Light = Color{0.89, 0.91, 0.93}
	Green = Color{0.18, 0.49, 0.36}
	Red   = Color{0.70, 0.21, 0.18}
	Amber = Color{0.75, 0.54, 0.12}
	Blue  = Color{0.17, 0.37, 0.54}
)

// Doc sammelt Seiten.
type Doc struct {
	pages []*bytes.Buffer
	cur   *bytes.Buffer
	Title string
	Now   time.Time
}

// New beginnt ein Dokument mit einer leeren Seite.
func New(title string, now time.Time) *Doc {
	d := &Doc{Title: title, Now: now}
	d.AddPage()
	return d
}

// AddPage beginnt eine neue Seite.
func (d *Doc) AddPage() {
	d.cur = &bytes.Buffer{}
	d.pages = append(d.pages, d.cur)
}

// Pages: Anzahl der Seiten.
func (d *Doc) Pages() int { return len(d.pages) }

// winAnsi wandelt UTF-8 in WinAnsiEncoding; Unbekanntes wird zu „?“.
func winAnsi(s string) []byte {
	special := map[rune]byte{'€': 0x80, '‚': 0x82, '„': 0x84, '…': 0x85, '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94,
		'•': 0x95, '–': 0x96, '—': 0x97, '™': 0x99}
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			out = append(out, '?')
		case r < 0x20:
			out = append(out, ' ')
		case r < 0x7f:
			out = append(out, byte(r))
		case r >= 0xa0 && r <= 0xff:
			out = append(out, byte(r))
		default:
			if b, ok := special[r]; ok {
				out = append(out, b)
			} else {
				out = append(out, '?')
			}
		}
	}
	return out
}

func escape(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch c {
		case '(', ')', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			if c >= 0x80 {
				fmt.Fprintf(&sb, "\\%03o", c)
			} else {
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}

// Text schreibt eine Zeile; y von oben gemessen.
func (d *Doc) Text(x, y, size float64, bold bool, c Color, s string) {
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(d.cur, "BT %.3f %.3f %.3f rg /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n", c.R, c.G, c.B, font, size, x, Height-y,
		escape(winAnsi(s)))
}

// TextRight schreibt rechtsbündig bis x.
func (d *Doc) TextRight(x, y, size float64, bold bool, c Color, s string) {
	d.Text(x-TextWidth(s, size, bold), y, size, bold, c, s)
}

// Rect füllt ein Rechteck (y = obere Kante, von oben).
func (d *Doc) Rect(x, y, w, h float64, c Color) {
	fmt.Fprintf(d.cur, "%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n", c.R, c.G, c.B, x, Height-y-h, w, h)
}

// Line zeichnet eine Linie.
func (d *Doc) Line(x1, y1, x2, y2, width float64, c Color) {
	fmt.Fprintf(d.cur, "%.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S\n", c.R, c.G, c.B, width, x1, Height-y1, x2, Height-y2)
}

// TextWidth schätzt die Breite (Helvetica-Breiten, ausreichend für Layout).
func TextWidth(s string, size float64, bold bool) float64 {
	w := 0.0
	for _, c := range winAnsi(s) {
		w += charWidth(c, bold)
	}
	return w * size / 1000
}

func charWidth(c byte, bold bool) float64 {
	switch {
	case c == ' ':
		return 278
	case c == 'i' || c == 'j' || c == 'l' || c == '.' || c == ',' || c == ':' || c == ';' || c == '\'' || c == '|' || c == '!':
		return 222 + map[bool]float64{true: 56}[bold]
	case c == 'f' || c == 't' || c == 'r' || c == 'I' || c == '(' || c == ')' || c == '-' || c == '/':
		return 333
	case c == 'm' || c == 'M' || c == 'W':
		return 833 + map[bool]float64{true: 56}[bold]
	case c == 'w':
		return 722 + map[bool]float64{true: 56}[bold]
	case c >= 'A' && c <= 'Z' || c >= 0xc0 && c <= 0xde:
		return 667 + map[bool]float64{true: 55}[bold]
	case c >= '0' && c <= '9':
		return 556
	case c == '%':
		return 889
	default:
		return 556 + map[bool]float64{true: 55}[bold]
	}
}

// Fit kürzt s mit „…“ auf die Breite w.
func Fit(s string, w, size float64, bold bool) string {
	if TextWidth(s, size, bold) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && TextWidth(string(r)+"…", size, bold) > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// Bytes erzeugt die PDF-Datei.
func (d *Doc) Bytes() []byte {
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		n := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	// 1 Katalog, 2 Seitenbaum, 3/4 Schriften, 5 Info; Seiten danach.
	n := len(d.pages)
	firstPage := 6
	kids := make([]string, n)
	for i := range n {
		kids[i] = fmt.Sprintf("%d 0 R", firstPage+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	obj(fmt.Sprintf("<< /Title (%s) /Producer (OpenWacht) /CreationDate (D:%s) >>", escape(winAnsi(d.Title)),
		d.Now.UTC().Format("20060102150405Z")))
	for i, p := range d.pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			Width, Height, firstPage+2*i+1))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", p.Len(), p.String()))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return out.Bytes()
}
