// SPDX-License-Identifier: AGPL-3.0-only

package pdf

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDokument(t *testing.T) {
	d := New("Bericht (Test) – Ärger", time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC))
	d.Text(50, 50, 14, true, Black, "Verfügbarkeit: 99,95 % (Ziel 99,5 %) – Größe €")
	d.Rect(50, 70, 200, 10, Green)
	d.Line(50, 90, 545, 90, 0.5, Gray)
	d.AddPage()
	d.TextRight(545, 50, 9, false, Gray, `Klammer ) und \ Backslash`)
	b := d.Bytes()
	if !bytes.HasPrefix(b, []byte("%PDF-1.4")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("Rahmen")
	}
	if !bytes.Contains(b, []byte("/Count 2")) {
		t.Error("Seitenzahl")
	}
	// Umlaute als WinAnsi (oktal), Klammern escaped
	if !bytes.Contains(b, []byte(`Verf\374gbarkeit`)) || !bytes.Contains(b, []byte(`\226 Gr\366\337e \200`)) {
		t.Error("Umlaute")
	}
	if !bytes.Contains(b, []byte(`Klammer \) und \\ Backslash`)) {
		t.Error("Escape")
	}
	// xref-Einträge zeigen auf die Objekte
	m := regexp.MustCompile(`(?m)^(\d{10}) 00000 n $`).FindAllSubmatch(b, -1)
	if len(m) != 9 {
		t.Fatalf("xref: %d Einträge", len(m))
	}
	for i, x := range m {
		off, _ := strconv.Atoi(string(x[1]))
		if !bytes.HasPrefix(b[off:], []byte(strconv.Itoa(i+1)+" 0 obj")) {
			t.Errorf("xref %d zeigt nicht auf das Objekt", i+1)
		}
	}
	sx := regexp.MustCompile(`startxref\n(\d+)`).FindSubmatch(b)
	off, _ := strconv.Atoi(string(sx[1]))
	if !bytes.HasPrefix(b[off:], []byte("xref")) {
		t.Error("startxref")
	}
	// Streamlänge stimmt
	for _, s := range regexp.MustCompile(`(?s)/Length (\d+) >>\nstream\n(.*?)endstream`).FindAllSubmatch(b, -1) {
		n, _ := strconv.Atoi(string(s[1]))
		if n != len(s[2]) {
			t.Errorf("Length %d, tatsächlich %d", n, len(s[2]))
		}
	}
}

func TestFitUndBreite(t *testing.T) {
	long := strings.Repeat("Dateiserver ", 20)
	f := Fit(long, 100, 9, false)
	if TextWidth(f, 9, false) > 100 || !strings.HasSuffix(f, "…") {
		t.Errorf("%q", f)
	}
	if Fit("kurz", 100, 9, false) != "kurz" {
		t.Error("kurz gekürzt")
	}
	if w := string(winAnsi("a\x00b😀")); w != "a b?" {
		t.Errorf("%q", w)
	}
}
