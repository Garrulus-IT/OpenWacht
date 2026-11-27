// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Schriften (OFL, unverändert), ihre Lizenztexte und das Bildzeichen, in die
// Programmdatei eingebettet (Liste und Herkunft: schriften/LIESMICH.md,
// marke/LIESMICH.md).
//
//go:embed schriften/*.ttf schriften/OFL-*.txt marke/*.png
var eingebettet embed.FS

// Schriften liefert die TTF-Dateien (Name → Inhalt).
func Schriften() map[string][]byte {
	out := map[string][]byte{}
	ents, _ := fs.ReadDir(eingebettet, "schriften")
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".ttf") {
			b, _ := eingebettet.ReadFile(path.Join("schriften", e.Name()))
			out[e.Name()] = b
		}
	}
	return out
}

// Lizenztexte der Schriften (Dateiname → Text).
func Lizenztexte() map[string][]byte {
	out := map[string][]byte{}
	ents, _ := fs.ReadDir(eingebettet, "schriften")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "OFL-") {
			b, _ := eingebettet.ReadFile(path.Join("schriften", e.Name()))
			out[e.Name()] = b
		}
	}
	return out
}

// Zeichen liefert das kleine Bildzeichen als PNG in der nächstgrößeren
// vorhandenen Größe (mindestens px).
func Zeichen(px int) []byte {
	groessen := []int{24, 32, 40, 48, 64}
	sort.Ints(groessen)
	n := groessen[len(groessen)-1]
	for _, g := range groessen {
		if g >= px {
			n = g
			break
		}
	}
	b, _ := eingebettet.ReadFile(fmt.Sprintf("marke/zeichen-klein-%d.png", n))
	return b
}
