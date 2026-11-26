// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Zertifikate wie web/src/Zertifikate.tsx: alle Sensoren
// „TLS-Zertifikat“ im Bereich, das zuerst ablaufende oben, Filter Alle /
// Bald fällig / Mit Problem. Die Daten stehen schon im Stand (Checks).

import (
	"fmt"
	"time"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

var zert = struct {
	filter int // 0 alle, 1 bald, 2 Probleme
	tage   int
}{tage: 30}

var zertTage = []int{14, 30, 60, 90}

func init() {
	seiten[seiteZertifikate] = &seitenDef{malen: zertMalen, klick: zertKlick}
}

func zertMalen(m *maler, _ any) {
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	ids, mehrere, _ := a.bereich()
	m.klein("Alle Sensoren „TLS-Zertifikat“ im gewählten Bereich, das zuerst ablaufende oben. Datum und Aussteller stammen " +
		"aus dem letzten Lauf des Sensors. Neue Zertifikate kommen über einen Sensor am Gerät dazu (Hosts › Gerät › " +
		"Sensor hinzufügen › TLS-Zertifikat).")
	if st.Zeit.IsZero() {
		m.klein("Lädt …")
		return
	}
	zeilen := desktop.Zertifikate(st.Checks, ids, time.Now())
	nBald, nProb := 0, 0
	for _, z := range zeilen {
		if z.Bald(zert.tage) {
			nBald++
		}
		if z.MitProblem() {
			nProb++
		}
	}
	m.umschalter([]string{fmt.Sprintf("Alle (%d)", len(zeilen)), fmt.Sprintf("Bald fällig (%d)", nBald),
		fmt.Sprintf("Mit Problem (%d)", nProb)}, zert.filter, "filter")
	m.auswahlFeld("bald fällig: höchstens", fmt.Sprintf("%d Tage", zert.tage), "tage", m.s(160))
	var gezeigt []desktop.ZertZeile
	for _, z := range zeilen {
		if zert.filter == 0 || (zert.filter == 1 && z.Bald(zert.tage)) || (zert.filter == 2 && z.MitProblem()) {
			gezeigt = append(gezeigt, z)
		}
	}
	switch {
	case len(zeilen) == 0:
		m.leer("Im gewählten Bereich gibt es noch keinen Sensor „TLS-Zertifikat“.")
		return
	case len(gezeigt) == 0 && zert.filter == 1:
		m.leer(fmt.Sprintf("Kein Zertifikat läuft in den nächsten %d Tagen ab.", zert.tage))
		return
	case len(gezeigt) == 0:
		m.leer("Kein Zertifikat mit Problem.")
		return
	}
	geraete := map[string]string{}
	for _, g := range st.Geraete {
		geraete[g.ID] = g.Name
	}
	var tab [][]sZelle
	for _, z := range gezeigt {
		stand := z.Stand
		if stand == "neu" || stand == "pause" {
			stand = "ende"
		}
		name := geraete[z.Check.GeraetID]
		if name == "" {
			name = "Gerät"
		}
		bis := "–"
		if z.Bis != nil {
			bis = z.Bis.Format("02.01.2006")
		}
		rest := sZelle{text: z.RestText()}
		if z.Bald(zert.tage) {
			rest.fett, rest.farbe = true, th.f.TextWarn
		}
		zelle := sZelle{text: z.Adresse(), fett: true, klein: z.Check.Name}
		if mehrere {
			zelle.mandant = a.mandantName(z.Check.MandantID)
		}
		hinweis := z.Problem
		if hinweis == "" {
			hinweis = z.Aussteller
		}
		tab = append(tab, []sZelle{
			zustandsZelle(stand, desktop.AnzeigeText[z.Stand]),
			zelle,
			{text: name, link: &ziel{art: "geraet", wert: z.Check.GeraetID}},
			{text: bis},
			rest,
			{text: hinweis, farbe: th.f.Leise},
		})
	}
	m.tabelle([]sSpalte{{"Zustand", 14, false}, {"Zertifikat", 26, false}, {"Gerät", 14, false}, {"Gültig bis", 11, false},
		{"Rest", 14, false}, {"Aussteller oder Hinweis", 24, false}}, tab)
}

func zertKlick(z ziel, _ any) {
	switch z.art {
	case "filter":
		fmt.Sscan(z.wert, &zert.filter)
	case "tage":
		texte := make([]string, len(zertTage))
		aktiv := 0
		for i, t := range zertTage {
			texte[i] = fmt.Sprintf("%d Tage", t)
			if t == zert.tage {
				aktiv = i
			}
		}
		if i := a.listeWaehlen(z, texte, aktiv); i >= 0 {
			zert.tage = zertTage[i]
		}
	case "geraet":
		a.hostOeffnen(z.wert)
	}
}
