// SPDX-License-Identifier: AGPL-3.0-only

package main

// Assistent im Agent-MSI (1.0.6): Wer das Paket per Doppelklick startet,
// gibt Zentrale und Token in einem Fenster ein und gibt dort Sensoren und den
// Sammler frei, ohne Kommandozeile. Still per GPO/Intune (msiexec /qn) gelten
// weiter die Eigenschaften; dazu kommen SENSOREN, ORDNER, INDIKATOREN und
// NETZE. Die Dialoge sind Tabellen der MSI-Datenbank (MSI SDK „Dialog“,
// „Control“, „ControlEvent“ …); Maße in Dialogeinheiten, 370 × 270 wie die
// Assistenten von Windows Installer.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
)

// Eigenschaften des Assistenten. Die Kästchen setzen ihre Eigenschaft auf
// die Art, wie sie „sensoren -arten“ erwartet; ArtenSetzen fügt alles zu
// OW_ARTEN zusammen.
var msiKaestchen = []struct{ prop, art, text string }{
	{"OW_S_DIENST", "dienst", "Windows-Dienste (läuft ein Dienst?)"},
	{"OW_S_AUTO", "autodienste", "Alle automatisch startenden Dienste"},
	{"OW_S_PROZESS", "prozess", "Prozesse (läuft ein Programm?)"},
	{"OW_S_DATEI", "datei", "Dateien und Ordner (Alter, Größe, Anzahl) unter:"},
	{"OW_S_INDIKATOR", "leistungsindikator", "Leistungsindikatoren aus den Objekten:"},
	{"OW_S_HYPERV", "hyperv", "Hyper-V (virtuelle Maschinen dieses Hosts)"},
}

// msiOeffentlich: Eigenschaften, die von der Oberfläche bzw. der Befehlszeile
// in die Ausführung gelangen müssen (SecureCustomProperties).
func msiOeffentlich() string {
	s := "ZENTRALE;TOKEN;HOSTNAME;SENSOREN;ORDNER;INDIKATOREN;NETZE"
	for _, k := range msiKaestchen {
		s += ";" + k.prop
	}
	return s
}

// msiArtenZiel: Wert für OW_ARTEN (Typ 51), leere Teile entfernt der Agent.
func msiArtenZiel() string {
	s := "[SENSOREN]"
	for _, k := range msiKaestchen {
		s += ",[" + k.prop + "]"
	}
	return s
}

type msiCtrl struct {
	name, typ  string
	x, y, w, h int
	attr       int
	prop       any // string oder nil
	text       any // string oder nil
	fokus      bool
}

// Attribute der Steuerelemente (MSI SDK „Control Table“).
const (
	ctlSichtbar   = 1
	ctlAn         = 2
	ctlVertieft   = 4
	ctlDurchsicht = 0x10000
	ctlOhnePraefx = 0x20000
	ctlPasswort   = 0x200000
	ctlSchild     = 0x800000 // Schild der Benutzerkontensteuerung
	ctlText       = ctlSichtbar | ctlAn | ctlDurchsicht | ctlOhnePraefx
	ctlFeld       = ctlSichtbar | ctlAn | ctlVertieft
	ctlKnopf      = ctlSichtbar | ctlAn
)

const (
	dlgSichtbar = 1
	dlgModal    = 2
	dlgModeless = 4
	dlgFehler   = 65536
)

type msiDlg struct {
	name, titel  string
	attr         int
	ctrls        []msiCtrl
	vor, abbruch string // Knopf für Enter bzw. Esc
}

// rahmen: Kopf in Nachtblau mit Bildzeichen (Banner), darauf Titel und
// Beschreibung in Weiß, Linien und Knöpfe unten. Das Banner steht als erstes
// Steuerelement in der Tabelle, damit die Texte darüber liegen.
func rahmen(titel, text string, knoepfe ...msiCtrl) []msiCtrl {
	c := []msiCtrl{
		{name: "Banner", typ: "Bitmap", x: 0, y: 0, w: 370, h: 59, attr: ctlSichtbar, text: "OwBanner"},
		{name: "Titel", typ: "Text", x: 20, y: 11, w: 290, h: 16, attr: ctlText, text: "{\\OwTitel}" + titel},
		{name: "Beschreibung", typ: "Text", x: 20, y: 30, w: 290, h: 24, attr: ctlText, text: "{\\OwHell}" + text},
		{name: "LinieOben", typ: "Line", x: 0, y: 59, w: 370, h: 0, attr: ctlSichtbar},
		{name: "LinieUnten", typ: "Line", x: 0, y: 234, w: 370, h: 0, attr: ctlSichtbar},
	}
	return append(c, knoepfe...)
}

func knopf(name, text string, x int, an bool) msiCtrl {
	a := ctlKnopf
	if !an {
		a = ctlSichtbar
	}
	return msiCtrl{name: name, typ: "PushButton", x: x, y: 243, w: 56, h: 17, attr: a, text: text, fokus: an}
}

var (
	kZurueck    = knopf("Zurueck", "&Zurück", 180, true)
	kZurueckAus = knopf("Zurueck", "&Zurück", 180, false)
	kWeiter     = knopf("Weiter", "&Weiter", 236, true)
	kAbbrechen  = knopf("Abbrechen", "Abbrechen", 304, true)
)

func msiDialoge() []msiDlg {
	modal := dlgSichtbar | dlgModal
	titel := "[ProductName] [ProductVersion]"
	text := func(name string, y, h int, t string) msiCtrl {
		return msiCtrl{name: name, typ: "Text", x: 20, y: y, w: 330, h: h, attr: ctlText, text: t}
	}
	feld := func(name, prop string, y int, attr int, max int) msiCtrl {
		return msiCtrl{name: name, typ: "Edit", x: 20, y: y, w: 330, h: 18, attr: attr, prop: prop, text: fmt.Sprintf("{%d}", max), fokus: true}
	}
	var sensoren []msiCtrl
	y := 72
	for _, k := range msiKaestchen {
		sensoren = append(sensoren, msiCtrl{name: "K" + k.prop[5:], typ: "CheckBox", x: 20, y: y, w: 330, h: 14, attr: ctlKnopf,
			prop: k.prop, text: k.text, fokus: true})
		y += 16
		switch k.prop {
		case "OW_S_DATEI":
			sensoren = append(sensoren, msiCtrl{name: "Ordner", typ: "Edit", x: 34, y: y, w: 316, h: 16, attr: ctlFeld, prop: "ORDNER",
				text: "{250}", fokus: true})
			y += 20
		case "OW_S_INDIKATOR":
			sensoren = append(sensoren, msiCtrl{name: "Indikatoren", typ: "Edit", x: 34, y: y, w: 316, h: 16, attr: ctlFeld,
				prop: "INDIKATOREN", text: "{250}", fokus: true})
			y += 20
		}
	}
	sensoren = append(sensoren, text("Hinweis", y+4, 12, "Mehrere Ordner bzw. Objekte trennst du mit Komma."))
	return []msiDlg{
		{name: "WillkommenDlg", titel: titel, attr: modal, vor: "Weiter", abbruch: "Abbrechen", ctrls: rahmen(
			"Willkommen",
			"Richtet den OpenWacht-Agent auf diesem Rechner ein.",
			kZurueckAus, kWeiter, kAbbrechen,
			text("Text", 72, 64, "Der Agent läuft als Dienst „openwacht-agent“ und meldet Messwerte dieses Rechners "+
				"verschlüsselt an deine OpenWacht-Zentrale. Er nimmt keine Verbindungen an und führt keine Befehle aus, "+
				"die die Zentrale schickt; Sensoren misst er nur, wenn du sie im übernächsten Schritt freigibst."),
			text("Text2", 124, 40, "Du brauchst die Adresse des Agent-Ports der Zentrale und ein Registrierungs-Token. Beides "+
				"findest du in OpenWacht unter Benutzer und Mandanten › Agent-Tokens."),
		)},
		{name: "ZentraleDlg", titel: titel, attr: modal, vor: "Weiter", abbruch: "Abbrechen", ctrls: rahmen(
			"Verbindung zur Zentrale",
			"Bei einem Update bleiben Adresse und Token leer.",
			kZurueck, kWeiter, kAbbrechen,
			text("LZentrale", 72, 12, "Adresse der Zentrale mit Port für Agents, z. B. https://openwacht.firma.de:8444"),
			feld("Zentrale", "ZENTRALE", 85, ctlFeld, 250),
			text("LToken", 112, 12, "Registrierungs-Token (Agent-Token)"),
			feld("Token", "TOKEN", 125, ctlFeld|ctlPasswort, 250),
			text("LHost", 152, 12, "Name des Rechners in OpenWacht (leer = Computername)"),
			feld("Host", "HOSTNAME", 165, ctlFeld, 63),
			text("Hinweis", 194, 30, "Der Agent meldet sich damit einmal an und bekommt ein eigenes Zertifikat. Das Token "+
				"wird nicht gespeichert und erscheint nicht im Installationsprotokoll."),
		)},
		{name: "SensorenDlg", titel: titel, attr: modal, vor: "Weiter", abbruch: "Abbrechen", ctrls: append(rahmen(
			"Sensoren freigeben",
			"Ohne Häkchen meldet der Agent nur CPU, Speicher, Platten und Netz.",
			kZurueck, kWeiter, kAbbrechen,
		), sensoren...)},
		{name: "SammlerDlg", titel: titel, attr: modal, vor: "Weiter", abbruch: "Abbrechen", ctrls: rahmen(
			"Sammler für SNMP-Geräte",
			"Freiwillig: SNMP-Geräte abfragen, die die Zentrale nicht erreicht.",
			kZurueck, kWeiter, kAbbrechen,
			text("LNetze", 72, 12, "Netze, in denen der Agent SNMP-Geräte abfragen darf (leer = kein Sammler):"),
			msiCtrl{name: "Netze", typ: "Edit", x: 20, y: 85, w: 330, h: 18, attr: ctlFeld, prop: "NETZE", text: "{250}", fokus: true},
			text("Hinweis", 112, 40, "Zum Beispiel 10.20.0.0/16, mehrere mit Komma getrennt. Welche Geräte der Sammler "+
				"abfragt, legst du danach in OpenWacht beim Gerät unter SNMP fest („Abgefragt von“)."),
		)},
		{name: "BereitDlg", titel: titel, attr: modal, vor: "Installieren", abbruch: "Abbrechen", ctrls: rahmen(
			"Bereit zur Installation",
			"Ziel: C:\\Program Files\\OpenWacht",
			kZurueck,
			msiCtrl{name: "Installieren", typ: "PushButton", x: 236, y: 243, w: 56, h: 17, attr: ctlKnopf | ctlSchild, text: "&Installieren", fokus: true},
			kAbbrechen,
			text("Text", 72, 60, "Mit „Installieren“ fragt Windows nach Administratorrechten. Danach wird der Dienst "+
				"eingerichtet und, mit Token, bei der Zentrale registriert. Der Rechner erscheint dann in OpenWacht unter Hosts."),
		)},
		{name: "ProgressDlg", titel: titel, attr: dlgSichtbar | dlgModeless, vor: "Abbrechen", abbruch: "Abbrechen", ctrls: rahmen(
			"OpenWacht-Agent wird eingerichtet",
			"Bitte warten, das dauert meist nur einige Sekunden.",
			kAbbrechen,
			msiCtrl{name: "Aktion", typ: "Text", x: 20, y: 80, w: 330, h: 12, attr: ctlText},
			msiCtrl{name: "Fortschritt", typ: "ProgressBar", x: 20, y: 96, w: 330, h: 12, attr: ctlSichtbar | 1<<16},
		)},
		{name: "WartungDlg", titel: titel, attr: modal, vor: "Abbrechen", abbruch: "Abbrechen", ctrls: rahmen(
			"OpenWacht-Agent ist installiert",
			"Diese Version ist schon eingerichtet.",
			msiCtrl{name: "Entfernen", typ: "PushButton", x: 236, y: 243, w: 56, h: 17, attr: ctlKnopf | ctlSchild, text: "&Entfernen", fokus: true},
			kAbbrechen,
			text("Text", 72, 60, "„Entfernen“ hält den Dienst an und entfernt Agent und Dienst. Die Registrierung im "+
				"Ordner C:\\ProgramData bleibt, damit eine spätere Installation ohne neues Token weiterläuft."),
		)},
		{name: "ExitDlg", titel: titel, attr: modal, vor: "Fertig", abbruch: "Fertig", ctrls: rahmen(
			"Fertig",
			"Der OpenWacht-Agent ist eingerichtet.",
			msiCtrl{name: "Fertig", typ: "PushButton", x: 304, y: 243, w: 56, h: 17, attr: ctlKnopf, text: "&Fertig", fokus: true},
			text("Text", 72, 60, "Mit Token läuft jetzt der Dienst „openwacht-agent“, und der Rechner erscheint in OpenWacht "+
				"unter Hosts. Ohne Token richtest du ihn später mit „openwacht-agent registrieren“ ein."),
		)},
		{name: "FatalErrorDlg", titel: titel, attr: modal, vor: "Fertig", abbruch: "Fertig", ctrls: rahmen(
			"Einrichtung fehlgeschlagen",
			"Agent und Dienst sind wieder entfernt.",
			msiCtrl{name: "Fertig", typ: "PushButton", x: 304, y: 243, w: 56, h: 17, attr: ctlKnopf, text: "&Fertig", fokus: true},
			text("Text", 72, 50, "Die Ursache steht in der Ereignisanzeige unter Windows-Protokolle › Anwendung, Quelle "+
				"„openwacht-agent“, z. B. Token falsch oder abgelaufen, Zentrale nicht erreichbar oder falscher Port für Agents."),
			text("Text2", 128, 50, "Hatte sich der Agent schon registriert, bleibt die Registrierung erhalten: Ein zweiter "+
				"Versuch braucht dann kein neues Token."),
		)},
		{name: "UserExitDlg", titel: titel, attr: modal, vor: "Fertig", abbruch: "Fertig", ctrls: rahmen(
			"Abgebrochen",
			"Der Rechner ist unverändert.",
			msiCtrl{name: "Fertig", typ: "PushButton", x: 304, y: 243, w: 56, h: 17, attr: ctlKnopf, text: "&Fertig", fokus: true},
		)},
		{name: "CancelDlg", titel: titel, attr: modal, vor: "Nein", abbruch: "Nein", ctrls: []msiCtrl{
			{name: "Text", typ: "Text", x: 20, y: 15, w: 220, h: 24, attr: ctlText, text: "Möchtest du die Einrichtung abbrechen?"},
			{name: "Ja", typ: "PushButton", x: 100, y: 50, w: 56, h: 17, attr: ctlKnopf, text: "&Ja", fokus: true},
			{name: "Nein", typ: "PushButton", x: 164, y: 50, w: 56, h: 17, attr: ctlKnopf, text: "&Nein", fokus: true},
		}},
		{name: "FehlerDlg", titel: titel, attr: modal, vor: "OK", abbruch: "OK", ctrls: []msiCtrl{
			{name: "Text", typ: "Text", x: 20, y: 15, w: 220, h: 40, attr: ctlText, text: "[OW_FEHLER]"},
			{name: "OK", typ: "PushButton", x: 184, y: 62, w: 56, h: 17, attr: ctlKnopf, text: "OK", fokus: true},
		}},
		// Meldungen von Windows Installer (Datei in Benutzung u. a.): Knöpfe A, C, I, N, O, R, Y nach SDK
		{name: "ErrorDlg", titel: "[ProductName]", attr: dlgSichtbar | dlgModal | dlgFehler, vor: "O", abbruch: "C", ctrls: []msiCtrl{
			{name: "ErrorText", typ: "Text", x: 20, y: 15, w: 280, h: 60, attr: ctlText},
			{name: "A", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Abbrechen", fokus: true},
			{name: "C", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Abbrechen", fokus: true},
			{name: "I", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Ignorieren", fokus: true},
			{name: "N", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Nein", fokus: true},
			{name: "O", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "OK", fokus: true},
			{name: "R", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Wiederholen", fokus: true},
			{name: "Y", typ: "PushButton", x: 240, y: 82, w: 56, h: 17, attr: ctlKnopf, text: "Ja", fokus: true},
		}},
	}
}

// msiDialogGroesse: kleine Dialoge für Rückfragen und Fehler.
func msiDialogGroesse(name string) (int, int) {
	switch name {
	case "CancelDlg", "FehlerDlg":
		return 260, 85
	case "ErrorDlg":
		return 320, 105
	}
	return 370, 270
}

// Ereignisse der Knöpfe: Dialog, Knopf, Ereignis, Argument, Bedingung, Reihenfolge.
func msiEreignisse() [][]any {
	zentraleFehlt := "ZENTRALE AND NOT TOKEN OR TOKEN AND NOT ZENTRALE"
	ordnerFehlt := "OW_S_DATEI AND NOT ORDNER"
	indikatorFehlt := "OW_S_INDIKATOR AND NOT INDIKATOREN"
	abbrechen := func(dlg string) []any { return []any{dlg, "Abbrechen", "SpawnDialog", "CancelDlg", "1", 1} }
	return [][]any{
		{"WillkommenDlg", "Weiter", "NewDialog", "ZentraleDlg", "1", 1},
		abbrechen("WillkommenDlg"),
		{"ZentraleDlg", "Zurueck", "NewDialog", "WillkommenDlg", "1", 1},
		{"ZentraleDlg", "Weiter", "[OW_FEHLER]", "Bitte Adresse und Token zusammen angeben oder beide leer lassen (Update eines registrierten Agents).", zentraleFehlt, 1},
		{"ZentraleDlg", "Weiter", "SpawnDialog", "FehlerDlg", zentraleFehlt, 2},
		{"ZentraleDlg", "Weiter", "NewDialog", "SensorenDlg", "NOT (" + zentraleFehlt + ")", 3},
		abbrechen("ZentraleDlg"),
		{"SensorenDlg", "Zurueck", "NewDialog", "ZentraleDlg", "1", 1},
		{"SensorenDlg", "Weiter", "[OW_FEHLER]", "Für Dateien und Ordner bitte mindestens einen Ordner angeben, z. B. C:\\Daten\\Export.", ordnerFehlt, 1},
		{"SensorenDlg", "Weiter", "[OW_FEHLER]", "Für Leistungsindikatoren bitte mindestens ein Objekt angeben, z. B. SwyxServer.", indikatorFehlt + " AND NOT (" + ordnerFehlt + ")", 2},
		{"SensorenDlg", "Weiter", "SpawnDialog", "FehlerDlg", ordnerFehlt + " OR " + indikatorFehlt, 3},
		{"SensorenDlg", "Weiter", "NewDialog", "SammlerDlg", "NOT (" + ordnerFehlt + ") AND NOT (" + indikatorFehlt + ")", 4},
		abbrechen("SensorenDlg"),
		{"SammlerDlg", "Zurueck", "NewDialog", "SensorenDlg", "1", 1},
		{"SammlerDlg", "Weiter", "NewDialog", "BereitDlg", "1", 1},
		abbrechen("SammlerDlg"),
		{"BereitDlg", "Zurueck", "NewDialog", "SammlerDlg", "1", 1},
		{"BereitDlg", "Installieren", "EndDialog", "Return", "1", 1},
		abbrechen("BereitDlg"),
		abbrechen("ProgressDlg"),
		{"WartungDlg", "Entfernen", "Remove", "ALL", "1", 1},
		{"WartungDlg", "Entfernen", "EndDialog", "Return", "1", 2},
		{"WartungDlg", "Abbrechen", "EndDialog", "Exit", "1", 1},
		{"ExitDlg", "Fertig", "EndDialog", "Return", "1", 1},
		{"FatalErrorDlg", "Fertig", "EndDialog", "Exit", "1", 1},
		{"UserExitDlg", "Fertig", "EndDialog", "Exit", "1", 1},
		{"CancelDlg", "Ja", "EndDialog", "Exit", "1", 1},
		{"CancelDlg", "Nein", "EndDialog", "Return", "1", 1},
		{"FehlerDlg", "OK", "EndDialog", "Return", "1", 1},
		{"ErrorDlg", "A", "EndDialog", "ErrorAbort", "1", 1},
		{"ErrorDlg", "C", "EndDialog", "ErrorCancel", "1", 1},
		{"ErrorDlg", "I", "EndDialog", "ErrorIgnore", "1", 1},
		{"ErrorDlg", "N", "EndDialog", "ErrorNo", "1", 1},
		{"ErrorDlg", "O", "EndDialog", "ErrorOk", "1", 1},
		{"ErrorDlg", "R", "EndDialog", "ErrorRetry", "1", 1},
		{"ErrorDlg", "Y", "EndDialog", "ErrorYes", "1", 1},
	}
}

// msiUITabellen: Dialoge, Steuerelemente, Ereignisse, Schriften, Kästchen.
func msiUITabellen() []msiTable {
	dialog := msiTable{name: "Dialog", cols: []msiCol{{"Dialog", cK(72)}, {"HCentering", cI2()}, {"VCentering", cI2()},
		{"Width", cI2()}, {"Height", cI2()}, {"Attributes", cI4N()}, {"Title", cLN(128)}, {"Control_First", cS(50)},
		{"Control_Default", cSN(50)}, {"Control_Cancel", cSN(50)}}}
	control := msiTable{name: "Control", cols: []msiCol{{"Dialog_", cK(72)}, {"Control", cK(50)}, {"Type", cS(20)},
		{"X", cI2()}, {"Y", cI2()}, {"Width", cI2()}, {"Height", cI2()}, {"Attributes", cI4N()}, {"Property", cSN(72)},
		{"Text", cLN(0)}, {"Control_Next", cSN(50)}, {"Help", cLN(50)}}}
	for _, d := range msiDialoge() {
		// Fokus zuerst auf der ersten Eingabe, sonst auf dem Knopf für Enter
		erst := d.vor
		for _, c := range d.ctrls {
			if c.fokus && c.attr&ctlAn != 0 && c.typ != "PushButton" {
				erst = c.name
				break
			}
		}
		// Tab-Reihenfolge: Eingaben in Reihenfolge, dann alle Knöpfe (auch
		// ausgegraute, wie bei WiX). Windows Installer verlangt einen
		// geschlossenen Kreis, auch bei nur einem Steuerelement (sonst Fehler
		// 2814), deshalb zeigt ein einzelnes auf sich selbst.
		var reihe []string
		for _, c := range d.ctrls {
			if c.fokus && c.attr&ctlAn != 0 && c.typ != "PushButton" {
				reihe = append(reihe, c.name)
			}
		}
		for _, c := range d.ctrls {
			if c.typ == "PushButton" {
				reihe = append(reihe, c.name)
			}
		}
		naechst := map[string]any{}
		for i, n := range reihe {
			naechst[n] = reihe[(i+1)%len(reihe)]
		}
		w, h := msiDialogGroesse(d.name)
		dialog.rows = append(dialog.rows, []any{d.name, 50, 50, w, h, d.attr, d.titel, erst, d.vor, d.abbruch})
		for _, c := range d.ctrls {
			n := naechst[c.name]
			control.rows = append(control.rows, []any{d.name, c.name, c.typ, c.x, c.y, c.w, c.h, c.attr, c.prop, c.text, n, nil})
		}
	}
	event := msiTable{name: "ControlEvent", cols: []msiCol{{"Dialog_", cK(72)}, {"Control_", cK(50)}, {"Event", cK(50)},
		{"Argument", cK(255)}, {"Condition", cSNK(255)}, {"Ordering", cI2N()}}, rows: msiEreignisse()}
	cond := msiTable{name: "ControlCondition", cols: []msiCol{{"Dialog_", cK(72)}, {"Control_", cK(50)}, {"Action", cK(50)},
		{"Condition", cK(255)}}, rows: [][]any{
		{"SensorenDlg", "Ordner", "Disable", "NOT OW_S_DATEI"}, {"SensorenDlg", "Ordner", "Enable", "OW_S_DATEI"},
		{"SensorenDlg", "Indikatoren", "Disable", "NOT OW_S_INDIKATOR"}, {"SensorenDlg", "Indikatoren", "Enable", "OW_S_INDIKATOR"},
	}}
	mapping := msiTable{name: "EventMapping", cols: []msiCol{{"Dialog_", cK(72)}, {"Control_", cK(50)}, {"Event", cK(50)},
		{"Attribute", cS(50)}}, rows: [][]any{
		{"ProgressDlg", "Aktion", "ActionText", "Text"},
		{"ProgressDlg", "Fortschritt", "SetProgress", "Progress"},
	}}
	check := msiTable{name: "CheckBox", cols: []msiCol{{"Property", cK(72)}, {"Value", cSN(64)}}}
	for _, k := range msiKaestchen {
		check.rows = append(check.rows, []any{k.prop, k.art})
	}
	style := msiTable{name: "TextStyle", cols: []msiCol{{"TextStyle", cK(72)}, {"FaceName", cS(32)}, {"Size", cI2()},
		{"Color", cI4N()}, {"StyleBits", cI2N()}}, rows: [][]any{
		{"OwText", "Segoe UI", 9, nil, nil},
		{"OwTitel", "Segoe UI", 12, 0xffffff, 1}, // fett, weiß auf dem Banner
		{"OwHell", "Segoe UI", 9, 0xf6ede4, 0},   // --nacht-tinte #e4edf6 (BGR)
	}}
	bild := msiTable{name: "Binary", cols: []msiCol{{"Name", cK(72)}, {"Data", cV()}}, rows: [][]any{
		{"OwBanner", msiStrom(msiBanner())},
	}}
	// Text unter dem Fortschritt, damit das Warten auf die Zentrale einen Namen hat.
	aktion := msiTable{name: "ActionText", cols: []msiCol{{"Action", cK(72)}, {"Description", cLN(0)}, {"Template", cLN(0)}},
		rows: [][]any{
			{"InstallFiles", "Dateien werden kopiert", nil},
			{"StopServices", "Dienst wird angehalten", nil},
			{"PaketEinrichten", "Agent wird als Dienst eingerichtet, bei der Zentrale registriert und gestartet", nil},
			{"PaketEntfernen", "Dienst wird entfernt", nil},
		}}
	return []msiTable{dialog, control, event, cond, mapping, check, style, bild, aktion}
}

// msiBanner: Kopf der Dialoge als BMP (24 Bit), 740 × 118 Pixel für 370 × 59
// Dialogeinheiten: Fläche in --nacht #102238, rechts das Bildzeichen
// (internal/desktop/marke/zeichen-klein-64.png) auf dem Nachtblau.
func msiBanner() []byte {
	const w, h = 740, 118
	nacht := [3]byte{0x10, 0x22, 0x38}
	px := make([][3]byte, w*h)
	for i := range px {
		px[i] = nacht
	}
	if img := msiZeichen(); img != nil {
		b := img.Bounds()
		x0, y0 := w-24-b.Dx(), (h-b.Dy())/2
		for y := 0; y < b.Dy(); y++ {
			for x := 0; x < b.Dx(); x++ {
				r, g, bl, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
				if a == 0 {
					continue
				}
				i := (y0+y)*w + x0 + x
				// vormultiplizierte Werte: c = src + dst·(1−a)
				px[i] = [3]byte{
					byte(r>>8 + uint32(nacht[0])*(0xffff-a)/0xffff),
					byte(g>>8 + uint32(nacht[1])*(0xffff-a)/0xffff),
					byte(bl>>8 + uint32(nacht[2])*(0xffff-a)/0xffff),
				}
			}
		}
	}
	zeile := (w*3 + 3) &^ 3
	var buf bytes.Buffer
	le := binary.LittleEndian
	buf.WriteString("BM")
	binary.Write(&buf, le, uint32(14+40+zeile*h))
	binary.Write(&buf, le, uint32(0))
	binary.Write(&buf, le, uint32(14+40))
	for _, v := range []any{uint32(40), int32(w), int32(h), uint16(1), uint16(24), uint32(0), uint32(zeile * h),
		int32(3780), int32(3780), uint32(0), uint32(0)} {
		binary.Write(&buf, le, v)
	}
	for y := h - 1; y >= 0; y-- { // BMP: unterste Zeile zuerst
		z := make([]byte, zeile)
		for x := 0; x < w; x++ {
			p := px[y*w+x]
			z[x*3], z[x*3+1], z[x*3+2] = p[2], p[1], p[0]
		}
		buf.Write(z)
	}
	return buf.Bytes()
}

// msiZeichen: Bildzeichen aus dem Repository (Bau aus dem Wurzelverzeichnis
// oder Test aus tools/build).
func msiZeichen() image.Image {
	for _, d := range []string{".", filepath.Join("..", "..")} {
		b, err := os.ReadFile(filepath.Join(d, "internal", "desktop", "marke", "zeichen-klein-64.png"))
		if err != nil {
			continue
		}
		if img, err := png.Decode(bytes.NewReader(b)); err == nil {
			return img
		}
	}
	return nil
}
