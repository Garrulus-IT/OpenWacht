// SPDX-License-Identifier: AGPL-3.0-only

// openwacht-desktop (1.0.4): OpenWacht im Infobereich von Windows. Das Symbol
// zeigt den schlimmsten offenen Alarm (Form und Farbe), neue Alarme,
// Verschlechterungen und Entwarnungen kommen als Benachrichtigung von Windows.
// Ab 1.0.6 zeigt ein eigenes Fenster Mandanten, Gruppen, Geräte und Sensoren
// in einem Baum mit Sensorliste; mit einem API-Token der Rolle Operator lassen sich dort
// Geräte und Sensoren pflegen, mit der Rolle Leser nur ansehen. Das Token
// liegt in der Windows-Anmeldeinformationsverwaltung.
//
// Aufruf: openwacht-desktop             Symbol im Infobereich (beim ersten Start Einrichtung)
//
//	openwacht-desktop einrichten  Adresse und Token neu eingeben
//	openwacht-desktop entfernen   Token, Einstellungen und Autostart löschen
package main

import "os"

func main() { os.Exit(run(os.Args[1:])) }
