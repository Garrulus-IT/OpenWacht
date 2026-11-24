# Vertrag zur Auftragsverarbeitung (Vorlage, Art. 28 DSGVO)

**Wann nötig:** Nur wenn ein Dienstleister (z. B. der Hersteller oder ein Systemhaus) im Auftrag des Betreibers Zugriff
auf eine OpenWacht-Installation oder ihre Sicherungen bekommt, etwa bei Fernwartung, Fehlersuche oder Betrieb. Der
reine Kauf bzw. die Nutzung der Software ohne solchen Zugriff ist keine Auftragsverarbeitung.

**Hinweis:** Vorlage ohne Gewähr. Viele Organisationen haben eigene Muster (z. B. von Landesbeauftragten
oder Verbänden); dann gilt deren Muster, und diese Vorlage liefert nur die Angaben zu OpenWacht (Anlagen 1 und 2).

---

zwischen **[Verantwortlicher, Anschrift]** („Auftraggeber“)
und **[Dienstleister, Anschrift]** („Auftragnehmer“)

## § 1 Gegenstand und Dauer

1. Gegenstand: [Fernwartung / Betrieb / Fehlersuche] der Überwachungsplattform OpenWacht des Auftraggebers.
2. Dauer: [Laufzeit des Hauptvertrags vom … / Einzelauftrag vom …].

## § 2 Art, Zweck, Daten und Betroffene

Siehe Anlage 1. Der Auftragnehmer verarbeitet die Daten nur, soweit es für den Auftrag nötig ist, und nicht für
eigene Zwecke.

## § 3 Weisungen

1. Der Auftragnehmer verarbeitet nur auf dokumentierte Weisung des Auftraggebers, auch bei Übermittlungen in
   Drittländer, sofern er nicht gesetzlich verpflichtet ist (dann Mitteilung vorab, soweit erlaubt).
2. Weisungsberechtigt: [Name, Funktion]. Weisungsempfänger: [Name, Funktion].
3. Hält der Auftragnehmer eine Weisung für rechtswidrig, teilt er das unverzüglich mit.

## § 4 Pflichten des Auftragnehmers

1. Vertraulichkeit: Nur Personen, die zur Vertraulichkeit verpflichtet sind, erhalten Zugriff.
2. Sicherheit: Maßnahmen nach Anlage 2 (Art. 32 DSGVO). Zugriff auf die Installation nur
   - mit einem eigenen, persönlichen Konto mit eingerichtetem zweiten Faktor (Authenticator-App oder Passkey),
   - mit der geringsten nötigen Rolle (in der Regel Leser oder Operator im betroffenen Mandanten; Betreiber-Rechte nur
     nach ausdrücklicher Freigabe),
   - für die Dauer des Auftrags; danach sperrt der Auftraggeber das Konto.
3. Kein Kopieren von Datenbank, Sicherungen oder Hauptschlüssel ohne Weisung. Wird eine Kopie zur Fehlersuche nötig,
   dann verschlüsselt, mit Löschung nach Abschluss und Bestätigung in Textform.
4. Unterstützung bei Betroffenenrechten, Meldungen nach Art. 33/34 DSGVO und Folgenabschätzungen.
5. Meldung von Verletzungen des Schutzes personenbezogener Daten an den Auftraggeber unverzüglich, spätestens [24]
   Stunden nach Kenntnis.
6. Nach Ende des Auftrags: Rückgabe oder Löschung aller Daten nach Wahl des Auftraggebers.

## § 5 Unterauftragsverarbeiter

[Keine / folgende, mit Zustimmung des Auftraggebers: …]. Weitere nur nach vorheriger Information mit
Widerspruchsrecht.

## § 6 Kontrollen

Der Auftraggeber darf die Einhaltung prüfen (Auskunft, Nachweise, Vor-Ort-Prüfung nach Anmeldung). Jede Anmeldung und
Änderung des Auftragnehmers steht im Audit-Log von OpenWacht; der Auftraggeber kann es exportieren
(`GET /api/v1/audit/export`).

## § 7 Haftung, Schlussbestimmungen

[Nach Hauptvertrag.]

Ort, Datum, Unterschriften: [ ]

---

## Anlage 1: Beschreibung der Verarbeitung

| Feld | Inhalt |
| --- | --- |
| Art | Zugriff auf die Oberfläche und ggf. die Datenbank von OpenWacht zur [Fernwartung, Fehlersuche, Betrieb] |
| Zweck | Wiederherstellung und Erhalt der Funktion der Überwachung |
| Daten | Konten der Administratoren (E-Mail, Name, Rollen, letzte Anmeldung), Audit-Log, Alarmprotokoll, Gerätenamen und Messwerte; bei Datenbankzugriff zusätzlich verschlüsselte Geheimnisse (ohne Hauptschlüssel nicht lesbar) |
| Betroffene | Beschäftigte des Auftraggebers mit Konto in OpenWacht; mittelbar Personen, deren Name in Gerätenamen steht |
| Ort | [Remote aus der EU / vor Ort] |

## Anlage 2: Technische und organisatorische Maßnahmen

- Maßnahmen der Software: siehe [tom.md](tom.md), Teil A.
- Maßnahmen des Auftragnehmers beim Fernzugriff: [VPN des Auftraggebers / Jump-Host, verschlüsselte Endgeräte,
  persönliche Konten, Protokollierung, …].
