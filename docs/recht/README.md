# Recht und Nachweise

Vorlagen für den Betreiber einer OpenWacht-Installation (Stand 1.0.0, November 2026). Sie beschreiben, was die
Software tut und speichert, und lassen Lücken für das, was nur der Betreiber weiß (Namen, Zuständigkeiten, eigene
Fristen). **Keine Rechtsberatung:** Die Vorlagen ersetzen nicht die Prüfung durch die eigene Datenschutzbeauftragte
oder einen Anwalt.

| Datei | Wofür | Wer füllt aus |
| --- | --- | --- |
| [Verzeichnis der Verarbeitungstätigkeiten](verzeichnis-verarbeitungstaetigkeiten.md) | Art. 30 DSGVO | Betreiber |
| [Löschkonzept](loeschkonzept.md) | Art. 5 Abs. 1 lit. e, Art. 17 DSGVO, BSI CON.6 | Betreiber, Fristen aus der Software |
| [Technische und organisatorische Maßnahmen](tom.md) | Art. 32 DSGVO | Hersteller (Software), Betreiber (Umgebung) |
| [Auftragsverarbeitung (Vorlage)](auftragsverarbeitung-vorlage.md) | Art. 28 DSGVO, nur bei Fernwartung oder Betrieb durch Dritte | Betreiber und Dienstleister |
| [Zuordnung BSI IT-Grundschutz](bsi-grundschutz.md) | Nachweis im ISMS | Hersteller (Software), Betreiber (Umgebung) |
| [Erklärung zur Barrierefreiheit (Vorlage)](barrierefreiheit-erklaerung.md) | BITV 2.0 / BFSG, wo gefordert | Betreiber |
| [Auftrag externer Penetrationstest](pentest-auftrag.md) | Prüfung vor dem ersten Kunden | Hersteller |

Den Meldeweg für Sicherheitslücken beschreibt [SECURITY.md](../../SECURITY.md).

## Grundsätze, auf die sich die Vorlagen stützen

1. **Selbst betrieben.** OpenWacht läuft beim Betreiber, nicht als Dienst des Herstellers. Der Betreiber ist
   Verantwortlicher im Sinne der DSGVO. Der Hersteller sieht keine Daten, solange er nicht im Auftrag hilft (dann gilt
   die Vorlage zur Auftragsverarbeitung).
2. **Nur Infrastruktur.** OpenWacht überwacht Server, Netzgeräte und Dienste. Arbeitsplatzrechner zu überwachen ist nicht
   vorgesehen; wer es trotzdem tut, muss die Vorlagen erweitern.
3. **Datensparsam.** Agents melden keine Benutzernamen, keine Prozesslisten mit Benutzerbezug und keine Inhalte.
   Personenbezogene Daten entstehen vor allem bei den Konten der Administratoren (Anmeldung, Audit-Log).
4. **Kein Verkehr nach außen.** Die Zentrale baut im Betrieb nur Verbindungen auf, die der Betreiber einträgt
   (Netzfreigabe, Alarmziele, Mail-Relay, Verzeichnisse). Es gibt keine Telemetrie an den Hersteller.

Fristen und Felder in diesen Dateien stammen aus dem Code von 0.35.0 (Migrationen bis 0041). Ändert eine neue Version
etwas daran, steht es in den [Release-Notizen](../release-notizen.md).
