# 18. Recht und Nachweise

OpenWacht läuft beim Betreiber; er ist für den Datenschutz verantwortlich. Unter [`docs/recht/`](../recht/README.md)
liegen Vorlagen, die beschreiben, was die Software speichert und wie lange, und Lücken für die Angaben des Betreibers
lassen:

- Verzeichnis der Verarbeitungstätigkeiten, Löschkonzept mit den Fristen der Software, technische und organisatorische
  Maßnahmen,
- Vorlage zur Auftragsverarbeitung (nur bei Fernwartung durch Dritte),
- Zuordnung zum BSI IT-Grundschutz (Kompendium Edition 2023),
- Erklärung zur Barrierefreiheit,
- Entwurf für einen externen Penetrationstest.

## Was der Betreiber einstellen sollte

| Wo | Was | Kapitel |
| --- | --- | --- |
| Einstellungen → Installation | Aufbewahrung des Audit-Logs (Standard unbegrenzt) und der Sicherungen | 13 |
| Einstellungen → Aufbewahrung | Messwerte global und je Mandant | 16 |
| Startoption `-sicherheitskontakt` | eigener Meldeweg in `security.txt` | 17 |
| Verwaltung → Mandanten | Rezertifizierung im festen Turnus | 3 |

## Barrierefreiheit

Die Oberfläche ist mit axe-core (WCAG 2.1 A/AA) auf allen Hauptseiten, hell und dunkel, breit und schmal, geprüft und
per Tastatur bedienbar. Grafiken (Graphen, Sonnendiagramm) haben Text-Alternativen für Zustände, nicht für den Verlauf;
PDF-Berichte sind nicht getaggt. Details und offene Punkte in der Vorlage zur Erklärung.

## Lizenz

OpenWacht ist freie Software unter der GNU Affero General Public License, Version 3 (`AGPL-3.0-only`); der Volltext
liegt in `LICENSE` und in jeder Installation unter `/lizenzen/AGPL-3.0.txt`. Für den Betrieb heißt das:

- Nutzen, auch gewerblich und für Kunden, ist ohne Lizenzgebühr erlaubt.
- Wer OpenWacht **verändert** und die veränderte Fassung anderen über das Netz zur Verfügung stellt (z. B. Mandanten
  einer gemeinsamen Zentrale), muss ihnen den Quellcode genau dieser Fassung anbieten (§ 13). Die Oberfläche verlinkt
  dafür unter der Anmeldung und in der Seitenleiste den Quellcode; bei einer eigenen Fassung zeigt der Link auf den
  eigenen Quellcode (`web/src/Lizenz.tsx`).
- Wer OpenWacht weitergibt (Paket, Offline-Paket), gibt die Lizenz und den Quellcode mit oder bietet ihn an.

Die mitgelieferten Schriften stehen unter der SIL Open Font License 1.1 (`/lizenzen/`). Das ist eine Zusammenfassung,
keine Rechtsberatung; im Zweifel gilt der Lizenztext.

## Sicherheitslücken

Meldeweg und Zusagen: [`SECURITY.md`](../../SECURITY.md).
