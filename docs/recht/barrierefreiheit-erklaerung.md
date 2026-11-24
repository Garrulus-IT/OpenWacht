# Erklärung zur Barrierefreiheit (Vorlage)

Für Betreiber, die eine Erklärung veröffentlichen müssen (öffentliche Stellen nach BITV 2.0 bzw. Landesrecht; Hinweis:
Die Oberfläche von OpenWacht ist ein internes Werkzeug für Administratoren. Ob eine Pflicht besteht, klärt der Betreiber).

---

[Name der Stelle] ist bemüht, die Oberfläche der Überwachungsplattform OpenWacht unter [Adresse] im Einklang mit
[§ 12a BGG / Landesgesetz] und der BITV 2.0 barrierefrei zugänglich zu machen.

## Stand der Vereinbarkeit

Die Oberfläche ist **teilweise** mit den Anforderungen der WCAG 2.1, Stufe AA, vereinbar.

Grundlage ist eine Prüfung durch den Hersteller mit OpenWacht 0.35.0 (22.11.2026):

- automatisierte Prüfung mit axe-core 4.11 (Regeln WCAG 2.0/2.1 A und AA) auf 15 Ansichten, hell und dunkel, 1280 und
  390 Pixel Breite: keine Funde;
- Bedienung der Anmeldung, der Verwaltung und der Dialoge per Tastatur;
- Prüfung des Zugänglichkeitsbaums (Beschriftungen, Rollen, Überschriften).

Eine Prüfung mit echten Screenreadern (NVDA, JAWS, VoiceOver) und durch Menschen mit Behinderungen steht aus.

## Nicht barrierefreie Inhalte

- **Graphen und Sonnendiagramm** (Dashboard, Wandanzeige, Verlauf): Die Werte sind als Grafik dargestellt; Zustände und
  aktuelle Werte stehen zusätzlich als Text in Tabellen und Listen, der Verlauf über die Zeit nicht.
- **Ziehen und Ablegen** (Gruppen, Widgets): Für jede Ziehaktion gibt es eine Alternative per Auswahlfeld bzw. Knöpfen.
- **QR-Code** beim Einrichten der Authenticator-App: Der Schlüssel steht zusätzlich als Text daneben.
- **PDF-Berichte** (Monatsbericht, Rezertifizierung): Sie sind nicht getaggt (kein PDF/UA). Dieselben Inhalte gibt es in
  der Oberfläche bzw. als CSV.
- **Passkeys**: Der Dialog des Betriebssystems bzw. Browsers liegt außerhalb von OpenWacht.

## Erstellung dieser Erklärung

Erstellt am [Datum], zuletzt überprüft am [Datum]. Methode: Selbstbewertung (siehe oben).

## Feedback und Kontakt

Mängel in der Barrierefreiheit melden Sie bitte an: [E-Mail, Telefon].

## Durchsetzungsverfahren

[Schlichtungsstelle nach § 16 BGG bzw. die zuständige Stelle des Landes, mit Adresse.]
