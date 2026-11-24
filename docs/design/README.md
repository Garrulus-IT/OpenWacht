# Corporate Design OpenWacht

Verbindliche Vorgabe für das Erscheinungsbild von OpenWacht: Marke, Siegel, Farben, Schrift, Raster, Zustände, Piktogramme und Sprache. Sie gilt für Oberfläche, Mails, PNG-Graphen, Wandanzeige, Handbuch und Website.

Stand 22.11.2026, Status **verbindlich** für Name und Bildzeichen (Vorab-Markenrecherche ohne Konflikt; anwaltliche Prüfung erst vor einer Anmeldung). Gewählte Richtung: „Norm + Leuchtfeuer“, Bildzeichen „Wachendes Auge“ mit Herkunftssiegel, Name OpenWacht (fest seit 22.11.2026).

| Datei | Inhalt |
| --- | --- |
| [`tokens.css`](tokens.css) | alle Farben, Schriftgrößen, Abstände und Radien (hell und dunkel), einzige Quelle |
| [`marke/`](marke/) | Bildzeichen in allen Fassungen und die zwei Siegel als SVG |
| [`muster.html`](muster.html) | Musterseite: Marke, Farben mit gemessenem Kontrast, Zustände, Bausteine |

## 1. Grundsätze

1. **Zustand vor Dekoration.** Farbe und Form gehören zuerst dem Zustand. Die Marke tritt dahinter zurück.
2. **Nie nur Farbe.** Jeder Zustand hat eine eigene Form und einen Text.
3. **Deutsch in der Ordnung, europäisch in der Wirkung.** DIN-Schrift, Raster und Schildlogik, dazu Nachtblau und Signal-Cyan. Keine Hoheitszeichen.
4. **Eine Quelle für alles.** Oberfläche, Mail, PNG und Wandanzeige nutzen dieselben Tokens.
5. **Barrierefrei als Untergrenze.** WCAG 2.2 AA ist Pflicht und wird bei jeder Änderung gemessen.

## 2. Marke

### Bildzeichen „Wachendes Auge“

Entschieden am 22.11.2026. Ein Auge, dessen Iris ein Radarschirm ist. Der Mittelpunkt liegt über Deutschland, im Auge liegt Europa. „Wacht“ bedeutet wachen und schauen, das Radar steht für Überwachung im Sinne von Monitoring.

| Datei | Einsatz |
| --- | --- |
| `marke/zeichen.svg` | ab 32 px: Anmeldeseite, Wandanzeige, Handbuch, Website |
| `marke/zeichen-klein.svg` | unter 32 px: Favicon, Tab, Seitenleiste (ohne Karte, kräftigere Linien) |
| `marke/zeichen-app.svg` | App-Icon und Startbildschirm (Auge im nachtblauen Quadrat) |
| `marke/zeichen-schwarz.svg` | einfarbig, z. B. Druck, Stempel |
| `marke/zeichen-negativ.svg` | einfarbig auf Weiß |
| `marke/wortmarke-hell.svg` | Zeichen und Schriftzug für helle Flächen (Schrift in Pfaden) |
| `marke/wortmarke-dunkel.svg` | Zeichen und Schriftzug für dunkle Flächen |
| `marke/wortmarke-schwarz.svg` | Zeichen und Schriftzug einfarbig |

- **Aufbau (Raster 64 × 64):**
  - Augenform aus zwei Bögen von 2 bis 62 (`M2 32 C14 12 50 12 62 32 C50 52 14 52 2 32 Z`), Fläche Nachtblau `#102238`, Kontur Signal-Cyan `#45c3e6` mit 1,6.
  - Im Auge der Umriss Europas in `#2f5f8f`, verschoben so, dass Deutschland in der Mitte (32 | 32) liegt. Daten: Natural Earth 1:110 Mio. (gemeinfrei), flächentreue Azimutalprojektion.
  - Iris: Radarringe mit den Radien 7, 12 und 16,5 in Cyan.
  - Strahl mit Nachleuchten: drei Sektoren zu je 30°, Deckkraft 0,42, 0,22 und 0,10, Führungskante bei −40° in Weiß.
  - Pupille: weißer Punkt mit Radius 2,6.
- **Schutzraum:** ringsum ¼ der Zeichenbreite. **Mindestgröße:** 16 px Breite (Fassung „klein“) bzw. 8 mm im Druck.
- **Verboten:**
  - Flaggen, Sternenkranz, Adler und Wappen, auch angedeutet (§ 8 Abs. 2 Nr. 6 und Abs. 4 MarkenG, Art. 6ter PVÜ)
  - Zustandsfarben im Zeichen
  - Verzerren, Drehen, Schatten
  - zusätzliche Wimpern oder Lider (bleibt geometrisch)
- **Markenrecherche:** Auge mit konzentrischen Kreisen ist in den Klassen 9 und 42 verbreitet (DPMAregister: 49 lebende Marken mit Bildklassen 02.09.04 + 26.01.05). Erst die Kombination aus Radarstrahl und Europakarte macht das Zeichen eigenständig. Deshalb Strahl und Karte nie weglassen. Ausnahme: die kleine und die einfarbige Fassung, dort bleibt der Strahl.

### Wortmarke

- „**Open**“ in D-DIN Bold, „Wacht“ in D-DIN Regular, ohne Leerzeichen. Abstand zum Bildzeichen ¼ der Zeichenhöhe.
- Unterzeile „Open-Source-Monitoring aus Europa“ (OpenWacht steht unter der AGPL-3.0-only).
- Als Datei: `marke/wortmarke-hell.svg`, `-dunkel.svg` und `-schwarz.svg`. Die Schrift ist dort in Pfade umgewandelt, mit Unterschneidung über HarfBuzz, und sieht ohne installierte Schrift gleich aus. Mindesthöhe 24 px.

### Herkunftssiegel

- `marke/siegel-deutschland.svg`: „Entwickelt in Deutschland“ mit Deutschland-Umriss (Natural Earth 1:50 Mio.)
- `marke/siegel-im-haus.svg`: „Selbst betrieben · Daten bleiben im Haus“
- Einsatz: Anmeldeseite (unter dem Formular), Website, Handbuch-Titel, Release-Seite. Nicht in der Seitenleiste und nicht in Mails.
- Nicht verwenden: „DSGVO-konform“ oder ein DSGVO-Siegel. Ob die DSGVO eingehalten wird, hängt vom Betreiber ab, nicht von der Software.

## 3. Farben

Alle Werte stehen in [`tokens.css`](tokens.css). Kontrast in Klammern, gemessen auf `--flaeche` nach WCAG.

| Token | Hell | Dunkel | Verwendung |
| --- | --- | --- | --- |
| `--marke` | `#0b6a8a` (6,1) | `#45c3e6` (8,3) | Akzent: Knöpfe, Links, aktiver Menüpunkt, Panel-Oberkante |
| `--marke-tief` | `#0a4f68` (9,0) | `#86d9f0` (10,8) | Text in Markenfarbe, Zweitknöpfe |
| `--auf-marke` | `#ffffff` (6,1) | `#04161e` (9,0) | Text auf Markenfarbe |
| `--nacht` | `#102238` | `#060c14` | Seitenleiste, Kopf, Befehlsblöcke |
| `--nacht-tinte` | `#e4edf6` (13,6) | `#dfe8f2` | Text in der Seitenleiste |
| `--tinte` | `#14202e` (16,5) | `#dfe8f2` (13,9) | Text |
| `--leise` | `#526172` (6,3) | `#94a6ba` (6,9) | Nebentext |
| `--linie` | `#c9d3de` | `#2a3a4d` | Rahmen, nur Schmuck |

**Zustände:**

| Zustand | Form | Fläche hell / dunkel | Text auf Hauch hell / dunkel |
| --- | --- | --- | --- |
| OK | Kreis | `#2c7a57` (5,2) / `#5cb88b` (7,1) | `#1f6446` (7,1) / `#7fd0a6` (9,4) |
| Warnung | Dreieck | `#b07c12` (3,7) / `#dba843` (7,9) | `#7d5600` (6,6) / `#e6b85c` (9,3) |
| Kritisch | Achteck | `#b3362f` (6,0) / `#e8685d` (5,4) | `#9c2a24` (7,6) / `#f08a80` (7,1) |
| Bestätigt | Achteck-Umriss mit Haken | Hauch von Kritisch | wie Kritisch |
| Unbekannt | gestricheltes Quadrat | `#7b8590` (3,8) / `#8a95a1` (5,6) | `--leise` |
| Wartung / pausiert | Raute | `#6b4f8f` (6,7) / `#b49ad8` (7,0) | `--tinte` |

- Warnung (3,7:1) nur als Fläche, Rand oder Symbol, nie als Textfarbe auf Weiß. Für Text gilt `--text-warn`.
- Wartung ist **Violett**, weil die Marke blau ist. Blau ist nie ein Zustand.
- **Graphenreihen** (`--reihe-1` … `--reihe-4`):

  | Reihe | Hell | Dunkel |
  | --- | --- | --- |
  | 1 Blau | `#2a78d6` | `#3987e5` |
  | 2 Magenta | `#d6457f` | `#d9488a` |
  | 3 Cyan | `#0a97b0` | `#0e98ae` |
  | 4 Indigo | `#5a63d8` | `#8188f2` |

  - Höchstens 8 Linien (wie bisher im Dashboard). Die Reihen 5–8 nehmen die Farben 1–4 erneut, gestrichelt (`--reihe-strich`, 6/4). Eine neunte Farbe wird nie erzeugt.
  - Prüfung mit dem Dataviz-Prüfskript: Hell bestehen alle Prüfungen (Farbabstand bei Farbfehlsichtigkeit ≥ 8,6, normal ≥ 16,9, Kontrast ≥ 3:1). Dunkel liegt Cyan/Magenta bei Farbfehlsichtigkeit bei 7,1, das ist im Grenzband. Zulässig ist das nur mit zweiter Kennzeichnung, deshalb gilt: Legende immer, ab 2 Reihen direkte Beschriftung am Linienende.
  - Keine Zustandsfarbe als Reihe: kein Grün, Gelb, Orange, Rot, Violett. Orange ist bewusst ausgelassen, weil es in Monitoring-Oberflächen als Warnung gelesen wird.
  - Die Farbe gehört zur Reihe (Host, Wert), nicht zum Rang. Filtern färbt die verbleibenden Reihen nicht um.
- Wandanzeige (immer dunkel) und Mail (immer hell): Werte siehe `tokens.css`.

## 4. Schrift

- **Text und Überschriften:** D-DIN (Datto, SIL OFL 1.1) in Regular 400 und Bold 700, selbst ausgeliefert als unveränderte WOFF2-Originale (keine Teilmenge: „D-DIN“ ist ein reservierter Schriftname, eine veränderte Fassung dürfte nicht so heißen). Zwischenstufen gibt es nicht; die Oberfläche nutzt nur 400 und 700.
- **Werte, Befehle, Zeitstempel:** JetBrains Mono (SIL OFL 1.1), Regular.
- **Ersatz:** `system-ui` bzw. `ui-monospace`. D-DIN fehlen ł, č, ő und Pfeile, diese kommen gewollt aus der Ersatzschrift.
- **Skala (große Terz 1,25, Basis 16 px):** 13 / 16 / 20 / 25 / 31 / 39 px (`--s-1` … `--s4`). Andere Größen sind nicht erlaubt.
- In Tabellen gelten Tabellenziffern. D-DIN hat keine (proportionale Ziffern, kein `tnum`); Zahlenspalten stehen deshalb in JetBrains Mono. Versalien nur für Tabellenköpfe und Zustandsmarken, mit Sperrung +0,05 em.
- **Lizenz:** Die Schriftdateien liegen unter `web/src/schriften/` (Liste `schriften.json`, Herkunft in `LIESMICH.md`), die OFL-Texte unter `web/public/lizenzen/` und werden mit ausgeliefert. Die Stückliste (`tools/sbom`) führt jede Datei mit SHA-256 und Lizenz; eine nicht eingetragene Schriftdatei bricht den Build ab. Ausnahme „SIL OFL 1.1 nur für Schriftdateien“ in `CONTRIBUTING.md`.

## 5. Raster, Abstände, Formen

- **Abstände:** 4 / 8 / 12 / 16 / 24 / 32 / 48 px (`--a1` … `--a7`), andere Werte sind nicht erlaubt.
- **Radien:** 3 px für Bedienelemente, 6 px für Panels. 50 % nur für runde Zustandsformen. Keine Pillenformen.
- **Linien:** 1 px. Panels haben eine Oberkante von 3 px in `--marke`, Meldungen einen linken Rand von 4 px in der Zustandsfarbe.
- **Schatten:** nur für schwebende Elemente (Menüs, Dialoge).
- **Dashboard:** 12-Spalten-Raster wie bisher.

## 6. Zustandsformen und Piktogramme

- **Zustandsformen** nach der Logik von Verkehrszeichen:
  - Kreis = OK
  - Dreieck = Warnung
  - Achteck = kritisch
  - Raute = Wartung
  - gestricheltes Quadrat = unbekannt
  - Achteck-Umriss mit Haken = bestätigt

  Raster 16, als SVG unter `web/public/formen/`. Die Oberfläche färbt sie per CSS-Maske ein (`.signal-*`, `.kachel-*`, `.zst-*`), daher keine `data:`-URLs. Ohne Wertung (pausiert, neu, gesperrt) steht ein Kreisring.
- **Piktogramme** im Stil von Otl Aicher:
  - Raster 24, Strich 2 px, eckige Enden.
  - Nur 0°, 45° und 90°, dazu Kreise.
  - Eigene SVG-Symbole ohne Bibliothek.

## 7. Sprache

- **Anrede:** du (wie in der Oberfläche).
- **Begriffe:**
  - Gerät (das Menü heißt „Hosts“)
  - Sensor statt „Check“ in sichtbaren Texten
  - Alarm für das Ereignis, Meldung für die Nachricht
  - Mandant und Untermandant
- **Zustandsnamen:** OK, Warnung, Kritisch, Bestätigt, Unbekannt, Wartung. Kurzform nur im Mail-Betreff: OK, WARN, KRIT.
- **Ton:** sachlich, kurz, aktiv. Fehlermeldungen nennen Ursache und nächsten Schritt. Keine Ausrufezeichen, keine Emojis.
- **Format:** `4,2 %`, `22.11.2026, 14:05`, „vor 12 Min.“.

### Textbausteine

| Lage | So | Nicht so |
| --- | --- | --- |
| Fehler beim Speichern | „Speichern fehlgeschlagen: Der Name ist schon vergeben. Wähle einen anderen Namen.“ | „Fehler 409!“ |
| Fehler ohne Verbindung | „Die Zentrale antwortet nicht. Die Anzeige versucht es alle 30 s erneut.“ | „Netzwerkfehler“ |
| Gefährliche Aktion | Titel „Gerät löschen?“, Text nennt, was verschwindet; Knopf „pve-1 löschen“ | Knopf „OK“ / „Ja“ |
| Erfolg | „Gespeichert.“ oder „Sensor angelegt.“ – kurz, ohne Ausrufezeichen | „Erfolgreich gespeichert!!“ |
| Leere Liste | „Noch keine Geräte. Lege das erste mit „+ Gerät“ an oder installiere einen Agent.“ | „Keine Daten“ |
| Leere Alarmliste | „Keine aktiven Alarme.“ | „Alles super!“ |
| Wartung | „In Wartung bis 18:00 · Patchday“ | „Pausiert (Wartung)“ |
| Zeit | „seit 14:05 (vor 12 Min.)“ | „2026-11-22T14:05:00Z“ |
| Rechte fehlen | „Dafür brauchst du die Rolle Admin. Frag einen Admin dieses Mandanten.“ | „403 Forbidden“ |
| Knopfbeschriftung | Verb + Gegenstand: „Sensor hinzufügen“, „Jetzt abfragen“ | „Hinzufügen“, „Ausführen“ |

Regeln: Ursache zuerst, dann nächster Schritt. Fachbegriffe nur, wenn der Admin sie braucht (z. B. „SNMPv3 authPriv“). Fehlercodes gehören in Klammern ans Ende, wenn sie bei der Suche helfen: „… (HTTP 502)“.

## 8. Anwendungen

| Ort | Regel |
| --- | --- |
| Oberfläche | Tokens hell/dunkel, Seitenleiste `--nacht`, im Leistenkopf `zeichen-klein.svg` |
| Anmeldeseite | `zeichen.svg` groß, Wortmarke, beide Siegel |
| App-Icon, Startbildschirm | `zeichen-app.svg` |
| Mail | immer hell, Kopfbalken in Zustandsfarbe mit weißer Schrift ≥ 4,5:1 (Warnung `--text-warn`, Unbekannt `--leise`), Link `--marke` |
| PNG-Graph | Linie `--marke`, Schwellen gestrichelt in Warnung und Kritisch, Achsen `--leise` |
| Wandanzeige | immer dunkel, `zeichen.svg` in der Mitte des Sonnendiagramms, Formen auf auffälligen Hosts |
| Handbuch, Website | Titel mit Zeichen, Wortmarke und Siegel |
| Favicon | `zeichen-klein.svg` (als `web/public/favicon.svg`) |
| Home-Bildschirm | `web/public/apple-touch-icon.png` (180 px), `icon-192.png`, `icon-512.png`, `manifest.json` mit `display: browser` |

## 9. Umbau (D4)

| Schritt | Inhalt | sichtbar |
| --- | --- | --- |
| D4a | `web/src/tokens.css` mit den Namen aus `docs/design/tokens.css`, alle festen Farben in `styles.css` durch Tokens ersetzt (Wandanzeige eingeschlossen), eigene Tokens für Wartung. Werte unverändert, berechnete Stile vorher/nachher identisch | nein |
| D4b | Schrift (mit Lizenz-Ausnahme und SBOM), neue Werte in `web/src/tokens.css`, Wartung in Violett, Graphenreihen mit Strichelung, Schriftstärken nur 400/700 | ja |
| D4b-2 | Schriftgrößen und Abstände auf die Skalen abbilden (aus D4a verschoben), Zahlenspalten in JetBrains Mono, Zustandsformen | ja |
| D4c | Bausteine und Piktogramme, Sprache angleichen | ja |
| D4d | Wandanzeige auf die Tokens (Mail `report.go` und PNG `chart.go` sind vorgezogen) | ja |
| D4e | Bildzeichen in der Oberfläche, Anmeldeseite mit Siegeln, Bilder im Handbuch (Favicon, Wortmarke als Pfade, App-Icon und Manifest sind vorgezogen) | ja |

Jeder Schritt ist ein eigener Pull Request mit Bildschirmfotos (vorher/nachher, hell/dunkel, 1280/390 px) und automatisch gemessenem Kontrast.

**Stand: abgeschlossen (0.40.0).** Alle Schritte D4a bis D4e sind umgesetzt. Die Bilder in Handbuch und README erzeugt
seitdem `npm run bilder` (`web/werkzeuge/bilder.ts`) aus erfundenen Demodaten; nach sichtbaren Änderungen an der
Oberfläche das Skript erneut laufen lassen.

## Quellen

- Kartenumrisse: [Natural Earth](https://www.naturalearthdata.com/) 1:110 Mio. und 1:50 Mio., gemeinfrei. Einmalig mit d3-geo in SVG-Pfade umgerechnet, keine Abhängigkeit im Projekt.
- D-DIN: Datto Inc., SIL Open Font License 1.1, reservierter Name „D-DIN“.
- JetBrains Mono: JetBrains, SIL Open Font License 1.1.
