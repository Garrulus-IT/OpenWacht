# OpenWacht

Hinweise für Claude in diesem Repository. Aufbau, Bauen und Prüfen stehen in `README.md`.

## Corporate Design (gilt für Garrulus IT und alle vier Produkte)

Ein Erscheinungsbild für die ganze Familie: Garrulus IT, OpenWacht, OpenPforte, OpenChronik und OpenQuartier.

- **Zeichen, Wortmarken, Favicons, App-Symbole, Vorschaubilder und Siegel entstehen nur aus einem Generator:**
  `werkzeuge/logos/bauen.py` im Repository der Website (`Garrulus-IT/website`). Nichts davon von Hand zeichnen oder
  ändern. Neu erzeugen und verteilen:
  `python3 werkzeuge/logos/bauen.py --website --repo <marke>=<pfad>` (Marken: garrulus, openwacht, openpforte,
  openchronik, openquartier).
- **Dateisatz je Marke** in `docs/design/marke/`: `zeichen`, `zeichen-klein`, `zeichen-negativ`,
  `zeichen-klein-negativ`, `zeichen-schwarz`, `zeichen-app`, `favicon` (SVG), `wortmarke-hell`, `wortmarke-dunkel`,
  `wortmarke-schwarz`, `siegel-herkunft-{de,en}-{hell,dunkel}`, `siegel-betrieb-{de,en}-{hell,dunkel}`, dazu
  `favicon-32.png`, `apple-touch-icon.png`, `icon-192.png`, `icon-512.png`, `vorschau-de.png`, `vorschau-en.png`
  (1200 × 630). In `web/public/` liegen `favicon.svg`, `apple-touch-icon.png`, `icon-192.png`, `icon-512.png` aus
  demselben Satz.
- **Favicon immer als abgerundete nachtblaue Kachel** mit dem Zeichen; unter 32 px das kleine Zeichen ohne
  Europakarte.
- **Farben:** Nachtblau `#102238`, Signal-Cyan `#45c3e6`, Karte `#2f5f8f`, Fläche auf dunklem Grund `#1d3a5c`.
  Zustandsfarben und Tokens wie in OpenWacht (`web/src/tokens.css`).
- **Zeichen:** Raster 64 × 64, Kontur Cyan 1,6 (klein 3,2), Dreiklang aus drei Elementen mit Deckkraft 1 / 0,55 /
  0,25, ein weißer Blickpunkt, darunter Deutschland auf der Europakarte.
- **Schrift:** D-DIN (Wortmarke: erster Teil Bold, zweiter Regular, ohne Leerzeichen), JetBrains Mono für Code und
  Werte.
- **Zweisprachig:** Oberfläche, Doku, Klick-Demo, Vorschaubild und Siegel gibt es auf Deutsch und Englisch
  („Entwickelt in Deutschland“ / „Developed in Germany“, „Selbst betrieben · Daten bleiben im Haus“ /
  „Self-hosted · your data stays in-house“).
- Vorgabe im Detail: Vault-Notiz „Konzept Corporate Design OpenWacht“ (gilt für die Familie).
