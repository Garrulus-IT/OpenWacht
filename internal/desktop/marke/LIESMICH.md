# Bildzeichen für die Desktop-App

Aus den verbindlichen SVG-Dateien in `docs/design/marke/` gerechnet, nicht
von Hand verändert. Windows kann kein SVG zeichnen, deshalb liegen sie hier
als PNG in den Größen für 100 bis 200 % Skalierung.

| Dateien | Quelle | Einsatz |
| --- | --- | --- |
| `zeichen-klein-<px>.png` | `zeichen-klein.svg` | Markenleiste des Fensters |
| `app-<px>.png` | `zeichen-app.svg` | Programm-, Fenster- und Taskleistensymbol (vom Build als Icon-Ressource in die exe geschrieben) |

Neu erzeugen nach einer Änderung am Zeichen (librsvg):

    for n in 24 32 40 48 64; do rsvg-convert -w $n -h $n docs/design/marke/zeichen-klein.svg -o internal/desktop/marke/zeichen-klein-$n.png; done
    for n in 16 20 24 32 40 48 64 256; do rsvg-convert -w $n -h $n docs/design/marke/zeichen-app.svg -o internal/desktop/marke/app-$n.png; done
