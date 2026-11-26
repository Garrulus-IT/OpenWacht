# Schriften der Desktop-App

Unveränderte Original-Dateien (TrueType), nicht neu erzeugt und nicht auf
Teilmengen reduziert. Windows lädt sie beim Start aus der Programmdatei
(`AddFontMemResourceEx`, nur für diesen Prozess); installiert wird nichts.
WOFF2 kann Windows dafür nicht lesen, deshalb liegen hier dieselben Schriften
wie in `web/src/schriften/` als TTF aus denselben Quellen.

| Datei | Schrift | Version | Lizenz | Quelle |
| --- | --- | --- | --- | --- |
| `D-DIN.ttf`, `D-DIN-Bold.ttf` | D-DIN, © 2017 Datto Inc. | 1.00 | SIL OFL 1.1 | https://github.com/amcchord/datto-d-din (Stand e199c84, aus dem auch die WOFF2-Dateien der Oberfläche stammen) |
| `JetBrainsMono-Regular.ttf` | JetBrains Mono, © 2020 The JetBrains Mono Project Authors | 2.304 | SIL OFL 1.1 | https://github.com/JetBrains/JetBrainsMono (Tag v2.304, `fonts/ttf/`) |

Die Lizenztexte `OFL-D-DIN.txt` und `OFL-JetBrains-Mono.txt` sind in die
Programmdatei eingebettet; `openwacht-desktop lizenzen` legt sie neben die
Datei bzw. zeigt, wo sie stehen.

`schriften.json` ist die Liste für die Stückliste (`tools/sbom`). Eine neue
Schriftdatei muss dort eingetragen werden, sonst bricht der Build ab.
