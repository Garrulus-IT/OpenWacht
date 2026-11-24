# Schriften der Oberfläche

Unveränderte Original-Dateien, nicht neu erzeugt und nicht auf Teilmengen
reduziert. D-DIN hat den reservierten Schriftnamen „D-DIN“: Eine veränderte
Fassung dürfte nicht mehr so heißen.

| Datei | Schrift | Version | Lizenz | Quelle |
| --- | --- | --- | --- | --- |
| `D-DIN.woff2`, `D-DIN-Bold.woff2` | D-DIN, © 2017 Datto Inc. | 1.00 | SIL OFL 1.1 | https://github.com/amcchord/datto-d-din |
| `JetBrainsMono-Regular.woff2` | JetBrains Mono, © 2020 The JetBrains Mono Project Authors | 2.304 | SIL OFL 1.1 | https://github.com/JetBrains/JetBrainsMono |

Die Lizenztexte liegen unter `web/public/lizenzen/` und werden mit der
Oberfläche ausgeliefert (`/lizenzen/OFL-D-DIN.txt`,
`/lizenzen/OFL-JetBrains-Mono.txt`).

`schriften.json` ist die Liste für die Stückliste (`tools/sbom`). Eine neue
Schriftdatei muss dort eingetragen werden, sonst bricht der Build ab.

D-DIN deckt Latin-1 und ISO 8859-15 ab (Deutsch, Englisch, Französisch, …),
aber nicht ł, č oder ő. Solche Zeichen zeichnet der Browser aus der
nächsten Schrift in `--schrift` (Systemschrift).
