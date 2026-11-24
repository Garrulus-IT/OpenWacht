# Beiträge zu OpenWacht

Danke für dein Interesse. OpenWacht steht unter der GNU AGPL v3 (`AGPL-3.0-only`, siehe `LICENSE`).

## Beiträge

**Pull Requests von Dritten nehmen wir derzeit nicht an.** Fehler und Wünsche gern als Issue mit Beschreibung.
Sollten wir später Beiträge annehmen, dann nur mit einer Beitragslizenz (Contributor License Agreement, CLA), die
dem Herausgeber die Rechte gibt, OpenWacht neben der AGPL auch unter anderen Lizenzen anzubieten.

## Sicherheitslücken

Nicht über Issues, sondern vertraulich: siehe [`SECURITY.md`](SECURITY.md).

## Regeln für Code

- Zentrale und Agent in Go, Oberfläche in TypeScript (`web/`). Jede Quelldatei beginnt mit
  `SPDX-License-Identifier: AGPL-3.0-only`.
- `gofmt`, `go vet`, `go test -race ./...` und `govulncheck` müssen grün sein.
- Neue Abhängigkeiten nur mit Begründung und nur unter MIT, BSD-2/3-Clause, ISC, Apache-2.0 oder MPL-2.0; keine GPL,
  LGPL oder AGPL. Ausnahme nur für Schriftdateien: SIL OFL 1.1 (unverändert, Lizenztext unter `web/public/lizenzen/`,
  eingetragen in `web/src/schriften/schriften.json`).
- Statisch bauen (`CGO_ENABLED=0`), über `go run ./tools/build`; möglichst nur die Standardbibliothek.
- Kommentare, Fehlermeldungen, Oberfläche und Doku auf Deutsch, Bezeichner auf Englisch.
