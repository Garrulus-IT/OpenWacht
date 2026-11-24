# Sicherheit bei OpenWacht

## Schwachstellen melden

Bitte melde Sicherheitslücken **nicht** über öffentliche Issues, sondern vertraulich an den Hersteller:

- Meldeweg: **security@garrulus.de** (steht auch als `Contact:` in `/.well-known/security.txt` jeder
  OpenWacht-Installation, Quelle `internal/version/sicherheitskontakt.txt`).
- Betreiber einer Installation geben dort zusätzlich ihren eigenen Kontakt an (Startoption `-sicherheitskontakt`).

Hilfreich sind: betroffene Version (Fußzeile der Oberfläche oder `openwacht-zentrale -version`), Komponente (Zentrale,
Agent, Trap-Dienst), Schritte zum Nachstellen, eingeschätzte Auswirkung. Bitte keine echten Zugangsdaten oder
personenbezogenen Daten mitschicken.

## Was wir zusagen

| Schritt | Frist |
| --- | --- |
| Eingangsbestätigung | 3 Werktage |
| Erste Bewertung mit Schwere | 10 Werktage |
| Korrektur für kritische Lücken | angestrebt 14 Tage |
| Korrektur für hohe Lücken | angestrebt 30 Tage |
| Veröffentlichung | nach Verfügbarkeit der Korrektur, abgestimmt mit der meldenden Person (koordinierte Offenlegung, höchstens 90 Tage nach Eingang) |

Wer meldet, wird auf Wunsch in den Release-Notizen genannt. Gutgläubige Sicherheitsforschung im Rahmen dieser Regeln
verfolgen wir nicht rechtlich; Tests nur an eigenen Installationen.

## Unterstützte Versionen

Sicherheitsupdates gibt es für die jeweils neueste Version der Reihe 1.x; ältere Versionen bitte aktualisieren.
Sobald der Cyber Resilience Act für OpenWacht gilt, sind es mindestens fünf Jahre kostenlose Sicherheitsupdates ab dem
Inverkehrbringen (Art. 13 Abs. 8 CRA). Agent-Updates sind signiert
(Offline-Schlüssel), das Installationspaket hat signierte Prüfsummen (Handbuch Kapitel 12 und 14).

## Meldepflichten (Cyber Resilience Act)

Aktiv ausgenutzte Schwachstellen und schwerwiegende Sicherheitsvorfälle meldet der Hersteller, soweit der CRA für das
Produkt gilt, über die Meldeplattform der ENISA in den gesetzlichen Fristen und informiert die Betreiber.

## Weiteres

- Sicherheitskonzept und Restrisiken: Handbuch Kapitel 17 (Härtung) und die Vorlagen unter [`docs/recht/`](docs/recht/).
- Betreiber: Hinweise zu `security.txt` im Handbuch Kapitel 17.
