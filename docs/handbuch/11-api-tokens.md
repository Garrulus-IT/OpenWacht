# 11. API-Tokens

Für Skripte und andere Werkzeuge (Inventar, Ticketsystem). **Benutzer und Mandanten → API-Tokens → Token anlegen**
(Admins des Mandanten, mit Bestätigung): Name, Rolle **Leser** oder **Operator**, 1–365 Tage.

![API-Tokens](bilder/api-tokens.webp)

Das Token (`owt1.…`) wird genau einmal angezeigt; gespeichert ist nur sein Hash. Aufruf:

```bash
curl -H "Authorization: Bearer owt1.…" https://openwacht.beispiel.example/api/v1/mandanten
curl -H "Authorization: Bearer owt1.…" https://openwacht.beispiel.example/api/v1/geraete
```

- Ein Token sieht und darf, was seine Rolle im Mandanten und darunter erlaubt, nie Admin-Rechte.
- Nicht möglich: Sitzungen, Zwei-Faktor, Verwaltung und Einstellungen.
- Höchstens 300 Anfragen je Minute und Token. Anlegen und Widerrufen stehen im Audit. „Zuletzt benutzt“ zeigt, ob ein
  Token noch gebraucht wird; „Widerrufen“ sperrt es sofort.

## Beschreibung der API (OpenAPI)

Die lesenden Endpunkte, die ein Token mit der Rolle **Leser** nutzen darf, sind in
[`docs/api/openapi.json`](../api/openapi.json) beschrieben (OpenAPI 3.1). Die Datei liegt auch im Paket der Zentrale unter
`/usr/share/doc/openwacht-zentrale/openapi.json` und lässt sich in Werkzeuge wie Swagger UI, Postman oder einen
Generator für Clients laden.

| Bereich | Endpunkte |
| --- | --- |
| Mandanten | `/api/v1/mandanten` |
| Geräte | `/api/v1/geraete`, `/api/v1/gruppen`, `/api/v1/agents`, `/api/v1/snmp`, Verläufe `…/{id}/verlauf`, `/api/v1/geraete/{id}/sparklines` |
| Sensoren | `/api/v1/sensoren` (alle Sensoren mit Zustand), `/api/v1/checks`, `/api/v1/kennfarben` |
| Alarme | `/api/v1/alarme`, `/api/v1/wartung`, `/api/v1/snmp/{id}/traps` |
| Berichte | `/api/v1/berichte` (auch `/pdf`), `/api/v1/prognose/platten`, `/api/v1/dashboard/kennzahlen`, `/api/v1/dashboard/verlauf` |
| Betrieb | `/api/v1/gesund` (ohne Token) |

Beispiele:

```bash
T="Authorization: Bearer owt1.…"
Z=https://openwacht.beispiel.example
curl -H "$T" "$Z/api/v1/sensoren"                                   # alle Sensoren mit Zustand
curl -H "$T" "$Z/api/v1/alarme?limit=50"                            # neueste Alarme
curl -H "$T" "$Z/api/v1/agents/<id>/verlauf?zeitraum=7t"            # Verlauf, 1h, 24h, 7t oder 30t
curl -H "$T" -o bericht.pdf "$Z/api/v1/berichte/pdf?mandant=<id>&monat=2026-10"
```

- Fehler kommen als JSON `{"fehler": "…"}` mit Status 400, 401, 403, 404 oder 429 (dann mit `Retry-After`). Objekte
  anderer Mandanten antworten wie fehlende mit 404.
- Neue Felder können in späteren Versionen dazukommen; Skripte sollen unbekannte Felder übergehen. Entfernt oder
  umbenannt wird ein Feld nur mit Hinweis in den Release-Notizen.
- Weitere lesende Routen (Verwaltung, Formulare und persönliche Einstellungen der Oberfläche) sind absichtlich nicht
  beschrieben und können sich ohne Ankündigung ändern.
- Ein Test prüft die Datei bei jedem Lauf gegen den Code: Jeder beschriebene Endpunkt antwortet einem Leser-Token mit
  200 und passt zum Schema, und jeder lesende Endpunkt, den ein Leser-Token erreicht, ist beschrieben oder bewusst
  ausgenommen.
