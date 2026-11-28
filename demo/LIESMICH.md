# Klick-Demo

Die Klick-Demo ist das echte OpenWacht im Browser, kein Nachbau:

- **Zentrale:** derselbe Go-Code wie im Programm, als WebAssembly übersetzt (`cmd/openwacht-demo`). Sie beantwortet die Anfragen, die ein Service Worker abfängt, und arbeitet im Hintergrund wie im Betrieb: Sensoren, Abfragen, Alarme, Verläufe.
- **Datenbank:** PostgreSQL als [PGlite](https://pglite.dev) (Apache-2.0), mit denselben Migrationen, Funktionen und Zeilenrichtlinien (RLS). Die Zentrale arbeitet wie im Betrieb als Rolle in `openwacht_app`.
- **Oberfläche:** derselbe Build aus `web/`.
- **Netz:** Im Browser gibt es keins. Die Simulation (`cmd/openwacht-demo/sim.go`) spielt die Gegenstellen: Agents melden über den echten Agent-Handler (mit Zertifikaten aus einer echten Registrierung beim Bau), Ping, HTTP, TLS & Co. und die Abfragen (SNMP, Proxmox, FRITZ!Box) bekommen erfundene, aber stimmige Antworten. Die Zentrale bemerkt davon nur, dass die Antworten aus der Simulation kommen (`zentrale.Config.Simulation`, im Betrieb immer leer).

Nichts verlässt den Browser. Vom Webserver kommen nur die Dateien unter `/_demo/` und `/demo-sw.js`. Der Stand (Datenbank, Anmeldung) bleibt in IndexedDB, bis jemand in der Leiste „Zurücksetzen“ wählt.

## Was die Demo zeigt

Hauptmandant „Beispiel GmbH“ (Köln) mit den Untermandanten „Standort Bonn“ und „Praxis am Markt“ (betreuter Kunde): Server mit Agent (Windows und Linux), Firewall, Switches mit Ports, PoE und LLDP (Topologie), NAS, USV, Drucker mit Toner, Proxmox-Host mit Gästen, FRITZ!Box, Websites mit Zertifikat. Ein paar Dinge stimmen absichtlich nicht: Die Platte D: von srv-file01 läuft voll, PostgreSQL in Bonn steht, die Sicherung der Praxis ist zu alt, das Intranet antwortet mit 502, ein Agent meldet sich nie.

Personen (Passwort für alle in der Leiste der Demo):

| Person | Rolle |
| --- | --- |
| Alex Admin | Admin und Betreiber, sieht alles (mit zweitem Faktor; die Leiste zeigt den Code) |
| Jonas Weber | Operator, bestätigt Alarme |
| Lea Schmidt | nur lesen |
| Ben Bonn | Admin, sieht nur den Standort Bonn |
| Paula Praxis | Kundin, sieht nur ihre Praxis |

Verlauf über Tage: Beim Bau entstehen keine Messwerte, damit ihre Zeiten im Browser stimmen. Beim Start ergänzt die Demo den Verlauf rückwärts aus den ersten Meldungen (`verlauf.go`): Rohwerte für den letzten Tag, Verdichtungen für sieben und 30 Tage. Wer nach Tagen wiederkommt, bekommt die Lücke ebenso gefüllt.

## Bauen

```sh
cd demo
npm ci
node bauen.mjs --basis=/openwacht/demo                 # alles, etwa drei Minuten
node bauen.mjs --basis=/openwacht/demo --nur-dateien   # Daten behalten, nur Code neu
```

Braucht Go und Node wie das Programm. Ablauf:

1. Die Oberfläche wird gebaut (`--ohne-oberflaeche`: die schon gebaute nehmen, etwa eine unminifizierte zum Fehlersuchen).
2. Die Zentrale (für diesen Rechner) migriert eine PGlite-Datenbank über einen lokalen Socket und richtet sie ein.
3. Danach startet die Demo-Zentrale (`cmd/openwacht-demo/nativ.go`, ohne Hintergrundarbeit), und über die HTTP-API entstehen Mandanten, Geräte, Sensoren und Personen. Die Agents registrieren sich über den echten Handler (`POST /_demo/agents`, nur beim Bau).
4. Der Stand der Datenbank wird gespeichert (`_demo/daten.tar.gz`), dazu kommen die Zentrale als WebAssembly, PGlite und der Service Worker.

Ergebnis in `demo/ausgabe/`, etwa 16 MB. Die großen Dateien liegen schon gepackt vor, der Service Worker entpackt sie
(`DecompressionStream`); die Größe hängt damit nicht davon ab, ob der Webserver komprimiert.

| Pfad | Inhalt |
| --- | --- |
| `demo-sw.js` | Service Worker (gebündelt, mit PGlite) |
| `_demo/openwacht.wasm.gz` | Zentrale |
| `_demo/daten.tar.gz` | Datenbank mit Beispieldaten |
| `_demo/pglite/` | PostgreSQL als WebAssembly (`*.gz`) |
| `_demo/demo.json` | Version, Personen, Agents, Demo-Schlüssel (alles erfunden, schützt nichts) |
| `index.html`, `_demo/start.html`, `hilfe.js` … | Startseite und Leiste der Demo (Deutsch oder Englisch nach der Sprache des Browsers) |

Zum Fehlersuchen: `"debug": true` in `_demo/demo.json` schreibt jede Nachricht an PGlite in die Konsole des Service
Workers. `openwacht-demo -laufen ausgabe/_demo/demo.json` lässt die Zentrale samt Hintergrundarbeit auf dem Rechner
laufen (gegen PGlite über einen Socket), etwa um mit `SIGQUIT` hängende Goroutinen zu finden.

## Ansehen und prüfen

```sh
node zeigen.mjs           # http://localhost:8099/openwacht/demo/
npm run pruefen           # Tests der Demo (Chrome)
```

## Ausliefern

`--basis` ist der Pfad, unter dem die Demo liegt, etwa `/openwacht/demo` auf `garrulus.de` (ohne Angabe: die Wurzel
einer eigenen Domain). Die Zentrale bekommt ihn als Basis-Pfad wie im Betrieb (Basis-URL mit Pfad), der Service Worker
gilt nur für diesen Pfad. Der Rest der Website bleibt unberührt.

Der Webserver liefert `demo/ausgabe/` unter dem Pfad statisch aus (auf der Website: `public/openwacht/demo/`).
Er braucht dafür:

- `Content-Type: application/wasm` für `.wasm` (Caddy und die meisten Server tun das von selbst);
- eine Content-Security-Policy, die `'wasm-unsafe-eval'` für Skripte erlaubt;
- empfohlen: unbekannte Pfade unter dem Pfad → `_demo/start.html`. Ohne das funktioniert der Einstieg über
  `/openwacht/demo/` trotzdem, nur ein direkter Link tief in die Demo zeigt beim allerersten Besuch die 404-Seite.

Beispiel für Caddy:

```
handle /openwacht/demo/* {
	try_files {path} /openwacht/demo/_demo/start.html
	file_server
}
```

## Grenzen

- **Keine Verbindung nach draußen:** Mail, SMS, ntfy, Webhooks, Anmeldung über AD oder Firmen-Login und Updates gehen nicht. Der Mail-Kanal der Demo meldet deshalb „Mailversand nicht eingerichtet“. Die Knöpfe sind trotzdem da wie im Programm.
- **Erfundene Gegenstellen:** Neue Geräte und Sensoren, die man in der Demo anlegt, beantwortet die Simulation nur grob (Ping und TCP gehen, Unbekanntes meldet „in der Demo nicht simuliert“). Traps gibt es keine.
- **Eine Sitzung für alles:** PGlite hat nur ein Backend. Die Verbindungen der Zentrale teilen es sich der Reihe nach; eine Anfrage, die die Zentrale mitten in einer Transaktion über eine zweite Verbindung stellt, läuft in einem Sicherungspunkt dieser Transaktion (`pgconn.go`). Die Rolle für den Trap-Dienst gibt es, sie wird nie benutzt.
- **Mehrere Personen gleichzeitig:** Jeder Browser hat seine eigene Demo. Die Rollen lassen sich nacheinander über die Leiste ausprobieren.
- **Die Datenbank:** PGlite ist PostgreSQL in einer neueren Hauptversion als im Betrieb. Die Migrationen laufen unverändert.
- **Nur Deutsch in der Oberfläche:** OpenWacht selbst ist (noch) einsprachig; Startseite und Leiste der Demo gibt es auf Deutsch und Englisch.
- **Browser:** Chrome lädt Links mit `download`-Attribut am Service Worker vorbei; `hilfe.js` holt sie deshalb selbst. Liest der Browser keine Cookies im Service Worker (Cookie Store API), bleibt die Wahl hell/dunkel nur bis zum Neuladen.
