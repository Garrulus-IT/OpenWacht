# 17. Härtungsleitfaden

Was eine Installation sicher macht, über die Grundeinstellungen hinaus. Die Grundeinstellungen sind schon streng
(Dienste ohne Root und Capabilities, Mandantentrennung in der Datenbank, nur TLS 1.3 am Agent-Port); dieses Kapitel
sagt, was der Betreiber zusätzlich tun sollte. Reihenfolge nach Wirkung.

## 1. Netz und Ports

| Richtung | Port | Wofür | Von / nach |
| --- | --- | --- | --- |
| eingehend | 443/tcp | Oberfläche (HTTPS durch die Zentrale) | Arbeitsplätze der Admins, Wandanzeigen |
| eingehend | 8444/tcp | Agent-Port (TLS 1.3, Client-Zertifikate) | überwachte Rechner, Sammler |
| eingehend | 162/udp | SNMP-Traps (eigener Dienst `openwacht-traps`) | nur die Geräte, die Traps senden |
| ausgehend | je Sensor | Ping, TCP, HTTP, DNS, NTP; SNMP 161/udp; Proxmox 8006; vCenter 443; NetApp ONTAP 443; XenServer/XCP-ng 443 (Pool-Master und, für Messwerte, die übrigen Hosts); FRITZ!Box 49000/49443 | nur Netze aus der Netzfreigabe |
| ausgehend | 465/587/tcp | Mail-Relay | nur das eingetragene Relay |
| ausgehend | 443/tcp | ntfy, Webhooks, Teams, OIDC-Anbieter, Totmannschalter | nur eingetragene Alarmziele bzw. Anbindungen |
| ausgehend | 443/tcp (bzw. Port des Gateways) | SMS über ein brevis.one-Gateway, HTTPS mit festem Fingerabdruck | nur das als Alarmziel freigegebene Gateway |
| ausgehend | 636/tcp | AD/LDAPS | nur die Domänencontroller |
| ausgehend | 6514/tcp | Audit-Export per Syslog (optional) | nur das SIEM |

- **Firewall am Server** (nftables) mit Standard „verwerfen“, eingehend nur die drei Ports oben, jeweils nur aus den
  Netzen, die sie brauchen. Die Oberfläche nicht aus Netzen der Benutzer erreichbar machen, die nichts verwalten.
- **Oberfläche und Agent-Port trennen**, wenn das Netz es erlaubt: 443 nur aus dem Admin-Netz, 8444 aus den
  Servernetzen. Beide Ports sind unabhängig; ein Agent kann mit seinem Zertifikat nichts an der Oberfläche.
- **Keinen ausgehenden Weg ins Internet**, wenn nicht nötig (Kapitel 14). Die Zentrale braucht keinen.
- **Netzfreigabe eng halten** (Einstellungen → Netzfreigabe, je Mandant eingrenzbar): Sie begrenzt, was Sensoren der
  Mandanten erreichen; eine übernommene Mandanten-Sitzung kann damit nicht das ganze Netz abtasten.
- **SNMP:** v3 mit authPriv statt v2c; Communities und v3-Konten nur lesend; Traps von v1/v2c gelten als fälschbar.

## 2. Anmeldung

- Zwei-Faktor-Anmeldung **Pflicht für alle** (Einstellungen → Anmeldung), mindestens für Admins (Standard). Der
  Betreiber braucht sie immer.
- Firmen-Login (AD/LDAPS oder OIDC, Kapitel 10) statt lokaler Konten; lokale Konten nur für den Notfall-Betreiber.
- Sitzungsdauer für SSO kurz halten (z. B. 4 Std.), damit ein Entzug im Verzeichnis schnell wirkt.
- Wiederherstellungscodes erzeugen und offline aufbewahren (Kapitel 3), Betreiber-Konto mit zweitem TOTP-Gerät.
- API-Tokens nur mit Rolle Leser, kurzer Laufzeit, je Werkzeug ein eigenes.

- Passkeys für Admins einrichten (Kapitel 3): Sie sind gegen nachgemachte Anmeldeseiten (Phishing) geschützt.
- Rollen regelmäßig rezertifizieren (Bericht unter Verwaltung → Mandanten, Kapitel 3).

### Meldeweg für Sicherheitslücken (security.txt)

Die Zentrale liefert unter `/.well-known/security.txt` (RFC 9116) den Meldeweg aus: zuerst den Kontakt des Betreibers
(Startoption `-sicherheitskontakt mailto:…` oder `https://…`, mehrere kommagetrennt), dann den des Herstellers. Ohne
Kontakt oder mit `-security-txt=false` gibt es die Datei nicht (404). `Expires` liegt immer 180 Tage in der Zukunft.

## 3. Betrieb hinter einem Reverse Proxy

Die Zentrale macht HTTPS selbst; ein Reverse Proxy ist nicht nötig. Wenn doch (z. B. vorhandene WAF):

- Zentrale mit `-adresse 127.0.0.1:8443` (dann ohne eigenes TLS, nur auf Loopback) oder mit eigenem Zertifikat, und
  **`-proxy <Adresse des Proxys>/32`** in `/etc/openwacht/zentrale.env`. Ohne `-proxy` sieht die Zentrale alle
  Anmeldungen von der Adresse des Proxys: Rate Limit und Sperre nach Fehlversuchen träfen dann alle gemeinsam.
- `-basis-url https://openwacht.example.com` auf die Adresse setzen, unter der Benutzer die Oberfläche aufrufen
  (Herkunftsprüfung, SSO-Rückleitung, Links in Mails).
- Der Proxy setzt `X-Forwarded-For` und überschreibt vorhandene Werte; er darf keine Antworten zwischenspeichern
  (`Cache-Control` der Zentrale beachten) und keine eigenen Header wie `Content-Security-Policy` lockern.
- **Den Agent-Port nie durch einen TLS-terminierenden Proxy leiten.** Er braucht die Client-Zertifikate der Agents
  Ende-zu-Ende; wenn überhaupt, nur als TCP-Weiterleitung (Layer 4).

## 4. Server und Dateien

- Eigene VM oder eigener Container nur für OpenWacht; keine anderen Dienste dort.
- `/etc/openwacht/schluessel` (Hauptschlüssel, 0600 `svc_openwacht`) **zusätzlich offline sichern**: ohne ihn sind die
  Sicherungen der Datenbank nutzlos. Nie zusammen mit den Sicherungen am selben Ort.
- Sicherungen (`/var/backups/openwacht`) auf ein anderes System kopieren, das die Zentrale nicht löschen kann
  (Pull vom Sicherungsserver, nicht Push).
- Audit-Export einschalten (`-audit-datei` oder `-audit-syslog`) und außerhalb der Zentrale aufbewahren: Er ist der
  Anker gegen nachträgliche Änderungen (Kapitel 13).
- Updates des Betriebssystems und von PostgreSQL regelmäßig einspielen; beim Offline-Paket heißt das: neu bauen.
- `systemd-analyze security openwacht-zentrale` sollte „OK“ (≤ 2) zeigen; eigene Drop-ins nicht lockern.

## 5. Agents

- Agent aus dem Paket (Kapitel 5), Programmdatei nur von root bzw. Administratoren beschreibbar (der Agent prüft das
  beim Einrichten).
- Sensoren und Sammler nur so weit freigeben wie nötig (`openwacht-agent sensoren`, `sammler -netze`); Leistungsindikatoren
  nur für die Objekte, die eine Vorlage braucht (`-indikatoren`).
- Windows-SNMP-Dienst (nur v1/v2c) nie ins Netz öffnen: nur `localhost` annehmen, 161/udp in der Firewall zu, Agent als
  Sammler auf `127.0.0.1/32` (Kapitel 5). Software ohne andere Schnittstelle lieber nur über Dienste überwachen als mit
  einer Community im Netz.
- Agent-Updates nur signiert (Kapitel 12); Freigabe je Gerät oder Gruppe, nicht für alles auf einmal.
- Windows: signierte Programme (Kapitel 15), dann bleibt Smart App Control an.

## 6. Was nicht hilft

- Die Mandantentrennung schützt Mandanten voneinander, **nicht** gegen eine übernommene Zentrale: Wer den Dienst
  oder die Datenbank als Eigentümer kontrolliert, sieht alles. Deshalb Abschnitt 1 und 4.
- Ein Download des Agents von der Zentrale ist nur so sicher wie der Vergleich der Schlüssel-Kennung mit einer
  zweiten Quelle (Kapitel 5).
