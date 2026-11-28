# 14. Betrieb ohne Internet

OpenWacht braucht im Betrieb kein Internet. Was Internet bräuchte, ist optional und abschaltbar:

| Funktion | ohne Internet |
| --- | --- |
| Oberfläche, Agents, SNMP, Traps, Proxmox, vCenter, FRITZ!Box, Sensoren | geht |
| HTTPS | eigene OpenWacht-Wurzel oder Zertifikat der Firmen-CA |
| Alarm-Mail | über ein internes Relay (STARTTLS/TLS mit eigener CA) |
| Webhook | an eigene Systeme im Netz |
| SMS | über ein brevis.one-Gateway im Netz, braucht nur Mobilfunk am Gateway |
| ntfy | Android lokal; **iPhone-Push braucht Internet** (Apple) |
| Teams, Entra ID | brauchen Internet; stattdessen Mail/Webhook bzw. Keycloak/ADFS |
| Totmannschalter | eigener Healthchecks-Dienst oder Webhook im Netz statt healthchecks.io |
| Installation, Updates | Offline-Paket (unten) |
| Agent-Updates | kommen signiert über die Zentrale |

Die Oberfläche lädt nichts von fremden Servern (keine CDNs, keine Webfonts; die Content Security Policy erlaubt nur
die Zentrale selbst). Zeitzonen sind eingebaut.

## Offline-Paket bauen

Das Offline-Paket baut man auf einem Rechner **mit** Internet und bringt die eine Datei zum Kunden.

Voraussetzungen auf dem Bau-Rechner: apt (Debian oder Ubuntu), `apt-utils`, `debian-archive-keyring`; root ist nicht
nötig. Am einfachsten ein Debian 13 (VM, Container oder WSL).

```bash
# 1. OpenWacht bauen (oder dist/ aus dem CI-Artefakt nehmen)
go run ./tools/build -ziele linux/amd64

# 2. Offline-Paket bauen: lädt PostgreSQL samt Abhängigkeiten aus deb.debian.org
sudo apt install apt-utils debian-archive-keyring     # einmalig
sh deploy/offline/paket-bauen.sh -dist dist

# Ergebnis
ls dist/linux/openwacht-offline_1.0.12_debian-13_amd64.tar*
```

Das Skript

1. prüft das Paket `openwacht-zentrale_*.deb` und die Stückliste gegen `dist/linux/SHA256SUMS`,
2. lädt mit einem eigenen, leeren apt-Verzeichnis (ändert nichts am Bau-Rechner) **PostgreSQL und alle
   Abhängigkeiten** aus `trixie`, `trixie-updates` und `trixie-security`; apt prüft dabei die Signaturen des
   Debian-Archivs,
3. legt Paketindex, `installieren.sh`, `LIESMICH.txt` (mit allen Paketversionen), Stückliste und `SHA256SUMS` dazu,
4. packt alles in eine `.tar` mit einer `.sha256` daneben.

Optionen: `-arch arm64`, `-aus <ordner>`, `-quellen <datei>` (z. B. ein Spiegel im Firmennetz), `-zusatz <liste>`
(unten).

### Zusatzpakete, z. B. für den Beitritt zur Domäne

Mit `-zusatz` nimmt das Skript weitere Debian-Pakete **samt Abhängigkeiten** ins Paket auf, durch Komma getrennt. Beispiel
für eine Zentrale, die ohne Internet einer Active-Directory-Domäne beitreten soll (Anmeldung am Rechner mit
Domänenkonten; für die Anmeldung an OpenWacht selbst reicht LDAPS aus Kapitel 10, dafür ist das nicht nötig):

```bash
sh deploy/offline/paket-bauen.sh -dist dist \
  -zusatz realmd,sssd,sssd-tools,adcli,libnss-sss,libpam-sss,samba-common-bin
```

- Aufgelöst wird alles in einem Durchgang mit PostgreSQL, damit die Versionen zueinander passen; Empfehlungen
  (`Recommends`) kommen nicht mit. Was dabei fehlt, muss in der Liste stehen.
- Erlaubt sind nur Paketnamen (Kleinbuchstaben, Ziffern, `+ - .`), höchstens 50; keine Versionen. Ein virtuelles Paket
  bricht mit einer Meldung ab: dann das konkrete Paket nennen.
- Die Liste steht als Datei `ZUSATZ` im Paket, damit in `SHA256SUMS` und in der Signatur, und in `LIESMICH.txt`.
- `installieren.sh` installiert die Zusatzpakete nach `openwacht-zentrale` aus derselben, nur lokalen Quelle mit; mit
  `-ohne-zusatz` nicht. Den Beitritt selbst macht man danach von Hand (`realm join …`), OpenWacht ändert daran nichts.
- Für Sicherheitsupdates gilt dasselbe wie für PostgreSQL: Paket mit denselben `-zusatz` neu bauen und einspielen.

Getestet (25.11.2026) mit Ubuntu 24.04 als Quelle und Ziel, weil `deb.debian.org` in der Entwicklungsumgebung gesperrt
ist: Paket mit der Liste oben gebaut (163 Pakete aus dem Spiegel), in einer frischen Minimal-Umgebung ohne jedes Netz
installiert; `realmd`, `sssd`, `adcli` und `samba-common-bin` waren danach installiert, `realm` lief. Den Beitritt zu einer
echten Domäne deckt der Test nicht ab, ebenso wenig Debian 13.

**Signieren (Hersteller).** Das Paket ist zunächst unsigniert. `SHA256SUMS` wird offline mit dem
Update-Schlüssel signiert (eigener Kontext, eine Update-Signatur gilt dafür nicht):

```bash
tar -xOf dist/linux/openwacht-offline_1.0.12_debian-13_amd64.tar openwacht-offline_1.0.12_debian-13_amd64/SHA256SUMS >SHA256SUMS
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen SHA256SUMS      # offline
sh deploy/offline/paket-bauen.sh -dist dist -signatur SHA256SUMS.sig -paket dist/linux/openwacht-offline_1.0.12_debian-13_amd64.tar
```

Der letzte Schritt legt `SHA256SUMS.sig` ins Paket, prüft sie mit `dist/linux/openwacht-zentrale_linux_amd64` und packt neu.
Ebenso lässt sich `dist/linux/SHA256SUMS` aus `tools/build` signieren. Die Signatur lässt sich auch ohne OpenWacht prüfen:
signiert sind die Bytes `openwacht-sha256sums v1\n` gefolgt vom Inhalt von `SHA256SUMS` (Ed25519,
`openssl pkeyutl -verify -rawin`).

**Restrisiko bis zum ersten Signaturschlüssel:** Solange der Herausgeber keinen Update-Schlüssel erzeugt hat, sind Pakete
unsigniert und lassen sich nur mit `-unsigniert` installieren. Wer das Paket auf dem Transportweg ändert, kann dann
auch `SHA256SUMS` anpassen; nur ein Vergleich der Prüfsumme über einen zweiten Weg hilft. Das Paket ist etwa
100 MB groß. Für Sicherheitsupdates von PostgreSQL das Paket regelmäßig neu bauen und mit `installieren.sh`
einspielen (apt aktualisiert dann nur, was neuer ist).

Beim Kunden: [Kapitel 1, Weg B](01-installation.md#weg-b-ganz-ohne-internet-offline-paket).

## Testergebnis: Zentrale ohne Netz nach außen (22.11.2026)

**Aufbau.** Eigener Netz-Namensraum mit nur zwei Schnittstellen: Loopback und ein „LAN“ `10.20.0.0/24`. Die
Standardroute zeigt auf ein Gateway, das nicht antwortet; jedes Paket, das das LAN verlassen will, wird an dieser
Schnittstelle mitgeschnitten (tcpdump). Darin:

| Rolle | Adresse |
| --- | --- |
| Zentrale (frische Minimal-Installation per debootstrap, sonst nichts installiert) | 10.20.0.1 |
| SNMP-Gerät „switch-keller“ (Net-SNMP, v2c) | 10.20.0.20 |
| Mail-Relay mit STARTTLS und interner Test-CA | 10.20.0.25 |
| Agent „srv-halle1“ | 10.20.0.1 |
| „Drucker“ ohne Gerät (für einen echten Ausfall) | 10.20.0.50 |
| DNS-Server laut `resolv.conf` (gibt es nicht) | 10.20.0.53 |

**Einschränkung.** Die Entwicklungsumgebung sperrt `deb.debian.org`. Getestet wurde deshalb dasselbe Skript mit
**Ubuntu 24.04** als Quelle und Ziel (`-quellen`, PostgreSQL 16 statt 17). Die Minimal-Umgebung hatte kein systemd:
PostgreSQL musste nach dem Auspacken von Hand gestartet werden (`pg_ctlcluster 16 main start`, dann
`dpkg --configure -a`), die Zentrale lief über `systemd-socket-activate` wie unter systemd. Auf Debian 13 mit systemd
startet das postgresql-Paket den Dienst selbst. Ein Lauf auf echtem Debian 13 steht noch aus.

**Ergebnisse**

| Prüfung | Ergebnis |
| --- | --- |
| Offline-Paket bauen (85 Pakete + OpenWacht, 96 MB) | ok |
| `installieren.sh -pruefen`; veränderte Datei, fremde Datei, falsches Zielsystem, ohne root | ok; alle vier Fehlerfälle brechen ab, ohne etwas zu ändern |
| Installation ohne Netz (PostgreSQL und alle Abhängigkeiten aus dem Paket, 34 Migrationen) | ok; kein Paket verließ das LAN |
| Einrichtungsassistent im Browser (eigene Wurzel, Netzfreigabe, Zwei-Faktor) | ok, keine Fehler im Browser |
| Anmeldung mit Passwort und Code | ok |
| Agent registrieren und melden (Token aus der Oberfläche) | ok |
| SNMP v2c mit Zugangsprofil | ok, Werte und Neustart erkannt |
| SNMP-Gerät abgeschaltet | nach 3 Min. Alarm „antwortet nicht“ |
| Mail-Relay mit STARTTLS und eigener CA: Testmail | ok |
| Alarm-Mails (Ausfall, Warnung, Entwarnung) über das Relay | ok |
| Sicherung (`sichern -jetzt`) und Rücksicherung (`wiederherstellen -ersetzen`) | ok |
| **Verkehr nach außen, 5½ Minuten Dauerbetrieb ohne Browser** (Prüfungen, Agent, SNMP-Ausfall, Alarm-Mail, Sicherung) | **keiner**; nur ARP-Anfragen im LAN für den absichtlich fehlenden Drucker |
| Verkehr nach außen während der Browsertests | nur DNS-Anfragen des Test-Browsers (Chrome) nach Google-Diensten; keine von OpenWacht |

Während der Paketinstallation gab es sechs ARP-Anfragen an den (nicht vorhandenen) DNS-Server im LAN, vermutlich
aus einem Paketskript; die Installation lief trotzdem durch, und kein Paket verließ das LAN. Im Betrieb stellte die
Zentrale keine DNS-Anfrage, weil alle Ziele IP-Adressen waren. Sensoren mit einem Namen als Ziel brauchen einen
DNS-Server im eigenen Netz.
