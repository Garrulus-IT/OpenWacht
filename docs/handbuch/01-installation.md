# 1. Installation

## Voraussetzungen

- **Debian 13** (amd64 oder arm64), als VM, LXC-Container oder eigener Rechner. Als Richtwert (nicht gemessen) 2 CPU-Kerne, 2 GB RAM
  und 20 GB Platte für ein kleines bis mittleres Netz; der Verlauf (Rohdaten 48 h, 5-Minuten-Mittel 30 Tage,
  Stundenmittel 1 Jahr) wächst mit der Zahl der Geräte.
- Eine feste IP-Adresse oder ein DNS-Name im eigenen Netz.
- Freie Ports: **443/tcp** (Oberfläche), **8444/tcp** (Agents), **162/udp** (SNMP-Traps, nur wenn genutzt).
- **Kein Internet nötig.** Was Internet bräuchte (Push aufs iPhone über ntfy.sh, Teams, Entra ID, healthchecks.io), ist
  optional und abschaltbar.

Alle Dateien kommen aus dem Build (`dist/`): das Paket `openwacht-zentrale_<version>_<arch>.deb`, die Agents, die
Stückliste `openwacht-<version>.cdx.json` und `SHA256SUMS`. Vor jeder Installation die Prüfsumme vergleichen:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

## Weg A: mit Debian-Spiegel (Netz zum Spiegel vorhanden)

**Vorher die Sprache des Systems setzen.** PostgreSQL legt seinen Cluster beim Installieren mit der Locale des Systems
an. Ist keine gesetzt (häufig bei LXC-Vorlagen und Minimalinstallationen), entsteht er mit `SQL_ASCII`:

```bash
sudo apt install locales
sudo sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
sudo locale-gen && sudo update-locale LANG=de_DE.UTF-8
```

```bash
sudo apt install postgresql
sudo apt install ./openwacht-zentrale_1.0.2_amd64.deb
```

**Empfohlen bei einer neuen Maschine:** den noch leeren Cluster einmal neu anlegen, mit Prüfsummen für die Datenseiten
(beschädigte Blöcke fallen auf, statt still falsche Werte zu liefern) und der eingebauten Sortierung `C.UTF-8`
(unabhängig von glibc-Updates, kein `REINDEX` nach einem Debian-Upgrade). **Nur vor** dem Paket, solange der Cluster
leer ist – `pg_dropcluster` löscht ihn:

```bash
sudo pg_dropcluster 17 main --stop
sudo pg_createcluster 17 main --locale C.UTF-8 --start -- --locale-provider=builtin --builtin-locale=C.UTF-8 --data-checksums
```

Liegt das Paket unter `/root` oder in einem anderen Ordner, den der apt-Benutzer `_apt` nicht lesen darf, meldet apt
„Download is performed unsandboxed as root“. Das ist harmlos; wer es vermeiden will, legt das Paket nach `/tmp`.

## Weg B: ganz ohne Internet (Offline-Paket)

Das Offline-Paket enthält die Zentrale **und** PostgreSQL mit allen Abhängigkeiten für Debian 13. Wie man es baut, steht
in [Kapitel 14](14-betrieb-ohne-internet.md#offline-paket-bauen).

```bash
tar xf openwacht-offline_1.0.2_debian-13_amd64.tar
cd openwacht-offline_1.0.2_debian-13_amd64
sudo sh installieren.sh -pruefen -abdruck <kennung>   # nur prüfen, nichts ändern
sudo sh installieren.sh -abdruck <kennung>            # erste Installation
sudo sh installieren.sh                               # Update einer bestehenden Installation
```

`installieren.sh` kopiert das Paket in einen Ordner, den nur root lesen kann, und prüft dort **zuerst die Signatur**
von `SHA256SUMS` (`SHA256SUMS.sig`), dann **alle** Prüfsummen (und lehnt Dateien ab, die nicht in
`SHA256SUMS` stehen), prüft System und Architektur und ruft dann `apt` mit einer eigenen
Paketliste auf, die nur dieses Paket kennt. Die normalen Paketquellen des Systems werden dabei weder gefragt noch
geändert. apt installiert nur, was fehlt oder älter ist; nichts wird zurückgestuft.

**Woher die Signatur ihr Vertrauen hat.** Der Schlüssel im Paket allein beweist nichts; wer das Paket ändert, kann
auch ihn tauschen. Deshalb:

- **Erste Installation:** Die Kennung des Signaturschlüssels (`-abdruck`, 16 Hexziffern) kommt aus einer **zweiten
  Quelle**: diesem Handbuch in der vom Hersteller erhaltenen Fassung, dem Vertrag oder einem Anruf. Geprüft wird mit
  `openssl` (bei Debian meist vorhanden, sonst `apt install openssl`).
- **Update:** Die schon installierte Zentrale prüft mit ihrem eingebetteten Schlüssel; sie stammt aus einer früher
  geprüften Installation. `-abdruck` ist dann nicht nötig.
- **Ohne Signatur** (solange der Hersteller noch keinen Schlüssel erzeugt hat) bricht das Skript
  ab. Mit `-unsigniert` nimmt es das Paket trotzdem an: Dann schützt `SHA256SUMS` nur vor Beschädigung, **nicht** vor
  absichtlicher Änderung auf dem Transportweg. Die Prüfsumme der `.tar` vorher über einen zweiten Weg vergleichen
  (`sha256sum -c …tar.sha256` gegen eine vom Hersteller getrennt übermittelte Prüfsumme).

## Was das Paket einrichtet

Nach dem Auspacken ruft das Paket `openwacht-zentrale installieren` auf (mehrfach ausführbar):

- Systembenutzer `svc_openwacht`, `svc_openwacht_db`, `svc_openwacht_traps`
- `/etc/openwacht` mit dem **Hauptschlüssel** (`/etc/openwacht/schluessel`). Er verschlüsselt alle Geheimnisse in der
  Datenbank. **Getrennt sichern** (Passwortmanager, Tresor). Ohne ihn ist eine Sicherung der Datenbank wertlos.
- PostgreSQL-Rollen und die Datenbank `openwacht`, Anmeldung ohne Passwörter über den lokalen Socket
- Migrationen, systemd-Units (Oberfläche auf 443, Agent-Port 8444, Trap-Dienst, stündlicher Sicherungs-Timer)

Am Ende steht der **Einrichtungslink**:

```text
Einrichtung im Browser öffnen (gilt 120 Minuten, nur einmal bis „Fertig“):

    https://openwacht.beispiel.example/einrichtung#…
    https://10.20.0.1/einrichtung#…
```

Der Teil nach `#` ist ein Einmal-Schlüssel; er landet nicht in Logs. **Nicht weitergeben** (auch nicht in Tickets
oder Chats): Wer ihn hat, legt den ersten Admin an. Neuer Link, der den alten ungültig macht:
`sudo openwacht-zentrale einrichtungslink`.

Der Link nennt die Namen des vorläufigen Zertifikats, also den Hostnamen und die Adressen des Rechners. Steht dort nur
ein kurzer Name (z. B. `https://openwacht/…`), den Browser im Netz nicht auflösen, den Link mit dem vollen Namen oder der
IP-Adresse öffnen (`https://openwacht.firma.example/einrichtung#…`). Öffentliche IPv6-Adressen schlägt die Zentrale
nicht vor; ihr Präfix wechselt meist mit dem Provider.
Solange die Einrichtung offen ist, liefert die Zentrale nur den Assistenten aus (kein Agent-Port, keine Prüfungen).

Weiter mit der [ersten Einrichtung](02-erste-einrichtung.md).

## Update

Ein Update ist derselbe Befehl mit dem neuen Paket (Weg A) bzw. `sudo sh installieren.sh` aus dem neuen Offline-Paket
(Weg B). Fehlende Migrationen laufen dabei automatisch, die Dienste starten neu. Das Paket sichert die
Datenbank vorher selbst (Zeile „Vor dem Update gesichert“), wenn das Update das Schema ändert; schlägt das fehl, wird
nichts migriert. Migrationen sind nicht umkehrbar: Zurück geht es nur mit dieser Sicherung und dem alten Paket
([Kapitel 13](13-sicherung.md)) oder mit einem Snapshot der VM bzw. des Containers von vorher.
Details je Version: [Release-Notizen](../release-notizen.md).

## Deinstallieren

`sudo apt remove openwacht-zentrale` hält die Dienste an. Datenbank, `/etc/openwacht` und `/var/backups/openwacht`
bleiben auch bei `purge` erhalten: Sie sind die Daten.
