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
sudo apt install ./openwacht-zentrale_1.0.13_amd64.deb
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
tar xf openwacht-offline_1.0.13_debian-13_amd64.tar
cd openwacht-offline_1.0.13_debian-13_amd64
sudo sh installieren.sh -pruefen -abdruck <kennung>   # nur prüfen, nichts ändern
sudo sh installieren.sh -abdruck <kennung>            # erste Installation
sudo sh installieren.sh                               # Update einer bestehenden Installation
```

`installieren.sh` kopiert das Paket in einen Ordner, den nur root lesen kann, und prüft dort **zuerst die Signatur**
von `SHA256SUMS` (`SHA256SUMS.sig`), dann **alle** Prüfsummen (und lehnt Dateien ab, die nicht in
`SHA256SUMS` stehen), prüft System und Architektur und ruft dann `apt` mit einer eigenen
Paketliste auf, die nur dieses Paket kennt. Die normalen Paketquellen des Systems werden dabei weder gefragt noch
geändert. apt installiert nur, was fehlt oder älter ist; nichts wird zurückgestuft. Enthält das Paket Zusatzpakete
(z. B. für den Beitritt zur Domäne, [Kapitel 14](14-betrieb-ohne-internet.md#zusatzpakete-z-b-für-den-beitritt-zur-domäne)),
installiert es sie danach mit; `-ohne-zusatz` lässt sie weg.

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

Ein Update betrifft nur die **Zentrale**. Agents laufen an einer neueren Zentrale weiter und müssen nicht gleichzeitig
mit (siehe unten). Fehlende Migrationen laufen beim Update von selbst, die Dienste starten neu. Migrationen sind nicht
umkehrbar: Zurück geht es nur mit einer Sicherung und dem alten Paket.

### In der Oberfläche (ab 1.0.4)

Ist die Zentrale als Debian-Paket installiert, geht das Update auch ohne Shell: **Einstellungen → Update der Zentrale**
(nur der Betreiber).

1. Aus demselben Build das Paket `openwacht-zentrale_<version>_amd64.deb` (bzw. `_arm64`), `SHA256SUMS` und
   `SHA256SUMS.sig` wählen und den Code aus der Authenticator-App eingeben.
2. **Prüfen und installieren:** Die Zentrale prüft die Signatur von `SHA256SUMS` mit dem Update-Schlüssel
   ([Kapitel 12](12-agent-updates.md)), dass das Paket dort mit seiner Prüfsumme steht, die Plattform und dass die
   Version neuer ist. Erst dann legt sie es ab. Ein Paket ohne gültige Signatur oder eine ältere Version lehnt sie ab;
   das steht im Audit-Log (`zentrale.update_abgelehnt`).
3. Den Rest macht ein **getrennter Dienst mit root-Rechten** (`openwacht-zentrale-update`): Er prüft dasselbe noch
   einmal an einer eigenen Kopie, mit den Schlüsseln seines eigenen, von root installierten Programms, und ruft dann
   `apt-get install` auf. Der Webdienst selbst bekommt nie root-Rechte. Das Paket sichert vor Änderungen an der
   Datenbank wie immer selbst.
4. Die Zentrale startet dabei neu; die Seite ist eine halbe Minute nicht erreichbar und zeigt danach das Ergebnis mit der
   Ausgabe von apt. Unten links steht die neue Version.

Vorher einen Snapshot der VM anlegen. Schlägt apt fehl, läuft die bisherige Version weiter; Einzelheiten in der Ausgabe
und mit `journalctl -u openwacht-zentrale-update`. **Das erste Mal, auf 1.0.4, geht es noch wie unten von Hand**: Erst
ab 1.0.4 ist der Dienst dafür installiert.

### Von Hand

**1. Lesen, was kommt.** [Release-Notizen](../release-notizen.md) der neuen Version: neue Migrationen, geänderte
Einstellungen, bekannte Grenzen. Wer mehrere Versionen überspringt, liest alle dazwischen; ein Sprung ist erlaubt.

**2. Paket holen und prüfen.** Paket, `SHA256SUMS` und `SHA256SUMS.sig` in einen Ordner legen und vergleichen:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

Unter Windows, bevor das Paket auf den Server geht:

```powershell
Get-FileHash .\openwacht-zentrale_<version>_amd64.deb -Algorithm SHA256
Select-String -Path .\SHA256SUMS -Pattern "openwacht-zentrale_<version>_amd64.deb"
```

Beide Werte müssen gleich sein (Groß- und Kleinschreibung zählt nicht). Die Echtheit von `SHA256SUMS` selbst zeigt die
Signatur mit dem Update-Schlüssel (Kennungen in [Kapitel 12](12-agent-updates.md)); das Offline-Paket prüft sie selbst.

**3. Auf den Server kopieren**, z. B. `scp openwacht-zentrale_<version>_amd64.deb admin@openwacht.beispiel.example:/tmp/`,
und dort mit `sha256sum /tmp/openwacht-zentrale_<version>_amd64.deb` noch einmal vergleichen.

**4. Von Hand sichern.** Das Paket sichert vor einer Migration zwar selbst, eine eigene Sicherung kostet aber nur
Sekunden und ist der sichere Rückweg:

```bash
sudo -u svc_openwacht_db env OPENWACHT_DB_EIGENTUEMER="host=/run/postgresql user=openwacht_owner dbname=openwacht" \
  openwacht-zentrale sichern -verzeichnis /var/backups/openwacht -jetzt
sudo ls -lt /var/backups/openwacht | head -3
```

Läuft die Zentrale in einer VM oder einem Container, zusätzlich einen Snapshot anlegen.

**5. Installieren.**

- Weg A (Debian-Spiegel): `sudo apt install /tmp/openwacht-zentrale_<version>_amd64.deb`
- Weg B (ohne Internet): neues Offline-Paket entpacken, darin `sudo sh installieren.sh` (beim Update ohne
  `-abdruck`: die installierte Zentrale prüft die Signatur mit ihrem eigenen Schlüssel)

Das Paket schreibt „Vor dem Update gesichert“, wenn sich das Schema ändert; schlägt diese Sicherung fehl, wird nichts
migriert und die alte Version läuft weiter.

**6. Kontrollieren.**

```bash
dpkg-query -W openwacht-zentrale
systemctl is-active openwacht-zentrale openwacht-traps.socket
sudo journalctl -u openwacht-zentrale --since "10 min ago" --no-pager | tail -20
```

Erwartet: die neue Version, zweimal `active`, im Journal „Zentrale gestartet version=…“ und keine Fehler. In der
Oberfläche (einmal mit Strg+F5 neu laden) steht die Version unten links in der Leiste. Kurz prüfen: Dashboard,
Agents melden sich (Spalte „zuletzt da“ unter Hosts), unter Alarme → Kanäle bei einem Kanal „Testen“.

**7. Rückweg, falls nötig.** Am einfachsten den Snapshot von vorher zurückspielen. Ohne Snapshot erst das alte Paket
installieren, dann mit dessen Programm die Sicherung von vorher einspielen (in dieser Reihenfolge: `wiederherstellen`
führt am Ende die Migrationen des installierten Programms aus):

```bash
sudo apt install --allow-downgrades ./openwacht-zentrale_<alte-version>_amd64.deb
sudo openwacht-zentrale wiederherstellen -datei /var/backups/openwacht/openwacht-<zeit>.dump -ersetzen
```

`wiederherstellen` hält die Dienste selbst an, behält die bisherige Datenbank als `openwacht_vor_<zeit>` und startet die
Dienste wieder. Einzelheiten zur Rücksicherung: [Kapitel 13](13-sicherung.md).

### Agents nach einem Update

- **Müssen nicht mit.** Eine neuere Zentrale nimmt Meldungen älterer Agents an. Neue Sensorarten oder Korrekturen im
  Agent stehen in den Release-Notizen; erst dann lohnt das Update der Agents.
- **Windows:** neues MSI über das alte installieren (GPO, Intune, Softwareverteilung oder per Skript); Registrierung und
  Freigaben bleiben ([Kapitel 5](05-agent.md#msi-unter-windows-doppelklick-gpo-intune)).
- **Linux:** neues `.deb` bzw. `.rpm` installieren; Registrierung und Freigaben bleiben.
- **Selbst-Update:** Mit signierten Paketen holen sich ausgewählte Agents die neue Version beim nächsten Melden selbst
  ([Kapitel 12](12-agent-updates.md)).

## Deinstallieren

`sudo apt remove openwacht-zentrale` hält die Dienste an. Datenbank, `/etc/openwacht` und `/var/backups/openwacht`
bleiben auch bei `purge` erhalten: Sie sind die Daten.
