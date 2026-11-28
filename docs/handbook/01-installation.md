# 1. Installation

## Requirements

- **Debian 13** (amd64 or arm64), as VM, LXC container or dedicated computer. As a guideline (not measured) 2 CPU cores,
  2 GB RAM and 20 GB disk for a small to medium network; the history (raw data 48 h, 5-minute averages 30 days, hourly
  averages 1 year) grows with the number of devices.
- A fixed IP address or a DNS name in your own network.
- Free ports: **443/tcp** (interface), **8444/tcp** (agents), **162/udp** (SNMP traps, only if used).
- **No internet required.** Whatever would need internet (push to the iPhone via ntfy.sh, Teams, Entra ID,
  healthchecks.io) is optional and can be switched off.

All files come from the build (`dist/`): the package `openwacht-zentrale_<version>_<arch>.deb`, the agents, the bill of
materials `openwacht-<version>.cdx.json` and `SHA256SUMS`. Compare the checksum before every installation:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

## Way A: with a Debian mirror (network access to the mirror)

**Set the system language first.** PostgreSQL creates its cluster during installation with the system locale. If none is
set (common with LXC templates and minimal installations), it is created with `SQL_ASCII`:

```bash
sudo apt install locales
sudo sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
sudo locale-gen && sudo update-locale LANG=de_DE.UTF-8
```

```bash
sudo apt install postgresql
sudo apt install ./openwacht-zentrale_1.0.12_amd64.deb
```

**Recommended on a new machine:** recreate the still empty cluster once, with checksums for the data pages (damaged
blocks are noticed instead of silently returning wrong values) and the built-in collation `C.UTF-8` (independent of
glibc updates, no `REINDEX` after a Debian upgrade). **Only before** the package, while the cluster is empty –
`pg_dropcluster` deletes it:

```bash
sudo pg_dropcluster 17 main --stop
sudo pg_createcluster 17 main --locale C.UTF-8 --start -- --locale-provider=builtin --builtin-locale=C.UTF-8 --data-checksums
```

If the package is under `/root` or in another folder that the apt user `_apt` may not read, apt reports “Download is
performed unsandboxed as root”. This is harmless; to avoid it, put the package into `/tmp`.

## Way B: completely without internet (offline package)

The offline package contains the central server **and** PostgreSQL with all dependencies for Debian 13. How to build it
is described in [chapter 14](14-betrieb-ohne-internet.md#building-the-offline-package).

```bash
tar xf openwacht-offline_1.0.12_debian-13_amd64.tar
cd openwacht-offline_1.0.12_debian-13_amd64
sudo sh installieren.sh -pruefen -abdruck <identifier>   # only check, change nothing
sudo sh installieren.sh -abdruck <identifier>            # first installation
sudo sh installieren.sh                                  # update of an existing installation
```

`installieren.sh` copies the package into a folder that only root can read and there checks **first the signature** of
`SHA256SUMS` (`SHA256SUMS.sig`), then **all** checksums (and rejects files that are not in `SHA256SUMS`), checks system
and architecture and then calls `apt` with its own package list that only knows this package. The system’s normal
package sources are neither queried nor changed. apt only installs what is missing or older; nothing is downgraded. If
the package contains additional packages (for example for joining the domain,
[chapter 14](14-betrieb-ohne-internet.md#additional-packages-for-example-for-joining-the-domain)), it installs them
afterwards; `-ohne-zusatz` leaves them out.

**Where the signature gets its trust from.** The key in the package alone proves nothing; whoever changes the package
can also swap it. Therefore:

- **First installation:** The identifier of the signing key (`-abdruck`, 16 hex digits) comes from a **second source**:
  this handbook in the version received from the vendor, the contract or a phone call. It is checked with `openssl`
  (usually present on Debian, otherwise `apt install openssl`).
- **Update:** The already installed central server checks with its embedded key; it comes from a previously checked
  installation. `-abdruck` is then not needed.
- **Without signature** (as long as the vendor has not created a key yet) the script aborts. With `-unsigniert` it
  accepts the package anyway: then `SHA256SUMS` only protects against damage, **not** against deliberate change in
  transit. Compare the checksum of the `.tar` beforehand through a second channel (`sha256sum -c …tar.sha256` against a
  checksum sent separately by the vendor).

## What the package sets up

After unpacking, the package calls `openwacht-zentrale installieren` (can be run several times):

- system users `svc_openwacht`, `svc_openwacht_db`, `svc_openwacht_traps`
- `/etc/openwacht` with the **master key** (`/etc/openwacht/schluessel`). It encrypts all secrets in the database. **Back
  it up separately** (password manager, safe). Without it a database backup is worthless.
- PostgreSQL roles and the database `openwacht`, sign-in without passwords over the local socket
- migrations, systemd units (interface on 443, agent port 8444, trap service, hourly backup timer)

At the end there is the **setup link**:

```text
Einrichtung im Browser öffnen (gilt 120 Minuten, nur einmal bis „Fertig“):

    https://openwacht.beispiel.example/einrichtung#…
    https://10.20.0.1/einrichtung#…
```

(Open the setup in the browser – valid for 120 minutes, only once until “Fertig”.) The part after `#` is a one-time key;
it does not end up in logs. **Do not pass it on** (not in tickets or chats either): whoever has it creates the first
admin. A new link that invalidates the old one: `sudo openwacht-zentrale einrichtungslink`.

The link names the names of the temporary certificate, i.e. the host name and the computer’s addresses. If only a short
name appears there (for example `https://openwacht/…`) that browsers cannot resolve in the network, open the link with
the full name or the IP address (`https://openwacht.firma.example/einrichtung#…`). The central server does not suggest
public IPv6 addresses; their prefix usually changes with the provider. As long as the setup is open, the central server
only delivers the assistant (no agent port, no checks).

Continue with the [first setup](02-erste-einrichtung.md).

## Update

An update only affects the **central server**. Agents keep running against a newer central server and do not have to be
updated at the same time (see below). Missing migrations run automatically during the update; the services restart.
Migrations cannot be reversed: the only way back is a backup and the old package.

### In the interface (from 1.0.4)

If the central server is installed as a Debian package, the update also works without a shell: **Einstellungen → Update
der Zentrale** (Settings → Update of the central server; operator only).

1. From the same build, choose the package `openwacht-zentrale_<version>_amd64.deb` (or `_arm64`), `SHA256SUMS` and
   `SHA256SUMS.sig` and enter the code from the authenticator app.
2. **Check and install:** The central server checks the signature of `SHA256SUMS` with the update key
   ([chapter 12](12-agent-updates.md)), that the package is listed there with its checksum, the platform and that the
   version is newer. Only then does it store it. It rejects a package without a valid signature or an older version;
   this is recorded in the audit log (`zentrale.update_abgelehnt`).
3. The rest is done by a **separate service with root rights** (`openwacht-zentrale-update`): it checks the same once
   more on its own copy, with the keys of its own program installed by root, and then calls `apt-get install`. The web
   service itself never gets root rights. As always, the package backs up by itself before changes to the database.
4. The central server restarts in the process; the page is unreachable for half a minute and then shows the result with
   the apt output. The new version appears at the bottom left.

Create a snapshot of the VM first. If apt fails, the previous version keeps running; details in the output and with
`journalctl -u openwacht-zentrale-update`. **The first time, to 1.0.4, it still works by hand as below**: the service
for this is only installed from 1.0.4.

### By hand

**1. Read what is coming.** [Release notes](../release-notizen.md) (German) of the new version: new migrations, changed
settings, known limits. Whoever skips several versions reads all in between; skipping is allowed.

**2. Get and check the package.** Put package, `SHA256SUMS` and `SHA256SUMS.sig` into a folder and compare:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

On Windows, before the package goes to the server:

```powershell
Get-FileHash .\openwacht-zentrale_<version>_amd64.deb -Algorithm SHA256
Select-String -Path .\SHA256SUMS -Pattern "openwacht-zentrale_<version>_amd64.deb"
```

Both values must be equal (upper and lower case do not matter). The authenticity of `SHA256SUMS` itself is shown by the
signature with the update key (identifiers in [chapter 12](12-agent-updates.md)); the offline package checks it itself.

**3. Copy to the server**, for example `scp openwacht-zentrale_<version>_amd64.deb admin@openwacht.beispiel.example:/tmp/`,
and compare once more there with `sha256sum /tmp/openwacht-zentrale_<version>_amd64.deb`.

**4. Back up by hand.** The package backs up by itself before a migration, but your own backup only takes seconds and is
the safe way back:

```bash
sudo -u svc_openwacht_db env OPENWACHT_DB_EIGENTUEMER="host=/run/postgresql user=openwacht_owner dbname=openwacht" \
  openwacht-zentrale sichern -verzeichnis /var/backups/openwacht -jetzt
sudo ls -lt /var/backups/openwacht | head -3
```

If the central server runs in a VM or container, additionally create a snapshot.

**5. Install.**

- Way A (Debian mirror): `sudo apt install /tmp/openwacht-zentrale_<version>_amd64.deb`
- Way B (without internet): unpack the new offline package, run `sudo sh installieren.sh` in it (for an update without
  `-abdruck`: the installed central server checks the signature with its own key)

The package writes “Vor dem Update gesichert” (backed up before the update) if the schema changes; if this backup fails,
nothing is migrated and the old version keeps running.

**6. Check.**

```bash
dpkg-query -W openwacht-zentrale
systemctl is-active openwacht-zentrale openwacht-traps.socket
sudo journalctl -u openwacht-zentrale --since "10 min ago" --no-pager | tail -20
```

Expected: the new version, `active` twice, in the journal “Zentrale gestartet version=…” and no errors. In the interface
(reload once with Ctrl+F5) the version appears at the bottom left of the sidebar. Briefly check: dashboard, agents report
(column “zuletzt da” under Hosts), under Alarme → Kanäle “Testen” on one channel.

**7. Way back, if necessary.** Easiest is to restore the snapshot from before. Without a snapshot, first install the old
package, then restore the backup from before with its program (in this order: `wiederherstellen` runs the installed
program’s migrations at the end):

```bash
sudo apt install --allow-downgrades ./openwacht-zentrale_<old-version>_amd64.deb
sudo openwacht-zentrale wiederherstellen -datei /var/backups/openwacht/openwacht-<time>.dump -ersetzen
```

`wiederherstellen` stops the services itself, keeps the previous database as `openwacht_vor_<time>` and starts the
services again. Details on restoring: [chapter 13](13-sicherung.md).

### Agents after an update

- **Do not have to follow.** A newer central server accepts reports from older agents. New sensor types or corrections
  in the agent are listed in the release notes; only then is updating the agents worthwhile.
- **Windows:** install the new MSI over the old one (GPO, Intune, software distribution or by script); registration and
  permissions remain ([chapter 5](05-agent.md#msi-on-windows-double-click-gpo-intune)).
- **Linux:** install the new `.deb` or `.rpm`; registration and permissions remain.
- **Self-update:** with signed packages, selected agents fetch the new version themselves at their next report
  ([chapter 12](12-agent-updates.md)).

## Uninstalling

`sudo apt remove openwacht-zentrale` stops the services. Database, `/etc/openwacht` and `/var/backups/openwacht` remain
even with `purge`: they are the data.
