# 14. Operation without internet

OpenWacht needs no internet in operation. Whatever would need internet is optional and can be switched off:

| Function | without internet |
| --- | --- |
| Interface, agents, SNMP, traps, Proxmox, vCenter, FRITZ!Box, sensors | works |
| HTTPS | own OpenWacht root or certificate of the company CA |
| Alert e-mail | through an internal relay (STARTTLS/TLS with own CA) |
| Webhook | to your own systems in the network |
| SMS | through a brevis.one gateway in the network, only needs mobile network at the gateway |
| ntfy | Android locally; **iPhone push needs internet** (Apple) |
| Teams, Entra ID | need internet; instead mail/webhook or Keycloak/ADFS |
| Dead man’s switch | own Healthchecks service or webhook in the network instead of healthchecks.io |
| Installation, updates | offline package (below) |
| Agent updates | come signed through the central server |

The interface loads nothing from foreign servers (no CDNs, no web fonts; the content security policy only allows the
central server itself). Time zones are built in.

## Building the offline package

The offline package is built on a computer **with** internet, and the single file is brought to the customer.

Prerequisites on the build computer: apt (Debian or Ubuntu), `apt-utils`, `debian-archive-keyring`; root is not
required. Easiest is a Debian 13 (VM, container or WSL).

```bash
# 1. Build OpenWacht (or take dist/ from the CI artefact)
go run ./tools/build -ziele linux/amd64

# 2. Build the offline package: downloads PostgreSQL with dependencies from deb.debian.org
sudo apt install apt-utils debian-archive-keyring     # once
sh deploy/offline/paket-bauen.sh -dist dist

# Result
ls dist/openwacht-offline_1.0.11_debian-13_amd64.tar*
```

The script

1. checks the package `openwacht-zentrale_*.deb` and the bill of materials against `dist/SHA256SUMS`,
2. downloads, with its own empty apt directory (changes nothing on the build computer), **PostgreSQL and all
   dependencies** from `trixie`, `trixie-updates` and `trixie-security`; apt checks the signatures of the Debian archive,
3. adds package index, `installieren.sh`, `LIESMICH.txt` (with all package versions), bill of materials and
   `SHA256SUMS`,
4. packs everything into a `.tar` with a `.sha256` next to it.

Options: `-arch arm64`, `-aus <folder>`, `-quellen <file>` (for example a mirror in the company network), `-zusatz <list>`
(below).

### Additional packages, for example for joining the domain

With `-zusatz`, the script adds further Debian packages **with dependencies** to the package, separated by commas.
Example for a central server that should join an Active Directory domain without internet (sign-in on the computer with
domain accounts; for sign-in to OpenWacht itself, LDAPS from chapter 10 is enough, this is not needed for that):

```bash
sh deploy/offline/paket-bauen.sh -dist dist \
  -zusatz realmd,sssd,sssd-tools,adcli,libnss-sss,libpam-sss,samba-common-bin
```

- Everything is resolved in one pass together with PostgreSQL so that the versions match; recommendations
  (`Recommends`) are not included. Whatever is missing must be in the list.
- Only package names are allowed (lower-case letters, digits, `+ - .`), at most 50; no versions. A virtual package
  aborts with a message: then name the concrete package.
- The list is in the package as the file `ZUSATZ`, hence in `SHA256SUMS` and in the signature, and in `LIESMICH.txt`.
- `installieren.sh` installs the additional packages after `openwacht-zentrale` from the same, purely local source; with
  `-ohne-zusatz` it does not. The domain join itself is done by hand afterwards (`realm join …`); OpenWacht changes
  nothing about it.
- Security updates work as for PostgreSQL: rebuild the package with the same `-zusatz` and install it.

Tested (25 Nov 2026) with Ubuntu 24.04 as source and target, because `deb.debian.org` is blocked in the development
environment: package built with the list above (163 packages from the mirror), installed in a fresh minimal environment
without any network; `realmd`, `sssd`, `adcli` and `samba-common-bin` were installed afterwards, `realm` ran. The test
does not cover joining a real domain, nor Debian 13.

**Signing (vendor).** The package is initially unsigned. `SHA256SUMS` is signed offline with the update key (own
context; an update signature does not count for it):

```bash
tar -xOf dist/openwacht-offline_1.0.11_debian-13_amd64.tar openwacht-offline_1.0.11_debian-13_amd64/SHA256SUMS >SHA256SUMS
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen SHA256SUMS      # offline
sh deploy/offline/paket-bauen.sh -dist dist -signatur SHA256SUMS.sig -paket dist/openwacht-offline_1.0.11_debian-13_amd64.tar
```

The last step puts `SHA256SUMS.sig` into the package, checks it with `dist/openwacht-zentrale_linux_amd64` and repacks.
`dist/SHA256SUMS` from `tools/build` can be signed the same way. The signature can also be checked without OpenWacht:
signed are the bytes `openwacht-sha256sums v1\n` followed by the content of `SHA256SUMS` (Ed25519,
`openssl pkeyutl -verify -rawin`).

**Residual risk until the first signing key:** As long as the publisher has not created an update key, packages are
unsigned and can only be installed with `-unsigniert`. Whoever changes the package in transit can then also adjust
`SHA256SUMS`; only comparing the checksum through a second channel helps. The package is about 100 MB. For security
updates of PostgreSQL, rebuild the package regularly and install it with `installieren.sh` (apt then only updates what
is newer).

At the customer: [chapter 1, way B](01-installation.md#way-b-completely-without-internet-offline-package).

## Test result: central server without any outside network (22 Nov 2026)

**Setup.** Own network namespace with only two interfaces: loopback and a “LAN” `10.20.0.0/24`. The default route points
to a gateway that does not answer; every packet that wants to leave the LAN is captured at this interface (tcpdump).
Inside:

| Role | Address |
| --- | --- |
| Central server (fresh minimal installation via debootstrap, nothing else installed) | 10.20.0.1 |
| SNMP device “switch-keller” (Net-SNMP, v2c) | 10.20.0.20 |
| Mail relay with STARTTLS and internal test CA | 10.20.0.25 |
| Agent “srv-halle1” | 10.20.0.1 |
| “Printer” without a device (for a real outage) | 10.20.0.50 |
| DNS server according to `resolv.conf` (does not exist) | 10.20.0.53 |

**Limitation.** The development environment blocks `deb.debian.org`. The same script was therefore tested with **Ubuntu
24.04** as source and target (`-quellen`, PostgreSQL 16 instead of 17). The minimal environment had no systemd:
PostgreSQL had to be started by hand after unpacking (`pg_ctlcluster 16 main start`, then `dpkg --configure -a`); the
central server ran via `systemd-socket-activate` as under systemd. On Debian 13 with systemd, the postgresql package
starts the service itself. A run on a real Debian 13 is still pending.

**Results**

| Check | Result |
| --- | --- |
| Build offline package (85 packages + OpenWacht, 96 MB) | ok |
| `installieren.sh -pruefen`; changed file, foreign file, wrong target system, without root | ok; all four error cases abort without changing anything |
| Installation without network (PostgreSQL and all dependencies from the package, 34 migrations) | ok; no packet left the LAN |
| Setup assistant in the browser (own root, network allow-list, two-factor) | ok, no errors in the browser |
| Sign-in with password and code | ok |
| Register agent and report (token from the interface) | ok |
| SNMP v2c with access profile | ok, values and restart detected |
| SNMP device switched off | after 3 min. alert “antwortet nicht” (not responding) |
| Mail relay with STARTTLS and own CA: test mail | ok |
| Alert e-mails (outage, warning, all-clear) through the relay | ok |
| Backup (`sichern -jetzt`) and restore (`wiederherstellen -ersetzen`) | ok |
| **Traffic to the outside, 5½ minutes of continuous operation without browser** (checks, agent, SNMP outage, alert e-mail, backup) | **none**; only ARP requests in the LAN for the deliberately missing printer |
| Traffic to the outside during the browser tests | only DNS requests of the test browser (Chrome) for Google services; none from OpenWacht |

During the package installation there were six ARP requests to the (non-existent) DNS server in the LAN, probably from a
package script; the installation still completed, and no packet left the LAN. In operation the central server made no
DNS request because all targets were IP addresses. Sensors with a name as target need a DNS server in your own network.
