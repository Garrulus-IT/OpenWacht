# 17. Hardening guide

What makes an installation secure, beyond the default settings. The defaults are already strict (services without root
and capabilities, tenant separation in the database, only TLS 1.3 on the agent port); this chapter says what the
operator should additionally do. Ordered by effect.

## 1. Network and ports

| Direction | Port | For | From / to |
| --- | --- | --- | --- |
| incoming | 443/tcp | interface (HTTPS by the central server) | admins’ workstations, wall displays |
| incoming | 8444/tcp | agent port (TLS 1.3, client certificates) | monitored computers, collectors |
| incoming | 162/udp | SNMP traps (own service `openwacht-traps`) | only the devices that send traps |
| outgoing | per sensor | ping, TCP, HTTP, DNS, NTP; SNMP 161/udp; Proxmox 8006; vCenter 443; NetApp ONTAP 443; XenServer/XCP-ng 443 (pool master and, for measurements, the other hosts); FRITZ!Box 49000/49443 | only networks from the network allow-list |
| outgoing | 465/587/tcp | mail relay | only the entered relay |
| outgoing | 443/tcp | ntfy, webhooks, Teams, OIDC provider, dead man’s switch | only entered alert targets or connections |
| outgoing | 443/tcp (or the gateway’s port) | SMS through a brevis.one gateway, HTTPS with a fixed fingerprint | only the gateway allowed as alert target |
| outgoing | 636/tcp | AD/LDAPS | only the domain controllers |
| outgoing | 6514/tcp | audit export via syslog (optional) | only the SIEM |

- **Firewall on the server** (nftables) with default “drop”, incoming only the three ports above, each only from the
  networks that need them. Do not make the interface reachable from user networks that manage nothing.
- **Separate interface and agent port** if the network allows: 443 only from the admin network, 8444 from the server
  networks. Both ports are independent; an agent can do nothing in the interface with its certificate.
- **No outgoing route to the internet** if not needed (chapter 14). The central server needs none.
- **Keep the network allow-list narrow** (Einstellungen → Netzfreigabe, can be restricted per tenant): it limits what
  the tenants’ sensors reach; a hijacked tenant session cannot scan the whole network with it.
- **SNMP:** v3 with authPriv instead of v2c; communities and v3 accounts read-only; v1/v2c traps count as forgeable.

## 2. Sign-in

- Two-factor sign-in **required for all** (Einstellungen → Anmeldung), at least for admins (default). The operator
  always needs it.
- Company login (AD/LDAPS or OIDC, chapter 10) instead of local accounts; local accounts only for the emergency
  operator.
- Keep the session duration for SSO short (for example 4 hours), so that a revocation in the directory takes effect
  quickly.
- Create recovery codes and keep them offline (chapter 3), operator account with a second TOTP device.
- API tokens only with the role reader, short lifetime, a separate one per tool.
- Limits per user (from 1.0.5, built in): at most 8 concurrent requests and 1200 per minute, API tokens additionally 300
  per minute; above that the central server answers with 429. Every database query of a user or a wall display aborts
  after 60 seconds. A signed-in reader thus cannot paralyse the central server with expensive queries.
- **Set up mail delivery** (from 1.0.6): OpenWacht then reports sign-ins from new computers, locks after failed attempts
  and emergency commands on the central server to the account and the operator (chapter 3). Ten wrong codes for an
  account within 15 minutes lock its second factor for 15 minutes, no matter from how many computers they come.
- When creating a user, an address already in use only reveals that it is in use (the same message for every tenant).
  An admin gets at most 20 such rejections per hour; each is recorded in the audit log (`benutzer.anlegen_abgelehnt`).
- Set up passkeys for admins (chapter 3): they are protected against fake sign-in pages (phishing).
- Recertify roles regularly (report under Verwaltung → Mandanten, chapter 3).

### Reporting channel for security vulnerabilities (security.txt)

The central server delivers the reporting channel under `/.well-known/security.txt` (RFC 9116): first the operator’s
contact (start option `-sicherheitskontakt mailto:…` or `https://…`, several comma-separated), then the vendor’s.
Without a contact or with `-security-txt=false` the file does not exist (404). `Expires` is always 180 days in the
future.

## 3. Operation behind a reverse proxy

The central server does HTTPS itself; a reverse proxy is not needed. If you use one anyway (for example an existing
WAF):

- Central server with `-adresse 127.0.0.1:8443` (then without its own TLS, only on loopback) or with its own
  certificate, and **`-proxy <address of the proxy>/32`** in `/etc/openwacht/zentrale.env`. Without `-proxy`, the
  central server sees all sign-ins from the proxy’s address: rate limit and lock after failed attempts would then hit
  everyone together.
- Set `-basis-url https://openwacht.example.com` to the address under which users open the interface (origin check, SSO
  return, links in e-mails).
- The proxy sets `X-Forwarded-For` and overwrites existing values; it must not cache responses (respect the central
  server’s `Cache-Control`) and must not relax its own headers such as `Content-Security-Policy`.
- **Never route the agent port through a TLS-terminating proxy.** It needs the agents’ client certificates end to end;
  if at all, only as TCP forwarding (layer 4).

## 4. Server and files

- Own VM or own container only for OpenWacht; no other services there.
- **Additionally back up offline** `/etc/openwacht/schluessel` (master key, 0600 `svc_openwacht`): without it the
  database backups are useless. Never in the same place as the backups.
- Copy backups (`/var/backups/openwacht`) to another system that the central server cannot delete (pull from the
  backup server, not push).
- Switch on the audit export (`-audit-datei` or `-audit-syslog`) and keep it outside the central server: it is the
  anchor against later changes (chapter 13).
- Install updates of the operating system and of PostgreSQL regularly; with the offline package this means: rebuild.
- `systemd-analyze security openwacht-zentrale` should show “OK” (≤ 2); do not relax your own drop-ins.
- **Update from the interface (from 1.0.4):** The only service with root rights is `openwacht-zentrale-update`. It only
  starts when the web service places an order in `/var/lib/openwacht-update`, and only installs a package whose
  `SHA256SUMS` is signed with the update key and which is newer than the running version; it does the check itself,
  with the keys of its own program. If you do not want this: `systemctl disable --now openwacht-zentrale-update.path`
  (updates then by hand again, chapter 1).
- **Desktop app:** only use tokens with the role **reader**, a separate one per person, with an expiry date; revoke them
  when someone leaves (chapter 11).

## 5. Agents

- Agent from the package (chapter 5), program file only writable by root or administrators (the agent checks this
  during setup).
- Allow sensors and collectors only as far as needed (`openwacht-agent sensoren`, `sammler -netze`); performance
  counters only for the objects that a template needs (`-indikatoren`).
- Never open the Windows SNMP service (only v1/v2c) to the network: only accept `localhost`, close 161/udp in the
  firewall, agent as collector on `127.0.0.1/32` (chapter 5). Prefer monitoring software without another interface only
  through services rather than with a community in the network.
- Reports per agent are limited twice: in the central server 12 per minute, in the database 20 per minute with
  measurements (from 1.0.5). A compromised computer thus does not fill the central server’s disk.
- Agent updates only signed (chapter 12); release per device or group, not for everything at once.
- Windows: signed programs (chapter 15), then Smart App Control stays on.

## 6. What does not help

- Tenant separation protects tenants from each other, **not** against a compromised central server: whoever controls
  the service or the database as owner sees everything. Hence sections 1 and 4.
- A download of the agent from the central server is only as secure as comparing the key identifier with a second
  source (chapter 5).
