# 16. Operation and scaling

## Load test (22 Nov 2026, measured with version 0.34.0)

**Setup:** 20 tenants (main tenant, 4 divisions, 15 sub-tenants below), 500 agents (25 per tenant, simulated with
`tools/simagent`, report every 60 s, each site with its own sender address) and 2000 SNMP devices (100 per tenant, mocks
with CPU, memory, disk and two interfaces, polled every 60 s, created via CSV import with access profile). Tool:
`tools/lasttest` (Go test with build tag `lasttest`, does not run in CI) and `tools/lasttest/tag.sql` for extrapolating
to one day.

**Environment:** a sandbox with **2 vCPU and 7 GB RAM**, PostgreSQL 16 with default settings (`shared_buffers` 128 MB),
central server, database, simulated agents and SNMP mocks on the same computer. The mocks themselves needed more CPU time
than the central server. The values are therefore rather too high than too low; on your own hardware there is more
headroom.

### Results under load

| Metric | Value |
| --- | --- |
| CPU time central server | ≈ 7 % of one core (average over 15 minutes), memory 60 MB |
| CPU time PostgreSQL | ≈ 9 % of one core |
| New measurements | ≈ 15,000 rows per minute (SNMP 11,800, agents 3,000) |
| Maintenance `metrics_maintain()` (every 5 min.) | 2–3 s |
| Catching up the aggregation of a whole day (for example after an outage of the central server) | 108 s |
| Setup: 20 CSV imports with 100 devices each | 11 s |
| Registration of 500 agents | ≈ 1 minute (25 per site; limit 30 per minute and sender address) |

Response times of the interface (median / 95 %), signed in as admin of the main tenant (sees everything):

| Query | after 1 hour of operation | with full history (7 days 5-min., 30 days hourly) |
| --- | --- | --- |
| Graph of a host or SNMP device (24 hours, 7 days, 30 days) | ≤ 10 ms | ≤ 35 ms |
| List agents / alerts / SNMP | 9 / 3 / 51 ms | unchanged |
| List of all devices (2500) | 314 / 394 ms | unchanged |
| Dashboard: key figures (availability of all sources) | 368 / 454 ms | **over 60 s, aborts** |
| Dashboard: history of all hosts (highest 8 lines) | 150 / 170 ms | **8.5 s (24 hours) to 28–54 s (7 days)** |

**Limit (known, open):** The two dashboard widgets “Kennzahlen” (key figures) and “Graph über alle Hosts” (graph over
all hosts) compute over all sources and the whole period on every call. With 2500 sources and full history they are too
slow; the other pages stay fast. Until this is rebuilt (precomputed values per source): in large installations set
these widgets per tenant or remove them. Extrapolated linearly (not measured), with 300 sources they take about 1 s
(24 hours) to 3–6 s (7 days).

**Scheduler:** It fetches new tasks for checks and SNMP as soon as slots are free; in the load test all 2000 devices were
served at the 60 s interval (test `TestPlanerDurchsatz`). The limit is now the devices’ response time: with 32
concurrent queries and 200 ms per device about 160 devices per second.

### Space requirements

Measured per day with 2500 sources (500 agents, 2000 SNMP devices each with CPU, memory, disk, two interfaces):

| Level | per day | default retention | occupied (default) |
| --- | --- | --- | --- |
| Raw values | 1.9 GB | 2 days (plus current day) | ≈ 6 GB |
| 5-minute values | 0.8 GB | 30 days | ≈ 24 GB |
| Hourly values | 65 MB | 365 days | ≈ 24 GB |
| **total** | | | **≈ 54 GB** |

So a good 2 GB per 100 sources. The size grows linearly with the number of sources and the series per source (one more
interface = two more series). The page **Einstellungen → Aufbewahrung der Messwerte** (retention of measurements) shows
the occupied space per level.

### Recommendations

| Installation | CPU | RAM | Disk (database) |
| --- | --- | --- | --- |
| up to 100 sources (small office, one site) | 2 | 4 GB | 20 GB |
| up to 500 sources | 2–4 | 4–8 GB | 40 GB |
| up to 2500 sources (measured) | 4 | 8 GB | 100 GB SSD |

- Tune PostgreSQL with more than 500 sources: `shared_buffers` about a quarter of the RAM, `effective_cache_size` about
  half, `max_wal_size` 4 GB.
- Saving space: 5-minute values to 14 days (graph “7 days” stays complete) or hourly values shorter per tenant
  (Einstellungen → Aufbewahrung). Shortening deletes at the next maintenance run, irrevocably.
- Backups need additional space (compressed). In the load test the backup was only 430 MB for 9.5 GB because the
  extrapolated test data repeats; with real data, expect about one fifth of the database per backup (assumption, not
  measured), times the number of kept backups.
- Many agents behind one NAT address: registration at most 30 per minute; a rollout of 500 computers through one
  address therefore takes a good 15 minutes (the package manager reports “Zu viele Registrierungsversuche”, too many
  registration attempts; running it again is enough).

## Retention of measurements

| Level | Default | adjustable globally | per tenant |
| --- | --- | --- | --- |
| Raw values (for 1-hour and 24-hour graphs, alerts) | 2 days | 2–7 days | no (shared daily partitions) |
| 5-minute values (graph 7 days, availability) | 30 days | 30–400 days | yes |
| Hourly values (graph 30 days, reports, forecast) | 365 days | 90–1830 days | yes |

Sub-tenants inherit the value of the nearest tenant above. Only the operator may adjust it, shorter only with a fresh
2FA code; every change is recorded in the audit log (`einstellungen.aufbewahrung`). State changes of the sensors are
kept as long as the 5-minute values.

## Failover concept: cold standby

There is no real high availability (two running central servers). For an outage of the central server there is a
**cold standby**: a second computer on which OpenWacht is installed but not running. It restores every new backup of
the main instance by itself, checks it and keeps it ready as a standby copy. In an outage, one command makes it the
central server.

OpenWacht does not fetch the backups itself over the network. Copying them into a folder on the second computer is the
operator’s task (rsync over SSH, NFS, if need be a USB drive). This means no new network path and no credentials in
OpenWacht, and the procedure also works without internet.

### Setting up (once)

1. Create a second computer (VM or LXC) with the same operating system on **different hardware** and install OpenWacht
   in **the same version** (`apt install ./openwacht-zentrale_….deb`, chapter 1). Do not run the setup assistant.
2. Copy the main instance’s **master key** to `/etc/openwacht/schluessel` (replaces the one created there; owner
   `svc_openwacht`, permissions 0400) and likewise `/etc/openwacht/zentrale.env`.
3. Create an inbox folder, for example `/var/lib/openwacht-zweitinstanz-eingang` (not `/var/backups/openwacht`, the
   second computer stores its own backups there), and have the main instance’s backups copied there, see below.
4. On the second computer:

   ```bash
   sudo openwacht-zentrale zweitinstanz -einrichten -quelle /var/lib/openwacht-zweitinstanz-eingang
   ```

   This creates the marker `/etc/openwacht/zweitinstanz`, switches off central server, trap service and backup there,
   switches on the timer `openwacht-zweitinstanz.timer` and restores the newest backup once immediately. If the database
   there already has accounts or a central server is running there, the command aborts (protection against mixing up
   the computers); `-ersetzen` overrides this.
5. Agents and browsers reach the central server via a **DNS name** with a short TTL (for example 300 s), not via the IP.
   This name must be among the central server’s names (Einstellungen → Installation, agent names).
6. With every update, update both computers, the second computer **first**. The package update does not start a central
   server on a marked second computer.

**Copying via rsync (example):** On the main instance, create a user `openwacht-kopie` that may read the backups
(`setfacl -m u:openwacht-kopie:rx /var/backups/openwacht` and `setfacl -d -m u:openwacht-kopie:r /var/backups/openwacht`).
Put the second computer’s key into its `authorized_keys`, only for read-only rsync:

```text
command="rrsync -ro /var/backups/openwacht",restrict ssh-ed25519 AAAA… zweitrechner
```

On the second computer every hour (for example via a systemd timer or cron as root):

```bash
rsync -t --chmod=F600 'openwacht-kopie@zentrale.beispiel.example:openwacht-*.dump' /var/lib/openwacht-zweitinstanz-eingang/
```

`rsync` first creates the file under a hidden name; the standby only takes finished files `openwacht-<time>.dump` that
have been unchanged for one minute. It does not delete old files in the inbox; for that, put for example
`find /var/lib/openwacht-zweitinstanz-eingang -name 'openwacht-*.dump' -mtime +14 -delete` into the same timer.

### What the timer checks

Every hour, `zweitinstanz -lauf` takes the newest backup from the inbox (by the timestamp in the name). If it is new, it
restores it into its own database `openwacht_neu` and checks:

- The master key matches (the backup’s agent CA can be decrypted).
- This package knows every migration of the backup. If the backup is newer, the run fails with “Zweitinstanz auf die
  Version der Hauptinstanz aktualisieren” (update the standby to the main instance’s version). An older backup is fine.
- The audit log’s hash chain is intact, there is at least one tenant.

Only then does it replace the previous standby copy (the database `openwacht`); the previous one is deleted. If a check
fails, the previous copy remains unchanged. The run also fails if the newest backup in the inbox is **older than 26
hours** (are backups no longer arriving?). Without a marker or if a central server is running on the computer, the run
changes nothing.

```bash
sudo openwacht-zentrale zweitinstanz -status      # state: last backup, restored, content, errors
journalctl -u openwacht-zweitinstanz              # history
```

When restoring, the second computer briefly needs space for two databases.

**Monitoring:** The state is in `/var/lib/openwacht-zweitinstanz/` (without secrets, readable by everyone):
`status.json` after every run, `ok` only after a new backup was restored successfully. Register an OpenWacht agent on
the second computer (with the main instance), allow the folder (`openwacht-agent sensoren -arten datei -ordner
/var/lib/openwacht-zweitinstanz`) and create a “Datei” (file) sensor on `/var/lib/openwacht-zweitinstanz/ok` with a
maximum age of 26 hours (chapter 7). This way the main instance reports when the standby no longer keeps up.

### In an outage

| Step | Command | Duration |
| --- | --- | --- |
| 1. Decision: the main instance will not come back quickly; it stays off | | |
| 2. The standby becomes the central server | `sudo openwacht-zentrale zweitinstanz -umschalten` | < 1 min. |
| 3. Point the DNS name to the standby | in DNS | 1 min. + TTL |
| 4. Check | interface, `curl -k https://<name>/api/v1/gesund`, agents “report” | 2–5 min. |

`-umschalten` asks for confirmation (`-ja` without asking), restores an even newer finished backup if there is one in
the inbox, runs the migrations, removes the marker, switches off the timer and switches on central server, trap service
and backup. If restoring the newer backup fails, the existing standby copy applies; the command names its date.

Because the copy is already restored, switching takes less than a minute; the **recovery time** is mainly determined by
DNS (about 5–10 minutes with a short TTL). For comparison: restoring by hand (`wiederherstellen`, chapter 13) took about
4 minutes in the load test (2 vCPU, database 9.5 GB), extrapolated to 54 GB about 25 minutes.

What remains: agents, SNMP devices, credentials, agent CA and HTTPS root come from the backup; agents reconnect without
intervention as soon as the name points to the standby. **What is lost:** everything since the last backup (up to 24
hours with daily backups): measurements, alert history, changes to devices and users. Whoever wants to lose less backs
up more often (own timer with `sichern -jetzt`, for example every 4 hours); the standby takes every new backup.

**Back to the main instance:** The previous main instance now becomes the standby: install the same version there,
check the master key, `zweitinstanz -einrichten -quelle … -ersetzen` with the backups of the new central server, after
the first successful run `-umschalten` there at a quiet moment and switch the DNS name back. Then make the other side
the standby again with `-einrichten -ersetzen`. **Never let both run at the same time:** agents report to the one the
DNS name points to; the other would hold outdated data and send its own alerts.

**Drills:** every six months, run `-umschalten` on a copy of the second computer (for example a VM snapshot without
network), sign in, note the time and discard the snapshot.

The dead man’s switch (Einstellungen → Totmann) reports the central server’s outage to the outside; without it nobody
notices that monitoring itself has stopped.
