# 18. Legal and evidence

OpenWacht runs at the operator; the operator is responsible for data protection. [`docs/recht/`](../recht/README.md)
(German) contains templates that describe what the software stores and for how long, and leave gaps for the operator’s
details:

- record of processing activities, deletion concept with the software’s retention periods, technical and
  organisational measures,
- template for data processing on behalf (only for remote maintenance by third parties),
- mapping to the BSI IT baseline protection (Kompendium edition 2023),
- accessibility statement,
- draft for an external penetration test.

## What the operator should configure

| Where | What | Chapter |
| --- | --- | --- |
| Einstellungen → Installation (Settings → Installation) | retention of the audit log (default unlimited) and of the backups | 13 |
| Einstellungen → Aufbewahrung (Settings → Retention) | measurements globally and per tenant | 16 |
| Start option `-sicherheitskontakt` | own reporting channel in `security.txt` | 17 |
| Verwaltung → Mandanten (Administration → Tenants) | recertification at a fixed interval | 3 |

## Accessibility

The interface is checked with axe-core (WCAG 2.1 A/AA) on all main pages, light and dark, wide and narrow, and can be
used with the keyboard. Graphics (graphs, sunburst chart) have text alternatives for states, not for the history; PDF
reports are not tagged. Details and open points are in the template for the statement.

## Licence

OpenWacht is free software under the GNU Affero General Public License, version 3 (`AGPL-3.0-only`); the full text is
in `LICENSE` and in every installation under `/lizenzen/AGPL-3.0.txt`. For operation this means:

- Use, including commercial use and for customers, is allowed without licence fees.
- Whoever **modifies** OpenWacht and makes the modified version available to others over the network (for example
  tenants of a shared central server) must offer them the source code of exactly this version (§ 13). For this, the
  interface links the source code below the sign-in and in the sidebar; with your own version the link points to your
  own source code (`web/src/Lizenz.tsx`).
- Whoever passes OpenWacht on (package, offline package) includes the licence and the source code or offers it.

The bundled fonts are licensed under the SIL Open Font License 1.1 (`/lizenzen/`). This is a summary, not legal advice;
in case of doubt the licence text applies.

## Security vulnerabilities

Reporting channel and commitments: [`SECURITY.md`](../../SECURITY.md).
