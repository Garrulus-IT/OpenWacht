-- SPDX-License-Identifier: AGPL-3.0-only

-- Rollen und Datenbank von OpenWacht anlegen. Einmalig als Superuser ausführen:
--   runuser -u postgres -- psql -v ON_ERROR_STOP=1 -f rollen.sql
-- Alle Logins ohne Passwort: Angemeldet wird nur über den Unix-Socket mit
-- Peer-Authentifizierung (siehe pg_hba-openwacht.conf und pg_ident-openwacht.conf).
CREATE ROLE openwacht_app NOLOGIN;                                  -- Gruppenrolle, für sie gilt Row-Level Security
CREATE ROLE openwacht_owner LOGIN;                                  -- Migrationen, besitzt das Schema
CREATE ROLE openwacht_zentrale LOGIN IN ROLE openwacht_app;          -- Login der Zentrale
CREATE ROLE openwacht_traps NOLOGIN;                                -- Gruppenrolle des Trap-Dienstes (nur Funktionen traps_*)
CREATE ROLE openwacht_trapdienst LOGIN IN ROLE openwacht_traps;      -- Login des Trap-Dienstes
CREATE DATABASE openwacht OWNER openwacht_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE openwacht FROM PUBLIC;
GRANT CONNECT ON DATABASE openwacht TO openwacht_owner, openwacht_zentrale, openwacht_trapdienst;
