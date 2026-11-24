-- SPDX-License-Identifier: AGPL-3.0-only

-- Rollen für den Trap-Dienst (ab Migration 0017). Einmalig als Superuser,
-- VOR dem Update auf 0017 (sonst bricht die Migration mit Hinweis ab):
--   runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d openwacht -f rollen-traps.sql
-- Ohne Passwort: Anmeldung nur über den Unix-Socket mit Peer-Authentifizierung
-- (svc_openwacht_traps → openwacht_trapdienst, siehe pg_ident-openwacht.conf).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_traps') THEN
        CREATE ROLE openwacht_traps NOLOGIN;            -- Gruppenrolle, darf nur die Funktionen traps_*
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_trapdienst') THEN
        CREATE ROLE openwacht_trapdienst LOGIN IN ROLE openwacht_traps;   -- Login des Trap-Dienstes
    END IF;
END
$$;
GRANT CONNECT ON DATABASE openwacht TO openwacht_trapdienst;
