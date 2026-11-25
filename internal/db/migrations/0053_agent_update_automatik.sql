-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.4: Agents übernehmen neue signierte Versionen auf Wunsch selbst
-- (Entscheidung Philipp, 25.11.2026), gestaffelt je Mandant:
--   * erst die Agents der Pilotgruppe (Gerätegruppe mit Untergruppen),
--   * die übrigen frühestens nach der Wartezeit, nur wenn kein Pilot einen
--     Fehler meldet und, falls es Piloten gibt, mindestens einer die neue
--     Version schon fährt,
--   * nur im Zeitfenster (Wochentage, Stunden in der Zeitzone der Installation).
-- Eine Freigabe von Hand für einen Agent geht immer vor. Leitprinzipien 1 und
-- 4 bleiben: Der Agent fragt beim Melden, lädt und prüft selbst die Signatur;
-- die Zentrale schickt nichts und kann nichts signieren.

CREATE TABLE openwacht.agent_update_auto (
    tenant_id   uuid PRIMARY KEY REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    enabled     boolean NOT NULL DEFAULT false,
    pilot_group uuid,
    wait_hours  integer NOT NULL DEFAULT 24 CHECK (wait_hours BETWEEN 0 AND 720),
    -- Wochentage als Bits, Montag = 1, Dienstag = 2 … Sonntag = 64
    days        smallint NOT NULL DEFAULT 127 CHECK (days BETWEEN 1 AND 127),
    -- Stunden von … bis (bis ausschließlich); gleich = ganzer Tag, von > bis = über Mitternacht
    hour_from   smallint NOT NULL DEFAULT 0 CHECK (hour_from BETWEEN 0 AND 23),
    hour_to     smallint NOT NULL DEFAULT 0 CHECK (hour_to BETWEEN 0 AND 23),
    updated_by  uuid,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, pilot_group) REFERENCES openwacht.device_groups (tenant_id, id) ON DELETE SET NULL (pilot_group)
);

CREATE FUNCTION openwacht.agent_update_auto_stamp() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, openwacht AS $$
BEGIN
    NEW.updated_by := openwacht.current_user_id();
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER agent_update_auto_stamp BEFORE INSERT OR UPDATE ON openwacht.agent_update_auto
    FOR EACH ROW EXECUTE FUNCTION openwacht.agent_update_auto_stamp();

ALTER TABLE openwacht.agent_update_auto ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON openwacht.agent_update_auto TO openwacht_app;
CREATE POLICY agent_update_auto_select ON openwacht.agent_update_auto FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY agent_update_auto_write ON openwacht.agent_update_auto FOR ALL TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())) WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Freigaben, die die Zentrale nach der Regel selbst eingetragen hat.
ALTER TABLE openwacht.agent_update_releases ADD COLUMN auto boolean NOT NULL DEFAULT false;

-- Pilot: Gerät des Agents liegt in der Pilotgruppe oder einer Untergruppe.
CREATE FUNCTION openwacht.agent_in_group(p_agent uuid, p_group uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH RECURSIVE baum AS (
        SELECT g.id FROM openwacht.device_groups g WHERE g.id = p_group
        UNION
        SELECT g.id FROM openwacht.device_groups g JOIN baum b ON g.parent_id = b.id
    )
    SELECT p_group IS NOT NULL AND EXISTS (
        SELECT 1 FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id
         WHERE a.id = p_agent AND d.group_id IN (SELECT id FROM baum))
$$;

-- Kandidat für einen Agent (Agent-Port, ohne Benutzerkontext): die neueste
-- hochgeladene Version seiner Plattform mit nicht widerrufenem Schlüssel,
-- dazu die Regel seines Mandanten und der Stand der Piloten. Leer, wenn die
-- Automatik für seinen Mandanten aus ist. Die Entscheidung trifft die Zentrale
-- (Zeitfenster in der Zeitzone der Installation).
CREATE FUNCTION openwacht.agent_update_auto_candidate(p_agent uuid, p_os text, p_arch text)
    RETURNS TABLE (version text, uploaded_at timestamptz, pilot boolean, wait_hours integer, days smallint,
                   hour_from smallint, hour_to smallint, pilots integer, pilots_ok integer, pilots_error integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH ag AS (
        SELECT a.id, a.tenant_id FROM openwacht.agents a WHERE a.id = p_agent AND a.revoked_at IS NULL
    ), regel AS (
        SELECT r.* FROM openwacht.agent_update_auto r JOIN ag ON ag.tenant_id = r.tenant_id WHERE r.enabled
    ), kandidat AS (
        SELECT u.version, u.uploaded_at FROM openwacht.agent_updates u
         WHERE u.os = p_os AND u.arch = p_arch
           AND NOT EXISTS (SELECT 1 FROM openwacht.update_key_revocations k WHERE k.key_id = u.key_id)
         ORDER BY string_to_array(u.version, '.')::int[] DESC LIMIT 1
    ), piloten AS (
        SELECT a.id, coalesce(a.snapshot->>'agent', '') AS ver, coalesce(a.snapshot->>'update_fehler', '') AS fehler
          FROM openwacht.agents a, regel
         WHERE a.tenant_id = regel.tenant_id AND a.revoked_at IS NULL AND openwacht.agent_in_group(a.id, regel.pilot_group)
    )
    SELECT k.version, k.uploaded_at, openwacht.agent_in_group(p_agent, regel.pilot_group), regel.wait_hours, regel.days,
           regel.hour_from, regel.hour_to,
           (SELECT count(*)::int FROM piloten),
           (SELECT count(*)::int FROM piloten WHERE ver = k.version),
           (SELECT count(*)::int FROM piloten WHERE fehler <> '' AND ver <> k.version)
      FROM regel, kandidat k
$$;

-- Freigabe nach der Regel eintragen. Prüft selbst noch einmal: Automatik an,
-- Paket für die Plattform vorhanden, keine Freigabe von Hand.
CREATE FUNCTION openwacht.agent_update_auto_release(p_agent uuid, p_os text, p_arch text, p_version text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    t uuid;
BEGIN
    SELECT a.tenant_id INTO t FROM openwacht.agents a
      JOIN openwacht.agent_update_auto r ON r.tenant_id = a.tenant_id AND r.enabled
     WHERE a.id = p_agent AND a.revoked_at IS NULL;
    IF t IS NULL OR NOT EXISTS (SELECT 1 FROM openwacht.agent_updates u
                                 WHERE u.version = p_version AND u.os = p_os AND u.arch = p_arch) THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM openwacht.agent_update_releases r WHERE r.agent_id = p_agent AND NOT r.auto) THEN
        RETURN false;
    END IF;
    INSERT INTO openwacht.agent_update_releases (agent_id, tenant_id, version, auto) VALUES (p_agent, t, p_version, true)
        ON CONFLICT (agent_id) DO UPDATE SET version = EXCLUDED.version, auto = true;
    RETURN true;
END
$$;

REVOKE ALL ON FUNCTION openwacht.agent_in_group(uuid, uuid), openwacht.agent_update_auto_candidate(uuid, text, text),
    openwacht.agent_update_auto_release(uuid, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_update_auto_candidate(uuid, text, text),
    openwacht.agent_update_auto_release(uuid, text, text, text) TO openwacht_app;
