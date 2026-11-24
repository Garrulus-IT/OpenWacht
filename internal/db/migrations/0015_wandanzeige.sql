-- SPDX-License-Identifier: AGPL-3.0-only

-- 0015: Wandanzeige (Etappe 12) und Gruppen an Geräten.
--
-- Gruppe: optionaler Pfad am Gerät, Ebenen mit '/' getrennt
-- (z. B. 'Netzwerk/Switche'). Nur für die Darstellung; Rechte hängen
-- weiterhin allein am Mandanten.
--
-- Wandanzeige: ein Bildschirm ohne Benutzerkonto. Ein Admin legt sie in
-- einem Mandanten an und bekommt einmalig einen geheimen Link; gespeichert
-- ist nur der SHA-256-Hash des Schlüssels. Die Zentrale setzt für Anfragen
-- der Anzeige statt app.user_id den Kontext app.display_id. Daraus leitet
-- die Datenbank die sichtbaren Mandanten ab (der Mandant der Anzeige, auf
-- Wunsch mit Untermandanten), nie aus Request-Daten.
--
-- Die Anzeige liest wie ein Leser, aber nur die Tabellen, die sie für die
-- Zustände braucht (Mandanten, Geräte, Checks, Agents, SNMP-Quellen, Alarme,
-- Wartung, Rohwerte für den CPU-Mittelwert). Benutzer, Rollen, Audit-Log,
-- Alarmkanäle, Tokens und Verlauf bleiben für sie unsichtbar; neue Tabellen
-- ebenfalls, solange sie hier nicht ausdrücklich freigegeben werden.
-- Schreiben kann sie nichts: Alle schreibenden Policies hängen an Rollen
-- eines Benutzers.

-- ---------------------------------------------------------------------------
-- Gruppe am Gerät
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.devices ADD COLUMN group_path text;
ALTER TABLE openwacht.devices ADD CONSTRAINT devices_group_path_check CHECK (
    group_path IS NULL OR (
        char_length(group_path) BETWEEN 1 AND 200
        AND group_path !~ '[[:cntrl:]]'
        AND group_path = btrim(group_path)
        AND group_path !~ '(^/|/$|//|[[:space:]]/|/[[:space:]])'
        AND cardinality(string_to_array(group_path, '/')) <= 4));

GRANT SELECT (group_path), INSERT (group_path), UPDATE (group_path) ON openwacht.devices TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Wandanzeigen
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.displays (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name             text NOT NULL
                     CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]' AND name = btrim(name)),
    token_hash       bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    include_children boolean NOT NULL DEFAULT false,
    -- Optional: nur aus diesem Netz (Client-Adresse wie bei der Anmeldung).
    allowed_net      cidr,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz
);
CREATE INDEX displays_tenant ON openwacht.displays (tenant_id);

ALTER TABLE openwacht.displays ENABLE ROW LEVEL SECURITY;
-- Den Hash bekommt die Anwendung nie zu sehen, nur beim Anlegen schreibt sie ihn.
GRANT SELECT (id, tenant_id, name, include_children, allowed_net, created_at, last_seen),
      INSERT (tenant_id, name, token_hash, include_children, allowed_net),
      DELETE
    ON openwacht.displays TO openwacht_app;
CREATE POLICY displays_select ON openwacht.displays FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY displays_insert ON openwacht.displays FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY displays_delete ON openwacht.displays FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Aktuelle Anzeige aus dem Transaktionskontext; NULL, wenn nicht gesetzt.
CREATE FUNCTION openwacht.current_display_id() RETURNS uuid
    LANGUAGE plpgsql STABLE AS $$
DECLARE
    v text := current_setting('app.display_id', true);
BEGIN
    IF v IS NULL OR v = '' THEN
        RETURN NULL;
    END IF;
    RETURN v::uuid;
END
$$;

-- Mandanten, die die aktuelle Anzeige sehen darf. Ist zugleich ein Benutzer
-- gesetzt, sieht die Anzeige nichts: Beide Kontexte mischen sich nie.
CREATE FUNCTION openwacht.display_tenants() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.descendant
      FROM openwacht.displays d
      JOIN openwacht.tenant_closure c ON c.ancestor = d.tenant_id AND (c.depth = 0 OR d.include_children)
     WHERE d.id = openwacht.current_display_id()
       AND openwacht.current_user_id() IS NULL
$$;

-- Anmeldung einer Anzeige über den Hash ihres Schlüssels (ohne Kontext
-- aufrufbar). Merkt sich höchstens einmal je Minute, wann sie zuletzt da war.
CREATE FUNCTION openwacht.display_login(p_hash bytea)
    RETURNS TABLE (display_id uuid, tenant_id uuid, name text, allowed_net cidr)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.displays d SET last_seen = now()
     WHERE d.token_hash = p_hash AND (d.last_seen IS NULL OR d.last_seen < now() - interval '1 minute');
    RETURN QUERY SELECT d.id, d.tenant_id, d.name, d.allowed_net FROM openwacht.displays d WHERE d.token_hash = p_hash;
END
$$;

REVOKE ALL ON FUNCTION openwacht.current_display_id(), openwacht.display_tenants(), openwacht.display_login(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.current_display_id(), openwacht.display_tenants(), openwacht.display_login(bytea)
    TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Lesefreigabe für Anzeigen (Allowlist)
-- ---------------------------------------------------------------------------

ALTER POLICY tenants_select ON openwacht.tenants
    USING (id IN (SELECT openwacht.visible_tenants()) OR id IN (SELECT openwacht.display_tenants()));
ALTER POLICY devices_select ON openwacht.devices
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY checks_select ON openwacht.checks
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY agents_select ON openwacht.agents
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY snmp_sources_select ON openwacht.snmp_sources
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY alarms_select ON openwacht.alarms
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY maintenance_select ON openwacht.maintenance
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY metrics_host_raw_select ON openwacht.metrics_host_raw
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
ALTER POLICY metrics_snmp_raw_select ON openwacht.metrics_snmp_raw
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
