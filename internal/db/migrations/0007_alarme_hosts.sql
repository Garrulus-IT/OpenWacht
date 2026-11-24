-- SPDX-License-Identifier: AGPL-3.0-only

-- 0007: Alarme für Hosts – stumme Agents und Messwerte (Platte, Arbeitsspeicher).
--
-- Was ein Host-Alarm ist, entscheidet die Zentrale in Go (Schwellen aus den
-- Schaltern der Zentrale). Die Datenbank liefert je Agent die Kanäle, die für
-- ihn zuständig sind (wie bei Checks: Kanal des eigenen Mandanten, mit
-- include_children auch der Eltern), und merkt sich, was gemeldet wurde.
--
-- alert_state_agents: je Agent, Kanal und Gegenstand (subject) der zuletzt
-- gemeldete Zustand. Gegenstände: 'stumm', 'speicher', 'platte:<Einhängepunkt>'.
-- Eine Zeile gibt es nur, solange ein Problem gemeldet ist: Die Entwarnung
-- löscht sie. So wachsen verschwundene Einhängepunkte nicht an.

CREATE TABLE openwacht.alert_state_agents (
    agent_id   uuid NOT NULL REFERENCES openwacht.agents (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES openwacht.alert_channels (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    subject    text NOT NULL CHECK (char_length(subject) <= 300 AND subject !~ '[[:cntrl:]]'
                                    AND (subject IN ('stumm', 'speicher') OR subject ~ '^platte:.')),
    alerted    text NOT NULL CHECK (alerted IN ('warn', 'crit', 'unknown')),
    alerted_at timestamptz NOT NULL,
    PRIMARY KEY (agent_id, channel_id, subject)
);
CREATE INDEX alert_state_agents_channel ON openwacht.alert_state_agents (channel_id);

ALTER TABLE openwacht.alert_state_agents ENABLE ROW LEVEL SECURITY;
-- Keine Rechte und keine Policies für die Anwendung.
REVOKE ALL ON openwacht.alert_state_agents FROM PUBLIC, openwacht_app;

-- Neues Ziel eines Kanals: auch die Host-Zustände neu melden.
CREATE OR REPLACE FUNCTION openwacht.alert_channels_before_update() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant eines Alarmkanals sind unveränderlich.';
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server AND NEW.token_enc IS NOT DISTINCT FROM OLD.token_enc THEN
        NEW.token_enc := NULL;
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server OR NEW.topic IS DISTINCT FROM OLD.topic THEN
        DELETE FROM openwacht.alert_state WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_agents WHERE channel_id = OLD.id;
        NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------
-- Funktionen für den Versand (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Je Agent mit mindestens einem zuständigen aktiven Kanal: Name, Mandant,
-- Sekunden seit der letzten Meldung (nach der Datenbankuhr, wie last_seen),
-- die Messwerte und die Kanäle. Gesperrte Agents nur, solange an einen Kanal
-- noch ein Problem gemeldet ist: Sie bekommen eine letzte Entwarnung.
-- Vom Snapshot nur, was die Alarme brauchen.
CREATE FUNCTION openwacht.alert_host_candidates()
    RETURNS TABLE (agent_id uuid, agent_tenant uuid, tenant_name text, hostname text, revoked boolean,
                   silent_s double precision, metrics jsonb, channels uuid[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.id, a.tenant_id, t.name, a.hostname, a.revoked_at IS NOT NULL,
           extract(epoch FROM now() - coalesce(a.last_seen, a.created_at))::double precision,
           CASE WHEN a.snapshot IS NULL THEN NULL
                ELSE jsonb_build_object('speicher', a.snapshot -> 'speicher', 'platten', a.snapshot -> 'platten') END,
           array_agg(ch.id ORDER BY ch.id)
      FROM openwacht.agents a
      JOIN openwacht.tenants t ON t.id = a.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = a.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
     WHERE a.revoked_at IS NULL
        OR EXISTS (SELECT 1 FROM openwacht.alert_state_agents s WHERE s.agent_id = a.id)
     GROUP BY a.id, t.name
     ORDER BY a.id
     LIMIT 20000
$$;

-- Gemeldete Host-Probleme (nur Problemzustände, siehe oben).
CREATE FUNCTION openwacht.alert_host_states()
    RETURNS TABLE (agent_id uuid, channel_id uuid, subject text, alerted text, alerted_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.agent_id, s.channel_id, s.subject, s.alerted, s.alerted_at
      FROM openwacht.alert_state_agents s
     ORDER BY s.channel_id, s.agent_id, s.subject
     LIMIT 200000
$$;

-- Erfolgreich gemeldet: Problemzustand merken, Entwarnung ('ok') löscht ihn.
-- Nur für Agents, für die der Kanal noch zuständig ist.
CREATE FUNCTION openwacht.alert_host_commit(p_channel uuid, p_agents uuid[], p_subjects text[], p_status text[])
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF cardinality(p_agents) IS DISTINCT FROM cardinality(p_subjects)
       OR cardinality(p_agents) IS DISTINCT FROM cardinality(p_status) THEN
        RAISE EXCEPTION 'alert_host_commit: Listen unterschiedlich lang';
    END IF;
    DELETE FROM openwacht.alert_state_agents s
     USING unnest(p_agents, p_subjects, p_status) AS x(agent_id, subject, status)
     WHERE x.status = 'ok' AND s.channel_id = p_channel AND s.agent_id = x.agent_id AND s.subject = x.subject;
    INSERT INTO openwacht.alert_state_agents (agent_id, channel_id, tenant_id, subject, alerted, alerted_at)
    SELECT a.id, ch.id, a.tenant_id, x.subject, x.status, now()
      FROM unnest(p_agents, p_subjects, p_status) AS x(agent_id, subject, status)
      JOIN openwacht.agents a ON a.id = x.agent_id
      JOIN openwacht.alert_channels ch ON ch.id = p_channel
      JOIN openwacht.tenant_closure tc ON tc.ancestor = ch.tenant_id AND tc.descendant = a.tenant_id
     WHERE x.status <> 'ok' AND (tc.depth = 0 OR ch.include_children)
    ON CONFLICT (agent_id, channel_id, subject) DO UPDATE SET alerted = EXCLUDED.alerted, alerted_at = EXCLUDED.alerted_at;
    UPDATE openwacht.alert_channels SET last_ok = now(), last_error = NULL, last_error_at = NULL
     WHERE id = p_channel;
END
$$;

REVOKE ALL ON FUNCTION openwacht.alert_host_candidates(), openwacht.alert_host_states(),
    openwacht.alert_host_commit(uuid, uuid[], text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_host_candidates(), openwacht.alert_host_states(),
    openwacht.alert_host_commit(uuid, uuid[], text[], text[]) TO openwacht_app;
