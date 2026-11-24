-- SPDX-License-Identifier: AGPL-3.0-only

-- 0006: Alarme per ntfy.
--
-- Alarmkanäle gehören einem Mandanten und werden von dessen Admins gepflegt.
-- Ein Kanal meldet die Checks seines Mandanten; mit include_children auch die
-- aller Untermandanten (z. B. die IT für die Fertigung). Untermandanten sehen
-- die Kanäle ihrer Eltern nicht.
--
-- Das ntfy-Token liegt nur verschlüsselt in der Datenbank (AES-GCM mit dem
-- boxKey der Zentrale, gebunden an Kanal, Mandant und Server) und ist für die
-- Anwendungsrolle nicht lesbar; lesen kann es nur die Versandfunktion.
--
-- Was an welchen Kanal zuletzt gemeldet wurde, steht in alert_state, je Check
-- und Kanal. So bekommt ein neuer oder reparierter Kanal den aktuellen Stand,
-- ohne dass funktionierende Kanäle Meldungen doppelt erhalten.

CREATE TABLE openwacht.alert_channels (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    kind             text NOT NULL DEFAULT 'ntfy' CHECK (kind = 'ntfy'),
    -- normalisiert; muss in -alarm-ziele der Zentrale stehen (geprüft in Go)
    server           text NOT NULL CHECK (char_length(server) BETWEEN 8 AND 300 AND server ~ '^https?://[^[:space:][:cntrl:]]+$'),
    topic            text NOT NULL CHECK (topic ~ '^[-_A-Za-z0-9]{1,64}$'),
    token_enc        bytea CHECK (octet_length(token_enc) BETWEEN 29 AND 1024),
    has_token        boolean GENERATED ALWAYS AS (token_enc IS NOT NULL) STORED,
    include_children boolean NOT NULL DEFAULT false,
    enabled          boolean NOT NULL DEFAULT true,
    created_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    -- Versandzustand (nur über alert_channel_result)
    last_ok          timestamptz,
    last_error       text CHECK (char_length(last_error) <= 300),
    last_error_at    timestamptz
);
CREATE UNIQUE INDEX alert_channels_name ON openwacht.alert_channels (tenant_id, lower(name));

-- Zuletzt gemeldeter Zustand je Check und Kanal. Nur die Funktionen der
-- Zentrale schreiben und lesen hier.
CREATE TABLE openwacht.alert_state (
    check_id   uuid NOT NULL REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES openwacht.alert_channels (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    alerted    text NOT NULL CHECK (alerted IN ('ok', 'warn', 'crit', 'unknown')),
    alerted_at timestamptz NOT NULL,
    PRIMARY KEY (check_id, channel_id)
);
CREATE INDEX alert_state_channel ON openwacht.alert_state (channel_id);

CREATE FUNCTION openwacht.alert_channels_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM openwacht.alert_channels WHERE tenant_id = NEW.tenant_id) >= 20 THEN
        RAISE EXCEPTION 'Höchstens 20 Alarmkanäle je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.kind := 'ntfy';
    NEW.created_by := openwacht.current_user_id();
    NEW.created_at := now();
    NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    RETURN NEW;
END
$$;
CREATE TRIGGER alert_channels_before_insert BEFORE INSERT ON openwacht.alert_channels
    FOR EACH ROW EXECUTE FUNCTION openwacht.alert_channels_before_insert();

-- Neuer Server: Das alte Token darf nicht an ihn gehen (es gehört zum alten).
-- Neues Ziel (Server oder Topic): Die Empfänger kennen den aktuellen Stand
-- nicht, also alles neu melden. SECURITY DEFINER, weil die Anwendung
-- alert_state nicht ändern darf.
CREATE FUNCTION openwacht.alert_channels_before_update() RETURNS trigger
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
        NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER alert_channels_before_update BEFORE UPDATE ON openwacht.alert_channels
    FOR EACH ROW EXECUTE FUNCTION openwacht.alert_channels_before_update();

ALTER TABLE openwacht.alert_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.alert_state ENABLE ROW LEVEL SECURITY;
-- token_enc ist für die Anwendung nur schreibbar, nie lesbar.
GRANT SELECT (id, tenant_id, name, kind, server, topic, has_token, include_children, enabled, created_at,
              last_ok, last_error, last_error_at),
      INSERT (id, tenant_id, name, server, topic, token_enc, include_children, enabled),
      UPDATE (name, server, topic, token_enc, include_children, enabled),
      DELETE
    ON openwacht.alert_channels TO openwacht_app;
CREATE POLICY alert_channels_select ON openwacht.alert_channels FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY alert_channels_insert ON openwacht.alert_channels FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY alert_channels_update ON openwacht.alert_channels FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY alert_channels_delete ON openwacht.alert_channels FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
-- alert_state: keine Rechte und keine Policies für die Anwendung.
REVOKE ALL ON openwacht.alert_state FROM openwacht_app;

-- ---------------------------------------------------------------------------
-- Funktionen für den Versand (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Kandidaten: je aktivem Check und zuständigem aktivem Kanal der aktuelle und
-- der gemeldete Zustand. Ob gemeldet wird, entscheidet alarm.Decide in Go;
-- hier fallen nur Paare weg, die sicher still bleiben.
CREATE FUNCTION openwacht.alert_candidates()
    RETURNS TABLE (check_id uuid, check_tenant uuid, tenant_name text, check_name text, status text,
                   message text, fails integer, channel_id uuid, alerted text, alerted_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.tenant_id, t.name, c.name, c.status, coalesce(c.message, ''), c.fails,
           ch.id, s.alerted, s.alerted_at
      FROM openwacht.checks c
      JOIN openwacht.tenants t ON t.id = c.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = c.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
      LEFT JOIN openwacht.alert_state s ON s.check_id = c.id AND s.channel_id = ch.id
     WHERE c.enabled AND c.status IS NOT NULL
       -- IS NOT DISTINCT FROM: s.alerted ist NULL, solange nie gemeldet wurde,
       -- und ein NULL im NOT würde die Zeile still verwerfen.
       AND NOT (c.status = 'ok' AND s.alerted IS NOT DISTINCT FROM 'ok')
       AND NOT (c.status = 'ok' AND s.alerted IS NULL)
       AND NOT (c.status = 'warn' AND s.alerted IS NOT DISTINCT FROM 'warn')
     ORDER BY ch.id, c.id
     LIMIT 20000
$$;

-- Kanäle für den Versand, mit verschlüsseltem Token.
CREATE FUNCTION openwacht.alert_channels_for_send(p_ids uuid[])
    RETURNS TABLE (id uuid, tenant_id uuid, tenant_name text, name text, server text, topic text, token_enc bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT ch.id, ch.tenant_id, t.name, ch.name, ch.server, ch.topic, ch.token_enc
      FROM openwacht.alert_channels ch
      JOIN openwacht.tenants t ON t.id = ch.tenant_id
     WHERE ch.id = ANY (p_ids)
$$;

-- Erfolgreich gemeldet: Zustand je Check merken. Nur für Checks, für die der
-- Kanal noch zuständig ist (Check oder Kanal kann inzwischen gelöscht sein).
CREATE FUNCTION openwacht.alert_commit(p_channel uuid, p_checks uuid[], p_status text[]) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF cardinality(p_checks) IS DISTINCT FROM cardinality(p_status) THEN
        RAISE EXCEPTION 'alert_commit: Listen unterschiedlich lang';
    END IF;
    INSERT INTO openwacht.alert_state (check_id, channel_id, tenant_id, alerted, alerted_at)
    SELECT c.id, ch.id, c.tenant_id, x.status, now()
      FROM unnest(p_checks, p_status) AS x(check_id, status)
      JOIN openwacht.checks c ON c.id = x.check_id
      JOIN openwacht.alert_channels ch ON ch.id = p_channel
      JOIN openwacht.tenant_closure tc ON tc.ancestor = ch.tenant_id AND tc.descendant = c.tenant_id
     WHERE tc.depth = 0 OR ch.include_children
    ON CONFLICT (check_id, channel_id) DO UPDATE SET alerted = EXCLUDED.alerted, alerted_at = EXCLUDED.alerted_at;
    UPDATE openwacht.alert_channels SET last_ok = now(), last_error = NULL, last_error_at = NULL
     WHERE id = p_channel;
END
$$;

-- Ergebnis eines Versands (auch „Test senden“): p_error NULL = Erfolg.
CREATE FUNCTION openwacht.alert_channel_result(p_channel uuid, p_error text) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.alert_channels
       SET last_ok       = CASE WHEN p_error IS NULL THEN now() ELSE last_ok END,
           last_error    = CASE WHEN p_error IS NULL THEN NULL ELSE left(p_error, 300) END,
           last_error_at = CASE WHEN p_error IS NULL THEN NULL ELSE now() END
     WHERE id = p_channel
$$;

REVOKE ALL ON FUNCTION openwacht.alert_candidates(), openwacht.alert_channels_for_send(uuid[]),
    openwacht.alert_commit(uuid, uuid[], text[]), openwacht.alert_channel_result(uuid, text),
    openwacht.alert_channels_before_insert(), openwacht.alert_channels_before_update() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_candidates(), openwacht.alert_channels_for_send(uuid[]),
    openwacht.alert_commit(uuid, uuid[], text[]), openwacht.alert_channel_result(uuid, text)
    TO openwacht_app;
