-- SPDX-License-Identifier: AGPL-3.0-only

-- 0017: SNMPv3 (nur authPriv), Trap-Dienst und Trap-Regeln (Etappe 14).
--
-- SNMPv3: version '3'. Die Zugangsdaten (Benutzer, beide Passphrasen) liegen
-- wie die Community verschlüsselt in secret_enc. Die Verfahren (v3_auth,
-- v3_priv) sind kein Geheimnis und stehen lesbar daneben, damit die
-- Oberfläche sie anzeigen kann. Erlaubt sind nur SHA-1/SHA-2 und AES
-- (Entscheidung, 20.11.2026: nur authPriv, kein MD5/DES).
--
-- Traps empfängt ein eigener Dienst (openwacht-zentrale traps) mit eigener
-- Datenbankrolle openwacht_traps. Er sieht keine Tabelle direkt, sondern nur
-- die Funktionen traps_*: Quellen mit eingeschalteten Traps (Zugangsdaten
-- nur in trap_secret_enc, verschlüsselt mit einem eigenen, vom Hauptschlüssel
-- abgeleiteten Trap-Schlüssel), Regeln und das Schreiben von Protokoll und
-- Zustand. Er kann weder Benutzer noch Communities zum Abfragen, Tokens oder
-- TOTP-Geheimnisse lesen.
--
-- Regeln gehören einem Mandanten, gelten für seine Geräte und die seiner
-- Untermandanten und lassen sich auf eine Gruppe (mit Untergruppen) oder ein
-- Gerät des eigenen Mandanten eingrenzen. Die erste passende Regel gilt
-- (eigener Mandant zuerst, dann die Eltern). Pflegen dürfen nur Admins.
-- Wirkung: Warnung, Fehler, Entwarnung (beendet den Zustand einer anderen
-- Regel) oder ignorieren. Zustände enden per Entwarnung, nach Ablauf
-- (duration_min, 0 = nie) oder von Hand (Admins und Operatoren).
--
-- Protokoll: Trap-OID und höchstens 20 Werte à 200 Zeichen, 30 Tage, höchstens
-- 20000 Einträge je Quelle (Entscheidung, 20.11.2026; Leitprinzip 5: Traps können
-- Benutzernamen enthalten, gespeichert wird das bewusst).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_traps') THEN
        RAISE EXCEPTION 'Rolle openwacht_traps fehlt. Vor dem Update als Superuser anlegen (siehe deploy/linux/postgresql/rollen-traps.sql).';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_traps' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'Rolle openwacht_traps darf weder SUPERUSER noch BYPASSRLS noch LOGIN haben.';
    END IF;
    IF pg_has_role('openwacht_traps', 'openwacht_app', 'MEMBER') OR pg_has_role('openwacht_app', 'openwacht_traps', 'MEMBER') THEN
        RAISE EXCEPTION 'openwacht_traps und openwacht_app müssen getrennte Rollen sein.';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA openwacht TO openwacht_traps;

-- ---------------------------------------------------------------------------
-- SNMPv3 und Trap-Einstellungen an der Quelle
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_version_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_version_check CHECK (version IN ('1', '2c', '3', 'pve'));
ALTER TABLE openwacht.snmp_sources
    ADD COLUMN v3_auth text CHECK (v3_auth IN ('sha', 'sha224', 'sha256', 'sha384', 'sha512')),
    ADD COLUMN v3_priv text CHECK (v3_priv IN ('aes', 'aes192', 'aes256', 'aes192c', 'aes256c')),
    ADD COLUMN traps boolean NOT NULL DEFAULT false,
    ADD COLUMN trap_secret_enc bytea CHECK (octet_length(trap_secret_enc) BETWEEN 29 AND 2048),
    ADD CONSTRAINT snmp_sources_v3_check CHECK ((version = '3') = (v3_auth IS NOT NULL AND v3_priv IS NOT NULL)),
    ADD CONSTRAINT snmp_sources_traps_check CHECK (NOT traps OR version IN ('1', '2c', '3')),
    ADD CONSTRAINT snmp_sources_id_tenant UNIQUE (id, tenant_id);

GRANT SELECT (v3_auth, v3_priv, traps), INSERT (v3_auth, v3_priv, traps, trap_secret_enc),
      UPDATE (v3_auth, v3_priv, traps, trap_secret_enc) ON openwacht.snmp_sources TO openwacht_app;

-- Zugangsdaten gelten nur für die Art (v1/v2c, v3 oder Proxmox), Adresse,
-- Port und CA, für die sie eingegeben wurden. Die Trap-Zugangsdaten zusätzlich
-- nur, solange Traps an sind und sich die Zugangsdaten nicht ändern.
CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' ELSE 'v1' END;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id THEN
        RAISE EXCEPTION 'ID, Gerät und Mandant einer SNMP-Quelle sind unveränderlich.';
    END IF;
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
        OR v_kind_new IS DISTINCT FROM v_kind_old
        OR NEW.v3_auth IS DISTINCT FROM OLD.v3_auth OR NEW.v3_priv IS DISTINCT FROM OLD.v3_priv
        OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem)
       AND NEW.secret_enc IS NOT DISTINCT FROM OLD.secret_enc THEN
        NEW.secret_enc := NULL;
    END IF;
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
        OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc)
       AND NEW.trap_secret_enc IS NOT DISTINCT FROM OLD.trap_secret_enc THEN
        NEW.trap_secret_enc := NULL;
    END IF;
    IF NOT NEW.traps OR NEW.secret_enc IS NULL THEN
        NEW.trap_secret_enc := NULL;
    END IF;
    IF NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
       OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc
       OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem THEN
        NEW.revision := OLD.revision + 1;
        NEW.changed_at := now(); NEW.next_run := now();
        NEW.last_try := NULL; NEW.last_ok := NULL; NEW.last_error := NULL;
        NEW.snapshot := NULL; NEW.rebooted_at := NULL;
    ELSIF NEW.enabled AND NOT OLD.enabled THEN
        NEW.next_run := now(); NEW.changed_at := now();
    ELSIF NEW.interval_s < OLD.interval_s THEN
        NEW.next_run := least(NEW.next_run, now() + make_interval(secs => NEW.interval_s));
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION openwacht.snmp_sources_traps_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NOT NEW.traps OR NEW.secret_enc IS NULL THEN
        NEW.trap_secret_enc := NULL;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_sources_traps_insert BEFORE INSERT ON openwacht.snmp_sources
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_sources_traps_insert();

-- „Verbindung prüfen“ und „Traps einschalten“ ohne neue Zugangsdaten: die
-- gespeicherten, nur für Admins und nur für dieselbe Adresse, denselben Port
-- und dieselbe Art. Zusätzlich die Version, damit v3-Daten nie als Community
-- gelesen werden.
CREATE FUNCTION openwacht.snmp_secret_for_admin(p_device uuid, p_host text, p_port integer)
    RETURNS TABLE (id uuid, version text, secret_enc bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, s.version, s.secret_enc FROM openwacht.snmp_sources s
     WHERE s.device_id = p_device AND s.host = p_host AND s.port = p_port
       AND s.tenant_id IN (SELECT openwacht.admin_tenants())
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_secret_for_admin(uuid, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_secret_for_admin(uuid, text, integer) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Eigene SNMP-Engine (für v3-Informs: OpenWacht ist dann die maßgebliche Engine)
-- ---------------------------------------------------------------------------

-- Engine-ID nach RFC 3411: 0x80000000 (Unternehmen 0, keine IANA-Nummer),
-- Format 5 (vom Betreiber vergeben), 16 Zufallsbytes. engine_boots zählt jeden
-- Start des Trap-Dienstes (RFC 3414: snmpEngineBoots).
CREATE TABLE openwacht.snmp_engine (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    engine_id    bytea NOT NULL CHECK (octet_length(engine_id) BETWEEN 5 AND 32),
    engine_boots integer NOT NULL DEFAULT 0 CHECK (engine_boots BETWEEN 0 AND 2147483647),
    started_at   timestamptz
);
INSERT INTO openwacht.snmp_engine (engine_id)
VALUES ('\x8000000005'::bytea || decode(replace(gen_random_uuid()::text, '-', ''), 'hex'));
ALTER TABLE openwacht.snmp_engine ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_engine FROM PUBLIC;

-- Für die Oberfläche: Engine-ID (Hex) und ob der Trap-Dienst schon lief.
CREATE FUNCTION openwacht.snmp_engine_info()
    RETURNS TABLE (engine_id text, started_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT encode(e.engine_id, 'hex'), e.started_at FROM openwacht.snmp_engine e
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_engine_info() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_engine_info() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Regeln
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.valid_trap_oid(s text, wildcard boolean) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 200
       AND (s ~ '^[0-9]+(\.[0-9]+)*$' OR (wildcard AND (s = '*' OR s ~ '^[0-9]+(\.[0-9]+)*\.\*$')))
$$;

CREATE TABLE openwacht.snmp_trap_rules (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    position     integer NOT NULL DEFAULT 0 CHECK (position BETWEEN 0 AND 100000),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]' AND name = btrim(name)),
    enabled      boolean NOT NULL DEFAULT true,
    -- Eingrenzung (höchstens eine): Gruppe mit Untergruppen oder ein Gerät
    group_id     uuid,
    device_id    uuid,
    -- Trap-OID: genau, mit „.*“ am Ende als Präfix, „*“ = alle
    trap_oid     text NOT NULL CHECK (openwacht.valid_trap_oid(trap_oid, true)),
    -- optionale Bedingung an einen Wert (OID genau oder als Präfix)
    vb_oid       text CHECK (openwacht.valid_trap_oid(vb_oid, false)),
    vb_op        text CHECK (vb_op IN ('gleich', 'nicht', 'enthaelt', 'beginnt')),
    vb_value     text CHECK (char_length(vb_value) <= 200 AND vb_value !~ '[[:cntrl:]]'),
    action       text NOT NULL CHECK (action IN ('warn', 'crit', 'ok', 'ignore')),
    -- „unterscheiden nach“: Wert dieser OID trennt Zustände (z. B. ifIndex)
    key_oid      text CHECK (openwacht.valid_trap_oid(key_oid, false)),
    duration_min integer NOT NULL DEFAULT 60 CHECK (duration_min BETWEEN 0 AND 43200),
    -- nur Entwarnung: beendet die Zustände dieser Regel
    clears       uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id),
    CHECK (group_id IS NULL OR device_id IS NULL),
    CHECK ((vb_oid IS NULL) = (vb_op IS NULL) AND (vb_op IS NULL) = (vb_value IS NULL)),
    CHECK ((action = 'ok') = (clears IS NOT NULL)),
    CHECK (action IN ('warn', 'crit', 'ok') OR key_oid IS NULL),
    FOREIGN KEY (tenant_id, group_id) REFERENCES openwacht.device_groups (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (device_id, tenant_id) REFERENCES openwacht.devices (id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (clears, tenant_id) REFERENCES openwacht.snmp_trap_rules (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX snmp_trap_rules_tenant ON openwacht.snmp_trap_rules (tenant_id, position);
CREATE INDEX snmp_trap_rules_group ON openwacht.snmp_trap_rules (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX snmp_trap_rules_device ON openwacht.snmp_trap_rules (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX snmp_trap_rules_clears ON openwacht.snmp_trap_rules (clears) WHERE clears IS NOT NULL;

CREATE FUNCTION openwacht.snmp_trap_rules_before_write() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        RAISE EXCEPTION 'ID und Mandant einer Trap-Regel sind unveränderlich.' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('openwacht.snmp_trap_rules:' || NEW.tenant_id::text, 0));
        IF (SELECT count(*) FROM openwacht.snmp_trap_rules WHERE tenant_id = NEW.tenant_id) >= 500 THEN
            RAISE EXCEPTION 'Höchstens 500 Trap-Regeln je Mandant.' USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_limit';
        END IF;
        NEW.created_at := now();
    END IF;
    IF NEW.clears IS NOT NULL THEN
        IF NEW.clears = NEW.id THEN
            RAISE EXCEPTION 'Eine Entwarnung kann nicht sich selbst beenden.' USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_clears';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM openwacht.snmp_trap_rules r
                        WHERE r.id = NEW.clears AND r.tenant_id = NEW.tenant_id AND r.action IN ('warn', 'crit')) THEN
            RAISE EXCEPTION 'Eine Entwarnung muss eine Regel mit Warnung oder Fehler desselben Mandanten beenden.'
                USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_clears';
        END IF;
    END IF;
    -- Eine Regel, die von einer Entwarnung beendet wird, muss Warnung oder Fehler bleiben.
    IF TG_OP = 'UPDATE' AND NEW.action NOT IN ('warn', 'crit')
       AND EXISTS (SELECT 1 FROM openwacht.snmp_trap_rules r WHERE r.clears = NEW.id) THEN
        RAISE EXCEPTION 'Diese Regel wird von einer Entwarnung beendet und muss Warnung oder Fehler bleiben.'
            USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_clears';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_trap_rules_before_write BEFORE INSERT OR UPDATE ON openwacht.snmp_trap_rules
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_trap_rules_before_write();

ALTER TABLE openwacht.snmp_trap_rules ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_trap_rules FROM PUBLIC;
GRANT SELECT, DELETE ON openwacht.snmp_trap_rules TO openwacht_app;
GRANT INSERT (id, tenant_id, position, name, enabled, group_id, device_id, trap_oid, vb_oid, vb_op, vb_value, action,
              key_oid, duration_min, clears),
      UPDATE (position, name, enabled, group_id, device_id, trap_oid, vb_oid, vb_op, vb_value, action, key_oid,
              duration_min, clears)
    ON openwacht.snmp_trap_rules TO openwacht_app;
CREATE POLICY snmp_trap_rules_select ON openwacht.snmp_trap_rules FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY snmp_trap_rules_insert ON openwacht.snmp_trap_rules FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_trap_rules_update ON openwacht.snmp_trap_rules FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_trap_rules_delete ON openwacht.snmp_trap_rules FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- ---------------------------------------------------------------------------
-- Zustand und Protokoll
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.snmp_trap_state (
    source_id  uuid NOT NULL,
    tenant_id  uuid NOT NULL,
    rule_id    uuid NOT NULL REFERENCES openwacht.snmp_trap_rules (id) ON DELETE CASCADE,
    -- Name der Regel zum Zeitpunkt des Traps (die Anzeige braucht die Regel nicht)
    rule_name  text NOT NULL CHECK (char_length(rule_name) BETWEEN 1 AND 100 AND rule_name !~ '[[:cntrl:]]'),
    instance   text NOT NULL DEFAULT '' CHECK (char_length(instance) <= 100 AND instance !~ '[[:cntrl:]]'),
    status     text NOT NULL CHECK (status IN ('warn', 'crit')),
    message    text NOT NULL CHECK (char_length(message) <= 300 AND message !~ '[[:cntrl:]]'),
    authentic  boolean NOT NULL,
    since      timestamptz NOT NULL,
    last_at    timestamptz NOT NULL,
    hits       integer NOT NULL DEFAULT 1 CHECK (hits >= 1),
    expires_at timestamptz,
    PRIMARY KEY (source_id, rule_id, instance),
    FOREIGN KEY (source_id, tenant_id) REFERENCES openwacht.snmp_sources (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX snmp_trap_state_tenant ON openwacht.snmp_trap_state (tenant_id);
CREATE INDEX snmp_trap_state_rule ON openwacht.snmp_trap_state (rule_id);
ALTER TABLE openwacht.snmp_trap_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_trap_state FROM PUBLIC;
GRANT SELECT ON openwacht.snmp_trap_state TO openwacht_app;
-- Die Wandanzeige färbt Geräte auch nach Trap-Zuständen.
CREATE POLICY snmp_trap_state_select ON openwacht.snmp_trap_state FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));

CREATE TABLE openwacht.snmp_trap_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id   uuid NOT NULL,
    tenant_id   uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    version     text NOT NULL CHECK (version IN ('1', '2c', '3')),
    inform      boolean NOT NULL,
    authentic   boolean NOT NULL,
    trap_oid    text NOT NULL CHECK (openwacht.valid_trap_oid(trap_oid, false)),
    varbinds    jsonb NOT NULL CHECK (jsonb_typeof(varbinds) = 'array' AND jsonb_array_length(varbinds) <= 20
                                      AND octet_length(varbinds::text) <= 16384),
    rule_id     uuid REFERENCES openwacht.snmp_trap_rules (id) ON DELETE SET NULL,
    result      text NOT NULL CHECK (result IN ('warn', 'crit', 'ok', 'ignore', 'none')),
    FOREIGN KEY (source_id, tenant_id) REFERENCES openwacht.snmp_sources (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX snmp_trap_log_source ON openwacht.snmp_trap_log (source_id, id DESC);
CREATE INDEX snmp_trap_log_received ON openwacht.snmp_trap_log (received_at);
CREATE INDEX snmp_trap_log_rule ON openwacht.snmp_trap_log (rule_id) WHERE rule_id IS NOT NULL;
ALTER TABLE openwacht.snmp_trap_log ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_trap_log FROM PUBLIC;
GRANT SELECT ON openwacht.snmp_trap_log TO openwacht_app;
CREATE POLICY snmp_trap_log_select ON openwacht.snmp_trap_log FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));

-- Letzte Zeiten der Engines, von denen v3-Traps kamen (Schutz gegen
-- Wiederholung nach RFC 3414, 3.2.7 b). Nur für den Trap-Dienst.
CREATE TABLE openwacht.snmp_trap_engines (
    source_id   uuid NOT NULL,
    tenant_id   uuid NOT NULL,
    engine_id   bytea NOT NULL CHECK (octet_length(engine_id) BETWEEN 5 AND 32),
    boots       integer NOT NULL CHECK (boots BETWEEN 0 AND 2147483647),
    engine_time integer NOT NULL CHECK (engine_time BETWEEN 0 AND 2147483647),
    seen_at     timestamptz NOT NULL,
    PRIMARY KEY (source_id, engine_id),
    FOREIGN KEY (source_id, tenant_id) REFERENCES openwacht.snmp_sources (id, tenant_id) ON DELETE CASCADE
);
ALTER TABLE openwacht.snmp_trap_engines ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_trap_engines FROM PUBLIC;

-- Aktuelle Zustände einer Quelle für Alarme, Sensoren und Wandanzeige.
-- SECURITY INVOKER: In den Sensoren gilt RLS des Aufrufers.
CREATE FUNCTION openwacht.snmp_trap_states_json(p_source uuid) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'regel', t.rule_id, 'name', t.rule_name, 'instanz', t.instance, 'status', t.status,
               'meldung', t.message, 'bestaetigt', t.authentic, 'seit', t.since, 'zuletzt', t.last_at,
               'anzahl', t.hits, 'bis', t.expires_at)
             ORDER BY t.rule_name, t.instance), '[]'::jsonb)
      FROM (SELECT * FROM openwacht.snmp_trap_state x
             WHERE x.source_id = p_source AND (x.expires_at IS NULL OR x.expires_at > now())
             ORDER BY x.rule_name, x.instance LIMIT 200) t
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_trap_states_json(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_trap_states_json(uuid) TO openwacht_app;

-- Von Hand zurücksetzen: Admins und Operatoren. Liefert 'ok', 'fehlt' oder 'verboten'.
CREATE FUNCTION openwacht.snmp_trap_reset(p_source uuid, p_rule uuid, p_instance text) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
BEGIN
    SELECT s.tenant_id INTO v_tenant FROM openwacht.snmp_trap_state s
     WHERE s.source_id = p_source AND s.rule_id = p_rule AND s.instance = p_instance;
    IF v_tenant IS NULL OR v_tenant NOT IN (SELECT openwacht.visible_tenants()) THEN
        RETURN 'fehlt';
    END IF;
    IF v_tenant NOT IN (SELECT openwacht.operator_tenants()) THEN
        RETURN 'verboten';
    END IF;
    DELETE FROM openwacht.snmp_trap_state s WHERE s.source_id = p_source AND s.rule_id = p_rule AND s.instance = p_instance;
    RETURN 'ok';
END
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_trap_reset(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_trap_reset(uuid, uuid, text) TO openwacht_app;

-- Gegenstände 'trap:<Regel>' und 'trap:<Regel>:<Instanz>'.
CREATE OR REPLACE FUNCTION openwacht.valid_snmp_subject(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('stumm', 'speicher', 'cpu', 'neustart', 'system', 'temperatur', 'usv')
                OR s ~ '^(platte|if|laufwerk|raid|toner|meta|pvespeicher):.'
                OR s ~ '^(gast|backup):[1-9][0-9]{2,8}$'
                OR s ~ '^trap:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(:.+)?$')
$$;

-- Alarme und Alarmprotokoll: zusätzlich die Trap-Zustände.
DROP FUNCTION openwacht.alert_snmp_candidates();
CREATE FUNCTION openwacht.alert_snmp_candidates()
    RETURNS TABLE (snmp_id uuid, tenant_name text, name text, disabled boolean, silent_s double precision,
                   interval_s integer, last_error text, snapshot jsonb, cpu15 double precision,
                   rebooted_s double precision, watched text[], channels uuid[], version text, traps jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, t.name, d.name, NOT s.enabled,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched,
           array_agg(ch.id ORDER BY ch.id), s.version, openwacht.snmp_trap_states_json(s.id)
      FROM openwacht.snmp_sources s
      JOIN openwacht.devices d ON d.id = s.device_id
      JOIN openwacht.tenants t ON t.id = s.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = s.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
     WHERE s.enabled OR EXISTS (SELECT 1 FROM openwacht.alert_state_snmp x WHERE x.snmp_id = s.id)
     GROUP BY s.id, t.name, d.name
     ORDER BY s.id
     LIMIT 20000
$$;

DROP FUNCTION openwacht.alarm_snmp_sources();
CREATE FUNCTION openwacht.alarm_snmp_sources()
    RETURNS TABLE (snmp_id uuid, name text, silent_s double precision, interval_s integer, last_error text,
                   snapshot jsonb, cpu15 double precision, rebooted_s double precision, watched text[], version text,
                   traps jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, d.name,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched, s.version,
           openwacht.snmp_trap_states_json(s.id)
      FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
     WHERE s.enabled
     ORDER BY s.id
     LIMIT 20000
$$;

REVOKE ALL ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Funktionen des Trap-Dienstes (nur openwacht_traps)
-- ---------------------------------------------------------------------------

-- Start: snmpEngineBoots erhöhen, Engine-ID und Boots liefern.
CREATE FUNCTION openwacht.traps_engine_start() RETURNS TABLE (engine_id bytea, engine_boots integer)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.snmp_engine e
       SET engine_boots = least(e.engine_boots + 1, 2147483647), started_at = now()
     WHERE e.singleton
    RETURNING e.engine_id, e.engine_boots
$$;

-- Quellen mit eingeschalteten Traps: Adresse, Art und Trap-Zugangsdaten, dazu
-- Mandantenkette (eigener zuerst) und Gruppenkette (eigene zuerst) für die Regeln.
CREATE FUNCTION openwacht.traps_sources()
    RETURNS TABLE (id uuid, tenant_id uuid, device_id uuid, device_name text, version text, host text, port integer,
                   trap_secret_enc bytea, tenants uuid[], groups uuid[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, s.tenant_id, s.device_id, d.name, s.version, s.host, s.port, s.trap_secret_enc,
           (SELECT array_agg(tc.ancestor ORDER BY tc.depth) FROM openwacht.tenant_closure tc WHERE tc.descendant = s.tenant_id),
           (WITH RECURSIVE up(id, parent_id, lvl) AS (
                SELECT g.id, g.parent_id, 0 FROM openwacht.device_groups g WHERE g.id = d.group_id
                UNION ALL
                SELECT g.id, g.parent_id, up.lvl + 1 FROM openwacht.device_groups g JOIN up ON g.id = up.parent_id
                 WHERE up.lvl < 8)
            SELECT coalesce(array_agg(up.id ORDER BY up.lvl), '{}') FROM up)
      FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
     WHERE s.traps AND s.enabled AND s.trap_secret_enc IS NOT NULL AND s.version IN ('1', '2c', '3')
     ORDER BY s.id
     LIMIT 20000
$$;

CREATE FUNCTION openwacht.traps_rules()
    RETURNS TABLE (id uuid, tenant_id uuid, pos integer, name text, group_id uuid, device_id uuid, trap_oid text,
                   vb_oid text, vb_op text, vb_value text, action text, key_oid text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT r.id, r.tenant_id, r.position, r.name, r.group_id, r.device_id, r.trap_oid, r.vb_oid, r.vb_op, r.vb_value,
           r.action, r.key_oid
      FROM openwacht.snmp_trap_rules r
     WHERE r.enabled
     ORDER BY r.tenant_id, r.position, r.created_at, r.id
     LIMIT 100000
$$;

CREATE FUNCTION openwacht.traps_engines()
    RETURNS TABLE (source_id uuid, engine_id bytea, boots integer, engine_time integer, seen_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT e.source_id, e.engine_id, e.boots, e.engine_time, e.seen_at FROM openwacht.snmp_trap_engines e LIMIT 100000
$$;

-- Zeiten einer Absender-Engine merken; je Quelle höchstens 4 Engines.
CREATE FUNCTION openwacht.traps_engine_seen(p_source uuid, p_engine bytea, p_boots integer, p_time integer) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
BEGIN
    SELECT s.tenant_id INTO v_tenant FROM openwacht.snmp_sources s WHERE s.id = p_source;
    IF v_tenant IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO openwacht.snmp_trap_engines (source_id, tenant_id, engine_id, boots, engine_time, seen_at)
    VALUES (p_source, v_tenant, p_engine, p_boots, p_time, now())
    ON CONFLICT (source_id, engine_id) DO UPDATE
       SET boots = EXCLUDED.boots, engine_time = EXCLUDED.engine_time, seen_at = EXCLUDED.seen_at;
    DELETE FROM openwacht.snmp_trap_engines e
     WHERE e.source_id = p_source
       AND e.engine_id NOT IN (SELECT x.engine_id FROM openwacht.snmp_trap_engines x
                                WHERE x.source_id = p_source ORDER BY x.seen_at DESC LIMIT 4);
END
$$;

-- Einen Trap verbuchen: Protokoll, dann die Wirkung der Regel. Die Wirkung
-- liest die Funktion selbst aus der Regel; der Dienst sagt nur, welche Regel
-- passte. Die Regel muss dem Mandanten der Quelle oder einem Vorfahren
-- gehören. Liefert das Ergebnis ('warn', 'crit', 'ok', 'ignore', 'none')
-- oder 'fehlt', wenn die Quelle keine Traps (mehr) annimmt.
CREATE FUNCTION openwacht.traps_record(p_source uuid, p_version text, p_inform boolean, p_authentic boolean,
                                      p_trap_oid text, p_varbinds jsonb, p_rule uuid, p_instance text, p_message text)
    RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant   uuid;
    r          openwacht.snmp_trap_rules%ROWTYPE;
    v_result   text := 'none';
    v_instance text := left(openwacht.alarm_clean(p_instance), 100);
    v_message  text := left(openwacht.alarm_clean(p_message), 300);
    v_expires  timestamptz;
BEGIN
    -- v3-Quellen nehmen nur v3-Traps an, v1/v2c-Quellen nur v1/v2c.
    SELECT s.tenant_id INTO v_tenant FROM openwacht.snmp_sources s
     WHERE s.id = p_source AND s.traps AND s.enabled AND s.trap_secret_enc IS NOT NULL
       AND (s.version = '3') = (p_version = '3');
    IF v_tenant IS NULL THEN
        RETURN 'fehlt';
    END IF;
    IF p_authentic AND p_version <> '3' THEN
        RAISE EXCEPTION 'traps_record: v1/v2c sind nie authentifiziert' USING ERRCODE = '22023';
    END IF;
    IF p_rule IS NOT NULL THEN
        SELECT x.* INTO r FROM openwacht.snmp_trap_rules x
         WHERE x.id = p_rule AND x.enabled
           AND x.tenant_id IN (SELECT tc.ancestor FROM openwacht.tenant_closure tc WHERE tc.descendant = v_tenant);
        IF FOUND THEN
            v_result := r.action;
        ELSE
            p_rule := NULL; -- inzwischen gelöscht oder ausgeschaltet
        END IF;
    END IF;
    IF v_result NOT IN ('warn', 'crit', 'ok') THEN
        v_instance := '';
    END IF;
    INSERT INTO openwacht.snmp_trap_log (source_id, tenant_id, version, inform, authentic, trap_oid, varbinds, rule_id, result)
    VALUES (p_source, v_tenant, p_version, p_inform, p_authentic, p_trap_oid, p_varbinds, p_rule, v_result);

    IF v_result IN ('warn', 'crit') THEN
        IF r.duration_min > 0 THEN
            v_expires := now() + make_interval(mins => r.duration_min);
        END IF;
        IF EXISTS (SELECT 1 FROM openwacht.snmp_trap_state x
                    WHERE x.source_id = p_source AND x.rule_id = r.id AND x.instance = v_instance) THEN
            UPDATE openwacht.snmp_trap_state x
               SET status = v_result, message = v_message, authentic = p_authentic, rule_name = r.name,
                   last_at = now(), expires_at = v_expires,
                   -- abgelaufen: neuer Zustand
                   since = CASE WHEN x.expires_at <= now() THEN now() ELSE x.since END,
                   hits  = CASE WHEN x.expires_at <= now() THEN 1 ELSE least(x.hits, 2147483646) + 1 END
             WHERE x.source_id = p_source AND x.rule_id = r.id AND x.instance = v_instance;
        ELSIF (SELECT count(*) FROM openwacht.snmp_trap_state x WHERE x.source_id = p_source) < 200 THEN
            INSERT INTO openwacht.snmp_trap_state (source_id, tenant_id, rule_id, rule_name, instance, status, message,
                                                  authentic, since, last_at, expires_at)
            VALUES (p_source, v_tenant, r.id, r.name, v_instance, v_result, v_message, p_authentic, now(), now(), v_expires);
        ELSE
            RAISE WARNING 'Traps: Quelle % hat schon 200 Trap-Zustände, neuer Zustand verworfen', p_source;
        END IF;
    ELSIF v_result = 'ok' THEN
        DELETE FROM openwacht.snmp_trap_state x
         WHERE x.source_id = p_source AND x.rule_id = r.clears AND (r.key_oid IS NULL OR x.instance = v_instance);
    END IF;
    RETURN v_result;
END
$$;

-- Aufräumen: Protokoll 30 Tage und höchstens 20000 Einträge je Quelle,
-- abgelaufene Zustände.
CREATE FUNCTION openwacht.traps_maintain() RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    n integer := 0;
    m integer;
    q record;
BEGIN
    DELETE FROM openwacht.snmp_trap_log WHERE received_at < now() - interval '30 days';
    GET DIAGNOSTICS m = ROW_COUNT;
    n := n + m;
    FOR q IN SELECT l.source_id FROM openwacht.snmp_trap_log l GROUP BY l.source_id HAVING count(*) > 20000 LOOP
        DELETE FROM openwacht.snmp_trap_log l
         WHERE l.source_id = q.source_id
           AND l.id < (SELECT x.id FROM openwacht.snmp_trap_log x WHERE x.source_id = q.source_id
                        ORDER BY x.id DESC OFFSET 19999 LIMIT 1);
        GET DIAGNOSTICS m = ROW_COUNT;
        n := n + m;
    END LOOP;
    DELETE FROM openwacht.snmp_trap_state WHERE expires_at <= now();
    GET DIAGNOSTICS m = ROW_COUNT;
    RETURN n + m;
END
$$;

REVOKE ALL ON FUNCTION openwacht.traps_engine_start(), openwacht.traps_sources(), openwacht.traps_rules(),
    openwacht.traps_engines(), openwacht.traps_engine_seen(uuid, bytea, integer, integer),
    openwacht.traps_record(uuid, text, boolean, boolean, text, jsonb, uuid, text, text),
    openwacht.traps_maintain(), openwacht.valid_trap_oid(text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.traps_engine_start(), openwacht.traps_sources(), openwacht.traps_rules(),
    openwacht.traps_engines(), openwacht.traps_engine_seen(uuid, bytea, integer, integer),
    openwacht.traps_record(uuid, text, boolean, boolean, text, jsonb, uuid, text, text),
    openwacht.traps_maintain() TO openwacht_traps;
GRANT EXECUTE ON FUNCTION openwacht.valid_trap_oid(text, boolean) TO openwacht_app;
