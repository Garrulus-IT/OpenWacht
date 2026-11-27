-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Geräte zwischen Mandanten verschieben (Entscheidungen 25.11.2026).
--
-- Darf nur, wer Admin des bisherigen und des neuen Mandanten ist. Mit dem
-- Gerät ziehen um: Agent, Abfragen (SNMP und Anbindungen), Sensoren,
-- Schwellen, Trap-Regeln des Geräts, Ausnahmen, offene und vergangene Alarme,
-- Verlauf und Messwerte. Weg fallen die Bezüge zum alten Mandanten: Gruppe,
-- Abhängigkeiten (in beide Richtungen), Wartungsfenster und Wartungen,
-- Kennfarben, die im neuen Mandanten nicht gelten, Freigaben für
-- Agent-Updates und unbenutzte Registrierungs-Tokens des Geräts.
--
-- Leitprinzip 2 bleibt: Das Agent-Zertifikat trägt nur die Agent-ID, den
-- Mandanten liest die Zentrale aus agents.tenant_id. Eine neue Registrierung
-- ist nicht nötig.
--
-- Mandant und ID bleiben für alle anderen Wege unveränderlich: Die Trigger
-- lassen eine Änderung des Mandanten nur zu, wenn sie innerhalb von
-- device_move läuft (Schalter in der Transaktion UND Rolle = Eigentümer des
-- Schemas). Die App-Rolle kann den Schalter zwar setzen, ist aber nie
-- Eigentümer.
--
-- Zugangsdaten der Abfragen sind mit dem Mandanten als Zusatzdaten
-- verschlüsselt. Die Zentrale entschlüsselt sie vorher und übergibt sie neu
-- verschlüsselt (device_move_sources liefert die nötigen Felder).
--
-- Abgelehnt wird, wenn ein Sammler beteiligt ist, der nicht auf dem Gerät
-- selbst läuft (in beide Richtungen), wenn ein SNMP-Profil im neuen Mandanten
-- nicht gilt, oder wenn eine Trap-Regel des Geräts über „beendet“ mit einer
-- Regel verbunden ist, die nicht mitzieht.

CREATE FUNCTION openwacht.moving() RETURNS boolean
    LANGUAGE sql STABLE AS $$
    SELECT coalesce(current_setting('openwacht.verschieben', true), '') = 'an'
       AND current_user = (SELECT pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_namespace n WHERE n.nspname = 'openwacht')
$$;

CREATE OR REPLACE FUNCTION openwacht.devices_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving()) THEN
        RAISE EXCEPTION 'ID und Mandant eines Geräts sind unveränderlich.';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.agents_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'Ein gesperrter Agent kann nicht entsperrt werden.';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving()) THEN
        RAISE EXCEPTION 'ID und Mandant eines Agents sind unveränderlich.';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.checks_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving()) THEN
        RAISE EXCEPTION 'ID und Mandant eines Checks sind unveränderlich.';
    END IF;
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.target IS DISTINCT FROM OLD.target THEN
        NEW.revision := OLD.revision + 1;
        NEW.status := NULL; NEW.message := NULL; NEW.metric := NULL; NEW.since := NULL;
        NEW.fails := 0; NEW.last_run := NULL;
        NEW.next_run := now();
    ELSIF NEW.enabled AND NOT OLD.enabled THEN
        NEW.next_run := now();
    ELSIF NEW.interval_s < OLD.interval_s THEN
        NEW.next_run := least(NEW.next_run, now() + make_interval(secs => NEW.interval_s));
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064'
                            WHEN 'vcenter' THEN 'vcenter' WHEN 'ontap' THEN 'ontap' WHEN 'xapi' THEN 'xapi' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064'
                            WHEN 'vcenter' THEN 'vcenter' WHEN 'ontap' THEN 'ontap' WHEN 'xapi' THEN 'xapi' ELSE 'v1' END;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.device_id IS DISTINCT FROM OLD.device_id
       OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving()) THEN
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
       OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem OR NEW.collector_id IS DISTINCT FROM OLD.collector_id THEN
        NEW.revision := OLD.revision + 1;
        NEW.changed_at := now(); NEW.next_run := now();
        NEW.last_try := NULL; NEW.last_ok := NULL; NEW.last_error := NULL;
        NEW.snapshot := NULL; NEW.rebooted_at := NULL; NEW.poll_requested_at := NULL;
    ELSIF NEW.enabled AND NOT OLD.enabled THEN
        NEW.next_run := now(); NEW.changed_at := now();
    ELSIF NEW.interval_s < OLD.interval_s THEN
        NEW.next_run := least(NEW.next_run, now() + make_interval(secs => NEW.interval_s));
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.device_limits_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'Schwellen: Gerät nicht gefunden.' USING ERRCODE = '23503';
        END IF;
    ELSE
        NEW.device_id := OLD.device_id;
        IF NOT openwacht.moving() THEN
            NEW.tenant_id := OLD.tenant_id;
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.snmp_trap_rules_before_write() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id
                             OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving())) THEN
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
        IF NOT openwacht.moving() AND NOT EXISTS (SELECT 1 FROM openwacht.snmp_trap_rules r
                        WHERE r.id = NEW.clears AND r.tenant_id = NEW.tenant_id AND r.action IN ('warn', 'crit')) THEN
            RAISE EXCEPTION 'Eine Entwarnung muss eine Regel mit Warnung oder Fehler desselben Mandanten beenden.'
                USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_clears';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.action NOT IN ('warn', 'crit')
       AND EXISTS (SELECT 1 FROM openwacht.snmp_trap_rules r WHERE r.clears = NEW.id) THEN
        RAISE EXCEPTION 'Diese Regel wird von einer Entwarnung beendet und muss Warnung oder Fehler bleiben.'
            USING ERRCODE = '23514', CONSTRAINT = 'snmp_trap_rules_clears';
    END IF;
    RETURN NEW;
END
$$;

-- Fremdschlüssel über (ID, Mandant) erst am Ende der Transaktion prüfen, damit
-- Gerät, Agent, Abfragen und Sensoren nacheinander umziehen können. Außerhalb
-- von device_move ändert sich nichts (INITIALLY IMMEDIATE).
ALTER TABLE openwacht.agents ALTER CONSTRAINT agents_device_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.checks ALTER CONSTRAINT checks_device_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.agent_tokens ALTER CONSTRAINT agent_tokens_device_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.device_limits ALTER CONSTRAINT device_limits_device_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.devices ALTER CONSTRAINT devices_parent_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.maintenance_windows ALTER CONSTRAINT maintenance_windows_device_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_sources ALTER CONSTRAINT snmp_sources_device_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_sources ALTER CONSTRAINT snmp_sources_collector_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_trap_rules ALTER CONSTRAINT snmp_trap_rules_device_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_trap_engines ALTER CONSTRAINT snmp_trap_engines_source_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_trap_log ALTER CONSTRAINT snmp_trap_log_source_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE openwacht.snmp_trap_state ALTER CONSTRAINT snmp_trap_state_source_id_tenant_id_fkey DEFERRABLE INITIALLY IMMEDIATE;

-- Felder der Abfragen eines Geräts zum Neuverschlüsseln, nach denselben
-- Rechten wie device_move. Sperrt Gerät und Abfragen bis zum Ende der
-- Transaktion.
CREATE FUNCTION openwacht.device_move_sources(p_device uuid, p_target uuid)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, host text, port integer, ca_pem text,
                   secret_enc bytea, trap_secret_enc bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_old uuid;
BEGIN
    IF openwacht.current_user_id() IS NULL THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    SELECT d.tenant_id INTO v_old FROM openwacht.devices d WHERE d.id = p_device FOR UPDATE;
    IF NOT FOUND OR v_old NOT IN (SELECT openwacht.visible_tenants()) THEN
        RAISE EXCEPTION 'Gerät nicht gefunden' USING ERRCODE = 'P0002';
    END IF;
    IF v_old NOT IN (SELECT openwacht.admin_tenants()) OR p_target NOT IN (SELECT openwacht.admin_tenants()) THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
        SELECT s.id, s.tenant_id, s.version, s.host, s.port, s.ca_pem, s.secret_enc, s.trap_secret_enc
          FROM openwacht.snmp_sources s WHERE s.device_id = p_device ORDER BY s.id FOR UPDATE;
END
$$;
REVOKE ALL ON FUNCTION openwacht.device_move_sources(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.device_move_sources(uuid, uuid) TO openwacht_app;

CREATE FUNCTION openwacht.device_move(p_device uuid, p_target uuid, p_sources uuid[], p_secrets bytea[], p_trap_secrets bytea[])
    RETURNS jsonb
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user     uuid := openwacht.current_user_id();
    v_old      uuid;
    v_name     text;
    v_agents   uuid[];
    v_sources  uuid[];
    v_checks   uuid[];
    v_rules    uuid[];
    v_n_maint  integer;
    v_n_dep    integer;
    v_n_color  integer;
    v_n_alarms integer;
BEGIN
    IF v_user IS NULL THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    SELECT d.tenant_id, d.name INTO v_old, v_name FROM openwacht.devices d WHERE d.id = p_device FOR UPDATE;
    IF NOT FOUND OR v_old NOT IN (SELECT openwacht.visible_tenants()) THEN
        RAISE EXCEPTION 'Gerät nicht gefunden' USING ERRCODE = 'P0002';
    END IF;
    IF v_old NOT IN (SELECT openwacht.admin_tenants()) OR p_target NOT IN (SELECT openwacht.admin_tenants()) THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    IF p_target = v_old THEN
        RAISE EXCEPTION 'Das Gerät gehört schon zu diesem Mandanten.' USING ERRCODE = '23514';
    END IF;

    SELECT coalesce(array_agg(a.id), '{}') INTO v_agents FROM openwacht.agents a WHERE a.device_id = p_device;
    SELECT coalesce(array_agg(s.id ORDER BY s.id), '{}') INTO v_sources FROM openwacht.snmp_sources s WHERE s.device_id = p_device;
    SELECT coalesce(array_agg(c.id), '{}') INTO v_checks FROM openwacht.checks c WHERE c.device_id = p_device;
    SELECT coalesce(array_agg(r.id), '{}') INTO v_rules FROM openwacht.snmp_trap_rules r WHERE r.device_id = p_device;

    -- Neu verschlüsselte Zugangsdaten: genau die Abfragen des Geräts.
    IF p_sources IS DISTINCT FROM v_sources
       OR cardinality(p_secrets) IS DISTINCT FROM cardinality(v_sources)
       OR cardinality(p_trap_secrets) IS DISTINCT FROM cardinality(v_sources) THEN
        RAISE EXCEPTION 'Die Abfragen des Geräts haben sich geändert. Bitte erneut versuchen.' USING ERRCODE = '40001';
    END IF;

    -- Sammler nur, wenn sie auf dem Gerät selbst laufen.
    IF EXISTS (SELECT 1 FROM openwacht.snmp_sources s
                WHERE s.id = ANY (v_sources) AND s.collector_id IS NOT NULL AND NOT s.collector_id = ANY (v_agents)) THEN
        RAISE EXCEPTION 'Eine Abfrage dieses Geräts läuft über einen Sammler auf einem anderen Gerät. Erst den Sammler an der Abfrage entfernen.'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT 1 FROM openwacht.snmp_sources s
                WHERE s.collector_id = ANY (v_agents) AND NOT s.id = ANY (v_sources)) THEN
        RAISE EXCEPTION 'Der Agent dieses Geräts sammelt für andere Geräte. Erst dort einen anderen Sammler wählen.'
            USING ERRCODE = '23514';
    END IF;
    -- SNMP-Profile müssen auch im neuen Mandanten gelten.
    IF EXISTS (SELECT 1 FROM openwacht.snmp_sources s JOIN openwacht.snmp_profiles p ON p.id = s.profile_id
                WHERE s.id = ANY (v_sources)
                  AND NOT EXISTS (SELECT 1 FROM openwacht.tenant_closure c WHERE c.ancestor = p.tenant_id AND c.descendant = p_target)) THEN
        RAISE EXCEPTION 'Eine Abfrage nutzt ein SNMP-Profil, das im neuen Mandanten nicht gilt. Profil eines gemeinsamen übergeordneten Mandanten wählen oder das Profil von der Abfrage lösen.'
            USING ERRCODE = '23514';
    END IF;
    -- Trap-Regeln, die sich über „beendet“ auf Regeln außerhalb beziehen.
    IF EXISTS (SELECT 1 FROM openwacht.snmp_trap_rules r
                WHERE (r.id = ANY (v_rules) AND r.clears IS NOT NULL AND NOT r.clears = ANY (v_rules))
                   OR (NOT r.id = ANY (v_rules) AND r.clears = ANY (v_rules))) THEN
        RAISE EXCEPTION 'Eine Trap-Regel des Geräts ist über „beendet“ mit einer Regel verbunden, die nicht mitzieht. Erst die Verbindung lösen.'
            USING ERRCODE = '23514';
    END IF;

    -- Bezüge zum alten Mandanten lösen.
    WITH d AS (DELETE FROM openwacht.maintenance m WHERE m.device_id = p_device OR m.check_id = ANY (v_checks) RETURNING 1)
    SELECT count(*) INTO v_n_maint FROM d;
    DELETE FROM openwacht.maintenance_window_done w WHERE w.device_id = p_device OR w.check_id = ANY (v_checks);
    WITH d AS (DELETE FROM openwacht.maintenance_windows w WHERE w.device_id = p_device OR w.check_id = ANY (v_checks) RETURNING 1)
    SELECT v_n_maint + count(*) INTO v_n_maint FROM d;
    WITH u AS (UPDATE openwacht.devices d SET parent_id = NULL WHERE d.parent_id = p_device RETURNING 1)
    SELECT count(*) INTO v_n_dep FROM u;
    DELETE FROM openwacht.agent_update_releases r WHERE r.agent_id = ANY (v_agents);
    DELETE FROM openwacht.agent_tokens t WHERE t.device_id = p_device;
    WITH d AS (DELETE FROM openwacht.sensor_kennfarben k WHERE k.agent_id = ANY (v_agents) OR k.snmp_id = ANY (v_sources) RETURNING 1)
    SELECT count(*) INTO v_n_color FROM d;
    WITH u AS (UPDATE openwacht.checks c SET kennfarbe_id = NULL
                WHERE c.id = ANY (v_checks) AND c.kennfarbe_id IS NOT NULL
                  AND NOT openwacht.kennfarbe_allowed(c.kennfarbe_id, p_target) RETURNING 1)
    SELECT v_n_color + count(*) INTO v_n_color FROM u;
    WITH u AS (UPDATE openwacht.snmp_trap_rules r SET kennfarbe_id = NULL
                WHERE r.id = ANY (v_rules) AND r.kennfarbe_id IS NOT NULL
                  AND NOT openwacht.kennfarbe_allowed(r.kennfarbe_id, p_target) RETURNING 1)
    SELECT v_n_color + count(*) INTO v_n_color FROM u;
    UPDATE openwacht.snmp_trap_rules r SET group_id = NULL WHERE r.id = ANY (v_rules) AND r.group_id IS NOT NULL;

    -- Umziehen.
    SET CONSTRAINTS openwacht.agents_device_fk, openwacht.checks_device_fk, openwacht.agent_tokens_device_fk,
        openwacht.device_limits_device_id_tenant_id_fkey, openwacht.devices_parent_fk,
        openwacht.maintenance_windows_device_id_tenant_id_fkey, openwacht.snmp_sources_device_id_tenant_id_fkey,
        openwacht.snmp_sources_collector_fk, openwacht.snmp_trap_rules_device_id_tenant_id_fkey,
        openwacht.snmp_trap_engines_source_id_tenant_id_fkey, openwacht.snmp_trap_log_source_id_tenant_id_fkey,
        openwacht.snmp_trap_state_source_id_tenant_id_fkey DEFERRED;
    PERFORM set_config('openwacht.verschieben', 'an', true);

    UPDATE openwacht.devices d SET tenant_id = p_target, parent_id = NULL, group_id = NULL WHERE d.id = p_device;
    UPDATE openwacht.agents a SET tenant_id = p_target WHERE a.id = ANY (v_agents);
    UPDATE openwacht.snmp_sources s SET tenant_id = p_target, secret_enc = x.sec, trap_secret_enc = x.trap
      FROM unnest(p_sources, p_secrets, p_trap_secrets) AS x(id, sec, trap)
     WHERE s.id = x.id;
    UPDATE openwacht.snmp_trap_engines e SET tenant_id = p_target WHERE e.source_id = ANY (v_sources);
    UPDATE openwacht.snmp_trap_log l SET tenant_id = p_target WHERE l.source_id = ANY (v_sources);
    UPDATE openwacht.snmp_trap_state x SET tenant_id = p_target WHERE x.source_id = ANY (v_sources);
    UPDATE openwacht.device_limits l SET tenant_id = p_target WHERE l.device_id = p_device;
    UPDATE openwacht.checks c SET tenant_id = p_target WHERE c.id = ANY (v_checks);
    UPDATE openwacht.snmp_trap_rules r SET tenant_id = p_target WHERE r.id = ANY (v_rules);

    -- Verlauf und Alarme
    WITH u AS (UPDATE openwacht.alarms al SET tenant_id = p_target
                WHERE al.check_id = ANY (v_checks) OR al.agent_id = ANY (v_agents) OR al.snmp_id = ANY (v_sources) RETURNING 1)
    SELECT count(*) INTO v_n_alarms FROM u;
    UPDATE openwacht.alert_state x SET tenant_id = p_target WHERE x.check_id = ANY (v_checks);
    UPDATE openwacht.alert_state_agents x SET tenant_id = p_target WHERE x.agent_id = ANY (v_agents);
    UPDATE openwacht.alert_state_snmp x SET tenant_id = p_target WHERE x.snmp_id = ANY (v_sources);
    UPDATE openwacht.check_transitions x SET tenant_id = p_target WHERE x.check_id = ANY (v_checks);
    UPDATE openwacht.metrics_check_raw x SET tenant_id = p_target WHERE x.check_id = ANY (v_checks);
    UPDATE openwacht.metrics_check_5m x SET tenant_id = p_target WHERE x.check_id = ANY (v_checks);
    UPDATE openwacht.metrics_check_1h x SET tenant_id = p_target WHERE x.check_id = ANY (v_checks);
    UPDATE openwacht.metrics_host_raw x SET tenant_id = p_target WHERE x.agent_id = ANY (v_agents);
    UPDATE openwacht.metrics_host_5m x SET tenant_id = p_target WHERE x.agent_id = ANY (v_agents);
    UPDATE openwacht.metrics_host_1h x SET tenant_id = p_target WHERE x.agent_id = ANY (v_agents);
    UPDATE openwacht.metrics_snmp_raw x SET tenant_id = p_target WHERE x.snmp_id = ANY (v_sources);
    UPDATE openwacht.metrics_snmp_5m x SET tenant_id = p_target WHERE x.snmp_id = ANY (v_sources);
    UPDATE openwacht.metrics_snmp_1h x SET tenant_id = p_target WHERE x.snmp_id = ANY (v_sources);

    PERFORM set_config('openwacht.verschieben', '', true);
    -- Fremdschlüssel jetzt prüfen, nicht erst beim Commit: Ein Fehler soll
    -- hier mit Meldung abbrechen.
    SET CONSTRAINTS ALL IMMEDIATE;

    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    SELECT t, 'geraet.verschoben', jsonb_build_object('geraet', p_device, 'name', v_name, 'von', v_old, 'nach', p_target,
               'sensoren', cardinality(v_checks), 'abfragen', cardinality(v_sources), 'agent', cardinality(v_agents) > 0,
               'alarme', v_n_alarms, 'wartungen_entfernt', v_n_maint, 'abhaengigkeiten_geloest', v_n_dep,
               'kennfarben_entfernt', v_n_color)
      FROM unnest(ARRAY[v_old, p_target]) AS t;
    RETURN jsonb_build_object('sensoren', cardinality(v_checks), 'abfragen', cardinality(v_sources),
                              'agent', cardinality(v_agents) > 0, 'alarme', v_n_alarms,
                              'wartungen_entfernt', v_n_maint, 'abhaengigkeiten_geloest', v_n_dep,
                              'kennfarben_entfernt', v_n_color, 'trap_regeln', cardinality(v_rules));
END
$$;
REVOKE ALL ON FUNCTION openwacht.device_move(uuid, uuid, uuid[], bytea[], bytea[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.device_move(uuid, uuid, uuid[], bytea[], bytea[]) TO openwacht_app;
