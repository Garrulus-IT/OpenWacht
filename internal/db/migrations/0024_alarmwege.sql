-- SPDX-License-Identifier: AGPL-3.0-only

-- 0024: Alarmwege Mail, Webhook und Teams (Etappe 20a).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * Mail über EIN SMTP-Relay der Installation, eingetragen vom Betreiber
--     (Einstellungen, Passwort verschlüsselt, Ändern nur mit 2FA-Code).
--   * Empfänger sind Benutzerkonten, keine frei eingetippten Adressen: Ein
--     Mail-Kanal gehört einem Mandanten und meldet an ausgewählte Benutzer mit
--     einer Rolle in genau diesem Mandanten (oder an alle). Eltern-Benutzer
--     bekommen Alarme von Untermandanten nur über einen Kanal „mit
--     Untermandanten“, wie bei ntfy. Jeder kann Alarm-Mails abbestellen.
--   * Webhook (eigenes JSON, signiert nach „Standard Webhooks“) und Teams
--     (Workflows, Adaptive Card). Der Host muss als Alarmziel freigegeben
--     sein. Die URL ist ein Geheimnis (Teams: Signatur in der Abfrage) und
--     liegt verschlüsselt in token_enc; sichtbar ist nur der Ursprung
--     (server = https://host[:port]).
--   * Inhalt (ausdrückliche Entscheidung zu Leitprinzip 5): Gerät, Sensor,
--     Zustand, Meldung, seit wann, weitere Probleme am Gerät, Prognose bei
--     Platten, Wartung, Link; in der Mail ein Graph der letzten 24 Std.
--
-- Was ein Kanal bisher gemeldet hat, steht wie bei ntfy je Kanal in
-- alert_state*, daran ändert sich nichts.

-- ---------------------------------------------------------------------------
-- Kanäle: neue Arten
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_kind_check;
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_server_check;
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_topic_check;
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_token_enc_check;
ALTER TABLE openwacht.alert_channels ALTER COLUMN server DROP NOT NULL;
ALTER TABLE openwacht.alert_channels ALTER COLUMN topic DROP NOT NULL;
ALTER TABLE openwacht.alert_channels
    -- Signaturschlüssel eines Webhooks (verschlüsselt, AAD an Kanal und Mandant)
    ADD COLUMN secret_enc bytea CHECK (octet_length(secret_enc) BETWEEN 29 AND 1024),
    -- Mail: an alle Benutzer mit Rolle im Mandanten statt an die Auswahl
    ADD COLUMN all_users boolean NOT NULL DEFAULT false,
    ADD CHECK (kind IN ('ntfy', 'mail', 'webhook', 'teams')),
    ADD CHECK (server IS NULL OR char_length(server) BETWEEN 8 AND 300 AND server ~ '^https?://[^[:space:][:cntrl:]]+$'),
    ADD CHECK (topic IS NULL OR topic ~ '^[-_A-Za-z0-9]{1,64}$'),
    -- Webhook-URLs sind länger als ntfy-Tokens
    ADD CHECK (octet_length(token_enc) BETWEEN 29 AND 4096),
    ADD CHECK (CASE kind
        WHEN 'ntfy'    THEN server IS NOT NULL AND topic IS NOT NULL AND secret_enc IS NULL AND NOT all_users
        WHEN 'mail'    THEN server IS NULL AND topic IS NULL AND token_enc IS NULL AND secret_enc IS NULL
        WHEN 'webhook' THEN server IS NOT NULL AND topic IS NULL AND token_enc IS NOT NULL AND secret_enc IS NOT NULL AND NOT all_users
        WHEN 'teams'   THEN server IS NOT NULL AND topic IS NULL AND token_enc IS NOT NULL AND secret_enc IS NULL AND NOT all_users
    END);
-- Für den Fremdschlüssel der Empfänger (Kanal und Mandant gehören zusammen).
ALTER TABLE openwacht.alert_channels ADD CONSTRAINT alert_channels_id_tenant UNIQUE (id, tenant_id);

CREATE OR REPLACE FUNCTION openwacht.alert_channels_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM openwacht.alert_channels WHERE tenant_id = NEW.tenant_id) >= 20 THEN
        RAISE EXCEPTION 'Höchstens 20 Alarmkanäle je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.created_at := now();
    NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    RETURN NEW;
END
$$;

-- Wie 0013, dazu: Die Art ist unveränderlich; eine neue Webhook-URL ist ein
-- neues Ziel (alles neu melden). Der Signaturschlüssel bleibt.
CREATE OR REPLACE FUNCTION openwacht.alert_channels_before_update() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.kind IS DISTINCT FROM OLD.kind THEN
        RAISE EXCEPTION 'ID, Mandant und Art eines Alarmkanals sind unveränderlich.';
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server AND NEW.token_enc IS NOT DISTINCT FROM OLD.token_enc THEN
        NEW.token_enc := NULL;
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server OR NEW.topic IS DISTINCT FROM OLD.topic
       OR NEW.kind IN ('webhook', 'teams') AND NEW.token_enc IS DISTINCT FROM OLD.token_enc THEN
        DELETE FROM openwacht.alert_state WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_agents WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_snmp WHERE channel_id = OLD.id;
        NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

-- kind darf die Anwendung beim Anlegen setzen (vorher fest ntfy), secret_enc
-- und all_users ebenfalls; secret_enc ist wie token_enc nie lesbar.
GRANT SELECT (all_users) ON openwacht.alert_channels TO openwacht_app;
GRANT INSERT (kind, secret_enc, all_users), UPDATE (all_users) ON openwacht.alert_channels TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Empfänger eines Mail-Kanals
-- ---------------------------------------------------------------------------

-- Nur Benutzer mit einer Rolle in genau dem Mandanten des Kanals: Der
-- Fremdschlüssel auf role_assignments erzwingt das und entfernt den Eintrag,
-- sobald die Rolle entzogen wird.
CREATE TABLE openwacht.alert_channel_users (
    channel_id uuid NOT NULL,
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    PRIMARY KEY (channel_id, user_id),
    FOREIGN KEY (channel_id, tenant_id) REFERENCES openwacht.alert_channels (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, tenant_id) REFERENCES openwacht.role_assignments (user_id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX alert_channel_users_user ON openwacht.alert_channel_users (user_id, tenant_id);

-- Mandant aus dem Kanal (Leitprinzip 2), nur Mail-Kanäle, höchstens 100.
CREATE FUNCTION openwacht.alert_channel_users_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    k text;
BEGIN
    SELECT ch.tenant_id, ch.kind INTO NEW.tenant_id, k FROM openwacht.alert_channels ch WHERE ch.id = NEW.channel_id;
    IF k IS DISTINCT FROM 'mail' THEN
        RAISE EXCEPTION 'Empfänger gibt es nur bei Mail-Kanälen.' USING ERRCODE = '23514';
    END IF;
    IF (SELECT count(*) FROM openwacht.alert_channel_users WHERE channel_id = NEW.channel_id) >= 100 THEN
        RAISE EXCEPTION 'Höchstens 100 Empfänger je Kanal.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER alert_channel_users_before_insert BEFORE INSERT ON openwacht.alert_channel_users
    FOR EACH ROW EXECUTE FUNCTION openwacht.alert_channel_users_before_insert();

ALTER TABLE openwacht.alert_channel_users ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT (channel_id, user_id), DELETE ON openwacht.alert_channel_users TO openwacht_app;
CREATE POLICY alert_channel_users_select ON openwacht.alert_channel_users FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
-- Nur Admins des Kanals, und nur Benutzer, die sie sehen.
CREATE POLICY alert_channel_users_insert ON openwacht.alert_channel_users FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()) AND user_id IN (SELECT u.id FROM openwacht.users u));
CREATE POLICY alert_channel_users_delete ON openwacht.alert_channel_users FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Alarm-Mails abbestellen: jeder für sich selbst.
ALTER TABLE openwacht.users ADD COLUMN alert_mail boolean NOT NULL DEFAULT true;
GRANT SELECT (alert_mail) ON openwacht.users TO openwacht_app;

CREATE FUNCTION openwacht.set_alert_mail(p_on boolean) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF uid IS NULL OR p_on IS NULL THEN
        RAISE EXCEPTION 'set_alert_mail: kein Benutzer' USING ERRCODE = '42501';
    END IF;
    UPDATE openwacht.users SET alert_mail = p_on WHERE id = uid;
END
$$;
REVOKE ALL ON FUNCTION openwacht.set_alert_mail(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.set_alert_mail(boolean) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- SMTP-Relay (Einstellung des Betreibers)
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.settings
    ADD COLUMN smtp_host text CHECK (smtp_host ~ '^[A-Za-z0-9.:\[\]-]{1,253}$'),
    ADD COLUMN smtp_port integer CHECK (smtp_port BETWEEN 1 AND 65535),
    -- starttls (587), tls (465), keine (nur Loopback)
    ADD COLUMN smtp_tls text CHECK (smtp_tls IN ('starttls', 'tls', 'keine')),
    ADD COLUMN smtp_from text CHECK (char_length(smtp_from) BETWEEN 3 AND 254 AND smtp_from !~ '[[:cntrl:]]'),
    ADD COLUMN smtp_user text CHECK (char_length(smtp_user) BETWEEN 1 AND 254 AND smtp_user !~ '[[:cntrl:]]'),
    -- verschlüsselt (abgeleiteter Schlüssel, AAD „openwacht smtp v1“)
    ADD COLUMN smtp_pass_enc bytea CHECK (octet_length(smtp_pass_enc) BETWEEN 29 AND 1024),
    -- eigene CA (PEM) für ein Relay mit internem Zertifikat
    ADD COLUMN smtp_ca text CHECK (char_length(smtp_ca) <= 16384),
    ADD CHECK ((smtp_host IS NULL) = (smtp_port IS NULL) AND (smtp_host IS NULL) = (smtp_tls IS NULL)
               AND (smtp_host IS NULL) = (smtp_from IS NULL)),
    ADD CHECK (smtp_pass_enc IS NULL OR smtp_user IS NOT NULL);
GRANT UPDATE (smtp_host, smtp_port, smtp_tls, smtp_from, smtp_user, smtp_pass_enc, smtp_ca)
    ON openwacht.settings TO openwacht_app;

-- Audit wie 0023, dazu der Mailversand (Passwort nur „gesetzt/aus“).
CREATE OR REPLACE FUNCTION openwacht.settings_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    d jsonb := '{}'::jsonb;
BEGIN
    NEW.updated_at := now();
    IF NEW.check_nets IS DISTINCT FROM OLD.check_nets THEN
        d := d || jsonb_build_object('netze_alt', OLD.check_nets::text[], 'netze', NEW.check_nets::text[]);
    END IF;
    IF NEW.alert_targets IS DISTINCT FROM OLD.alert_targets THEN
        d := d || jsonb_build_object('alarmziele_alt', OLD.alert_targets, 'alarmziele', NEW.alert_targets);
    END IF;
    IF NEW.deadman_enc IS DISTINCT FROM OLD.deadman_enc THEN
        d := d || jsonb_build_object('totmann', CASE WHEN coalesce(octet_length(NEW.deadman_enc), 0) = 0 THEN 'aus' ELSE 'gesetzt' END);
    END IF;
    IF (NEW.silent_s, NEW.disk_warn, NEW.disk_crit, NEW.mem_warn, NEW.mem_crit, NEW.cpu_warn, NEW.cpu_crit)
       IS DISTINCT FROM (OLD.silent_s, OLD.disk_warn, OLD.disk_crit, OLD.mem_warn, OLD.mem_crit, OLD.cpu_warn, OLD.cpu_crit) THEN
        d := d || jsonb_build_object('schwellen', jsonb_build_object('stumm_s', NEW.silent_s,
            'platte', jsonb_build_array(NEW.disk_warn, NEW.disk_crit), 'speicher', jsonb_build_array(NEW.mem_warn, NEW.mem_crit),
            'cpu', jsonb_build_array(NEW.cpu_warn, NEW.cpu_crit)));
    END IF;
    IF (NEW.smtp_host, NEW.smtp_port, NEW.smtp_tls, NEW.smtp_from, NEW.smtp_user, NEW.smtp_pass_enc, NEW.smtp_ca)
       IS DISTINCT FROM (OLD.smtp_host, OLD.smtp_port, OLD.smtp_tls, OLD.smtp_from, OLD.smtp_user, OLD.smtp_pass_enc, OLD.smtp_ca) THEN
        d := d || jsonb_build_object('mail', jsonb_build_object('server', NEW.smtp_host, 'port', NEW.smtp_port,
            'tls', NEW.smtp_tls, 'absender', NEW.smtp_from, 'benutzer', NEW.smtp_user IS NOT NULL,
            'passwort', CASE WHEN NEW.smtp_pass_enc IS NULL THEN 'aus'
                             WHEN NEW.smtp_pass_enc IS DISTINCT FROM OLD.smtp_pass_enc THEN 'geändert' ELSE 'gesetzt' END,
            'eigene_ca', NEW.smtp_ca IS NOT NULL));
    END IF;
    IF d <> '{}'::jsonb THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NULL, CASE WHEN openwacht.current_user_id() IS NULL THEN 'einstellungen.uebernommen' ELSE 'einstellungen.geaendert' END, d);
    END IF;
    RETURN NEW;
END
$$;

-- Für die Zentrale ohne Benutzerkontext.
CREATE FUNCTION openwacht.runtime_mail()
    RETURNS TABLE (host text, port integer, tls text, sender text, username text, pass_enc bytea, ca text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.smtp_host, s.smtp_port, s.smtp_tls, s.smtp_from, s.smtp_user, s.smtp_pass_enc, s.smtp_ca
      FROM openwacht.settings s
$$;
REVOKE ALL ON FUNCTION openwacht.runtime_mail() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.runtime_mail() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Versand (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

DROP FUNCTION openwacht.alert_channels_for_send(uuid[]);
CREATE FUNCTION openwacht.alert_channels_for_send(p_ids uuid[])
    RETURNS TABLE (id uuid, tenant_id uuid, tenant_name text, name text, kind text, server text, topic text,
                   token_enc bytea, secret_enc bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT ch.id, ch.tenant_id, t.name, ch.name, ch.kind, ch.server, ch.topic, ch.token_enc, ch.secret_enc
      FROM openwacht.alert_channels ch
      JOIN openwacht.tenants t ON t.id = ch.tenant_id
     WHERE ch.id = ANY (p_ids)
$$;

-- Empfänger der Mail-Kanäle: aktive Benutzer mit Rolle im Mandanten des
-- Kanals, die Alarm-Mails nicht abbestellt haben.
CREATE FUNCTION openwacht.alert_mail_recipients(p_channels uuid[])
    RETURNS TABLE (channel_id uuid, email text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT x.channel_id, x.email FROM (
        SELECT ch.id AS channel_id, u.email,
               row_number() OVER (PARTITION BY ch.id ORDER BY u.email) AS n
          FROM openwacht.alert_channels ch
          JOIN openwacht.role_assignments ra ON ra.tenant_id = ch.tenant_id
          JOIN openwacht.users u ON u.id = ra.user_id
         WHERE ch.id = ANY (p_channels) AND ch.kind = 'mail' AND u.alert_mail AND NOT u.disabled
           AND (ch.all_users OR EXISTS (SELECT 1 FROM openwacht.alert_channel_users cu
                                         WHERE cu.channel_id = ch.id AND cu.user_id = u.id))
    ) x WHERE x.n <= 100
    ORDER BY 1, 2
$$;

-- Gerät und Zustand je Quelle eines Ereignisses (für Mail, Webhook, Teams).
-- last_ok: letzte erfolgreiche Prüfung eines Checks in den Rohdaten (48 h).
CREATE FUNCTION openwacht.alert_sources(p_checks uuid[], p_agents uuid[], p_snmp uuid[])
    RETURNS TABLE (kind text, source_id uuid, device_id uuid, device_name text, since timestamptz,
                   last_ok timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT 'check', c.id, d.id, d.name, c.since,
           (SELECT max(r.ts) FROM openwacht.metrics_check_raw r
             WHERE r.check_id = c.id AND r.status = 'ok' AND r.ts >= now() - interval '48 hours')
      FROM openwacht.checks c JOIN openwacht.devices d ON d.id = c.device_id
     WHERE c.id = ANY (p_checks)
    UNION ALL
    SELECT 'agent', a.id, d.id, d.name, NULL, NULL
      FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id
     WHERE a.id = ANY (p_agents)
    UNION ALL
    SELECT 'snmp', q.id, d.id, d.name, NULL, NULL
      FROM openwacht.snmp_sources q JOIN openwacht.devices d ON d.id = q.device_id
     WHERE q.id = ANY (p_snmp)
$$;

-- Offene Alarme der Geräte (Alarmprotokoll), höchstens 50 je Gerät.
CREATE FUNCTION openwacht.alert_open_alarms(p_devices uuid[])
    RETURNS TABLE (device_id uuid, check_id uuid, agent_id uuid, snmp_id uuid, subject text, name text,
                   status text, message text, started_at timestamptz, acked boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT x.device_id, x.check_id, x.agent_id, x.snmp_id, x.subject, x.name, x.status, x.message, x.started_at, x.acked
      FROM (
        SELECT coalesce(c.device_id, a.device_id, q.device_id) AS device_id, al.check_id, al.agent_id, al.snmp_id,
               al.subject, al.name, al.status, al.message, al.started_at, al.ack_at IS NOT NULL AS acked,
               row_number() OVER (PARTITION BY coalesce(c.device_id, a.device_id, q.device_id)
                                  ORDER BY openwacht.alarm_rank(al.status) DESC, al.started_at) AS n
          FROM openwacht.alarms al
          LEFT JOIN openwacht.checks c ON c.id = al.check_id
          LEFT JOIN openwacht.agents a ON a.id = al.agent_id
          LEFT JOIN openwacht.snmp_sources q ON q.id = al.snmp_id
         WHERE al.ended_at IS NULL
      ) x
     WHERE x.device_id = ANY (p_devices) AND x.n <= 50
     ORDER BY 1, openwacht.alarm_rank(x.status) DESC, x.started_at
$$;

-- Verlauf der letzten Stunden einer Reihe in 10-Minuten-Blöcken aus den
-- Rohdaten (48 h vorhanden): Agent- oder SNMP-Reihe bzw. Antwortzeit eines Checks.
CREATE FUNCTION openwacht.alert_series(p_kind text, p_id uuid, p_series text, p_hours integer)
    RETURNS TABLE (t timestamptz, v double precision)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_hours NOT BETWEEN 1 AND 48 THEN
        RAISE EXCEPTION 'alert_series: Zeitraum 1 bis 48 Stunden';
    END IF;
    IF p_kind = 'check' THEN
        RETURN QUERY SELECT date_bin('10 minutes', r.ts, timestamptz 'epoch'), avg(r.ms)
          FROM openwacht.metrics_check_raw r
         WHERE r.check_id = p_id AND r.ms IS NOT NULL AND r.ts >= now() - make_interval(hours => p_hours)
         GROUP BY 1 ORDER BY 1;
    ELSIF p_kind = 'agent' THEN
        RETURN QUERY SELECT date_bin('10 minutes', r.ts, timestamptz 'epoch'), avg(r.value)
          FROM openwacht.metrics_host_raw r
         WHERE r.agent_id = p_id AND r.series = p_series AND r.ts >= now() - make_interval(hours => p_hours)
         GROUP BY 1 ORDER BY 1;
    ELSIF p_kind = 'snmp' THEN
        RETURN QUERY SELECT date_bin('10 minutes', r.ts, timestamptz 'epoch'), avg(r.value)
          FROM openwacht.metrics_snmp_raw r
         WHERE r.snmp_id = p_id AND r.series = p_series AND r.ts >= now() - make_interval(hours => p_hours)
         GROUP BY 1 ORDER BY 1;
    END IF;
END
$$;

-- Platten-Prognose ohne Benutzerkontext (Mail jetzt, Alarm „bald voll“ in
-- 20b). Gleiche Rechnung wie forecastSQL in internal/zentrale/prognose.go
-- (dort mit RLS für die Oberfläche); p_devices NULL = alle Geräte.
CREATE FUNCTION openwacht.disk_forecasts_sys(p_devices uuid[], p_window interval, p_drop double precision)
    RETURNS TABLE (art text, quelle uuid, device_id uuid, platte text, slope_day double precision,
                   points bigint, span_days double precision, current double precision, after_drop boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
WITH w AS (
    SELECT done_1h, now() - p_window AS von FROM openwacht.metrics_watermarks()
), src AS (
    SELECT 'host'::text AS art, a.id AS quelle, a.device_id, m.series, m.bucket AS t, m.avg AS v
      FROM openwacht.metrics_host_1h m JOIN openwacht.agents a ON a.id = m.agent_id, w
     WHERE a.revoked_at IS NULL AND m.series LIKE 'platte:%' AND m.bucket >= w.von AND m.bucket < w.done_1h
       AND (p_devices IS NULL OR a.device_id = ANY (p_devices))
    UNION ALL
    SELECT 'host', a.id, a.device_id, r.series, date_bin('1 hour', r.ts, timestamptz 'epoch'), avg(r.value)
      FROM openwacht.metrics_host_raw r JOIN openwacht.agents a ON a.id = r.agent_id, w
     WHERE a.revoked_at IS NULL AND r.series LIKE 'platte:%' AND r.ts >= greatest(w.von, w.done_1h)
       AND (p_devices IS NULL OR a.device_id = ANY (p_devices))
     GROUP BY 1, 2, 3, 4, 5
    UNION ALL
    SELECT 'snmp', q.id, q.device_id, m.series, m.bucket, m.avg
      FROM openwacht.metrics_snmp_1h m JOIN openwacht.snmp_sources q ON q.id = m.snmp_id, w
     WHERE q.enabled AND m.series LIKE 'platte:%' AND m.bucket >= w.von AND m.bucket < w.done_1h
       AND (p_devices IS NULL OR q.device_id = ANY (p_devices))
    UNION ALL
    SELECT 'snmp', q.id, q.device_id, r.series, date_bin('1 hour', r.ts, timestamptz 'epoch'), avg(r.value)
      FROM openwacht.metrics_snmp_raw r JOIN openwacht.snmp_sources q ON q.id = r.snmp_id, w
     WHERE q.enabled AND r.series LIKE 'platte:%' AND r.ts >= greatest(w.von, w.done_1h)
       AND (p_devices IS NULL OR q.device_id = ANY (p_devices))
     GROUP BY 1, 2, 3, 4, 5
), d AS (
    SELECT src.*, lag(v) OVER (PARTITION BY art, quelle, series ORDER BY t) AS prev FROM src
), cut AS (
    SELECT art, quelle, series, max(t) FILTER (WHERE prev - v >= p_drop) AS c FROM d GROUP BY 1, 2, 3
), seg AS (
    SELECT d.*, cut.c FROM d JOIN cut USING (art, quelle, series) WHERE cut.c IS NULL OR d.t >= cut.c
)
SELECT seg.art, seg.quelle, seg.device_id, substr(seg.series, 8),
       coalesce(regr_slope(seg.v, extract(epoch FROM seg.t)) * 86400, 'NaN'::double precision),
       count(*), extract(epoch FROM max(seg.t) - min(seg.t))::double precision / 86400,
       (array_agg(seg.v ORDER BY seg.t DESC))[1], bool_or(seg.c IS NOT NULL)
  FROM seg
 GROUP BY seg.art, seg.quelle, seg.device_id, seg.series
HAVING max(seg.t) >= now() - interval '1 day'
 ORDER BY 1, 2, 4
 LIMIT 20000
$$;

REVOKE ALL ON FUNCTION openwacht.alert_channels_for_send(uuid[]), openwacht.alert_mail_recipients(uuid[]),
    openwacht.alert_sources(uuid[], uuid[], uuid[]), openwacht.alert_open_alarms(uuid[]),
    openwacht.alert_series(text, uuid, text, integer),
    openwacht.disk_forecasts_sys(uuid[], interval, double precision) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_channels_for_send(uuid[]), openwacht.alert_mail_recipients(uuid[]),
    openwacht.alert_sources(uuid[], uuid[], uuid[]), openwacht.alert_open_alarms(uuid[]),
    openwacht.alert_series(text, uuid, text, integer),
    openwacht.disk_forecasts_sys(uuid[], interval, double precision) TO openwacht_app;
