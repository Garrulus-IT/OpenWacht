-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.43.0: Alarmkanal „SMS (brevis.one)“.
--
-- Entscheidungen (23.11.2026):
--   * Je Mandant ein Kanal mit eigenem Gateway, wie Mail, Webhook und Teams.
--     Die Adresse (server = https://host[:port]) muss als Alarmziel
--     freigegeben sein; geprüft beim Speichern und vor jedem Versand.
--   * Eigener API-Benutzer auf dem Gateway, nicht admin (CHECK). Das Passwort
--     liegt verschlüsselt in token_enc, gebunden an Kanal, Mandant, Gateway,
--     Benutzer und Fingerabdruck: Wechselt einer davon, verwirft der Trigger
--     das Passwort (es geht nie an ein anderes Gateway oder Zertifikat), und
--     der CHECK verlangt ein neues.
--   * Fingerabdruck (SHA-256) des selbstsignierten Zertifikats statt CA.
--   * Empfänger: Benutzerkonten mit Rolle in genau dem Mandanten des Kanals
--     (wie Mail, alert_channel_users) und deren freiwillige „Mobilnummer für
--     Alarme“, oder eine Gruppe bzw. ein Kontakt auf dem Gateway
--     (mode=group). Kein Freitext mit Nummern im Kanal.
--   * Datensparsamkeit (Leitprinzip 5): Die Mobilnummer ist für die
--     Anwendungsrolle nicht lesbar. Jeder setzt und liest nur die eigene;
--     andere sehen nur, ob eine hinterlegt ist. Der Versand liest sie über
--     eine SECURITY-DEFINER-Funktion. Höchstens 20 Empfänger je SMS-Kanal.
--   * Optional „bei kritisch zusätzlich anrufen“ (ring) und „Gateway
--     überwachen“ (Hinweis, wenn das Gateway nicht erreichbar ist).

-- ---------------------------------------------------------------------------
-- Kanäle
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_kind_check;
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_check;
ALTER TABLE openwacht.alert_channels
    ADD COLUMN sms_user   text CHECK (char_length(sms_user) BETWEEN 1 AND 64 AND sms_user !~ '[[:space:][:cntrl:]]'
                                      AND lower(sms_user) <> 'admin'),
    ADD COLUMN sms_pin    text CHECK (sms_pin ~ '^[0-9a-f]{64}$'),
    ADD COLUMN sms_target text CHECK (sms_target IN ('benutzer', 'gruppe')),
    ADD COLUMN sms_group  text CHECK (sms_group ~ '^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$'),
    ADD COLUMN sms_ring   boolean NOT NULL DEFAULT false,
    ADD COLUMN sms_watch  boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT alert_channels_kind_check CHECK (kind IN ('ntfy', 'mail', 'webhook', 'teams', 'sms')),
    ADD CONSTRAINT alert_channels_check CHECK (CASE kind
        WHEN 'ntfy'    THEN server IS NOT NULL AND topic IS NOT NULL AND secret_enc IS NULL AND NOT all_users
        WHEN 'mail'    THEN server IS NULL AND topic IS NULL AND token_enc IS NULL AND secret_enc IS NULL
        WHEN 'webhook' THEN server IS NOT NULL AND topic IS NULL AND token_enc IS NOT NULL AND secret_enc IS NOT NULL AND NOT all_users
        WHEN 'teams'   THEN server IS NOT NULL AND topic IS NULL AND token_enc IS NOT NULL AND secret_enc IS NULL AND NOT all_users
        WHEN 'sms'     THEN server ~ '^https://[^/[:space:][:cntrl:]]+$' AND topic IS NULL AND token_enc IS NOT NULL
                            AND secret_enc IS NULL AND NOT all_users AND sms_user IS NOT NULL AND sms_pin IS NOT NULL
                            AND sms_target IS NOT NULL AND (sms_target = 'gruppe') = (sms_group IS NOT NULL)
    END),
    -- Die SMS-Spalten gehören nur zu SMS-Kanälen.
    ADD CONSTRAINT alert_channels_sms_only CHECK (kind = 'sms' OR (sms_user IS NULL AND sms_pin IS NULL AND sms_target IS NULL
        AND sms_group IS NULL AND NOT sms_ring AND NOT sms_watch));

GRANT SELECT (sms_user, sms_pin, sms_target, sms_group, sms_ring, sms_watch),
      INSERT (sms_user, sms_pin, sms_target, sms_group, sms_ring, sms_watch),
      UPDATE (sms_user, sms_pin, sms_target, sms_group, sms_ring, sms_watch) ON openwacht.alert_channels TO openwacht_app;

-- Wie 0024, dazu SMS: Neues Gateway, neuer Benutzer oder neuer
-- Fingerabdruck ohne neues Passwort verwirft das alte (der CHECK lehnt dann
-- ab). Neues Gateway, neues Passwort oder andere Empfänger auf dem Gateway
-- sind ein neues Ziel: alles neu melden.
CREATE OR REPLACE FUNCTION openwacht.alert_channels_before_update() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.kind IS DISTINCT FROM OLD.kind THEN
        RAISE EXCEPTION 'ID, Mandant und Art eines Alarmkanals sind unveränderlich.';
    END IF;
    IF (NEW.server IS DISTINCT FROM OLD.server OR NEW.sms_user IS DISTINCT FROM OLD.sms_user
        OR NEW.sms_pin IS DISTINCT FROM OLD.sms_pin)
       AND NEW.token_enc IS NOT DISTINCT FROM OLD.token_enc THEN
        NEW.token_enc := NULL;
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server OR NEW.topic IS DISTINCT FROM OLD.topic
       OR NEW.kind IN ('webhook', 'teams', 'sms') AND NEW.token_enc IS DISTINCT FROM OLD.token_enc
       OR NEW.sms_target IS DISTINCT FROM OLD.sms_target OR NEW.sms_group IS DISTINCT FROM OLD.sms_group THEN
        DELETE FROM openwacht.alert_state WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_agents WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_snmp WHERE channel_id = OLD.id;
        NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------
-- Empfänger: wie Mail, dazu SMS-Kanäle mit Empfänger „benutzer“ (höchstens 20)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.alert_channel_users_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    k text;
    tgt text;
BEGIN
    SELECT ch.tenant_id, ch.kind, ch.sms_target INTO NEW.tenant_id, k, tgt FROM openwacht.alert_channels ch WHERE ch.id = NEW.channel_id;
    IF k IS DISTINCT FROM 'mail' AND NOT (k = 'sms' AND tgt = 'benutzer') THEN
        RAISE EXCEPTION 'Empfänger gibt es nur bei Mail-Kanälen und SMS-Kanälen an Benutzer.' USING ERRCODE = '23514';
    END IF;
    IF (SELECT count(*) FROM openwacht.alert_channel_users WHERE channel_id = NEW.channel_id) >= (CASE k WHEN 'sms' THEN 20 ELSE 100 END) THEN
        RAISE EXCEPTION 'Zu viele Empfänger für diesen Kanal (Mail 100, SMS 20).' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- Wechselt ein SMS-Kanal auf eine Gruppe, gehören ihm keine Benutzer mehr.
CREATE FUNCTION openwacht.alert_channels_sms_target() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.kind = 'sms' AND NEW.sms_target = 'gruppe' AND OLD.sms_target IS DISTINCT FROM 'gruppe' THEN
        DELETE FROM openwacht.alert_channel_users WHERE channel_id = NEW.id;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER alert_channels_sms_target AFTER UPDATE OF sms_target ON openwacht.alert_channels
    FOR EACH ROW EXECUTE FUNCTION openwacht.alert_channels_sms_target();

-- ---------------------------------------------------------------------------
-- Mobilnummer für Alarme (freiwillig, am eigenen Konto)
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.users
    ADD COLUMN alert_mobile text CHECK (alert_mobile ~ '^\+[1-9][0-9]{6,14}$'),
    ADD COLUMN alert_mobile_set boolean GENERATED ALWAYS AS (alert_mobile IS NOT NULL) STORED;
-- Nur ob eine Nummer da ist, nicht welche.
GRANT SELECT (alert_mobile_set) ON openwacht.users TO openwacht_app;

-- Jeder für sich selbst: setzen (NULL = entfernen). Technische Konten der
-- API-Tokens haben keine Nummer.
CREATE FUNCTION openwacht.set_alert_mobile(p_number text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF uid IS NULL THEN
        RAISE EXCEPTION 'set_alert_mobile: kein Benutzer' USING ERRCODE = '42501';
    END IF;
    IF p_number IS NOT NULL AND p_number !~ '^\+[1-9][0-9]{6,14}$' THEN
        RAISE EXCEPTION 'Ungültige Mobilnummer.' USING ERRCODE = '23514';
    END IF;
    UPDATE openwacht.users SET alert_mobile = p_number WHERE id = uid AND auth_source <> 'token';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'set_alert_mobile: Konto ohne Mobilnummer' USING ERRCODE = '42501';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openwacht.set_alert_mobile(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.set_alert_mobile(text) TO openwacht_app;

-- Die eigene Nummer lesen.
CREATE FUNCTION openwacht.my_alert_mobile() RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.alert_mobile FROM openwacht.users u WHERE u.id = openwacht.current_user_id()
$$;
REVOKE ALL ON FUNCTION openwacht.my_alert_mobile() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.my_alert_mobile() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Versand (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- SMS-Einstellungen der Kanäle.
CREATE FUNCTION openwacht.alert_sms_channels(p_ids uuid[])
    RETURNS TABLE (id uuid, sms_user text, sms_pin text, sms_target text, sms_group text, sms_ring boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT ch.id, ch.sms_user, ch.sms_pin, ch.sms_target, ch.sms_group, ch.sms_ring
      FROM openwacht.alert_channels ch WHERE ch.id = ANY (p_ids) AND ch.kind = 'sms'
$$;

-- Nummern der Empfänger: ausgewählte, aktive Benutzer mit Rolle im Mandanten
-- des Kanals und hinterlegter Nummer, höchstens 20 je Kanal.
CREATE FUNCTION openwacht.alert_sms_recipients(p_channels uuid[])
    RETURNS TABLE (channel_id uuid, mobile text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT x.channel_id, x.mobile FROM (
        SELECT ch.id AS channel_id, u.alert_mobile AS mobile,
               row_number() OVER (PARTITION BY ch.id ORDER BY u.alert_mobile) AS n
          FROM openwacht.alert_channels ch
          JOIN openwacht.alert_channel_users cu ON cu.channel_id = ch.id
          JOIN openwacht.role_assignments ra ON ra.tenant_id = ch.tenant_id AND ra.user_id = cu.user_id
          JOIN openwacht.users u ON u.id = cu.user_id
         WHERE ch.id = ANY (p_channels) AND ch.kind = 'sms' AND ch.sms_target = 'benutzer'
           AND u.alert_mobile IS NOT NULL AND NOT u.disabled
    ) x WHERE x.n <= 20
    ORDER BY 1, 2
$$;

-- Gateways mit Überwachung (Selbstüberwachung, Hinweis an den Mandanten).
CREATE FUNCTION openwacht.alert_sms_watch()
    RETURNS TABLE (id uuid, tenant_id uuid, name text, server text, sms_pin text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT ch.id, ch.tenant_id, ch.name, ch.server, ch.sms_pin FROM openwacht.alert_channels ch
     WHERE ch.kind = 'sms' AND ch.sms_watch AND ch.enabled
     ORDER BY ch.id
$$;

REVOKE ALL ON FUNCTION openwacht.alert_sms_channels(uuid[]), openwacht.alert_sms_recipients(uuid[]),
    openwacht.alert_sms_watch() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_sms_channels(uuid[]), openwacht.alert_sms_recipients(uuid[]),
    openwacht.alert_sms_watch() TO openwacht_app;
