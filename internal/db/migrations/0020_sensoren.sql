-- SPDX-License-Identifier: AGPL-3.0-only

-- 0020: Eigene Sensoren und Sensor-Vorlagen (Etappe 18a).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * Neue Arten an der Zentrale: DNS-Auflösung und HTTP-JSON-Wert; Ping
--     bekommt Paketzahl und Schwellen für Verlust und Antwortzeit (gleiche Art).
--   * Neue Arten auf dem Agent: Dienst läuft, Prozess läuft (nur Name und
--     Anzahl), Datei-/Ordneralter. Der Agent holt dafür nur eine Liste mit
--     Art und Parametern ab (Daten, keine Skripte oder Befehle) und misst nur,
--     was auf dem Rechner selbst freigegeben ist (openwacht-agent sensoren …).
--     Leitprinzip 1 bleibt gewahrt: Der Agent öffnet keinen Port.
--   * Vorlagen: Ein Sensor aus einer Vorlage ist eine Kopie; checks.origin
--     merkt sich nur den Namen der Vorlage. Änderungen an der Vorlage ändern
--     keine Sensoren.
--
-- Sensoren sind weiter Zeilen in openwacht.checks: Zustand, Verlauf, Alarme,
-- Wartung und Rechte laufen unverändert mit.

CREATE FUNCTION openwacht.is_agent_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('dienst', 'prozess', 'datei')
$$;

ALTER TABLE openwacht.checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE openwacht.checks
    ADD CONSTRAINT checks_kind_check
        CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'dienst', 'prozess', 'datei')),
    -- Der Agent meldet höchstens einmal je Meldezyklus (60 s).
    ADD CONSTRAINT checks_agent_interval CHECK (NOT openwacht.is_agent_kind(kind) OR interval_s >= 60),
    -- Herkunft: Name der Vorlage beim Anlegen; NULL = eigener Sensor.
    ADD COLUMN origin text CHECK (origin IS NULL OR (char_length(origin) BETWEEN 1 AND 100 AND origin !~ '[[:cntrl:]]'));
GRANT SELECT (origin), INSERT (origin) ON openwacht.checks TO openwacht_app;

-- Sensoren auf dem Agent brauchen ein Gerät mit (nicht gesperrtem) Agent.
-- Mit den Rechten des Aufrufers: Wer am Gerät Sensoren anlegen darf, sieht
-- auch dessen Agent.
CREATE FUNCTION openwacht.checks_agent_device() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF openwacht.is_agent_kind(NEW.kind) AND NOT EXISTS (
           SELECT 1 FROM openwacht.agents a
            WHERE a.device_id = NEW.device_id AND a.tenant_id = NEW.tenant_id AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Sensoren auf dem Agent brauchen ein Gerät mit Agent.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
-- Name mit zz: Trigger laufen alphabetisch, der Mandant kommt vorher aus dem Gerät.
CREATE TRIGGER checks_zz_agent_device BEFORE INSERT OR UPDATE OF kind, device_id ON openwacht.checks
    FOR EACH ROW EXECUTE FUNCTION openwacht.checks_agent_device();

-- Planer der Zentrale: Sensoren auf dem Agent führt sie nicht aus.
CREATE OR REPLACE FUNCTION openwacht.checks_claim(p_limit integer)
    RETURNS TABLE (id uuid, kind text, target jsonb, revision integer)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.checks c SET next_run = now() + interval '2 minutes'
     WHERE c.id IN (SELECT d.id FROM openwacht.checks d
                     WHERE d.enabled AND d.next_run <= now() AND NOT openwacht.is_agent_kind(d.kind)
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING c.id, c.kind, c.target, c.revision
$$;

-- ---------------------------------------------------------------------------
-- Funktionen für den Agent-Port (Identität aus dem Client-Zertifikat)
-- ---------------------------------------------------------------------------

-- Sensoren, die dieser Agent messen soll: die seines Geräts, im selben
-- Mandanten, nur für einen gültigen Agent. due: fällig nach Plan der
-- Datenbank (neu, „Jetzt prüfen“ oder überfällig); check_record schiebt
-- next_run nach jedem Ergebnis um ein Intervall weiter.
CREATE FUNCTION openwacht.agent_sensor_jobs(p_agent uuid, p_serial text)
    RETURNS TABLE (id uuid, kind text, target jsonb, revision integer, interval_s integer, due boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.kind, c.target, c.revision, c.interval_s,
           c.next_run <= now()
      FROM openwacht.checks c
      JOIN openwacht.agents a ON a.device_id = c.device_id AND a.tenant_id = c.tenant_id
     WHERE a.id = p_agent AND a.revoked_at IS NULL AND p_serial IN (a.cert_serial, a.cert_serial_prev)
       AND c.enabled AND openwacht.is_agent_kind(c.kind)
     ORDER BY c.id
     LIMIT 200
$$;

-- Ergebnis eines Sensors. Nur für den Agent seines Geräts; eine andere
-- Revision (Ziel inzwischen geändert) verwirft check_record.
CREATE FUNCTION openwacht.agent_sensor_record(p_agent uuid, p_serial text, p_id uuid, p_revision integer,
                                             p_status text, p_message text, p_metric text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_status IS NULL OR p_status NOT IN ('ok', 'warn', 'crit', 'unknown') THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (
           SELECT 1 FROM openwacht.checks c
             JOIN openwacht.agents a ON a.device_id = c.device_id AND a.tenant_id = c.tenant_id
            WHERE c.id = p_id AND a.id = p_agent AND a.revoked_at IS NULL
              AND p_serial IN (a.cert_serial, a.cert_serial_prev)
              AND c.enabled AND openwacht.is_agent_kind(c.kind)) THEN
        RETURN false;
    END IF;
    RETURN openwacht.check_record(p_id, p_revision, p_status, left(coalesce(p_message, ''), 300),
                                 left(coalesce(p_metric, ''), 50), NULL);
END
$$;

REVOKE ALL ON FUNCTION openwacht.agent_sensor_jobs(uuid, text),
    openwacht.agent_sensor_record(uuid, text, uuid, integer, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_sensor_jobs(uuid, text),
    openwacht.agent_sensor_record(uuid, text, uuid, integer, text, text, text) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Eigene Sensor-Vorlagen je Mandant
-- ---------------------------------------------------------------------------
--
-- Eingebaute Vorlagen stehen im Code (internal/zentrale/vorlagen.go). Eigene
-- Vorlagen gehören einem Mandanten; sichtbar im eigenen Teilbaum wie alles
-- andere, pflegen dürfen Admins und Operatoren. Das Ziel prüft die API
-- (checks.ParseTemplate); {adresse} steht für die Adresse des Geräts.

CREATE TABLE openwacht.sensor_templates (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name !~ '[[:cntrl:]]'),
    kind       text NOT NULL CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'dienst', 'prozess', 'datei')),
    target     jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object' AND octet_length(target::text) <= 32768),
    interval_s integer NOT NULL CHECK (interval_s BETWEEN 30 AND 86400),
    note       text NOT NULL DEFAULT '' CHECK (char_length(note) <= 200 AND note !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sensor_templates_agent_interval CHECK (NOT openwacht.is_agent_kind(kind) OR interval_s >= 60)
);
CREATE UNIQUE INDEX sensor_templates_name ON openwacht.sensor_templates (tenant_id, lower(name));

CREATE FUNCTION openwacht.sensor_templates_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.sensor_templates WHERE tenant_id = NEW.tenant_id) >= 200 THEN
            RAISE EXCEPTION 'Höchstens 200 Vorlagen je Mandant.' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := now();
    ELSIF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant einer Vorlage sind unveränderlich.';
    END IF;
    NEW.changed_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER sensor_templates_before BEFORE INSERT OR UPDATE ON openwacht.sensor_templates
    FOR EACH ROW EXECUTE FUNCTION openwacht.sensor_templates_before();

ALTER TABLE openwacht.sensor_templates ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT (tenant_id, name, kind, target, interval_s, note),
      UPDATE (name, kind, target, interval_s, note), DELETE
    ON openwacht.sensor_templates TO openwacht_app;
CREATE POLICY sensor_templates_select ON openwacht.sensor_templates FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY sensor_templates_insert ON openwacht.sensor_templates FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_templates_update ON openwacht.sensor_templates FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_templates_delete ON openwacht.sensor_templates FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));
