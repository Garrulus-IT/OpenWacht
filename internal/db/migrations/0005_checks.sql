-- SPDX-License-Identifier: AGPL-3.0-only

-- 0005: Aktive Checks (Ping, TCP, HTTP, TLS) je Mandant und ihr Zustand.
--
-- Benutzer pflegen Checks über die API (RLS: sehen im eigenen Teilbaum,
-- ändern als Admin oder Operator). Den Zustand schreibt nur der Planer der
-- Zentrale, über SECURITY-DEFINER-Funktionen ohne Benutzerkontext. Welche
-- Netze Checks erreichen dürfen, entscheidet der Betreiber in der Zentrale.

CREATE TABLE openwacht.checks (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    kind        text NOT NULL CHECK (kind IN ('ping', 'tcp', 'http', 'tls')),
    -- Ziel; geprüft von der Zentrale (internal/checks.Parse)
    target      jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object' AND octet_length(target::text) <= 32768),
    interval_s  integer NOT NULL CHECK (interval_s BETWEEN 30 AND 86400),
    enabled     boolean NOT NULL DEFAULT true,
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- steigt bei jeder Änderung des Ziels; ein Ergebnis zum alten Ziel wird verworfen
    revision    integer NOT NULL DEFAULT 1,
    next_run    timestamptz NOT NULL DEFAULT now(),
    -- Zustand (nur über check_record)
    status      text CHECK (status IN ('ok', 'warn', 'crit', 'unknown')),
    message     text CHECK (char_length(message) <= 300),
    metric      text CHECK (char_length(metric) <= 50),
    since       timestamptz,
    fails       integer NOT NULL DEFAULT 0,
    last_run    timestamptz
);
CREATE UNIQUE INDEX checks_name ON openwacht.checks (tenant_id, lower(name));
CREATE INDEX checks_due ON openwacht.checks (next_run) WHERE enabled;

CREATE FUNCTION openwacht.checks_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM openwacht.checks WHERE tenant_id = NEW.tenant_id) >= 500 THEN
        RAISE EXCEPTION 'Höchstens 500 Checks je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.revision := 1;
    NEW.next_run := now();
    NEW.status := NULL; NEW.message := NULL; NEW.metric := NULL; NEW.since := NULL;
    NEW.fails := 0; NEW.last_run := NULL;
    RETURN NEW;
END
$$;
CREATE TRIGGER checks_before_insert BEFORE INSERT ON openwacht.checks
    FOR EACH ROW EXECUTE FUNCTION openwacht.checks_before_insert();

-- Neues Ziel: alter Zustand gilt nicht mehr, sofort neu prüfen.
CREATE FUNCTION openwacht.checks_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
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
CREATE TRIGGER checks_before_update BEFORE UPDATE ON openwacht.checks
    FOR EACH ROW EXECUTE FUNCTION openwacht.checks_before_update();

ALTER TABLE openwacht.checks ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, name, kind, target, interval_s, enabled, created_at, next_run,
              status, message, metric, since, fails, last_run),
      INSERT (tenant_id, name, kind, target, interval_s, enabled),
      UPDATE (name, kind, target, interval_s, enabled, next_run),
      DELETE
    ON openwacht.checks TO openwacht_app;
CREATE POLICY checks_select ON openwacht.checks FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY checks_insert ON openwacht.checks FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
-- „Jetzt prüfen“ darf next_run nur nach vorn holen, nicht weit in die Zukunft schieben.
CREATE POLICY checks_update ON openwacht.checks FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()) AND next_run <= now() + interval '1 day');
CREATE POLICY checks_delete ON openwacht.checks FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- ---------------------------------------------------------------------------
-- Funktionen für den Planer (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Fällige Checks holen und für zwei Minuten reservieren. SKIP LOCKED: Laufen
-- mehrere Zentralen, prüft jede andere Checks.
CREATE FUNCTION openwacht.checks_claim(p_limit integer)
    RETURNS TABLE (id uuid, kind text, target jsonb, revision integer)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.checks c SET next_run = now() + interval '2 minutes'
     WHERE c.id IN (SELECT d.id FROM openwacht.checks d
                     WHERE d.enabled AND d.next_run <= now()
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING c.id, c.kind, c.target, c.revision
$$;

-- Ergebnis speichern. Wurde das Ziel inzwischen geändert (andere Revision),
-- wird es verworfen.
CREATE FUNCTION openwacht.check_record(p_id uuid, p_revision integer, p_status text,
                                      p_message text, p_metric text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.checks c
       SET since    = CASE WHEN c.status IS DISTINCT FROM p_status THEN now() ELSE c.since END,
           status   = p_status,
           message  = p_message,
           metric   = nullif(p_metric, ''),
           fails    = CASE WHEN p_status = 'ok' THEN 0 ELSE c.fails + 1 END,
           last_run = now(),
           next_run = now() + make_interval(secs => c.interval_s)
     WHERE c.id = p_id AND c.revision = p_revision;
    RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION openwacht.checks_claim(integer), openwacht.check_record(uuid, integer, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.checks_claim(integer), openwacht.check_record(uuid, integer, text, text, text)
    TO openwacht_app;
