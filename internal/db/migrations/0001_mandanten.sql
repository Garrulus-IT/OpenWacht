-- SPDX-License-Identifier: AGPL-3.0-only

-- 0001: Mandantenbaum, Benutzer, Rollen, Audit-Log und Row-Level Security.
--
-- Rollenmodell in PostgreSQL:
--   * Eigentümer: die Rolle, die die Migrationen ausführt. Ihr gehören alle
--     Tabellen und Funktionen. Sie umgeht RLS (bewusst, für Migrationen und die
--     SECURITY-DEFINER-Funktionen unten). Die Anwendung darf NIE als diese
--     Rolle verbunden sein.
--   * openwacht_app: Gruppenrolle der Anwendung (NOLOGIN). Für sie gilt RLS.
--     Sie muss vor der Migration vom Datenbank-Admin angelegt werden; die
--     Login-Rolle der Zentrale wird Mitglied davon.
--
-- Mandantenkontext: Die Anwendung setzt je Transaktion
--   SELECT set_config('app.user_id', '<uuid>', true);
-- Daraus leitet die Datenbank selbst ab, welche Mandanten sichtbar sind
-- (Rollenzuweisungen + Mandantenbaum). Ohne gesetzten Kontext ist nichts
-- sichtbar (fail-closed).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_app') THEN
        RAISE EXCEPTION 'Rolle openwacht_app fehlt. Bitte vor der Migration anlegen: CREATE ROLE openwacht_app NOLOGIN;';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openwacht_app' AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'Rolle openwacht_app darf weder SUPERUSER noch BYPASSRLS haben.';
    END IF;
END
$$;

REVOKE ALL ON SCHEMA openwacht FROM PUBLIC;
GRANT USAGE ON SCHEMA openwacht TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Mandanten
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id  uuid REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    name       text NOT NULL
               CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]' AND name = btrim(name)),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (parent_id IS DISTINCT FROM id)
);

-- Genau ein Hauptmandant pro Installation.
CREATE UNIQUE INDEX tenants_single_root ON openwacht.tenants ((true)) WHERE parent_id IS NULL;
-- Namen innerhalb eines Elternknotens eindeutig (ohne Groß-/Kleinschreibung).
CREATE UNIQUE INDEX tenants_unique_name ON openwacht.tenants (parent_id, lower(name));

-- Abschlusstabelle: jede Vorfahr-Nachfahr-Beziehung, inklusive (x, x, 0).
-- Wird nur per Trigger gepflegt; die Anwendung hat keinen direkten Zugriff.
CREATE TABLE openwacht.tenant_closure (
    ancestor   uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    descendant uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    depth      integer NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor, descendant)
);
CREATE INDEX tenant_closure_descendant ON openwacht.tenant_closure (descendant);

CREATE FUNCTION openwacht.tenants_after_insert() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    INSERT INTO openwacht.tenant_closure (ancestor, descendant, depth)
    SELECT NEW.id, NEW.id, 0
    UNION ALL
    SELECT c.ancestor, NEW.id, c.depth + 1
      FROM openwacht.tenant_closure c
     WHERE c.descendant = NEW.parent_id;
    RETURN NULL;
END
$$;
CREATE TRIGGER tenants_after_insert AFTER INSERT ON openwacht.tenants
    FOR EACH ROW EXECUTE FUNCTION openwacht.tenants_after_insert();

CREATE FUNCTION openwacht.tenants_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'Die ID eines Mandanten ist unveränderlich.';
    END IF;
    IF NEW.parent_id IS DISTINCT FROM OLD.parent_id THEN
        RAISE EXCEPTION 'Mandanten verschieben wird noch nicht unterstützt.';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER tenants_before_update BEFORE UPDATE ON openwacht.tenants
    FOR EACH ROW EXECUTE FUNCTION openwacht.tenants_before_update();

-- ---------------------------------------------------------------------------
-- Benutzer und Rollen
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    email         text NOT NULL UNIQUE
                  CHECK (char_length(email) BETWEEN 3 AND 254 AND email = lower(email)
                         AND email ~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+$'),
    display_name  text NOT NULL
                  CHECK (char_length(display_name) BETWEEN 1 AND 100 AND display_name !~ '[[:cntrl:]]'),
    -- Argon2id-Hash im PHC-Format (Schritt 3). Für die Anwendung NICHT lesbar,
    -- siehe Spaltenrechte unten; die Anmeldung läuft über eine eigene Funktion.
    password_hash text,
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_tenant ON openwacht.users (tenant_id);

CREATE TABLE openwacht.role_assignments (
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'operator', 'leser')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX role_assignments_tenant ON openwacht.role_assignments (tenant_id);

-- ---------------------------------------------------------------------------
-- Kontextfunktionen (Grundlage aller Policies)
-- ---------------------------------------------------------------------------

-- Aktueller Benutzer aus dem Transaktionskontext; NULL, wenn nicht gesetzt.
-- Ein ungültiger Wert ist ein Fehler, kein stilles "niemand".
CREATE FUNCTION openwacht.current_user_id() RETURNS uuid
    LANGUAGE plpgsql STABLE AS $$
DECLARE
    v text := current_setting('app.user_id', true);
BEGIN
    IF v IS NULL OR v = '' THEN
        RETURN NULL;
    END IF;
    RETURN v::uuid;
END
$$;

-- Mandanten, auf die der aktuelle Benutzer mit einer der Rollen zugreifen darf:
-- jeder Knoten mit Rollenzuweisung und alles darunter. Deaktivierte Benutzer
-- sehen nichts. SECURITY DEFINER, weil die Abschlusstabelle für die Anwendung
-- gesperrt ist und die Policies sonst rekursiv würden.
CREATE FUNCTION openwacht.tenants_with_role(roles text[]) RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT DISTINCT c.descendant
      FROM openwacht.role_assignments r
      JOIN openwacht.users u ON u.id = r.user_id AND NOT u.disabled
      JOIN openwacht.tenant_closure c ON c.ancestor = r.tenant_id
     WHERE r.user_id = openwacht.current_user_id()
       AND r.role = ANY (roles)
$$;

CREATE FUNCTION openwacht.visible_tenants() RETURNS SETOF uuid
    LANGUAGE sql STABLE AS $$
    SELECT openwacht.tenants_with_role(ARRAY['admin', 'operator', 'leser'])
$$;

CREATE FUNCTION openwacht.admin_tenants() RETURNS SETOF uuid
    LANGUAGE sql STABLE AS $$
    SELECT openwacht.tenants_with_role(ARRAY['admin'])
$$;

-- Ist der aktuelle Benutzer Admin des Hauptmandanten? Nur diese Admins dürfen
-- neue Mandanten anlegen (Vorgabe: Untermandanten nur mit Freigabe der IT).
CREATE FUNCTION openwacht.is_root_admin() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1
          FROM openwacht.tenants t
         WHERE t.parent_id IS NULL
           AND t.id IN (SELECT openwacht.admin_tenants()))
$$;

-- ---------------------------------------------------------------------------
-- Audit-Log: nur anhängend, mit Hash-Kette
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.audit_log (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    chain_seq     bigint NOT NULL UNIQUE,
    at            timestamptz NOT NULL,
    tenant_id     uuid REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    actor_user_id uuid,
    action        text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,63}$'),
    details       jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(details::text) <= 8192),
    prev_hash     bytea,
    hash          bytea NOT NULL
);
CREATE INDEX audit_log_tenant ON openwacht.audit_log (tenant_id, at);

-- Kanonische Darstellung eines Eintrags für den Hash. Zeit in UTC mit festem
-- Format, damit das Ergebnis nicht von TimeZone/DateStyle der Sitzung abhängt.
CREATE FUNCTION openwacht.audit_entry_hash(e openwacht.audit_log) RETURNS bytea
    LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(
        coalesce(e.prev_hash, '\x'::bytea) ||
        convert_to(concat_ws('|',
            e.chain_seq,
            to_char(e.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            coalesce(e.tenant_id::text, '-'),
            coalesce(e.actor_user_id::text, '-'),
            e.action,
            e.details::text), 'UTF8'))
$$;

CREATE FUNCTION openwacht.audit_before_insert() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    -- Einträge nacheinander verketten, auch bei gleichzeitigen Transaktionen.
    PERFORM pg_advisory_xact_lock(hashtext('openwacht.audit_log'));
    -- Wer handelt, bestimmt die Datenbank, nicht die Anfrage (Leitprinzip 2).
    NEW.actor_user_id := openwacht.current_user_id();
    NEW.at := clock_timestamp();
    SELECT a.chain_seq + 1, a.hash INTO NEW.chain_seq, NEW.prev_hash
      FROM openwacht.audit_log a ORDER BY a.chain_seq DESC LIMIT 1;
    IF NEW.chain_seq IS NULL THEN
        NEW.chain_seq := 1;
        NEW.prev_hash := NULL;
    END IF;
    NEW.hash := openwacht.audit_entry_hash(NEW);
    RETURN NEW;
END
$$;
CREATE TRIGGER audit_before_insert BEFORE INSERT ON openwacht.audit_log
    FOR EACH ROW EXECUTE FUNCTION openwacht.audit_before_insert();

CREATE FUNCTION openwacht.audit_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Das Audit-Log ist unveränderlich.';
END
$$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON openwacht.audit_log
    FOR EACH ROW EXECUTE FUNCTION openwacht.audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON openwacht.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION openwacht.audit_immutable();

-- Prüft die gesamte Kette. Liefert die erste fehlerhafte chain_seq oder NULL.
CREATE FUNCTION openwacht.audit_verify() RETURNS bigint
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    e        openwacht.audit_log;
    expected bigint := 1;
    prev     bytea := NULL;
BEGIN
    FOR e IN SELECT * FROM openwacht.audit_log ORDER BY chain_seq LOOP
        IF e.chain_seq <> expected
           OR e.prev_hash IS DISTINCT FROM prev
           OR e.hash <> openwacht.audit_entry_hash(e) THEN
            RETURN e.chain_seq;
        END IF;
        prev := e.hash;
        expected := expected + 1;
    END LOOP;
    RETURN NULL;
END
$$;

-- ---------------------------------------------------------------------------
-- Rechte und Row-Level Security
-- ---------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA openwacht FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openwacht FROM PUBLIC;
-- Die Abschlusstabelle bleibt für die Anwendung unsichtbar.
REVOKE ALL ON openwacht.tenant_closure FROM openwacht_app;

GRANT EXECUTE ON FUNCTION
    openwacht.current_user_id(),
    openwacht.tenants_with_role(text[]),
    openwacht.visible_tenants(),
    openwacht.admin_tenants(),
    openwacht.is_root_admin()
TO openwacht_app;

ALTER TABLE openwacht.tenants          ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.users            ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.audit_log        ENABLE ROW LEVEL SECURITY;

-- Mandanten: sehen im eigenen Teilbaum; anlegen nur durch Admins des
-- Hauptmandanten (unterhalb eines Knotens, den sie verwalten); umbenennen durch
-- Admins des Knotens; löschen nur durch Admins des Elternknotens.
GRANT SELECT, INSERT (parent_id, name), UPDATE (name), DELETE ON openwacht.tenants TO openwacht_app;
CREATE POLICY tenants_select ON openwacht.tenants FOR SELECT TO openwacht_app
    USING (id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY tenants_insert ON openwacht.tenants FOR INSERT TO openwacht_app
    WITH CHECK (parent_id IN (SELECT openwacht.admin_tenants()) AND openwacht.is_root_admin());
CREATE POLICY tenants_update ON openwacht.tenants FOR UPDATE TO openwacht_app
    USING (id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY tenants_delete ON openwacht.tenants FOR DELETE TO openwacht_app
    USING (parent_id IN (SELECT openwacht.admin_tenants()));

-- Benutzer: sichtbar im eigenen Teilbaum und sich selbst; verwalten durch
-- Admins ihres Mandanten. Das Passwort-Hash ist nicht lesbar.
GRANT SELECT (id, tenant_id, email, display_name, disabled, created_at) ON openwacht.users TO openwacht_app;
GRANT INSERT (tenant_id, email, display_name), UPDATE (display_name, disabled), DELETE
    ON openwacht.users TO openwacht_app;
CREATE POLICY users_select ON openwacht.users FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR id = openwacht.current_user_id());
CREATE POLICY users_insert ON openwacht.users FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY users_update ON openwacht.users FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY users_delete ON openwacht.users FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Rollen: vergeben und entziehen nur Admins des Zielknotens, und nur an
-- Benutzer, die sie selbst sehen dürfen. Damit kann niemand Rechte oberhalb
-- oder neben seinem eigenen Teilbaum vergeben.
GRANT SELECT, INSERT (user_id, tenant_id, role), DELETE ON openwacht.role_assignments TO openwacht_app;
CREATE POLICY roles_select ON openwacht.role_assignments FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR user_id = openwacht.current_user_id());
CREATE POLICY roles_insert ON openwacht.role_assignments FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants())
                AND user_id IN (SELECT u.id FROM openwacht.users u));
CREATE POLICY roles_delete ON openwacht.role_assignments FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Audit-Log: lesen im eigenen Teilbaum (Einträge ohne Mandant nur Admins des
-- Hauptmandanten); schreiben für den eigenen Teilbaum; nie ändern oder löschen.
GRANT SELECT, INSERT (tenant_id, action, details) ON openwacht.audit_log TO openwacht_app;
CREATE POLICY audit_select ON openwacht.audit_log FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants())
           OR (tenant_id IS NULL AND openwacht.is_root_admin()));
CREATE POLICY audit_insert ON openwacht.audit_log FOR INSERT TO openwacht_app
    WITH CHECK (openwacht.current_user_id() IS NOT NULL
                AND (tenant_id IN (SELECT openwacht.visible_tenants())
                     OR (tenant_id IS NULL AND openwacht.is_root_admin())));
