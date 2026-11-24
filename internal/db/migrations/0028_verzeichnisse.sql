-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 22a: Anmeldung mit AD-Konto (LDAPS) und Zwei-Faktor-Pflicht als
-- Einstellung.
--
-- Entscheidung (22.11.2026): AD-Gruppen bestimmen Mandant und Rolle, Anbindung je
-- Mandant (Admin des Mandanten pflegt sie, Untermandanten ohne eigene erben),
-- Dienstkonto mit Suche, Zwei-Faktor optional, der Kunde entscheidet.

-- --- Zwei-Faktor-Pflicht ------------------------------------------------------

-- mfa_policy (nur lokale Konten): 'admins' = Pflicht für Admins (wie bisher,
-- Standard), 'alle' = Pflicht für alle, 'freiwillig' = niemand muss.
-- Verzeichniskonten richten sich nach directories.mfa_required.
ALTER TABLE openwacht.settings
    ADD COLUMN mfa_policy text CHECK (mfa_policy IN ('admins', 'alle', 'freiwillig'));
GRANT UPDATE (mfa_policy) ON openwacht.settings TO openwacht_app;

-- --- Verzeichnisse (LDAP) ---------------------------------------------------------

CREATE TABLE openwacht.directories (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name           text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    -- ldaps://host[:port] oder ldap://host[:port] mit Pflicht zu StartTLS
    url            text NOT NULL CHECK (url ~ '^ldaps?://[A-Za-z0-9.:\[\]-]{1,253}(:[0-9]{1,5})?$'),
    ca_pem         text CHECK (char_length(ca_pem) <= 65536),
    bind_dn        text NOT NULL CHECK (char_length(bind_dn) BETWEEN 3 AND 1000 AND bind_dn !~ '[[:cntrl:]]'),
    bind_pass_enc  bytea NOT NULL CHECK (octet_length(bind_pass_enc) BETWEEN 29 AND 2048),
    base_dn        text NOT NULL CHECK (char_length(base_dn) BETWEEN 3 AND 1000 AND base_dn !~ '[[:cntrl:]]'),
    netbios        text CHECK (netbios ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$'),
    nested_groups  boolean NOT NULL DEFAULT true,
    mfa_required   boolean NOT NULL DEFAULT false,
    enabled        boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);
CREATE UNIQUE INDEX directories_tenant_name ON openwacht.directories (tenant_id, lower(name));
CREATE UNIQUE INDEX directories_netbios ON openwacht.directories (upper(netbios)) WHERE netbios IS NOT NULL;

-- UPN-Suffixe (z. B. firma.de): installationsweit eindeutig, damit die
-- Anmeldung name@firma.de genau ein Verzeichnis findet.
CREATE TABLE openwacht.directory_domains (
    domain        text PRIMARY KEY CHECK (domain ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    directory_id  uuid NOT NULL,
    tenant_id     uuid NOT NULL,
    FOREIGN KEY (directory_id, tenant_id) REFERENCES openwacht.directories (id, tenant_id) ON DELETE CASCADE
);

-- Gruppe → Mandant und Rolle. Der Mandant muss im Teilbaum des Verzeichnisses liegen.
CREATE TABLE openwacht.directory_groups (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id   uuid NOT NULL,
    tenant_id      uuid NOT NULL,   -- Mandant des Verzeichnisses (für RLS)
    group_dn       text NOT NULL CHECK (char_length(group_dn) BETWEEN 3 AND 1000 AND group_dn !~ '[[:cntrl:]]'),
    target_tenant  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    role           text NOT NULL CHECK (role IN ('admin', 'operator', 'leser')),
    FOREIGN KEY (directory_id, tenant_id) REFERENCES openwacht.directories (id, tenant_id) ON DELETE CASCADE,
    UNIQUE (directory_id, group_dn, target_tenant)
);

CREATE FUNCTION openwacht.directory_groups_check() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM openwacht.tenant_closure c WHERE c.ancestor = NEW.tenant_id AND c.descendant = NEW.target_tenant) THEN
        RAISE EXCEPTION 'Der Mandant liegt nicht unter dem Mandanten der Anbindung.' USING ERRCODE = '23514';
    END IF;
    IF (SELECT count(*) FROM openwacht.directory_groups WHERE directory_id = NEW.directory_id) >= 200 THEN
        RAISE EXCEPTION 'Höchstens 200 Gruppen je Anbindung.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER directory_groups_check BEFORE INSERT OR UPDATE ON openwacht.directory_groups
    FOR EACH ROW EXECUTE FUNCTION openwacht.directory_groups_check();

-- Konten aus einem Verzeichnis
ALTER TABLE openwacht.users
    ADD COLUMN directory_id uuid REFERENCES openwacht.directories (id) ON DELETE SET NULL,
    ADD COLUMN external_id  text CHECK (char_length(external_id) <= 200),
    ADD COLUMN auth_source  text NOT NULL DEFAULT 'lokal' CHECK (auth_source IN ('lokal', 'ldap', 'oidc')),
    ADD COLUMN synced_at    timestamptz,
    -- vom Abgleich gesperrt (nur solche entsperrt der Abgleich wieder; von
    -- Hand gesperrte Konten bleiben gesperrt)
    ADD COLUMN directory_disabled boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX users_external ON openwacht.users (directory_id, external_id) WHERE directory_id IS NOT NULL;
GRANT SELECT (directory_id, auth_source, synced_at, directory_disabled) ON openwacht.users TO openwacht_app;

-- RLS wie andere Mandantendaten: lesen alle Admins im Teilbaum (die Anbindung
-- ist Verwaltung, kein Inhalt), pflegen nur Admins des Mandanten.
ALTER TABLE openwacht.directories ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.directory_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE openwacht.directory_groups ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, DELETE ON openwacht.directories TO openwacht_app;
GRANT UPDATE (name, url, ca_pem, bind_dn, bind_pass_enc, base_dn, netbios, nested_groups, mfa_required, enabled, updated_at)
    ON openwacht.directories TO openwacht_app;
-- bind_pass_enc lesen: nur über die Funktionen unten
REVOKE SELECT ON openwacht.directories FROM openwacht_app;
GRANT SELECT (id, tenant_id, name, url, ca_pem, bind_dn, base_dn, netbios, nested_groups, mfa_required, enabled, created_at, updated_at)
    ON openwacht.directories TO openwacht_app;
GRANT SELECT, INSERT, DELETE ON openwacht.directory_domains TO openwacht_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON openwacht.directory_groups TO openwacht_app;
CREATE POLICY directories_select ON openwacht.directories FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY directories_insert ON openwacht.directories FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY directories_update ON openwacht.directories FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())) WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY directories_delete ON openwacht.directories FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY directory_domains_all ON openwacht.directory_domains FOR ALL TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())) WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY directory_groups_all ON openwacht.directory_groups FOR ALL TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()) AND target_tenant IN (SELECT openwacht.admin_tenants()));

-- --- Funktionen für Anmeldung und Abgleich (ohne Benutzerkontext) -------------------

-- Verzeichnis zu einer Domäne bzw. einem NetBIOS-Namen (Anmeldung).
CREATE FUNCTION openwacht.directory_for_login(p_domain text, p_netbios text)
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups
      FROM openwacht.directories d
     WHERE d.enabled
       AND ((p_domain IS NOT NULL AND d.id = (SELECT dd.directory_id FROM openwacht.directory_domains dd WHERE dd.domain = lower(p_domain)))
         OR (p_netbios IS NOT NULL AND upper(d.netbios) = upper(p_netbios)))
     LIMIT 1
$$;

-- Alle aktiven Verzeichnisse mit ihren Konten (Abgleich alle 60 Minuten).
CREATE FUNCTION openwacht.directory_sync_list()
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups
      FROM openwacht.directories d WHERE d.enabled
$$;

CREATE FUNCTION openwacht.directory_group_map(p_directory uuid)
    RETURNS TABLE (group_dn text, target_tenant uuid, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT g.group_dn, g.target_tenant, g.role FROM openwacht.directory_groups g WHERE g.directory_id = p_directory
$$;

-- Domänen einer Anbindung: Konten bekommen nur Adressen aus diesen Domänen,
-- damit ein Verzeichnis keine Adressen fremder Domänen vergeben kann.
CREATE FUNCTION openwacht.directory_domain_list(p_directory uuid) RETURNS SETOF text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT dd.domain FROM openwacht.directory_domains dd WHERE dd.directory_id = p_directory
$$;

CREATE FUNCTION openwacht.directory_users(p_directory uuid)
    RETURNS TABLE (user_id uuid, external_id text, email text, disabled boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.id, u.external_id, u.email, u.disabled FROM openwacht.users u WHERE u.directory_id = p_directory
$$;

-- Konto aus dem Verzeichnis anlegen bzw. abgleichen. p_roles: [{"tenant":…,
-- "role":…}] aus den Gruppen (nur Ziele aus der Gruppentabelle dieses
-- Verzeichnisses zählen, die Anwendung kann keine eigenen Rechte erfinden).
-- Ohne Rolle wird das Konto gesperrt und seine Sitzungen enden. Rückgabe:
-- Konto-ID, NULL wenn es (noch) kein Konto gibt und keine Rolle passt.
CREATE FUNCTION openwacht.directory_user_sync(p_directory uuid, p_external text, p_email text, p_name text,
    p_groups text[], p_active boolean) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    d openwacht.directories;
    v_user uuid;
    v_disabled boolean;
    v_roles jsonb;
    v_old jsonb;
BEGIN
    SELECT * INTO d FROM openwacht.directories WHERE id = p_directory;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Anbindung unbekannt' USING ERRCODE = '42501';
    END IF;
    -- je Ziel-Mandant die höchste Rolle
    SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', t, 'role', r) ORDER BY t), '[]'::jsonb) INTO v_roles FROM (
        SELECT g.target_tenant AS t,
               (array_agg(g.role ORDER BY CASE g.role WHEN 'admin' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END))[1] AS r
          FROM openwacht.directory_groups g
         WHERE g.directory_id = p_directory AND lower(g.group_dn) = ANY (SELECT lower(x) FROM unnest(p_groups) x)
         GROUP BY g.target_tenant) s;

    SELECT id, disabled INTO v_user, v_disabled FROM openwacht.users WHERE directory_id = p_directory AND external_id = p_external;
    IF v_user IS NULL THEN
        IF NOT p_active OR v_roles = '[]'::jsonb THEN
            RETURN NULL;
        END IF;
        IF EXISTS (SELECT 1 FROM openwacht.users WHERE email = lower(p_email)) THEN
            RAISE EXCEPTION 'Es gibt schon ein Konto mit dieser Adresse.' USING ERRCODE = '23505';
        END IF;
        INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash, directory_id, external_id, auth_source, synced_at)
        VALUES (d.tenant_id, lower(p_email), left(btrim(p_name), 100), NULL, p_directory, p_external, 'ldap', now())
        RETURNING id INTO v_user;
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (d.tenant_id, 'verzeichnis.konto_angelegt', jsonb_build_object('konto', lower(p_email), 'anbindung', d.name));
    ELSE
        UPDATE openwacht.users SET email = lower(p_email), display_name = left(btrim(p_name), 100), synced_at = now()
         WHERE id = v_user;
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', tenant_id, 'role', role) ORDER BY tenant_id), '[]'::jsonb)
      INTO v_old FROM openwacht.role_assignments WHERE user_id = v_user;
    IF v_old IS DISTINCT FROM v_roles THEN
        DELETE FROM openwacht.role_assignments WHERE user_id = v_user;
        INSERT INTO openwacht.role_assignments (user_id, tenant_id, role)
        SELECT v_user, (e->>'tenant')::uuid, e->>'role' FROM jsonb_array_elements(v_roles) e;
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (d.tenant_id, 'verzeichnis.rechte', jsonb_build_object('konto', lower(p_email), 'vorher', v_old, 'nachher', v_roles));
    END IF;

    IF NOT p_active OR v_roles = '[]'::jsonb THEN
        IF NOT v_disabled THEN
            UPDATE openwacht.users SET disabled = true, directory_disabled = true WHERE id = v_user;
            DELETE FROM openwacht.sessions WHERE user_id = v_user;
            INSERT INTO openwacht.audit_log (tenant_id, action, details)
            VALUES (d.tenant_id, 'verzeichnis.konto_gesperrt', jsonb_build_object('konto', lower(p_email),
                'grund', CASE WHEN NOT p_active THEN 'im Verzeichnis gesperrt oder entfernt' ELSE 'keine passende Gruppe' END));
        END IF;
        RETURN v_user;
    END IF;
    UPDATE openwacht.users SET disabled = false, directory_disabled = false WHERE id = v_user AND directory_disabled;
    RETURN v_user;
END
$$;

-- Konto ist aus dem Verzeichnis verschwunden (Abgleich).
CREATE FUNCTION openwacht.directory_user_gone(p_user uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.users SET disabled = true, directory_disabled = true WHERE id = p_user AND directory_id IS NOT NULL AND NOT disabled;
    IF FOUND THEN
        DELETE FROM openwacht.sessions WHERE user_id = p_user;
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        SELECT u.tenant_id, 'verzeichnis.konto_gesperrt', jsonb_build_object('konto', u.email, 'grund', 'im Verzeichnis nicht mehr gefunden')
          FROM openwacht.users u WHERE u.id = p_user;
    END IF;
END
$$;

-- Zwei-Faktor-Pflicht für ein Konto.
CREATE FUNCTION openwacht.mfa_required_for(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE
        WHEN u.directory_id IS NOT NULL THEN coalesce((SELECT d.mfa_required FROM openwacht.directories d WHERE d.id = u.directory_id), false)
        ELSE CASE coalesce((SELECT s.mfa_policy FROM openwacht.settings s), 'admins')
            WHEN 'alle' THEN true
            WHEN 'freiwillig' THEN false
            ELSE EXISTS (SELECT 1 FROM openwacht.role_assignments r WHERE r.user_id = u.id AND r.role = 'admin')
        END
    END
      FROM openwacht.users u WHERE u.id = p_user
$$;

-- Gespeichertes Dienstkonto-Passwort (verschlüsselt) für Admins der Anbindung,
-- damit ein Ändern ohne erneute Eingabe möglich ist (nur bei gleicher Adresse,
-- gleichem Dienstkonto und gleicher CA, das prüft die Anwendung).
CREATE FUNCTION openwacht.directory_secret(p_directory uuid) RETURNS bytea
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.bind_pass_enc FROM openwacht.directories d
     WHERE d.id = p_directory AND d.tenant_id IN (SELECT openwacht.admin_tenants())
$$;

-- Zustand eines Kontos für die Anmeldung über das Verzeichnis (nach dem Abgleich).
CREATE FUNCTION openwacht.auth_state(p_user uuid) RETURNS TABLE (disabled boolean, totp_enabled boolean, locked_until timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.disabled, u.totp_enabled, u.locked_until FROM openwacht.users u WHERE u.id = p_user
$$;

-- Passwort-Hash für die Bestätigung per Passwort (nur eigenes Konto).
CREATE FUNCTION openwacht.auth_own_password() RETURNS TABLE (password_hash text, directory_id uuid, external_id text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.password_hash, u.directory_id, u.external_id FROM openwacht.users u WHERE u.id = openwacht.current_user_id() AND NOT u.disabled
$$;

-- Betreiber: 2FA nur noch, wenn die Pflicht sie verlangt (Entscheidung 22.11.2026).
CREATE OR REPLACE FUNCTION openwacht.is_platform_operator() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1 FROM openwacht.users u JOIN openwacht.tenants t ON t.id = u.tenant_id
         WHERE u.id = openwacht.current_user_id() AND u.platform_operator
           AND NOT u.disabled AND (u.totp_enabled OR NOT openwacht.mfa_required_for(u.id)) AND t.parent_id IS NULL)
$$;

-- Verzeichniskonten haben kein lokales Passwort.
CREATE OR REPLACE FUNCTION openwacht.auth_lookup(p_email text)
    RETURNS TABLE (user_id uuid, password_hash text, disabled boolean, totp_enabled boolean, locked_until timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.id, CASE WHEN u.directory_id IS NULL THEN u.password_hash END, u.disabled, u.totp_enabled, u.locked_until
      FROM openwacht.users u
     WHERE u.email = lower(btrim(p_email))
$$;

-- Rechte und Passwort von Verzeichniskonten kommen aus dem Verzeichnis: von
-- Hand (mit Benutzerkontext) nicht änderbar. Der Abgleich läuft ohne Kontext.
CREATE FUNCTION openwacht.directory_roles_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE v_user uuid;
BEGIN
    v_user := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF openwacht.current_user_id() IS NOT NULL
       AND EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = v_user AND u.directory_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Die Rechte dieses Kontos kommen aus dem Verzeichnis (Gruppen der Anbindung).' USING ERRCODE = '23514';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER role_assignments_directory BEFORE INSERT OR UPDATE OR DELETE ON openwacht.role_assignments
    FOR EACH ROW EXECUTE FUNCTION openwacht.directory_roles_guard();

CREATE FUNCTION openwacht.users_directory_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF OLD.directory_id IS NOT NULL AND NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        RAISE EXCEPTION 'Das Passwort dieses Kontos verwaltet das Verzeichnis.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER users_directory_guard BEFORE UPDATE ON openwacht.users
    FOR EACH ROW EXECUTE FUNCTION openwacht.users_directory_guard();

-- Anbindung löschen: ihre Konten werden gesperrt (sie hätten sonst weder
-- Passwort noch Verzeichnis), Sitzungen enden.
CREATE FUNCTION openwacht.directories_before_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.users SET disabled = true WHERE directory_id = OLD.id;
    DELETE FROM openwacht.sessions WHERE user_id IN (SELECT id FROM openwacht.users WHERE directory_id = OLD.id);
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (OLD.tenant_id, 'verzeichnis.geloescht', jsonb_build_object('name', OLD.name));
    RETURN OLD;
END
$$;
CREATE TRIGGER directories_before_delete BEFORE DELETE ON openwacht.directories
    FOR EACH ROW EXECUTE FUNCTION openwacht.directories_before_delete();

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['directory_for_login(text, text)', 'directory_sync_list()', 'directory_group_map(uuid)',
        'directory_users(uuid)', 'directory_user_sync(uuid, text, text, text, text[], boolean)', 'directory_user_gone(uuid)',
        'mfa_required_for(uuid)', 'auth_own_password()', 'auth_state(uuid)', 'directory_secret(uuid)', 'directory_domain_list(uuid)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;
