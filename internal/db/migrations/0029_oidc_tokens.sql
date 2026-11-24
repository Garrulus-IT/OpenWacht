-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 22b: Anmeldung über OIDC (Keycloak, ADFS, Entra ID) und API-Tokens.
--
-- OIDC-Anbindungen sind Verzeichnisse der Art 'oidc': gleiche Domänen,
-- Gruppenzuordnung, Kontenlogik und RLS wie LDAP (22a). url ist der Issuer,
-- bind_dn die Client-ID, bind_pass_enc das Client-Secret, base_dn der Name
-- des Gruppen-Claims. Ein Abgleich ohne Anmeldung ist bei OIDC nicht möglich.
--
-- API-Tokens (22.11.2026): je Mandant, Rolle Leser oder
-- Operator, Ablauf höchstens ein Jahr, nur der Hash wird gespeichert. Jedes
-- Token hat ein technisches Konto ohne Passwort; so gelten RLS und Rollen
-- unverändert.

ALTER TABLE openwacht.directories
    ADD COLUMN kind text NOT NULL DEFAULT 'ldap' CHECK (kind IN ('ldap', 'oidc'));
ALTER TABLE openwacht.directories DROP CONSTRAINT directories_url_check;
ALTER TABLE openwacht.directories ADD CONSTRAINT directories_url_check CHECK (
    (kind = 'ldap' AND url ~ '^ldaps?://[A-Za-z0-9.:\[\]-]{1,253}(:[0-9]{1,5})?$')
 OR (kind = 'oidc' AND url ~ '^https://[A-Za-z0-9.:\[\]-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~%!$&''()*+,;=:@/-]*)?$' AND char_length(url) <= 760));
ALTER TABLE openwacht.directories ADD CONSTRAINT directories_oidc_check CHECK (
    kind = 'ldap' OR (netbios IS NULL AND NOT nested_groups));
ALTER TABLE openwacht.directory_groups DROP CONSTRAINT directory_groups_group_dn_check;
ALTER TABLE openwacht.directory_groups ADD CONSTRAINT directory_groups_group_dn_check
    CHECK (char_length(group_dn) BETWEEN 1 AND 1000 AND group_dn !~ '[[:cntrl:]]');
GRANT SELECT (kind) ON openwacht.directories TO openwacht_app;

-- Login: Art der Anbindung mitliefern (OIDC leitet weiter statt Passwort).
DROP FUNCTION openwacht.directory_for_login(text, text);
CREATE FUNCTION openwacht.directory_for_login(p_domain text, p_netbios text)
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean, kind text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups, d.kind
      FROM openwacht.directories d
     WHERE d.enabled
       AND ((p_domain IS NOT NULL AND d.id = (SELECT dd.directory_id FROM openwacht.directory_domains dd WHERE dd.domain = lower(p_domain)))
         OR (p_netbios IS NOT NULL AND upper(d.netbios) = upper(p_netbios)))
     LIMIT 1
$$;

-- OIDC-Anbindung für die Rückkehr vom Identity Provider.
CREATE FUNCTION openwacht.directory_oidc(p_directory uuid)
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups
      FROM openwacht.directories d WHERE d.id = p_directory AND d.enabled AND d.kind = 'oidc'
$$;

-- Abgleich nur für LDAP.
CREATE OR REPLACE FUNCTION openwacht.directory_sync_list()
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups
      FROM openwacht.directories d WHERE d.enabled AND d.kind = 'ldap'
$$;

-- Konten bekommen die Art der Anbindung als Quelle.
CREATE OR REPLACE FUNCTION openwacht.directory_user_sync(p_directory uuid, p_external text, p_email text, p_name text,
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
        -- Konto einer gelöschten Anbindung desselben Mandanten übernehmen (nur
        -- Verzeichniskonten ohne Passwort, nie lokale Konten).
        UPDATE openwacht.users SET directory_id = p_directory, external_id = p_external, auth_source = d.kind
         WHERE email = lower(p_email) AND directory_id IS NULL AND auth_source IN ('ldap', 'oidc')
           AND password_hash IS NULL AND tenant_id = d.tenant_id
        RETURNING id, disabled INTO v_user, v_disabled;
    END IF;
    IF v_user IS NULL THEN
        IF EXISTS (SELECT 1 FROM openwacht.users WHERE email = lower(p_email)) THEN
            RAISE EXCEPTION 'Es gibt schon ein Konto mit dieser Adresse.' USING ERRCODE = '23505';
        END IF;
        INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash, directory_id, external_id, auth_source, synced_at)
        VALUES (d.tenant_id, lower(p_email), left(btrim(p_name), 100), NULL, p_directory, p_external, d.kind, now())
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

-- --- API-Tokens ------------------------------------------------------------------

ALTER TABLE openwacht.users DROP CONSTRAINT users_auth_source_check;
ALTER TABLE openwacht.users ADD CONSTRAINT users_auth_source_check CHECK (auth_source IN ('lokal', 'ldap', 'oidc', 'token'));
ALTER TABLE openwacht.users ADD CONSTRAINT users_token_check CHECK (auth_source <> 'token' OR (password_hash IS NULL AND directory_id IS NULL));

CREATE TABLE openwacht.api_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    user_id       uuid NOT NULL UNIQUE REFERENCES openwacht.users (id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    role          text NOT NULL CHECK (role IN ('leser', 'operator')),
    token_hash    bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at    timestamptz NOT NULL,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    CHECK (expires_at <= created_at + interval '366 days')
);
CREATE INDEX api_tokens_tenant ON openwacht.api_tokens (tenant_id);
ALTER TABLE openwacht.api_tokens ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, user_id, name, role, expires_at, created_by, created_at, last_used_at, revoked_at)
    ON openwacht.api_tokens TO openwacht_app;
CREATE POLICY api_tokens_select ON openwacht.api_tokens FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Anlegen nur durch Admins des Mandanten (Prüfung hier, die Funktion läuft
-- als Eigentümer). Liefert die ID des Tokens.
CREATE FUNCTION openwacht.api_token_create(p_tenant uuid, p_name text, p_role text, p_hash bytea, p_expires timestamptz)
    RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_actor uuid := openwacht.current_user_id();
    v_id uuid := gen_random_uuid();
    v_user uuid;
BEGIN
    IF v_actor IS NULL OR p_tenant NOT IN (SELECT openwacht.admin_tenants()) THEN
        RAISE EXCEPTION 'Nur Admins des Mandanten legen API-Tokens an.' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM openwacht.users WHERE id = v_actor AND auth_source = 'token') THEN
        RAISE EXCEPTION 'Ein API-Token legt keine Tokens an.' USING ERRCODE = '42501';
    END IF;
    IF p_role NOT IN ('leser', 'operator') THEN
        RAISE EXCEPTION 'Rolle: Leser oder Operator.' USING ERRCODE = '23514';
    END IF;
    IF p_expires <= now() OR p_expires > now() + interval '366 days' THEN
        RAISE EXCEPTION 'Ablauf: höchstens ein Jahr.' USING ERRCODE = '23514';
    END IF;
    IF (SELECT count(*) FROM openwacht.api_tokens WHERE tenant_id = p_tenant AND revoked_at IS NULL AND expires_at > now()) >= 50 THEN
        RAISE EXCEPTION 'Höchstens 50 gültige API-Tokens je Mandant.' USING ERRCODE = '23514';
    END IF;
    INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash, auth_source)
    VALUES (p_tenant, 'token-' || v_id || '@api-token.invalid', left('API-Token ' || btrim(p_name), 100), NULL, 'token')
    RETURNING id INTO v_user;
    PERFORM set_config('openwacht.token_role', 'an', true);
    INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES (v_user, p_tenant, p_role);
    PERFORM set_config('openwacht.token_role', '', true);
    INSERT INTO openwacht.api_tokens (id, tenant_id, user_id, name, role, token_hash, expires_at, created_by)
    VALUES (v_id, p_tenant, v_user, btrim(p_name), p_role, p_hash, p_expires, v_actor);
    INSERT INTO openwacht.audit_log (tenant_id, actor_user_id, action, details)
    VALUES (p_tenant, v_actor, 'api_token.angelegt', jsonb_build_object('name', btrim(p_name), 'rolle', p_role, 'ablauf', p_expires));
    RETURN v_id;
END
$$;

-- Widerrufen: Konto sperren, Sitzungen gibt es keine.
CREATE FUNCTION openwacht.api_token_revoke(p_id uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE t openwacht.api_tokens;
BEGIN
    SELECT * INTO t FROM openwacht.api_tokens WHERE id = p_id AND tenant_id IN (SELECT openwacht.admin_tenants()) AND revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE openwacht.api_tokens SET revoked_at = now() WHERE id = p_id;
    UPDATE openwacht.users SET disabled = true WHERE id = t.user_id;
    INSERT INTO openwacht.audit_log (tenant_id, actor_user_id, action, details)
    VALUES (t.tenant_id, openwacht.current_user_id(), 'api_token.widerrufen', jsonb_build_object('name', t.name));
    RETURN true;
END
$$;

-- Prüfung eines Tokens (ohne Benutzerkontext): Konto-ID oder NULL.
CREATE FUNCTION openwacht.api_token_auth(p_hash bytea) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE t openwacht.api_tokens;
BEGIN
    SELECT a.* INTO t FROM openwacht.api_tokens a JOIN openwacht.users u ON u.id = a.user_id
     WHERE a.token_hash = p_hash AND a.revoked_at IS NULL AND a.expires_at > now() AND NOT u.disabled;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF t.last_used_at IS NULL OR t.last_used_at < now() - interval '1 minute' THEN
        UPDATE openwacht.api_tokens SET last_used_at = now() WHERE id = t.id;
    END IF;
    RETURN t.user_id;
END
$$;

-- Rechte von Token-Konten: nur beim Anlegen, nie Admin. Passwort nie.
CREATE OR REPLACE FUNCTION openwacht.directory_roles_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE v_user uuid;
BEGIN
    v_user := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = v_user AND u.auth_source = 'token') THEN
        IF TG_OP <> 'DELETE' AND NEW.role NOT IN ('leser', 'operator') THEN
            RAISE EXCEPTION 'API-Tokens haben höchstens die Rolle Operator.' USING ERRCODE = '23514';
        END IF;
        IF openwacht.current_user_id() IS NOT NULL AND coalesce(current_setting('openwacht.token_role', true), '') <> 'an' THEN
            RAISE EXCEPTION 'Die Rolle eines API-Tokens steht beim Anlegen fest.' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF openwacht.current_user_id() IS NOT NULL
       AND EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = v_user AND u.directory_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Die Rechte dieses Kontos kommen aus dem Verzeichnis (Gruppen der Anbindung).' USING ERRCODE = '23514';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

-- 2FA nie für Token-Konten (sie melden sich nicht an).
CREATE OR REPLACE FUNCTION openwacht.mfa_required_for(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE
        WHEN u.auth_source = 'token' THEN false
        WHEN u.directory_id IS NOT NULL THEN coalesce((SELECT d.mfa_required FROM openwacht.directories d WHERE d.id = u.directory_id), false)
        ELSE CASE coalesce((SELECT s.mfa_policy FROM openwacht.settings s), 'admins')
            WHEN 'alle' THEN true
            WHEN 'freiwillig' THEN false
            ELSE EXISTS (SELECT 1 FROM openwacht.role_assignments r WHERE r.user_id = u.id AND r.role = 'admin')
        END
    END
      FROM openwacht.users u WHERE u.id = p_user
$$;

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['directory_for_login(text, text)', 'directory_oidc(uuid)',
        'api_token_create(uuid, text, text, bytea, timestamptz)', 'api_token_revoke(uuid)', 'api_token_auth(bytea)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;

-- Löschen einer Anbindung: Konten als „vom Verzeichnis gesperrt“ markieren,
-- damit eine neue Anbindung sie übernehmen und wieder freigeben kann. Von
-- Hand gesperrte bleiben gesperrt.
CREATE OR REPLACE FUNCTION openwacht.directories_before_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.users SET disabled = true, directory_disabled = true WHERE directory_id = OLD.id AND NOT disabled;
    DELETE FROM openwacht.sessions WHERE user_id IN (SELECT id FROM openwacht.users WHERE directory_id = OLD.id);
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (OLD.tenant_id, 'verzeichnis.geloescht', jsonb_build_object('name', OLD.name));
    RETURN OLD;
END
$$;
