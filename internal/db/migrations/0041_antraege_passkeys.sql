-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 36: Recht, Nachweise, Abschluss.
--
-- 1. Anträge auf neue Untermandanten (Konzept, Entscheidung 18.11.2026): Der Admin
--    eines Untermandanten beantragt einen neuen Mandanten in seinem Teilbaum.
--    Angelegt wird er erst, wenn ein Admin des Hauptmandanten freigibt.
--    Antrag, Freigabe und Ablehnung stehen im Audit-Log.
-- 2. Passkeys (WebAuthn) als zweiter Faktor neben TOTP (Entscheidung
--    Entscheidung 22.11.2026: bauen). Nur für Konten mit eingerichteter App: TOTP
--    bleibt Rückfallweg und Bestätigung für heikle Änderungen. Gespeichert
--    werden nur öffentliche Schlüssel; Challenges gelten 5 Minuten und nur einmal.
-- 3. Letzte Anmeldung je Konto für die Rezertifizierung („wer hat welche
--    Rolle, letzte Anmeldung“). Nur der Zeitpunkt, keine Adresse (Leitprinzip 5).

-- --- 1. Anträge auf Untermandanten ---------------------------------------------------

CREATE TABLE openwacht.tenant_requests (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Elternknoten des neuen Mandanten; Admins dieses Knotens beantragen.
    tenant_id    uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]' AND btrim(name) = name),
    reason       text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500 AND reason !~ '[[:cntrl:]]'),
    state        text NOT NULL DEFAULT 'beantragt' CHECK (state IN ('beantragt', 'freigegeben', 'abgelehnt')),
    requested_by uuid REFERENCES openwacht.users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_by   uuid REFERENCES openwacht.users (id) ON DELETE SET NULL,
    decided_at   timestamptz,
    note         text NOT NULL DEFAULT '' CHECK (char_length(note) <= 500 AND note !~ '[[:cntrl:]]'),
    new_tenant   uuid REFERENCES openwacht.tenants (id) ON DELETE SET NULL,
    CHECK ((state = 'beantragt') = (decided_at IS NULL))
);
CREATE INDEX tenant_requests_tenant ON openwacht.tenant_requests (tenant_id);
-- Je Elternknoten höchstens ein offener Antrag mit gleichem Namen.
CREATE UNIQUE INDEX tenant_requests_open_name ON openwacht.tenant_requests (tenant_id, lower(name)) WHERE state = 'beantragt';

ALTER TABLE openwacht.tenant_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.tenant_requests FROM PUBLIC;
GRANT SELECT, INSERT (tenant_id, name, reason) ON openwacht.tenant_requests TO openwacht_app;
GRANT UPDATE (state, note, new_tenant) ON openwacht.tenant_requests TO openwacht_app;
-- Sehen: Admins des Elternknotens und darüber (Geschwister und Kinder nicht).
CREATE POLICY tenant_requests_select ON openwacht.tenant_requests FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
-- Beantragen: Admin des Elternknotens. Der Hauptmandant legt direkt an.
CREATE POLICY tenant_requests_insert ON openwacht.tenant_requests FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()) AND NOT openwacht.is_root_admin());
-- Entscheiden: nur Admins des Hauptmandanten, nur offene Anträge.
CREATE POLICY tenant_requests_update ON openwacht.tenant_requests FOR UPDATE TO openwacht_app
    USING (state = 'beantragt' AND openwacht.is_root_admin())
    WITH CHECK (openwacht.is_root_admin());

CREATE FUNCTION openwacht.tenant_requests_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.requested_by := openwacht.current_user_id();
        NEW.state := 'beantragt';
        NEW.created_at := now();
        NEW.decided_by := NULL;
        NEW.decided_at := NULL;
        NEW.new_tenant := NULL;
        IF NEW.requested_by IS NULL THEN
            RAISE EXCEPTION 'Antrag nur mit Benutzer' USING ERRCODE = '42501';
        END IF;
        -- Schutz gegen Fluten: höchstens 20 offene Anträge je Elternknoten.
        IF (SELECT count(*) FROM openwacht.tenant_requests r
             WHERE r.tenant_id = NEW.tenant_id AND r.state = 'beantragt') >= 20 THEN
            RAISE EXCEPTION 'zu viele offene Anträge' USING ERRCODE = '54000';
        END IF;
        RETURN NEW;
    END IF;
    -- UPDATE: nur eine Entscheidung, nichts anderes ändern.
    IF OLD.state <> 'beantragt' OR NEW.state NOT IN ('freigegeben', 'abgelehnt') THEN
        RAISE EXCEPTION 'Antrag ist schon entschieden' USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.reason IS DISTINCT FROM OLD.reason OR NEW.requested_by IS DISTINCT FROM OLD.requested_by THEN
        RAISE EXCEPTION 'Antrag ist unveränderlich' USING ERRCODE = '42501';
    END IF;
    NEW.decided_by := openwacht.current_user_id();
    NEW.decided_at := now();
    IF NEW.state = 'freigegeben' THEN
        -- Der neue Mandant muss mit dem beantragten übereinstimmen.
        IF NOT EXISTS (SELECT 1 FROM openwacht.tenants t
                        WHERE t.id = NEW.new_tenant AND t.parent_id = OLD.tenant_id AND lower(t.name) = lower(OLD.name)) THEN
            RAISE EXCEPTION 'freigegeben ohne passenden Mandanten' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.new_tenant IS NOT NULL THEN
        RAISE EXCEPTION 'abgelehnt mit Mandant' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER tenant_requests_guard BEFORE INSERT OR UPDATE ON openwacht.tenant_requests
    FOR EACH ROW EXECUTE FUNCTION openwacht.tenant_requests_guard();

-- Namen der Antragsteller und Entscheider für die Liste. Wer den Antrag
-- sieht (RLS), sieht die beiden Namen, auch wenn das Konto in einem anderen
-- Teilbaum liegt (der Hauptmandant entscheidet über Anträge aus allen Ästen).
CREATE FUNCTION openwacht.tenant_request_people(p_request uuid)
    RETURNS TABLE (requested text, decided text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce(ru.display_name, ''), coalesce(du.display_name, '')
      FROM openwacht.tenant_requests r
      LEFT JOIN openwacht.users ru ON ru.id = r.requested_by
      LEFT JOIN openwacht.users du ON du.id = r.decided_by
     WHERE r.id = p_request AND r.tenant_id IN (SELECT openwacht.admin_tenants())
$$;
REVOKE ALL ON FUNCTION openwacht.tenant_request_people(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.tenant_request_people(uuid) TO openwacht_app;

-- --- 2. Passkeys (WebAuthn) -----------------------------------------------------------

CREATE TABLE openwacht.webauthn_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    -- COSE-Schlüssel, wie ihn der Authenticator geliefert hat (öffentlich).
    public_key    bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 2048),
    alg           integer NOT NULL CHECK (alg IN (-7, -8, -257)),
    sign_count    bigint NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name !~ '[[:cntrl:]]'),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX webauthn_credentials_user ON openwacht.webauthn_credentials (user_id);
ALTER TABLE openwacht.webauthn_credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.webauthn_credentials FROM PUBLIC;
-- Die App sieht nur die eigenen Passkeys (ohne Schlüssel) und darf sie löschen.
GRANT SELECT (id, user_id, name, alg, created_at, last_used_at), DELETE ON openwacht.webauthn_credentials TO openwacht_app;
CREATE POLICY webauthn_credentials_select ON openwacht.webauthn_credentials FOR SELECT TO openwacht_app
    USING (user_id = openwacht.current_user_id());
CREATE POLICY webauthn_credentials_delete ON openwacht.webauthn_credentials FOR DELETE TO openwacht_app
    USING (user_id = openwacht.current_user_id());

-- Challenges: je Konto und Zweck höchstens eine offene.
CREATE TABLE openwacht.webauthn_challenges (
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    purpose    text NOT NULL CHECK (purpose IN ('registrieren', 'anmelden')),
    challenge  bytea NOT NULL CHECK (octet_length(challenge) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, purpose)
);
ALTER TABLE openwacht.webauthn_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.webauthn_challenges FROM PUBLIC, openwacht_app;

-- Ohne eingerichtete App keine Passkeys; wird die App zurückgesetzt
-- (zweifaktor-zuruecksetzen), verfallen auch die Passkeys.
CREATE FUNCTION openwacht.webauthn_totp_off() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.webauthn_credentials WHERE user_id = NEW.id;
    DELETE FROM openwacht.webauthn_challenges WHERE user_id = NEW.id;
    RETURN NEW;
END
$$;
CREATE TRIGGER users_webauthn_totp_off AFTER UPDATE OF totp_enabled ON openwacht.users
    FOR EACH ROW WHEN (OLD.totp_enabled AND NOT NEW.totp_enabled)
    EXECUTE FUNCTION openwacht.webauthn_totp_off();

-- Registrierung: Challenge für das eigene Konto anlegen.
CREATE FUNCTION openwacht.webauthn_register_begin(p_user uuid, p_challenge bytea)
    RETURNS TABLE (credential_id bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    IF NOT EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = p_user AND u.totp_enabled AND NOT u.disabled) THEN
        RAISE EXCEPTION 'Zwei-Faktor ist nicht eingerichtet' USING ERRCODE = '55000';
    END IF;
    INSERT INTO openwacht.webauthn_challenges (user_id, purpose, challenge, expires_at)
    VALUES (p_user, 'registrieren', p_challenge, now() + interval '5 minutes')
    ON CONFLICT (user_id, purpose) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at;
    -- vorhandene Passkeys, damit derselbe Authenticator nicht doppelt registriert
    RETURN QUERY SELECT c.credential_id FROM openwacht.webauthn_credentials c WHERE c.user_id = p_user ORDER BY c.created_at;
END
$$;

-- Registrierung abschließen: Challenge verbrauchen (nur einmal, nur gültig)
-- und den Passkey speichern. Höchstens zehn je Konto.
CREATE FUNCTION openwacht.webauthn_register_finish(p_user uuid, p_challenge bytea, p_credential bytea,
                                                  p_key bytea, p_alg integer, p_count bigint, p_name text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_id uuid;
BEGIN
    PERFORM openwacht.require_self(p_user);
    DELETE FROM openwacht.webauthn_challenges
     WHERE user_id = p_user AND purpose = 'registrieren' AND challenge = p_challenge AND expires_at > now();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Challenge ungültig oder abgelaufen' USING ERRCODE = '28000';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = p_user AND u.totp_enabled AND NOT u.disabled) THEN
        RAISE EXCEPTION 'Zwei-Faktor ist nicht eingerichtet' USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(*) FROM openwacht.webauthn_credentials c WHERE c.user_id = p_user) >= 10 THEN
        RAISE EXCEPTION 'höchstens zehn Passkeys' USING ERRCODE = '54000';
    END IF;
    INSERT INTO openwacht.webauthn_credentials (user_id, credential_id, public_key, alg, sign_count, name)
    VALUES (p_user, p_credential, p_key, p_alg, p_count, p_name) RETURNING id INTO v_id;
    RETURN v_id;
END
$$;

-- Anmeldung (zweiter Schritt): gebunden an die halbe Sitzung nach dem
-- Passwort, nicht an einen Benutzerkontext.
CREATE FUNCTION openwacht.webauthn_pending_user(p_session bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.user_id FROM openwacht.sessions s JOIN openwacht.users u ON u.id = s.user_id
     WHERE s.token_hash = p_session AND s.kind = 'zweiter_faktor' AND s.expires_at > now()
       AND NOT u.disabled AND u.totp_enabled
$$;
REVOKE ALL ON FUNCTION openwacht.webauthn_pending_user(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.webauthn_pending_user(bytea) TO openwacht_app;

CREATE FUNCTION openwacht.webauthn_login_begin(p_session bytea, p_challenge bytea)
    RETURNS TABLE (credential_id bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user uuid := openwacht.webauthn_pending_user(p_session);
BEGIN
    IF v_user IS NULL THEN
        RAISE EXCEPTION 'keine offene Anmeldung' USING ERRCODE = '28000';
    END IF;
    INSERT INTO openwacht.webauthn_challenges (user_id, purpose, challenge, expires_at)
    VALUES (v_user, 'anmelden', p_challenge, now() + interval '5 minutes')
    ON CONFLICT (user_id, purpose) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at;
    RETURN QUERY SELECT c.credential_id FROM openwacht.webauthn_credentials c WHERE c.user_id = v_user ORDER BY c.created_at;
END
$$;

-- Challenge verbrauchen (auch wenn die Signatur danach nicht stimmt) und
-- den öffentlichen Schlüssel des genannten Passkeys des Kontos liefern.
CREATE FUNCTION openwacht.webauthn_login_take(p_session bytea, p_challenge bytea, p_credential bytea)
    RETURNS TABLE (user_id uuid, id uuid, public_key bytea, alg integer, sign_count bigint)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user uuid := openwacht.webauthn_pending_user(p_session);
BEGIN
    IF v_user IS NULL THEN
        RETURN;
    END IF;
    DELETE FROM openwacht.webauthn_challenges ch
     WHERE ch.user_id = v_user AND ch.purpose = 'anmelden' AND ch.challenge = p_challenge AND ch.expires_at > now();
    IF NOT FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY SELECT c.user_id, c.id, c.public_key, c.alg, c.sign_count
      FROM openwacht.webauthn_credentials c WHERE c.user_id = v_user AND c.credential_id = p_credential;
END
$$;

-- Zähler nach erfolgreicher Prüfung fortschreiben. Ein Zähler, der nicht
-- steigt (obwohl einer geführt wird), deutet auf einen geklonten Schlüssel.
CREATE FUNCTION openwacht.webauthn_login_used(p_session bytea, p_id uuid, p_count bigint) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user uuid := openwacht.webauthn_pending_user(p_session);
BEGIN
    UPDATE openwacht.webauthn_credentials c
       SET sign_count = p_count, last_used_at = now()
     WHERE c.id = p_id AND c.user_id = v_user
       AND ((p_count = 0 AND c.sign_count = 0) OR p_count > c.sign_count);
    RETURN FOUND;
END
$$;

-- Hat das Konto der halben Sitzung Passkeys? (Anmeldeseite bietet sie an.)
CREATE FUNCTION openwacht.webauthn_pending_has(p_session bytea) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (SELECT 1 FROM openwacht.webauthn_credentials c WHERE c.user_id = openwacht.webauthn_pending_user(p_session))
$$;

REVOKE ALL ON FUNCTION openwacht.webauthn_register_begin(uuid, bytea),
    openwacht.webauthn_register_finish(uuid, bytea, bytea, bytea, integer, bigint, text),
    openwacht.webauthn_login_begin(bytea, bytea), openwacht.webauthn_login_take(bytea, bytea, bytea),
    openwacht.webauthn_login_used(bytea, uuid, bigint), openwacht.webauthn_pending_has(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.webauthn_register_begin(uuid, bytea),
    openwacht.webauthn_register_finish(uuid, bytea, bytea, bytea, integer, bigint, text),
    openwacht.webauthn_login_begin(bytea, bytea), openwacht.webauthn_login_take(bytea, bytea, bytea),
    openwacht.webauthn_login_used(bytea, uuid, bigint), openwacht.webauthn_pending_has(bytea) TO openwacht_app;

-- Neue Anmeldeaktionen für das Audit-Log (Liste wie 0037 plus Passkeys).
CREATE OR REPLACE FUNCTION openwacht.audit_auth(p_user uuid, p_action text, p_details jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_action NOT IN ('anmeldung.erfolg', 'anmeldung.fehlgeschlagen', 'anmeldung.gesperrt',
                        'abmeldung', 'zweifaktor.eingerichtet', 'passwort.geaendert',
                        'bestaetigung.fehlgeschlagen', 'zweifaktor.code_verwendet',
                        'zweifaktor.codes_erzeugt', 'anmeldung.passkey', 'passkey.angelegt',
                        'passkey.abgelehnt', 'passkey.geloescht') THEN
        RAISE EXCEPTION 'unbekannte Anmeldeaktion %', p_action;
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    SELECT u.tenant_id, p_action, coalesce(p_details, '{}'::jsonb)
      FROM openwacht.users u WHERE u.id = p_user;
END
$$;

-- --- 3. Letzte Anmeldung und Rezertifizierung -----------------------------------------

ALTER TABLE openwacht.users ADD COLUMN last_login_at timestamptz;

CREATE FUNCTION openwacht.sessions_last_login() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.users SET last_login_at = now() WHERE id = NEW.user_id;
    RETURN NULL;
END
$$;
CREATE TRIGGER sessions_last_login AFTER INSERT ON openwacht.sessions
    FOR EACH ROW WHEN (NEW.kind = 'voll') EXECUTE FUNCTION openwacht.sessions_last_login();

-- Bericht für einen Mandanten (nur dessen Admins): je Rolle im Teilbaum eine
-- Zeile, dazu Konten des Teilbaums ohne Rolle. Pfade beginnen beim Mandanten
-- des Berichts, damit niemand Namen über seinem Knoten erfährt.
CREATE FUNCTION openwacht.recert_report(p_tenant uuid)
    RETURNS TABLE (email text, display_name text, source text, home text, disabled boolean, totp boolean,
                   passkeys integer, last_login timestamptz, role_tenant text, role text, role_since timestamptz,
                   token_expires timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_tenant IS NULL OR p_tenant NOT IN (SELECT openwacht.admin_tenants()) THEN
        RAISE EXCEPTION 'nur für Admins des Mandanten' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    WITH sub AS (
        SELECT c.descendant AS id FROM openwacht.tenant_closure c WHERE c.ancestor = p_tenant
    ), path AS (
        SELECT s.id, string_agg(t.name, ' / ' ORDER BY c.depth DESC) AS p
          FROM sub s
          JOIN openwacht.tenant_closure c ON c.descendant = s.id
          JOIN openwacht.tenants t ON t.id = c.ancestor
         WHERE c.ancestor IN (SELECT id FROM sub)
         GROUP BY s.id
    ), rows AS (
        SELECT u.id AS uid, r.tenant_id AS rt, r.role, r.created_at
          FROM openwacht.role_assignments r JOIN openwacht.users u ON u.id = r.user_id
         WHERE r.tenant_id IN (SELECT id FROM sub)
        UNION ALL
        SELECT u.id, NULL, NULL, NULL FROM openwacht.users u
         WHERE u.tenant_id IN (SELECT id FROM sub)
           AND NOT EXISTS (SELECT 1 FROM openwacht.role_assignments r
                            WHERE r.user_id = u.id AND r.tenant_id IN (SELECT id FROM sub))
    )
    SELECT u.email, u.display_name, u.auth_source,
           coalesce(hp.p, '(außerhalb)'), u.disabled, u.totp_enabled,
           (SELECT count(*)::integer FROM openwacht.webauthn_credentials w WHERE w.user_id = u.id),
           u.last_login_at, coalesce(rp.p, ''), coalesce(x.role, ''), x.created_at,
           (SELECT a.expires_at FROM openwacht.api_tokens a WHERE a.user_id = u.id AND a.revoked_at IS NULL)
      FROM rows x
      JOIN openwacht.users u ON u.id = x.uid
      LEFT JOIN path hp ON hp.id = u.tenant_id
      LEFT JOIN path rp ON rp.id = x.rt
     ORDER BY rp.p NULLS LAST, u.email;
END
$$;
REVOKE ALL ON FUNCTION openwacht.recert_report(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.recert_report(uuid) TO openwacht_app;
