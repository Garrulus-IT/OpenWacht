-- SPDX-License-Identifier: AGPL-3.0-only

-- 0002: Anmeldung, Sitzungen, Kontosperre und Zwei-Faktor (TOTP).
--
-- Grundsatz: Die Anwendung bekommt auf Sitzungen und Anmeldedaten keinen
-- direkten Tabellenzugriff, sondern nur eng geschnittene SECURITY-DEFINER-
-- Funktionen. Sitzungstoken liegen nur als SHA-256-Hash in der Datenbank;
-- wer die Datenbank liest, kann damit keine Sitzung übernehmen.

ALTER TABLE openwacht.users
    -- TOTP-Geheimnis, mit AES-256-GCM verschlüsselt. Der Schlüssel liegt NICHT
    -- in der Datenbank, sondern in einer Datei der Zentrale.
    ADD COLUMN totp_secret_enc bytea,
    ADD COLUMN totp_enabled    boolean NOT NULL DEFAULT false,
    -- Zuletzt verwendeter TOTP-Zeitschritt: jeder Code gilt nur einmal.
    ADD COLUMN totp_last_step  bigint NOT NULL DEFAULT 0,
    ADD COLUMN failed_logins   integer NOT NULL DEFAULT 0,
    ADD COLUMN locked_until    timestamptz;

-- Ob 2FA aktiv ist, dürfen Admins in Benutzerlisten sehen; das Geheimnis nicht.
GRANT SELECT (totp_enabled) ON openwacht.users TO openwacht_app;

CREATE TABLE openwacht.sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    -- 'voll': angemeldet. 'zweiter_faktor': Passwort stimmt, TOTP-Code fehlt noch.
    kind       text NOT NULL CHECK (kind IN ('voll', 'zweiter_faktor')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    idle       interval NOT NULL CHECK (idle > interval '0'),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user ON openwacht.sessions (user_id);
-- Kein Zugriff für die Anwendung; RLS zusätzlich als Absicherung.
ALTER TABLE openwacht.sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.sessions FROM PUBLIC, openwacht_app;

-- ---------------------------------------------------------------------------
-- Anmeldung (ohne Benutzerkontext aufrufbar)
-- ---------------------------------------------------------------------------

-- Daten für die Passwortprüfung. Liefert keine Zeile, wenn die E-Mail unbekannt ist.
CREATE FUNCTION openwacht.auth_lookup(p_email text)
    RETURNS TABLE (user_id uuid, password_hash text, disabled boolean,
                   totp_enabled boolean, locked_until timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.id, u.password_hash, u.disabled, u.totp_enabled, u.locked_until
      FROM openwacht.users u
     WHERE u.email = lower(btrim(p_email))
$$;

-- Fehlversuch zählen. Ab dem 5. Fehlversuch wird das Konto gesperrt:
-- 1, 2, 4, 8 ... Minuten, höchstens 60 Minuten.
CREATE FUNCTION openwacht.auth_login_failed(p_user uuid) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.users
       SET failed_logins = failed_logins + 1,
           locked_until = CASE
               WHEN failed_logins + 1 >= 5 THEN
                   now() + least(interval '60 minutes',
                                 interval '1 minute' * power(2, least(failed_logins + 1 - 5, 10)))
               ELSE locked_until END
     WHERE id = p_user
$$;

CREATE FUNCTION openwacht.auth_login_succeeded(p_user uuid) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL WHERE id = p_user
$$;

-- Anmeldeereignisse ins Audit-Log, dem Heimatmandanten des Kontos zugeordnet.
-- Die handelnde Person setzt der Audit-Trigger aus dem Kontext (bei einem
-- Fehlversuch also niemand). Nur fest definierte Aktionen.
CREATE FUNCTION openwacht.audit_auth(p_user uuid, p_action text, p_details jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_action NOT IN ('anmeldung.erfolg', 'anmeldung.fehlgeschlagen', 'anmeldung.gesperrt',
                        'abmeldung', 'zweifaktor.eingerichtet', 'passwort.geaendert') THEN
        RAISE EXCEPTION 'unbekannte Anmeldeaktion %', p_action;
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    SELECT u.tenant_id, p_action, coalesce(p_details, '{}'::jsonb)
      FROM openwacht.users u WHERE u.id = p_user;
END
$$;

-- ---------------------------------------------------------------------------
-- Sitzungen
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.session_create(p_user uuid, p_token_hash bytea, p_kind text,
                                        p_idle interval, p_lifetime interval) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    -- Abgelaufene Sitzungen bei Gelegenheit aufräumen.
    DELETE FROM openwacht.sessions
     WHERE expires_at < now() OR last_seen + idle < now();
    INSERT INTO openwacht.sessions (token_hash, user_id, kind, idle, expires_at)
    VALUES (p_token_hash, p_user, p_kind, p_idle, now() + p_lifetime);
$$;

-- Gültige Sitzung zum Token-Hash; verlängert die Leerlaufzeit. Gesperrte oder
-- deaktivierte Konten haben keine gültigen Sitzungen.
CREATE FUNCTION openwacht.session_get(p_token_hash bytea)
    RETURNS TABLE (user_id uuid, kind text, totp_enabled boolean, locked_until timestamptz)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.sessions s
       SET last_seen = now()
      FROM openwacht.users u
     WHERE s.token_hash = p_token_hash
       AND u.id = s.user_id
       AND NOT u.disabled
       AND s.expires_at > now()
       AND s.last_seen + s.idle > now()
    RETURNING s.user_id, s.kind, u.totp_enabled, u.locked_until
$$;

CREATE FUNCTION openwacht.session_delete(p_token_hash bytea) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    DELETE FROM openwacht.sessions WHERE token_hash = p_token_hash
$$;

-- Alle Sitzungen eines Benutzers beenden: nur er selbst oder ein Admin seines Mandanten.
CREATE FUNCTION openwacht.session_delete_user(p_user uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_user IS DISTINCT FROM openwacht.current_user_id()
       AND NOT EXISTS (SELECT 1 FROM openwacht.users u
                        WHERE u.id = p_user AND u.tenant_id IN (SELECT openwacht.admin_tenants())) THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    DELETE FROM openwacht.sessions WHERE user_id = p_user;
END
$$;

-- ---------------------------------------------------------------------------
-- Passwort und TOTP (nur im Kontext des betroffenen Benutzers)
-- ---------------------------------------------------------------------------

-- Passwort-Hash setzen: der Benutzer selbst oder ein Admin seines Mandanten.
CREATE FUNCTION openwacht.auth_set_password(p_user uuid, p_hash text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_hash IS NULL OR p_hash !~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$' THEN
        RAISE EXCEPTION 'ungültiges Passwort-Hash-Format';
    END IF;
    IF p_user IS DISTINCT FROM openwacht.current_user_id()
       AND NOT EXISTS (SELECT 1 FROM openwacht.users u
                        WHERE u.id = p_user AND u.tenant_id IN (SELECT openwacht.admin_tenants())) THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    UPDATE openwacht.users SET password_hash = p_hash WHERE id = p_user;
END
$$;

CREATE FUNCTION openwacht.require_self(p_user uuid) RETURNS void
    LANGUAGE plpgsql STABLE AS $$
BEGIN
    IF p_user IS NULL OR p_user IS DISTINCT FROM openwacht.current_user_id() THEN
        RAISE EXCEPTION 'nur für den angemeldeten Benutzer selbst' USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE FUNCTION openwacht.auth_totp_get(p_user uuid)
    RETURNS TABLE (secret_enc bytea, enabled boolean, last_step bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    RETURN QUERY SELECT u.totp_secret_enc, u.totp_enabled, u.totp_last_step
                   FROM openwacht.users u WHERE u.id = p_user;
END
$$;

-- Neues Geheimnis hinterlegen (noch nicht aktiv). Ist 2FA schon aktiv, wird
-- abgelehnt: Zurücksetzen ist eine eigene, auditierte Admin-Funktion (später).
CREATE FUNCTION openwacht.auth_totp_begin(p_user uuid, p_secret_enc bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    UPDATE openwacht.users SET totp_secret_enc = p_secret_enc
     WHERE id = p_user AND NOT totp_enabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Zwei-Faktor ist bereits eingerichtet' USING ERRCODE = '55000';
    END IF;
END
$$;

-- Zeitschritt verbrauchen: nur wenn er neuer ist als der zuletzt genutzte.
-- Liefert false bei Wiederverwendung (Replay).
CREATE FUNCTION openwacht.auth_totp_use_step(p_user uuid, p_step bigint) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    UPDATE openwacht.users SET totp_last_step = p_step
     WHERE id = p_user AND p_step > totp_last_step;
    RETURN FOUND;
END
$$;

CREATE FUNCTION openwacht.auth_totp_enable(p_user uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    UPDATE openwacht.users SET totp_enabled = true
     WHERE id = p_user AND totp_secret_enc IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'kein Zwei-Faktor-Geheimnis hinterlegt' USING ERRCODE = '55000';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Rechte
-- ---------------------------------------------------------------------------

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openwacht FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    openwacht.current_user_id(),
    openwacht.tenants_with_role(text[]),
    openwacht.visible_tenants(),
    openwacht.admin_tenants(),
    openwacht.is_root_admin(),
    openwacht.auth_lookup(text),
    openwacht.auth_login_failed(uuid),
    openwacht.auth_login_succeeded(uuid),
    openwacht.audit_auth(uuid, text, jsonb),
    openwacht.session_create(uuid, bytea, text, interval, interval),
    openwacht.session_get(bytea),
    openwacht.session_delete(bytea),
    openwacht.session_delete_user(uuid),
    openwacht.auth_set_password(uuid, text),
    openwacht.auth_totp_get(uuid),
    openwacht.auth_totp_begin(uuid, bytea),
    openwacht.auth_totp_use_step(uuid, bigint),
    openwacht.auth_totp_enable(uuid)
TO openwacht_app;
