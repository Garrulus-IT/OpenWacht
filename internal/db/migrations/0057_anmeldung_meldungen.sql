-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Benachrichtigung bei verdächtigen Anmeldungen und kontoweite Bremse
-- für den zweiten Faktor (Pentest-Hinweis H5).
--
-- Meldungen: Die Datenbank legt Ereignisse in einen Ausgang (auth_notices),
-- die Zentrale verschickt sie per Mail. So kommen auch Ereignisse von der
-- Shell (zweifaktor-zuruecksetzen, passwort-setzen) an. Gespeichert werden
-- nur Konto, Art und Zeit, keine Adressen (Leitprinzip 5).
--   neue_quelle               erfolgreiche Anmeldung von einer Quelle, die das
--                             Konto in 90 Tagen nicht benutzt hat (nur wenn es
--                             schon eine bekannte Quelle gibt) -> nur an das Konto
--   quelle_gesperrt           eine Quelle ist nach 5 Fehlversuchen gesperrt
--   zweifaktor_gesperrt       H5: zu viele falsche Codes aus allen Quellen
--   zweifaktor_zurueckgesetzt Shell
--   passwort_gesetzt          Shell
--   -> an das Konto und an den Betreiber
-- Je Konto und Art höchstens eine Meldung je Stunde (wer viele Quellen hat,
-- soll keine Mailflut auslösen).
--
-- H5 (Entscheidung 25.11.2026): 10 falsche Codes (App oder
-- Wiederherstellungscode) aus allen Quellen binnen 15 Minuten sperren den
-- zweiten Faktor des Kontos für 15 Minuten. Passkeys bleiben möglich (nicht
-- ratbar). Bewusster Nachteil: Wer das Passwort kennt, kann das Konto kurz
-- blockieren; die Meldung macht das sichtbar.

CREATE TABLE openwacht.auth_notices (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('neue_quelle', 'quelle_gesperrt', 'zweifaktor_gesperrt',
                                             'zweifaktor_zurueckgesetzt', 'passwort_gesetzt')),
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz,
    attempts   integer NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
CREATE INDEX auth_notices_open ON openwacht.auth_notices (created_at) WHERE sent_at IS NULL;
CREATE INDEX auth_notices_user ON openwacht.auth_notices (user_id, kind, created_at);
-- Ausnahme vom Grundsatz „tenant_id“ wie login_sources: technische Daten der
-- Anmeldung, nur über Funktionen erreichbar.
ALTER TABLE openwacht.auth_notices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.auth_notices FROM PUBLIC, openwacht_app;

CREATE FUNCTION openwacht.auth_notice_add(p_user uuid, p_kind text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM openwacht.auth_notices n
                WHERE n.user_id = p_user AND n.kind = p_kind AND n.created_at > now() - interval '1 hour') THEN
        RETURN;
    END IF;
    INSERT INTO openwacht.auth_notices (user_id, kind) VALUES (p_user, p_kind);
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_notice_add(uuid, text) FROM PUBLIC;

-- Offene Meldungen für den Versand (Zentrale ohne Benutzerkontext). Liefert
-- Empfänger: die Adresse des Kontos (nicht bei API-Token-Konten) und, außer
-- bei neue_quelle, die Adressen der wirksamen Betreiber.
CREATE FUNCTION openwacht.auth_notices_open(p_limit integer)
    RETURNS TABLE (id bigint, kind text, created_at timestamptz, email text, display_name text, operators text[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT n.id, n.kind, n.created_at,
           CASE WHEN u.auth_source <> 'token' AND NOT u.disabled THEN u.email END,
           u.display_name,
           CASE WHEN n.kind = 'neue_quelle' THEN ARRAY[]::text[]
                ELSE coalesce((SELECT array_agg(o.email ORDER BY o.email)
                                 FROM openwacht.users o JOIN openwacht.tenants t ON t.id = o.tenant_id
                                WHERE o.platform_operator AND NOT o.disabled AND o.totp_enabled
                                  AND t.parent_id IS NULL AND o.id <> u.id), ARRAY[]::text[]) END
      FROM openwacht.auth_notices n JOIN openwacht.users u ON u.id = n.user_id
     WHERE n.sent_at IS NULL AND n.attempts < 5 AND n.created_at > now() - interval '1 day'
     ORDER BY n.id
     LIMIT least(greatest(p_limit, 1), 100)
$$;
REVOKE ALL ON FUNCTION openwacht.auth_notices_open(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.auth_notices_open(integer) TO openwacht_app;

-- Versand quittieren; alte Einträge räumt dieselbe Funktion auf.
CREATE FUNCTION openwacht.auth_notice_done(p_id bigint, p_ok boolean) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_ok THEN
        UPDATE openwacht.auth_notices SET sent_at = now(), attempts = attempts + 1 WHERE id = p_id AND sent_at IS NULL;
    ELSE
        UPDATE openwacht.auth_notices SET attempts = attempts + 1 WHERE id = p_id AND sent_at IS NULL;
    END IF;
    DELETE FROM openwacht.auth_notices WHERE created_at < now() - interval '30 days';
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_notice_done(bigint, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.auth_notice_done(bigint, boolean) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Ereignisse in den Ausgang legen
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.auth_login_succeeded(p_user uuid, p_source bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_new boolean;
BEGIN
    IF octet_length(p_source) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'ungültige Quelle';
    END IF;
    UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL,
                               mfa_failures = 0, mfa_window = NULL
     WHERE id = p_user;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- Neu: Diese Quelle war in 90 Tagen nicht erfolgreich, eine andere schon.
    v_new := NOT EXISTS (SELECT 1 FROM openwacht.login_sources s
                          WHERE s.user_id = p_user AND s.source_hash = p_source
                            AND s.last_success > now() - interval '90 days')
         AND EXISTS (SELECT 1 FROM openwacht.login_sources s
                      WHERE s.user_id = p_user AND s.source_hash <> p_source
                        AND s.last_success > now() - interval '90 days');
    INSERT INTO openwacht.login_sources AS s (user_id, source_hash, last_success, updated_at)
    VALUES (p_user, p_source, now(), now())
    ON CONFLICT (user_id, source_hash) DO UPDATE
       SET failures = 0, locked_until = NULL, last_success = now(), updated_at = now();
    IF v_new THEN
        PERFORM openwacht.auth_notice_add(p_user, 'neue_quelle');
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.auth_login_failed(p_user uuid, p_source bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_failures integer;
BEGIN
    IF octet_length(p_source) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'ungültige Quelle';
    END IF;
    UPDATE openwacht.users SET failed_logins = failed_logins + 1 WHERE id = p_user;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO openwacht.login_sources AS s (user_id, source_hash, failures, last_failed, updated_at)
    VALUES (p_user, p_source, 1, now(), now())
    ON CONFLICT (user_id, source_hash) DO UPDATE
       SET failures = s.failures + 1,
           last_failed = now(),
           updated_at = now(),
           locked_until = CASE
               WHEN s.failures + 1 >= 5 THEN
                   now() + least(interval '60 minutes',
                                 interval '1 minute' * power(2, least(s.failures + 1 - 5, 10)))
               ELSE s.locked_until END
    RETURNING s.failures INTO v_failures;
    -- Gemeldet wird die erste Sperre einer Quelle, nicht jede Verlängerung.
    IF v_failures = 5 THEN
        PERFORM openwacht.auth_notice_add(p_user, 'quelle_gesperrt');
    END IF;
    DELETE FROM openwacht.login_sources s
     WHERE s.user_id = p_user
       AND s.source_hash NOT IN (SELECT x.source_hash FROM openwacht.login_sources x
                                  WHERE x.user_id = p_user ORDER BY x.updated_at DESC LIMIT 100);
    DELETE FROM openwacht.login_sources WHERE updated_at < now() - interval '90 days';
END
$$;

-- ---------------------------------------------------------------------------
-- H5: kontoweite Bremse für den zweiten Faktor
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.users
    ADD COLUMN mfa_failures     integer NOT NULL DEFAULT 0 CHECK (mfa_failures >= 0),
    ADD COLUMN mfa_window       timestamptz,
    ADD COLUMN mfa_locked_until timestamptz;

CREATE FUNCTION openwacht.auth_mfa_locked(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce((SELECT u.mfa_locked_until > now() FROM openwacht.users u WHERE u.id = p_user), false)
$$;
REVOKE ALL ON FUNCTION openwacht.auth_mfa_locked(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.auth_mfa_locked(uuid) TO openwacht_app;

-- Falscher Code: zählen; true, wenn damit die Sperre beginnt.
CREATE FUNCTION openwacht.auth_mfa_failed(p_user uuid) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_n      integer;
    v_tenant uuid;
BEGIN
    UPDATE openwacht.users
       SET mfa_failures = CASE WHEN mfa_window > now() - interval '15 minutes' THEN mfa_failures + 1 ELSE 1 END,
           mfa_window   = CASE WHEN mfa_window > now() - interval '15 minutes' THEN mfa_window ELSE now() END
     WHERE id = p_user
    RETURNING mfa_failures, tenant_id INTO v_n, v_tenant;
    IF NOT FOUND OR v_n < 10 THEN
        RETURN false;
    END IF;
    UPDATE openwacht.users SET mfa_locked_until = now() + interval '15 minutes', mfa_failures = 0, mfa_window = NULL
     WHERE id = p_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'zweifaktor.gesperrt', jsonb_build_object('benutzer', p_user, 'minuten', 15));
    PERFORM openwacht.auth_notice_add(p_user, 'zweifaktor_gesperrt');
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_mfa_failed(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.auth_mfa_failed(uuid) TO openwacht_app;

-- Shell: entsperren hebt auch diese Sperre auf, die beiden Notfall-Befehle
-- melden sich beim Konto und beim Betreiber.
CREATE OR REPLACE FUNCTION openwacht.auth_unlock(p_email text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user   uuid;
    v_tenant uuid;
    v_n      integer;
BEGIN
    SELECT u.id, u.tenant_id INTO v_user, v_tenant FROM openwacht.users u WHERE u.email = lower(btrim(p_email));
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO v_n FROM openwacht.login_sources WHERE user_id = v_user AND locked_until > now();
    IF (SELECT mfa_locked_until > now() FROM openwacht.users WHERE id = v_user) THEN
        v_n := v_n + 1;
    END IF;
    DELETE FROM openwacht.login_sources WHERE user_id = v_user AND last_success IS NULL;
    UPDATE openwacht.login_sources SET failures = 0, locked_until = NULL, updated_at = now() WHERE user_id = v_user;
    UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL,
                               mfa_failures = 0, mfa_window = NULL, mfa_locked_until = NULL
     WHERE id = v_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'konto.entsperrt', jsonb_build_object('benutzer', v_user, 'email', lower(btrim(p_email)),
                                                            'quelle', 'shell', 'sperren', v_n));
    RETURN v_n;
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_unlock(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openwacht.auth_2fa_reset(p_email text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user   uuid;
    v_tenant uuid;
    v_had    boolean;
BEGIN
    SELECT u.id, u.tenant_id, u.totp_enabled INTO v_user, v_tenant, v_had
      FROM openwacht.users u WHERE u.email = lower(btrim(p_email)) AND u.auth_source <> 'token';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    UPDATE openwacht.users SET totp_secret_enc = NULL, totp_enabled = false,
                               mfa_failures = 0, mfa_window = NULL, mfa_locked_until = NULL
     WHERE id = v_user;
    DELETE FROM openwacht.recovery_codes WHERE user_id = v_user;
    DELETE FROM openwacht.sessions WHERE user_id = v_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'zweifaktor.zurueckgesetzt', jsonb_build_object('benutzer', v_user, 'email', lower(btrim(p_email)),
                                                                      'quelle', 'shell', 'war_aktiv', v_had));
    PERFORM openwacht.auth_notice_add(v_user, 'zweifaktor_zurueckgesetzt');
    RETURN v_had;
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_2fa_reset(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openwacht.auth_password_set_shell(p_email text, p_hash text) RETURNS text
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user   uuid;
    v_tenant uuid;
    v_source text;
BEGIN
    IF p_hash IS NULL OR p_hash !~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$' THEN
        RAISE EXCEPTION 'ungültiges Passwort-Hash-Format' USING ERRCODE = '22023';
    END IF;
    SELECT u.id, u.tenant_id, u.auth_source INTO v_user, v_tenant, v_source
      FROM openwacht.users u WHERE u.email = lower(btrim(p_email));
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF v_source <> 'lokal' THEN
        RETURN v_source;
    END IF;
    UPDATE openwacht.users
       SET password_hash = p_hash, failed_logins = 0, locked_until = NULL, login_next_slot = NULL
     WHERE id = v_user;
    DELETE FROM openwacht.login_sources WHERE user_id = v_user AND last_success IS NULL;
    UPDATE openwacht.login_sources SET failures = 0, locked_until = NULL, updated_at = now() WHERE user_id = v_user;
    DELETE FROM openwacht.sessions WHERE user_id = v_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'passwort.gesetzt', jsonb_build_object('benutzer', v_user, 'email', lower(btrim(p_email)),
                                                             'quelle', 'shell'));
    PERFORM openwacht.auth_notice_add(v_user, 'passwort_gesetzt');
    RETURN 'lokal';
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_password_set_shell(text, text) FROM PUBLIC;
