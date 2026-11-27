-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Notfall-Befehl „passwort-setzen“ auf der Shell. Ist das Passwort des
-- einzigen Admins falsch gesetzt oder vergessen, gab es bisher nur
-- „entsperren“ und „zweifaktor-zuruecksetzen“. Nur der Eigentümer der
-- Datenbank darf die Funktion aufrufen (kein GRANT an die App-Rolle), nur für
-- lokale Konten: Bei AD- und SSO-Konten kommt das Passwort von dort.
-- Die Zwei-Faktor-Anmeldung bleibt bestehen; alle Sitzungen enden, Sperren
-- nach Fehlversuchen werden aufgehoben.

CREATE FUNCTION openwacht.auth_password_set_shell(p_email text, p_hash text) RETURNS text
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
    RETURN 'lokal';
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_password_set_shell(text, text) FROM PUBLIC;
