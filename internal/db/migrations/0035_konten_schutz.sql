-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 29, Befund H2: Konten mit Rollen außerhalb des eigenen Bereichs.
--
-- Ein Konto kann Rollen auf Mandanten außerhalb seines Heimat-Teilbaums
-- haben (z. B. Konto im Lager mit Operator-Rolle in der IT; bleibt erlaubt,
-- Entscheidung 22.11.2026). Bisher durfte jeder Admin des Heimatmandanten das
-- Passwort eines solchen Kontos setzen und sich damit dessen fremde Rechte
-- verschaffen.
--
-- Neu: Ein anderer als der Kontoinhaber darf Passwort, Sperre, Anzeigename,
-- Sitzungen und das Konto selbst nur ändern, wenn er Admin des
-- Heimatmandanten ist UND jede Rolle des Kontos auf einem Mandanten liegt, den
-- er administriert. Die Prüfung steht hier in der Datenbank und zusätzlich in
-- der API (403 mit Meldung).
--
-- Außerdem: Setzt ein Admin das Passwort, verwirft die Datenbank ein noch
-- nicht bestätigtes TOTP-Geheimnis des Kontos (eingerichtete 2FA bleibt).

-- Darf der angemeldete Benutzer das Konto p_user verwalten? Eigene Konten
-- zählen hier nicht (dafür gelten die bisherigen Regeln für „sich selbst“).
-- SECURITY DEFINER, weil die Rollen auf fremden Mandanten für den Aufrufer
-- unsichtbar sind (RLS); verraten wird nur ja/nein.
CREATE FUNCTION openwacht.user_manageable(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT openwacht.current_user_id() IS NOT NULL
       AND EXISTS (SELECT 1 FROM openwacht.users u
                    WHERE u.id = p_user
                      AND u.tenant_id IN (SELECT openwacht.admin_tenants()))
       AND NOT EXISTS (SELECT 1 FROM openwacht.role_assignments r
                        WHERE r.user_id = p_user
                          AND r.tenant_id NOT IN (SELECT openwacht.admin_tenants()))
$$;
REVOKE ALL ON FUNCTION openwacht.user_manageable(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.user_manageable(uuid) TO openwacht_app;

-- Passwort-Hash setzen: der Benutzer selbst oder ein Admin, der das Konto
-- ganz verwaltet. Durch einen Admin: unbestätigtes TOTP verwerfen.
CREATE OR REPLACE FUNCTION openwacht.auth_set_password(p_user uuid, p_hash text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_hash IS NULL OR p_hash !~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$' THEN
        RAISE EXCEPTION 'ungültiges Passwort-Hash-Format';
    END IF;
    IF p_user IS DISTINCT FROM openwacht.current_user_id() THEN
        IF NOT openwacht.user_manageable(p_user) THEN
            RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
        END IF;
        UPDATE openwacht.users SET password_hash = p_hash,
               totp_secret_enc = CASE WHEN totp_enabled THEN totp_secret_enc END
         WHERE id = p_user;
        RETURN;
    END IF;
    UPDATE openwacht.users SET password_hash = p_hash WHERE id = p_user;
END
$$;

-- Alle Sitzungen eines Benutzers beenden: er selbst oder ein Admin, der das
-- Konto ganz verwaltet.
CREATE OR REPLACE FUNCTION openwacht.session_delete_user(p_user uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_user IS DISTINCT FROM openwacht.current_user_id()
       AND NOT openwacht.user_manageable(p_user) THEN
        RAISE EXCEPTION 'keine Berechtigung' USING ERRCODE = '42501';
    END IF;
    DELETE FROM openwacht.sessions WHERE user_id = p_user;
END
$$;

-- Anzeigename, Sperre und Löschen über die App-Rolle: wie oben. Die
-- Policies gelten nur für openwacht_app; Definer-Funktionen (Verzeichnis-
-- Abgleich, Anbindung löschen) laufen als Eigentümer und sind nicht betroffen.
DROP POLICY users_update ON openwacht.users;
CREATE POLICY users_update ON openwacht.users FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())
           AND (id = openwacht.current_user_id() OR openwacht.user_manageable(id)))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
DROP POLICY users_delete ON openwacht.users;
CREATE POLICY users_delete ON openwacht.users FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())
           AND (id = openwacht.current_user_id() OR openwacht.user_manageable(id)));
