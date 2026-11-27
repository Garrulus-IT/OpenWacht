-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Konten löschen statt nur sperren (Löschkonzept, Entscheidung
-- 25.11.2026). Ein gesperrtes Konto wird 90 Tage nach dem Sperren
-- automatisch gelöscht; vorher löscht es ein Admin, der es ganz verwaltet,
-- von Hand (nur gesperrte Konten, nie sich selbst). Betreiber werden nie
-- automatisch gelöscht. Rollen, Sitzungen, Passkeys, Codes, API-Tokens und
-- persönliche Einstellungen gehen mit (ON DELETE CASCADE); Verweise in
-- Alarmen, Wartungen und Anträgen werden leer (SET NULL), der Name bei
-- bestätigten Alarmen bleibt als Text. Das Audit-Log bleibt unverändert (Hash-
-- Kette) und fällt erst mit seiner Aufbewahrungsfrist weg.

ALTER TABLE openwacht.users ADD COLUMN disabled_at timestamptz;
UPDATE openwacht.users SET disabled_at = now() WHERE disabled;
GRANT SELECT (disabled_at) ON openwacht.users TO openwacht_app;

CREATE FUNCTION openwacht.users_disabled_at() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.disabled AND NOT OLD.disabled THEN
        NEW.disabled_at := now();
    ELSIF NOT NEW.disabled THEN
        NEW.disabled_at := NULL;
    ELSE
        NEW.disabled_at := OLD.disabled_at;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER users_disabled_at BEFORE UPDATE ON openwacht.users
    FOR EACH ROW EXECUTE FUNCTION openwacht.users_disabled_at();

-- Löschen nach Frist (Zentrale, ohne Benutzerkontext, aus der Wartung).
CREATE FUNCTION openwacht.users_purge() RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_n integer := 0;
    v   record;
BEGIN
    FOR v IN SELECT u.id, u.tenant_id, u.email FROM openwacht.users u
              WHERE u.disabled AND u.disabled_at < now() - interval '90 days' AND NOT u.platform_operator
              ORDER BY u.disabled_at LIMIT 100 FOR UPDATE LOOP
        DELETE FROM openwacht.users WHERE id = v.id;
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (v.tenant_id, 'benutzer.geloescht', jsonb_build_object('id', v.id, 'email', v.email, 'quelle', 'frist', 'tage', 90));
        v_n := v_n + 1;
    END LOOP;
    RETURN v_n;
END
$$;
REVOKE ALL ON FUNCTION openwacht.users_purge() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.users_purge() TO openwacht_app;
