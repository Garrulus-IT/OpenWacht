-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 21a: Installation mit Einrichtungsassistent, HTTPS durch die Zentrale,
-- Sicherung nach Einstellung.
--
-- Drei Dinge gehören der ganzen Installation und haben deshalb keine tenant_id
-- (wie settings, Etappe 19): der Zustand der Einrichtung, das HTTPS-Zertifikat
-- und die Felder Adresse, Zeitzone und Sicherung in settings. Die App-Rolle
-- liest und schreibt sie nur über Funktionen mit eigener Prüfung.

-- --- Einrichtung -------------------------------------------------------------

-- Eine Zeile. token_hash = SHA-256 des Einrichtungs-Tokens (das Token selbst
-- steht nur im Link, den `installieren` ausgibt). done_at gesetzt = fertig,
-- danach gibt es kein Token mehr und keinen Weg zurück.
CREATE TABLE openwacht.setup_state (
    id          boolean PRIMARY KEY DEFAULT true CHECK (id),
    token_hash  bytea CHECK (octet_length(token_hash) = 32),
    expires_at  timestamptz,
    done_at     timestamptz,
    CHECK ((token_hash IS NULL) = (expires_at IS NULL)),
    CHECK (done_at IS NULL OR token_hash IS NULL)
);
-- Bestehende Installationen (Hauptmandant vorhanden) gelten als eingerichtet.
INSERT INTO openwacht.setup_state (done_at)
SELECT CASE WHEN EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id IS NULL) THEN now() END;
ALTER TABLE openwacht.setup_state ENABLE ROW LEVEL SECURITY;
-- Keine Rechte für openwacht_app: nur über die Funktionen unten.

-- setup_open: Ist die Einrichtung noch offen? (Zentrale wählt damit den Modus.)
CREATE FUNCTION openwacht.setup_open() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.done_at IS NULL AND NOT EXISTS (SELECT 1 FROM openwacht.tenants t WHERE t.parent_id IS NULL)
      FROM openwacht.setup_state s
$$;
REVOKE ALL ON FUNCTION openwacht.setup_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.setup_open() TO openwacht_app;

-- setup_check: gültiges, nicht abgelaufenes Token einer offenen Einrichtung?
CREATE FUNCTION openwacht.setup_check(p_hash bytea) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce(openwacht.setup_open() AND s.token_hash = p_hash AND s.expires_at > now(), false)
      FROM openwacht.setup_state s
$$;
REVOKE ALL ON FUNCTION openwacht.setup_check(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.setup_check(bytea) TO openwacht_app;

-- --- HTTPS ---------------------------------------------------------------------

-- Eine Zeile. kind: 'einrichtung' (vorläufig, selbstsigniert, nur bis „Fertig“),
-- 'eigene-ca' (eigene OpenWacht-CA mit Name Constraints, die Zentrale erneuert
-- das Serverzertifikat selbst) oder 'hochgeladen' (Zertifikat des Betreibers).
-- Private Schlüssel sind mit einem vom Hauptschlüssel abgeleiteten Schlüssel
-- verschlüsselt; wer nur die Datenbank hat, kann damit nichts anfangen.
CREATE TABLE openwacht.https_material (
    id          boolean PRIMARY KEY DEFAULT true CHECK (id),
    kind        text NOT NULL CHECK (kind IN ('einrichtung', 'eigene-ca', 'hochgeladen')),
    cert_pem    text NOT NULL CHECK (char_length(cert_pem) BETWEEN 100 AND 65536),
    key_enc     bytea NOT NULL CHECK (octet_length(key_enc) BETWEEN 29 AND 16384),
    ca_cert_pem text CHECK (char_length(ca_cert_pem) <= 16384),
    ca_key_enc  bytea CHECK (octet_length(ca_key_enc) <= 16384),
    names       text[] NOT NULL CHECK (cardinality(names) BETWEEN 1 AND 16 AND array_position(names, NULL) IS NULL),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((kind = 'eigene-ca') = (ca_cert_pem IS NOT NULL AND ca_key_enc IS NOT NULL))
);
ALTER TABLE openwacht.https_material ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION openwacht.https_get()
    RETURNS TABLE (kind text, cert_pem text, key_enc bytea, ca_cert_pem text, ca_key_enc bytea, names text[],
                   updated_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT h.kind, h.cert_pem, h.key_enc, h.ca_cert_pem, h.ca_key_enc, h.names, h.updated_at FROM openwacht.https_material h
$$;
REVOKE ALL ON FUNCTION openwacht.https_get() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.https_get() TO openwacht_app;

-- Vorläufiges Zertifikat für den Assistenten: nur solange die Einrichtung
-- offen ist und noch keines gespeichert ist (überschreibt nichts).
CREATE FUNCTION openwacht.https_setup_init(p_cert text, p_key bytea, p_names text[]) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.setup_open() THEN
        RAISE EXCEPTION 'Einrichtung ist abgeschlossen' USING ERRCODE = '42501';
    END IF;
    INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, names)
    VALUES ('einrichtung', p_cert, p_key, p_names)
    ON CONFLICT (id) DO NOTHING;
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openwacht.https_setup_init(text, bytea, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.https_setup_init(text, bytea, text[]) TO openwacht_app;

-- Neues Zertifikat (Seite Einstellungen): nur der Betreiber.
CREATE FUNCTION openwacht.https_put(p_kind text, p_cert text, p_key bytea, p_ca_cert text, p_ca_key bytea, p_names text[])
    RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    IF p_kind NOT IN ('eigene-ca', 'hochgeladen') THEN
        RAISE EXCEPTION 'ungültige Art' USING ERRCODE = '22023';
    END IF;
    INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names, updated_at)
    VALUES (p_kind, p_cert, p_key, p_ca_cert, p_ca_key, p_names, now())
    ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, cert_pem = EXCLUDED.cert_pem, key_enc = EXCLUDED.key_enc,
        ca_cert_pem = EXCLUDED.ca_cert_pem, ca_key_enc = EXCLUDED.ca_key_enc, names = EXCLUDED.names, updated_at = now();
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (NULL, 'https.geaendert', jsonb_build_object('art', p_kind, 'namen', to_jsonb(p_names)));
END
$$;
REVOKE ALL ON FUNCTION openwacht.https_put(text, text, bytea, text, bytea, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.https_put(text, text, bytea, text, bytea, text[]) TO openwacht_app;

-- Erneuerung des Serverzertifikats durch die Zentrale (ohne Benutzer): nur bei
-- eigener CA und nur das Serverzertifikat, CA und Namen bleiben. p_old_cert
-- verhindert, dass eine verspätete Erneuerung ein neues Zertifikat überschreibt.
CREATE FUNCTION openwacht.https_renew(p_old_cert text, p_cert text, p_key bytea) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.https_material SET cert_pem = p_cert, key_enc = p_key, updated_at = now()
     WHERE kind = 'eigene-ca' AND cert_pem = p_old_cert;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details) VALUES (NULL, 'https.erneuert', '{}'::jsonb);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openwacht.https_renew(text, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.https_renew(text, text, bytea) TO openwacht_app;

-- --- Einstellungen der Installation ------------------------------------------

-- base_url: Adresse der Oberfläche (https://<erster Name>), names: alle Namen
-- und IP-Adressen der Zentrale (Zertifikat, Agent-Port, erlaubte Ursprünge).
-- timezone: für Mails und neue Wartungsfenster. backup_hour/backup_days:
-- Uhrzeit (in timezone) und Aufbewahrung der nächtlichen Sicherung.
ALTER TABLE openwacht.settings
    ADD COLUMN base_url    text CHECK (base_url ~ '^https://[A-Za-z0-9.:\[\]-]{1,253}$'),
    ADD COLUMN names       text[] CHECK (cardinality(names) BETWEEN 1 AND 16 AND array_position(names, NULL) IS NULL),
    ADD COLUMN timezone    text CHECK (timezone ~ '^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$' AND char_length(timezone) <= 64),
    ADD COLUMN backup_hour smallint CHECK (backup_hour BETWEEN 0 AND 23),
    ADD COLUMN backup_days smallint CHECK (backup_days BETWEEN 1 AND 365);
GRANT UPDATE (timezone, backup_hour, backup_days) ON openwacht.settings TO openwacht_app;

CREATE FUNCTION openwacht.runtime_install()
    RETURNS TABLE (base_url text, names text[], timezone text, backup_hour smallint, backup_days smallint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.base_url, s.names, s.timezone, s.backup_hour, s.backup_days FROM openwacht.settings s
$$;
REVOKE ALL ON FUNCTION openwacht.runtime_install() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.runtime_install() TO openwacht_app;

-- --- Abschluss der Einrichtung -----------------------------------------------

-- setup_finish legt in einer Transaktion alles an, was der Assistent abgefragt
-- hat. Das Token muss gültig sein; danach ist es gelöscht und die Einrichtung
-- geschlossen. Der erste Admin hat die Zwei-Faktor-Anmeldung schon im
-- Assistenten eingerichtet (p_totp_step: zuletzt verwendeter Code, gegen
-- Wiederverwendung) und ist Betreiber.
CREATE FUNCTION openwacht.setup_finish(
    p_hash bytea, p_user_id uuid, p_tenant text, p_email text, p_name text, p_pw_hash text,
    p_totp_enc bytea, p_totp_step bigint, p_base_url text, p_names text[], p_timezone text, p_nets cidr[],
    p_smtp_host text, p_smtp_port integer, p_smtp_tls text, p_smtp_from text, p_smtp_user text, p_smtp_pass_enc bytea,
    p_backup_hour smallint, p_backup_days smallint,
    p_https_kind text, p_cert text, p_key bytea, p_ca_cert text, p_ca_key bytea)
    RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    st openwacht.setup_state;
    v_tenant uuid;
BEGIN
    SELECT * INTO st FROM openwacht.setup_state FOR UPDATE;
    LOCK TABLE openwacht.tenants IN EXCLUSIVE MODE;
    IF st.done_at IS NOT NULL OR st.token_hash IS NULL OR st.token_hash <> p_hash OR st.expires_at <= now()
       OR EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id IS NULL) THEN
        RAISE EXCEPTION 'Einrichtungs-Token ungültig' USING ERRCODE = '42501';
    END IF;
    IF p_https_kind NOT IN ('eigene-ca', 'hochgeladen') THEN
        RAISE EXCEPTION 'ungültige Art' USING ERRCODE = '22023';
    END IF;

    INSERT INTO openwacht.tenants (name) VALUES (btrim(p_tenant)) RETURNING id INTO v_tenant;
    INSERT INTO openwacht.users (id, tenant_id, email, display_name, password_hash, totp_secret_enc, totp_enabled, totp_last_step)
    VALUES (p_user_id, v_tenant, lower(btrim(p_email)), btrim(p_name), p_pw_hash, p_totp_enc, true, p_totp_step);
    INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES (p_user_id, v_tenant, 'admin');
    -- über UPDATE, damit der Trigger prüft (Hauptmandant) und auditiert
    UPDATE openwacht.users SET platform_operator = true WHERE id = p_user_id;

    UPDATE openwacht.settings SET base_url = p_base_url, names = p_names, timezone = p_timezone, check_nets = p_nets,
        smtp_host = p_smtp_host, smtp_port = p_smtp_port, smtp_tls = p_smtp_tls, smtp_from = p_smtp_from,
        smtp_user = p_smtp_user, smtp_pass_enc = p_smtp_pass_enc,
        backup_hour = p_backup_hour, backup_days = p_backup_days;

    INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names, updated_at)
    VALUES (p_https_kind, p_cert, p_key, p_ca_cert, p_ca_key, p_names, now())
    ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, cert_pem = EXCLUDED.cert_pem, key_enc = EXCLUDED.key_enc,
        ca_cert_pem = EXCLUDED.ca_cert_pem, ca_key_enc = EXCLUDED.ca_key_enc, names = EXCLUDED.names, updated_at = now();

    UPDATE openwacht.setup_state SET token_hash = NULL, expires_at = NULL, done_at = now();
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'installation.eingerichtet', jsonb_build_object('admin', lower(btrim(p_email)), 'assistent', true,
        'adresse', p_base_url, 'https', p_https_kind));
    RETURN v_tenant;
END
$$;
REVOKE ALL ON FUNCTION openwacht.setup_finish(bytea, uuid, text, text, text, text, bytea, bigint, text, text[], text, cidr[],
    text, integer, text, text, text, bytea, smallint, smallint, text, text, bytea, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.setup_finish(bytea, uuid, text, text, text, text, bytea, bigint, text, text[], text, cidr[],
    text, integer, text, text, text, bytea, smallint, smallint, text, text, bytea, text, bytea) TO openwacht_app;

-- Wer mit `einrichten` (Shell, ohne Assistent) einrichtet, schließt die
-- Einrichtung ebenfalls: Trigger auf den ersten Hauptmandanten.
CREATE FUNCTION openwacht.setup_close_on_root() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.parent_id IS NULL THEN
        UPDATE openwacht.setup_state SET token_hash = NULL, expires_at = NULL, done_at = coalesce(done_at, now());
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER tenants_setup_close AFTER INSERT ON openwacht.tenants
    FOR EACH ROW EXECUTE FUNCTION openwacht.setup_close_on_root();
