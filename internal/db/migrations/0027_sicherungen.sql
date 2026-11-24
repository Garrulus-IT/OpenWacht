-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 21b: Sicherungen in der Oberfläche.
--
-- `openwacht-zentrale sichern` läuft als Eigentümer-Rolle und trägt jeden Lauf
-- hier ein (auch Fehler). Die Zentrale selbst kann /var/backups/openwacht nicht
-- lesen (0700 svc_openwacht_db); die Oberfläche zeigt deshalb diese Liste.
-- Gehört der ganzen Installation (keine tenant_id, wie settings); RLS ohne
-- Policies, lesen nur der Betreiber über backup_list().
CREATE TABLE openwacht.backup_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at  timestamptz NOT NULL,
    finished_at timestamptz NOT NULL DEFAULT now(),
    file        text CHECK (file ~ '^openwacht-[0-9]{8}T[0-9]{6}Z\.dump$'),
    size_bytes  bigint CHECK (size_bytes >= 0),
    ok          boolean NOT NULL,
    message     text CHECK (char_length(message) <= 500),
    removed_at  timestamptz,
    CHECK (ok = (file IS NOT NULL AND size_bytes IS NOT NULL))
);
CREATE INDEX backup_log_started ON openwacht.backup_log (started_at DESC);
CREATE INDEX backup_log_file ON openwacht.backup_log (file) WHERE removed_at IS NULL;
ALTER TABLE openwacht.backup_log ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION openwacht.backup_list(p_limit integer)
    RETURNS TABLE (started_at timestamptz, finished_at timestamptz, file text, size_bytes bigint, ok boolean,
                   message text, removed_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT b.started_at, b.finished_at, b.file, b.size_bytes, b.ok, b.message, b.removed_at
        FROM openwacht.backup_log b ORDER BY b.started_at DESC LIMIT least(greatest(p_limit, 1), 500);
END
$$;
REVOKE ALL ON FUNCTION openwacht.backup_list(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.backup_list(integer) TO openwacht_app;

-- Adresse der Zentrale ändern (Einstellungen → Installation): nur der
-- Betreiber, zusammen mit einem Zertifikat für die neuen Namen.
CREATE FUNCTION openwacht.install_set_address(p_base_url text, p_names text[], p_kind text, p_cert text, p_key bytea,
    p_ca_cert text, p_ca_key bytea) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    old text;
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    SELECT base_url INTO old FROM openwacht.settings;
    UPDATE openwacht.settings SET base_url = p_base_url, names = p_names;
    PERFORM openwacht.https_put(p_kind, p_cert, p_key, p_ca_cert, p_ca_key, p_names);
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (NULL, 'installation.adresse', jsonb_build_object('alt', old, 'neu', p_base_url, 'namen', to_jsonb(p_names)));
END
$$;
REVOKE ALL ON FUNCTION openwacht.install_set_address(text, text[], text, text, bytea, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.install_set_address(text, text[], text, text, bytea, text, bytea) TO openwacht_app;
