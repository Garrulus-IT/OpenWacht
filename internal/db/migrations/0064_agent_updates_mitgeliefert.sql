-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 1.0.14: Agent-Updates, die mit dem Paket der Zentrale kommen (Seite
-- „Downloads“). Beim Start legt die Zentrale signierte Agents aus ihrem
-- Downloads-Ordner unter „Agent-Updates“ ab, ohne Hochladen von Hand. Die
-- Signatur prüft die Zentrale vorher (Go, internal/update) wie beim Hochladen;
-- der Agent prüft sie vor der Installation noch einmal selbst.
--
-- Eine Version, die es schon gibt (auch von Hand hochgeladen), bleibt
-- unverändert. Freigegeben wird nichts: Das bleibt bei der Freigabe von Hand
-- oder bei „Automatisch übernehmen“ je Mandant (0053).

CREATE FUNCTION openwacht.agent_update_mitliefern(p_version text, p_os text, p_arch text, p_sha256 text,
                                                  p_size bigint, p_signature text, p_data bytea, p_key_id text)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    n integer;
BEGIN
    INSERT INTO openwacht.agent_updates (version, os, arch, sha256, size, signature, data, uploaded_by, key_id)
    VALUES (p_version, p_os, p_arch, p_sha256, p_size, p_signature, p_data, NULL, p_key_id)
    ON CONFLICT (version, os, arch) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n = 1 THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NULL, 'agent_update.mitgeliefert',
                jsonb_build_object('version', p_version, 'plattform', p_os || '/' || p_arch, 'sha256', p_sha256));
    END IF;
    RETURN n = 1;
END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_update_mitliefern(text, text, text, text, bigint, text, bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_update_mitliefern(text, text, text, text, bigint, text, bytea, text) TO openwacht_app;
