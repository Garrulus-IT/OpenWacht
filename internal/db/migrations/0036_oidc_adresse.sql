-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 29, Befund M2: Die Adresse eines OIDC-Kontos kommt aus genau einem,
-- je Anbindung fest eingestellten Claim (Standard email). Bisher fiel die
-- Zentrale auf upn und preferred_username zurück; preferred_username ist bei
-- manchen Identity Providern vom Benutzer frei wählbar.
--
-- Bestehende Anbindungen bekommen email. Wer bisher auf den Rückfall
-- angewiesen war (z. B. Entra ID ohne E-Mail-Attribut), stellt den Claim in
-- der Anbindung auf upn um.

ALTER TABLE openwacht.directories
    ADD COLUMN email_claim text NOT NULL DEFAULT 'email'
        CHECK (email_claim IN ('email', 'upn', 'preferred_username'));
GRANT SELECT (email_claim), INSERT (email_claim), UPDATE (email_claim) ON openwacht.directories TO openwacht_app;

DROP FUNCTION openwacht.directory_oidc(uuid);
CREATE FUNCTION openwacht.directory_oidc(p_directory uuid)
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean, email_claim text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups, d.email_claim
      FROM openwacht.directories d WHERE d.id = p_directory AND d.enabled AND d.kind = 'oidc'
$$;
REVOKE ALL ON FUNCTION openwacht.directory_oidc(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.directory_oidc(uuid) TO openwacht_app;
