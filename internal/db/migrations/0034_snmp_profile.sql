-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 27: SNMP-Zugangsprofile je Mandant.
--
-- Ein Profil hält Version (1, 2c, 3), bei v3 die Verfahren, und die
-- Zugangsdaten (Community bzw. v3-Benutzer und Passwörter) verschlüsselt mit
-- eigenen Zusatzdaten (Profil|Mandant|Version). Die Anwendung darf secret_enc
-- schreiben, aber nicht per SELECT lesen; lesbar ist es nur über
-- snmp_profile_secret(), und nur für Admins des Profilmandanten, die zugleich
-- Admin des Gerätemandanten sind, wenn das Profil im Mandantenbaum über dem
-- Gerät liegt (oder im selben Mandanten).
--
-- Eine Quelle mit Profil bekommt eine eigene Kopie der Zugangsdaten, mit
-- ihren eigenen Zusatzdaten verschlüsselt (Abfrageweg, Sammler und
-- Trap-Dienst bleiben unverändert). Ändern sich die Zugangsdaten des Profils,
-- verschlüsselt die Zentrale in derselben Transaktion alle Quellen mit diesem
-- Profil neu. Gelöschtes Profil: Die Quellen behalten ihre Kopie.
--
-- Sichtbar sind Profile nur für Admins (RLS über admin_tenants): Admins der
-- Eltern sehen die Profile der Kinder, Admins eines Untermandanten die
-- Profile der Eltern nicht.

CREATE TABLE openwacht.snmp_profiles (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name !~ '[[:cntrl:]]' AND name = btrim(name)),
    version     text NOT NULL CHECK (version IN ('1', '2c', '3')),
    v3_auth     text CHECK (v3_auth IN ('sha', 'sha224', 'sha256', 'sha384', 'sha512')),
    v3_priv     text CHECK (v3_priv IN ('aes', 'aes192', 'aes256', 'aes192c', 'aes256c')),
    secret_enc  bytea NOT NULL CHECK (octet_length(secret_enc) BETWEEN 29 AND 2048),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((version = '3') = (v3_auth IS NOT NULL AND v3_priv IS NOT NULL))
);
CREATE UNIQUE INDEX snmp_profiles_tenant_name ON openwacht.snmp_profiles (tenant_id, lower(name));

CREATE FUNCTION openwacht.snmp_profiles_before_write() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        RAISE EXCEPTION 'ID und Mandant eines Profils sind unveränderlich.' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.snmp_profiles WHERE tenant_id = NEW.tenant_id) >= 200 THEN
            RAISE EXCEPTION 'Höchstens 200 SNMP-Profile je Mandant.' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_profiles_before_write BEFORE INSERT OR UPDATE ON openwacht.snmp_profiles
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_profiles_before_write();

ALTER TABLE openwacht.snmp_profiles ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, name, version, v3_auth, v3_priv, created_at, updated_at),
      INSERT (id, tenant_id, name, version, v3_auth, v3_priv, secret_enc),
      UPDATE (name, version, v3_auth, v3_priv, secret_enc),
      DELETE
    ON openwacht.snmp_profiles TO openwacht_app;
CREATE POLICY snmp_profiles_select ON openwacht.snmp_profiles FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_profiles_insert ON openwacht.snmp_profiles FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_profiles_update ON openwacht.snmp_profiles FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())) WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_profiles_delete ON openwacht.snmp_profiles FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- --- Zuordnung an der Quelle -------------------------------------------------

ALTER TABLE openwacht.snmp_sources
    ADD COLUMN profile_id uuid REFERENCES openwacht.snmp_profiles (id) ON DELETE SET NULL;
CREATE INDEX snmp_sources_profile ON openwacht.snmp_sources (profile_id) WHERE profile_id IS NOT NULL;
GRANT SELECT (profile_id), INSERT (profile_id), UPDATE (profile_id) ON openwacht.snmp_sources TO openwacht_app;

-- Profil an der Quelle: nur SNMP (1, 2c, 3), Version und Verfahren wie im
-- Profil. Neu zugeordnet werden darf ein Profil nur von einem Admin des
-- Profilmandanten, und nur, wenn das Profil über dem Gerät oder im selben
-- Mandanten liegt. Der Name sortiert nach snmp_sources_before_insert, damit
-- tenant_id schon aus dem Gerät gesetzt ist.
CREATE FUNCTION openwacht.snmp_sources_zz_profile() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    p openwacht.snmp_profiles;
BEGIN
    IF NEW.profile_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO p FROM openwacht.snmp_profiles WHERE id = NEW.profile_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SNMP-Profil nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'INSERT' OR NEW.profile_id IS DISTINCT FROM OLD.profile_id THEN
        IF NOT EXISTS (SELECT 1 FROM openwacht.tenant_closure c WHERE c.ancestor = p.tenant_id AND c.descendant = NEW.tenant_id) THEN
            RAISE EXCEPTION 'Das Profil gehört nicht zum Mandanten des Geräts oder einem darüber.' USING ERRCODE = '23514';
        END IF;
        IF openwacht.current_user_id() IS NOT NULL AND p.tenant_id NOT IN (SELECT openwacht.admin_tenants()) THEN
            RAISE EXCEPTION 'Profile zuordnen dürfen nur Admins des Profilmandanten.' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF NEW.version IS DISTINCT FROM p.version OR NEW.v3_auth IS DISTINCT FROM p.v3_auth OR NEW.v3_priv IS DISTINCT FROM p.v3_priv THEN
        RAISE EXCEPTION 'Version und Verfahren der Quelle müssen zum Profil passen.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_sources_zz_profile BEFORE INSERT OR UPDATE OF profile_id, version, v3_auth, v3_priv ON openwacht.snmp_sources
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_sources_zz_profile();

-- Zugangsdaten eines Profils für ein Gerät (nur lesbar, wenn der Aufrufer
-- Admin des Profilmandanten und des Gerätemandanten ist und das Profil über
-- dem Gerät oder im selben Mandanten liegt).
CREATE FUNCTION openwacht.snmp_profile_secret(p_profile uuid, p_device uuid)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, v3_auth text, v3_priv text, secret_enc bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT p.id, p.tenant_id, p.version, p.v3_auth, p.v3_priv, p.secret_enc
      FROM openwacht.snmp_profiles p
      JOIN openwacht.devices d ON d.id = p_device
      JOIN openwacht.tenant_closure c ON c.ancestor = p.tenant_id AND c.descendant = d.tenant_id
     WHERE p.id = p_profile
       AND p.tenant_id IN (SELECT openwacht.admin_tenants())
       AND d.tenant_id IN (SELECT openwacht.admin_tenants())
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_profile_secret(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_profile_secret(uuid, uuid) TO openwacht_app;

-- Anzahl aller Quellen mit einem Profil (auch solcher, die der Aufrufer nicht
-- sieht). Beim Neuverschlüsseln vergleicht die Zentrale damit, ob sie alle
-- erreicht hat. Nur für Admins des Profilmandanten, sonst NULL.
CREATE FUNCTION openwacht.snmp_profile_use_count(p_profile uuid) RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE WHEN EXISTS (SELECT 1 FROM openwacht.snmp_profiles p
                              WHERE p.id = p_profile AND p.tenant_id IN (SELECT openwacht.admin_tenants()))
                THEN (SELECT count(*)::integer FROM openwacht.snmp_sources s WHERE s.profile_id = p_profile) END
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_profile_use_count(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_profile_use_count(uuid) TO openwacht_app;
