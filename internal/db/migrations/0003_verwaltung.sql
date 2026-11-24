-- SPDX-License-Identifier: AGPL-3.0-only

-- 0003: Hilfsfunktionen für die Verwaltung über die API.

-- Effektive Rolle des aktuellen Benutzers je sichtbarem Mandanten: die
-- stärkste Rolle, die er auf diesem Knoten oder einem seiner Vorfahren hat.
-- Damit zeigt die Oberfläche nur Aktionen an, die auch erlaubt sind. Die
-- eigentliche Durchsetzung bleibt bei den RLS-Policies.
CREATE FUNCTION openwacht.my_tenant_roles() RETURNS TABLE (tenant_id uuid, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.descendant,
           (array_agg(r.role ORDER BY CASE r.role WHEN 'admin' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END))[1]
      FROM openwacht.role_assignments r
      JOIN openwacht.users u ON u.id = r.user_id AND NOT u.disabled
      JOIN openwacht.tenant_closure c ON c.ancestor = r.tenant_id
     WHERE r.user_id = openwacht.current_user_id()
     GROUP BY c.descendant
$$;

REVOKE ALL ON FUNCTION openwacht.my_tenant_roles() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.my_tenant_roles() TO openwacht_app;
