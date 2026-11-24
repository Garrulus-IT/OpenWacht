-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 25: Monatsberichte (PDF) mit Verfügbarkeit, SLA-Ziel, Alarmen und
-- Kapazitätsprognose; monatlich per Mail an die Empfänger von Mail-Kanälen,
-- die das wünschen. Jeder Empfänger bekommt den Bericht mit seinen eigenen
-- Rechten erstellt (RLS), nie mehr, als er in der Oberfläche sähe.

-- SLA-Ziel je Mandant in Prozent; NULL = vom übergeordneten Mandanten, sonst 99,5.
ALTER TABLE openwacht.tenants ADD COLUMN sla_target numeric(6,3) CHECK (sla_target BETWEEN 50 AND 100);
GRANT SELECT (sla_target), UPDATE (sla_target) ON openwacht.tenants TO openwacht_app;

-- Mail-Kanäle: Monatsbericht an die Empfänger
ALTER TABLE openwacht.alert_channels ADD COLUMN monthly_report boolean NOT NULL DEFAULT false;
GRANT SELECT (monthly_report), INSERT (monthly_report), UPDATE (monthly_report) ON openwacht.alert_channels TO openwacht_app;

-- Versand je Kanal, Empfänger und Monat (nur einmal)
CREATE TABLE openwacht.report_runs (
    channel_id uuid NOT NULL REFERENCES openwacht.alert_channels (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    month      date NOT NULL CHECK (extract(day FROM month) = 1),
    sent_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, user_id, month)
);
ALTER TABLE openwacht.report_runs ENABLE ROW LEVEL SECURITY;
-- keine Rechte für die Anwendung; nur über die Funktionen unten

-- Fällige Monatsberichte: Kanal, Empfänger, Mandant des Kanals, Untermandanten
CREATE FUNCTION openwacht.report_due(p_month date)
    RETURNS TABLE (channel_id uuid, channel_name text, tenant_id uuid, include_children boolean, user_id uuid, email text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT ch.id, ch.name, ch.tenant_id, ch.include_children, u.id, u.email
      FROM openwacht.alert_channels ch
      JOIN openwacht.role_assignments ra ON ra.tenant_id = ch.tenant_id
      JOIN openwacht.users u ON u.id = ra.user_id
     WHERE ch.kind = 'mail' AND ch.enabled AND ch.monthly_report AND u.alert_mail AND NOT u.disabled
       AND u.auth_source <> 'token'
       AND (ch.all_users OR EXISTS (SELECT 1 FROM openwacht.alert_channel_users cu WHERE cu.channel_id = ch.id AND cu.user_id = u.id))
       AND NOT EXISTS (SELECT 1 FROM openwacht.report_runs r WHERE r.channel_id = ch.id AND r.user_id = u.id AND r.month = p_month)
     ORDER BY ch.id, u.email
     LIMIT 500
$$;

CREATE FUNCTION openwacht.report_sent(p_channel uuid, p_user uuid, p_month date) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    INSERT INTO openwacht.report_runs (channel_id, user_id, month) VALUES (p_channel, p_user, p_month) ON CONFLICT DO NOTHING
$$;

-- Mandanten eines Berichts mit SLA-Ziel (eigenes, sonst des nächsten
-- Vorfahren mit Ziel, sonst p_default). Nur für den Aufrufer sichtbare.
CREATE FUNCTION openwacht.report_tenants(p_tenant uuid, p_children boolean, p_default numeric)
    RETURNS TABLE (id uuid, name text, sla numeric)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT t.id, t.name,
           coalesce((SELECT a.sla_target FROM openwacht.tenant_closure c JOIN openwacht.tenants a ON a.id = c.ancestor
                      WHERE c.descendant = t.id AND a.sla_target IS NOT NULL ORDER BY c.depth LIMIT 1), p_default)
      FROM openwacht.tenants t
     WHERE (t.id = p_tenant OR (p_children AND t.id IN (SELECT c.descendant FROM openwacht.tenant_closure c WHERE c.ancestor = p_tenant)))
       AND t.id IN (SELECT openwacht.visible_tenants())
     ORDER BY t.name
$$;

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['report_due(date)', 'report_sent(uuid, uuid, date)', 'report_tenants(uuid, boolean, numeric)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;
