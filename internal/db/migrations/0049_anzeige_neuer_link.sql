-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.99.2: „Neuer Link“ für eine Wandanzeige (24.11.2026). Ein Admin des
-- Mandanten ersetzt den Hash des Schlüssels; der alte Link und alle damit
-- angemeldeten Bildschirme gelten sofort nicht mehr (das Cookie enthält den
-- Schlüssel, die Zentrale prüft ihn bei jeder Abfrage). Gespeichert bleibt
-- nur der Hash; der neue Link wird einmal angezeigt.

GRANT UPDATE (token_hash) ON openwacht.displays TO openwacht_app;
CREATE POLICY displays_update ON openwacht.displays FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
