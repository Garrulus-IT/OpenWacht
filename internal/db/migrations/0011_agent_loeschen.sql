-- SPDX-License-Identifier: AGPL-3.0-only

-- 0011: Agents löschen.
--
-- Gelöscht werden darf nur ein gesperrter Agent: Ein aktiver Host verschwindet
-- so nie mit einem Klick samt Verlauf. Dürfen Admins und Operatoren des
-- Mandanten (wie sperren). Mit dem Agent gehen Verlauf, Meldezustand und
-- Wartung (ON DELETE CASCADE); Einträge im Alarmprotokoll bleiben stehen
-- (agent_id wird NULL), das Audit-Log vermerkt das Löschen.

GRANT DELETE ON openwacht.agents TO openwacht_app;
CREATE POLICY agents_delete ON openwacht.agents FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()) AND revoked_at IS NOT NULL);
