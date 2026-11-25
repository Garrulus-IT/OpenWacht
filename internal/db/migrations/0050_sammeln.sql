-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.1: Mail- und SMS-Kanäle sammeln Meldungen eine Minute lang und schicken
-- sie dann gemeinsam (eine Mail bzw. eine SMS statt vieler). Der Schalter ist
-- je Kanal; ab Werk an, auch für vorhandene Kanäle. Für andere Arten gilt er
-- nicht.

ALTER TABLE openwacht.alert_channels ADD COLUMN collect boolean NOT NULL DEFAULT true;
GRANT SELECT (collect), INSERT (collect), UPDATE (collect) ON openwacht.alert_channels TO openwacht_app;

-- Für den Versand (ohne Sitzung, daher als Eigentümer): welche der Kanäle sammeln.
CREATE FUNCTION openwacht.alert_channels_collecting(p_ids uuid[]) RETURNS TABLE (id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id FROM openwacht.alert_channels c
     WHERE c.id = ANY (p_ids) AND c.collect AND c.kind IN ('mail', 'sms')
$$;
REVOKE ALL ON FUNCTION openwacht.alert_channels_collecting(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_channels_collecting(uuid[]) TO openwacht_app;
