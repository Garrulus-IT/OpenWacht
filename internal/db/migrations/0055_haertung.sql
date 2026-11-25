-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.5 (Pentest-Hinweis H6): Grenze für Meldungen eines Agents auch in der
-- Datenbank. Die Zentrale lässt je Agent und Minute 12 Meldungen durch
-- (agentReportsPerMinute); agent_report nimmt danach je Minute höchstens 20
-- Meldungen mit Messwerten an. Weitere Meldungen aktualisieren nur noch
-- „zuletzt gesehen“ und den Zustand, schreiben aber keine Zeilen mehr in
-- metrics_host_raw. So füllt auch eine Zentrale mit Fehler in der Grenze
-- die Platte nicht.

ALTER TABLE openwacht.agents
    ADD COLUMN report_window timestamptz,
    ADD COLUMN report_count  integer NOT NULL DEFAULT 0 CHECK (report_count >= 0);

CREATE OR REPLACE FUNCTION openwacht.agent_report(p_agent uuid, p_serial text, p_hostname text, p_snapshot jsonb,
                                                 p_series text[], p_values double precision[], p_addr inet)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
    v_count  integer;
BEGIN
    IF cardinality(p_series) IS DISTINCT FROM cardinality(p_values) OR cardinality(p_series) > 100 THEN
        RAISE EXCEPTION 'agent_report: Reihen ungültig' USING ERRCODE = '22023';
    END IF;
    UPDATE openwacht.agents
       SET last_seen = now(), hostname = p_hostname, snapshot = p_snapshot,
           last_addr = coalesce(p_addr, last_addr),
           cert_serial_prev = CASE WHEN p_serial = cert_serial THEN NULL ELSE cert_serial_prev END,
           report_count = CASE WHEN report_window > now() - interval '1 minute' THEN least(report_count + 1, 1000000) ELSE 1 END,
           report_window = CASE WHEN report_window > now() - interval '1 minute' THEN report_window ELSE now() END
     WHERE id = p_agent AND revoked_at IS NULL
       AND p_serial IN (cert_serial, cert_serial_prev)
    RETURNING tenant_id, report_count INTO v_tenant, v_count;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF v_count > 20 THEN
        IF v_count = 21 THEN
            RAISE WARNING 'Verlauf: Agent % meldet zu oft, Messwerte bis zur nächsten Minute verworfen', p_agent;
        END IF;
        RETURN true;
    END IF;
    BEGIN
        INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
        SELECT DISTINCT ON (x.series) v_tenant, p_agent, now(), x.series, x.value
          FROM unnest(p_series, p_values) AS x(series, value);
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'Verlauf: Messwerte von Agent % nicht gespeichert: %', p_agent, SQLERRM;
    END;
    RETURN true;
END
$$;

-- Pentest-Hinweis H2: Eine Wandanzeige liest in der Datenbank nur offene
-- Alarme (mehr zeigt sie nicht). Die Rohwerte der Agents bleiben lesbar,
-- weil der Zustand „CPU“ daraus berechnet wird (agent_cpu15).
ALTER POLICY alarms_select ON openwacht.alarms
    USING (tenant_id IN (SELECT openwacht.visible_tenants())
           OR (ended_at IS NULL AND tenant_id IN (SELECT openwacht.display_tenants())));
