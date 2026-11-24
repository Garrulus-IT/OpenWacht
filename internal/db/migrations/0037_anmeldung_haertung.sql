-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 30: Härtung der Anmeldung (Review 22.11.2026, Befunde M1, M4, M8,
-- N5, I2).
--
-- M4 (Entscheidung, 22.11.2026: Mischform): Die Kontosperre gilt nur noch für das
-- Paar Konto + Quelle (IPv4-Adresse bzw. IPv6-/64). Andere Quellen bekommen
-- nach fünf Fehlversuchen nur eine wachsende Wartezeit je Konto; Quellen, von
-- denen sich das Konto in den letzten 90 Tagen erfolgreich angemeldet hat,
-- bleiben davon verschont. Wer die Anmeldeseite erreicht, kann damit niemanden
-- mehr aussperren, und laufende Sitzungen enden durch Fehlversuche nicht mehr.
-- Leitprinzip 5: Die Quelle wird nur als HMAC mit einem Schlüssel der Zentrale
-- gespeichert (Gleichheit prüfbar, Adresse nicht lesbar), Zeilen verfallen
-- nach 90 Tagen ohne Aktivität.
--
-- M8: Der Betreiber braucht immer eingerichtetes TOTP, unabhängig von der
-- Einstellung „freiwillig“.
--
-- N5 (Entscheidung, 22.11.2026: kein Zurücksetzen in der Oberfläche): zehn
-- Einmal-Codes je Konto (nur HMAC gespeichert) und der Shell-Befehl
-- zweifaktor-zuruecksetzen für den Eigentümer der Datenbank.
--
-- M1: Anmelde-Domänen und NetBIOS-Namen einer Anbindung außerhalb des
-- Hauptmandanten gelten erst nach Freigabe durch den Betreiber.
--
-- I2: Höchstdauer der Sitzung je Anbindung (1 bis 12 Stunden).

-- ---------------------------------------------------------------------------
-- Audit: neue Anmeldeaktionen
-- ---------------------------------------------------------------------------

-- 'bestaetigung.fehlgeschlagen' rief die Zentrale schon seit 0.22 auf, die
-- Liste kannte sie aber nicht (der Eintrag ging verloren).
CREATE OR REPLACE FUNCTION openwacht.audit_auth(p_user uuid, p_action text, p_details jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_action NOT IN ('anmeldung.erfolg', 'anmeldung.fehlgeschlagen', 'anmeldung.gesperrt',
                        'abmeldung', 'zweifaktor.eingerichtet', 'passwort.geaendert',
                        'bestaetigung.fehlgeschlagen', 'zweifaktor.code_verwendet',
                        'zweifaktor.codes_erzeugt') THEN
        RAISE EXCEPTION 'unbekannte Anmeldeaktion %', p_action;
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    SELECT u.tenant_id, p_action, coalesce(p_details, '{}'::jsonb)
      FROM openwacht.users u WHERE u.id = p_user;
END
$$;

-- ---------------------------------------------------------------------------
-- M4: Fehlversuche je Konto und Quelle
-- ---------------------------------------------------------------------------

-- Ausnahme vom Grundsatz „jede fachliche Tabelle hat tenant_id“ wie bei
-- sessions: technische Daten der Anmeldung, nur über Funktionen erreichbar.
CREATE TABLE openwacht.login_sources (
    user_id      uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    source_hash  bytea NOT NULL CHECK (octet_length(source_hash) = 32),
    failures     integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_until timestamptz,
    last_failed  timestamptz,
    last_success timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, source_hash)
);
CREATE INDEX login_sources_updated ON openwacht.login_sources (updated_at);
ALTER TABLE openwacht.login_sources ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.login_sources FROM PUBLIC, openwacht_app;

-- Nächster freier Zeitpunkt für einen Versuch aus einer unbekannten Quelle.
ALTER TABLE openwacht.users ADD COLUMN login_next_slot timestamptz;

-- Bisherige Sperren aufheben: Sie galten für das ganze Konto.
UPDATE openwacht.users SET locked_until = NULL, failed_logins = 0 WHERE locked_until IS NOT NULL OR failed_logins <> 0;

-- Darf ein Versuch von dieser Quelle jetzt geprüft werden?
--   -1  Quelle für dieses Konto gesperrt
--   -2  zu viele Versuche aus unbekannten Quellen (Wartezeit über 30 s)
--   >=0 so viele Millisekunden warten, dann prüfen
-- Jeder Aufruf aus einer unbekannten Quelle verbraucht einen Zeitschlitz;
-- so kommen auch parallele Versuche nur einzeln nacheinander dran.
CREATE FUNCTION openwacht.auth_login_gate(p_user uuid, p_source bytea) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_src  openwacht.login_sources;
    v_n    integer;
    v_slot timestamptz;
    v_step interval;
    v_wait interval;
BEGIN
    IF octet_length(p_source) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'ungültige Quelle';
    END IF;
    SELECT * INTO v_src FROM openwacht.login_sources WHERE user_id = p_user AND source_hash = p_source;
    IF v_src.locked_until > now() THEN
        RETURN -1;
    END IF;
    IF v_src.last_success > now() - interval '90 days' THEN
        RETURN 0;
    END IF;
    SELECT u.failed_logins, u.login_next_slot INTO v_n, v_slot FROM openwacht.users u WHERE u.id = p_user FOR UPDATE;
    IF NOT FOUND OR v_n < 5 THEN
        RETURN 0;
    END IF;
    -- 1, 2, 4, 8 Sekunden, höchstens 15 Sekunden je Versuch
    v_step := least(interval '15 seconds', interval '1 second' * power(2, least(v_n - 5, 10)));
    v_slot := greatest(now(), coalesce(v_slot, now()));
    v_wait := v_slot - now();
    IF v_wait > interval '30 seconds' THEN
        RETURN -2;
    END IF;
    UPDATE openwacht.users SET login_next_slot = v_slot + v_step WHERE id = p_user;
    RETURN ceil(extract(epoch FROM v_wait) * 1000)::integer;
END
$$;

-- Nur die Sperre der Quelle (zweiter Faktor, Bestätigung per Passwort).
CREATE FUNCTION openwacht.auth_source_locked(p_user uuid, p_source bytea) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (SELECT 1 FROM openwacht.login_sources s
                    WHERE s.user_id = p_user AND s.source_hash = p_source AND s.locked_until > now())
$$;

-- Fehlversuch zählen: für das Konto (Wartezeit anderer Quellen) und für die
-- Quelle. Ab dem 5. Fehlversuch einer Quelle ist sie gesperrt: 1, 2, 4 …
-- Minuten, höchstens 60 Minuten.
DROP FUNCTION openwacht.auth_login_failed(uuid);
CREATE FUNCTION openwacht.auth_login_failed(p_user uuid, p_source bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF octet_length(p_source) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'ungültige Quelle';
    END IF;
    UPDATE openwacht.users SET failed_logins = failed_logins + 1 WHERE id = p_user;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO openwacht.login_sources AS s (user_id, source_hash, failures, last_failed, updated_at)
    VALUES (p_user, p_source, 1, now(), now())
    ON CONFLICT (user_id, source_hash) DO UPDATE
       SET failures = s.failures + 1,
           last_failed = now(),
           updated_at = now(),
           locked_until = CASE
               WHEN s.failures + 1 >= 5 THEN
                   now() + least(interval '60 minutes',
                                 interval '1 minute' * power(2, least(s.failures + 1 - 5, 10)))
               ELSE s.locked_until END;
    -- Höchstens 100 Quellen je Konto (die ältesten fallen weg), keine Zeilen
    -- ohne Aktivität seit 90 Tagen.
    DELETE FROM openwacht.login_sources s
     WHERE s.user_id = p_user
       AND s.source_hash NOT IN (SELECT x.source_hash FROM openwacht.login_sources x
                                  WHERE x.user_id = p_user ORDER BY x.updated_at DESC LIMIT 100);
    DELETE FROM openwacht.login_sources WHERE updated_at < now() - interval '90 days';
END
$$;

DROP FUNCTION openwacht.auth_login_succeeded(uuid);
CREATE FUNCTION openwacht.auth_login_succeeded(p_user uuid, p_source bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF octet_length(p_source) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'ungültige Quelle';
    END IF;
    UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = p_user;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO openwacht.login_sources AS s (user_id, source_hash, last_success, updated_at)
    VALUES (p_user, p_source, now(), now())
    ON CONFLICT (user_id, source_hash) DO UPDATE
       SET failures = 0, locked_until = NULL, last_success = now(), updated_at = now();
END
$$;

-- Entsperren auf der Shell (nur Eigentümer, Befehl entsperren). Liefert die
-- Zahl der aufgehobenen Quellen-Sperren oder NULL, wenn es das Konto nicht gibt.
CREATE FUNCTION openwacht.auth_unlock(p_email text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user   uuid;
    v_tenant uuid;
    v_n      integer;
BEGIN
    SELECT u.id, u.tenant_id INTO v_user, v_tenant FROM openwacht.users u WHERE u.email = lower(btrim(p_email));
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO v_n FROM openwacht.login_sources WHERE user_id = v_user AND locked_until > now();
    DELETE FROM openwacht.login_sources WHERE user_id = v_user AND last_success IS NULL;
    UPDATE openwacht.login_sources SET failures = 0, locked_until = NULL, updated_at = now() WHERE user_id = v_user;
    UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = v_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'konto.entsperrt', jsonb_build_object('benutzer', v_user, 'email', lower(btrim(p_email)),
                                                            'quelle', 'shell', 'sperren', v_n));
    RETURN v_n;
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_unlock(text) FROM PUBLIC;

-- Anmeldung über das Verzeichnis: ohne locked_until (gilt nicht mehr).
-- (auth_state bleibt mit derselben Signatur; locked_until ist immer NULL.)

-- ---------------------------------------------------------------------------
-- M8: Betreiber immer mit Zwei-Faktor
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.mfa_required_for(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE
        WHEN u.auth_source = 'token' THEN false
        WHEN u.platform_operator THEN true
        WHEN u.directory_id IS NOT NULL THEN coalesce((SELECT d.mfa_required FROM openwacht.directories d WHERE d.id = u.directory_id), false)
        ELSE CASE coalesce((SELECT s.mfa_policy FROM openwacht.settings s), 'admins')
            WHEN 'alle' THEN true
            WHEN 'freiwillig' THEN false
            ELSE EXISTS (SELECT 1 FROM openwacht.role_assignments r WHERE r.user_id = u.id AND r.role = 'admin')
        END
    END
      FROM openwacht.users u WHERE u.id = p_user
$$;

CREATE OR REPLACE FUNCTION openwacht.is_platform_operator() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1 FROM openwacht.users u JOIN openwacht.tenants t ON t.id = u.tenant_id
         WHERE u.id = openwacht.current_user_id() AND u.platform_operator
           AND NOT u.disabled AND u.totp_enabled AND t.parent_id IS NULL)
$$;

-- ---------------------------------------------------------------------------
-- N5: Wiederherstellungscodes und Zurücksetzen auf der Shell
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.recovery_codes (
    user_id    uuid NOT NULL REFERENCES openwacht.users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    PRIMARY KEY (user_id, code_hash)
);
ALTER TABLE openwacht.recovery_codes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.recovery_codes FROM PUBLIC, openwacht_app;

-- Neue Codes (genau zehn) für das eigene Konto; die alten verfallen.
CREATE FUNCTION openwacht.auth_recovery_set(p_user uuid, p_hashes bytea[]) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    IF coalesce(array_length(p_hashes, 1), 0) <> 10
       OR EXISTS (SELECT 1 FROM unnest(p_hashes) h WHERE octet_length(h) IS DISTINCT FROM 32)
       OR (SELECT count(DISTINCT h) FROM unnest(p_hashes) h) <> 10 THEN
        RAISE EXCEPTION 'genau zehn verschiedene Codes' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = p_user AND u.totp_enabled) THEN
        RAISE EXCEPTION 'Zwei-Faktor ist nicht eingerichtet' USING ERRCODE = '55000';
    END IF;
    DELETE FROM openwacht.recovery_codes WHERE user_id = p_user;
    INSERT INTO openwacht.recovery_codes (user_id, code_hash) SELECT p_user, h FROM unnest(p_hashes) h;
END
$$;

-- Code verbrauchen. Liefert die Zahl der danach noch offenen Codes oder -1,
-- wenn der Code nicht passt oder schon benutzt ist.
CREATE FUNCTION openwacht.auth_recovery_use(p_user uuid, p_hash bytea) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    UPDATE openwacht.recovery_codes SET used_at = now()
     WHERE user_id = p_user AND code_hash = p_hash AND used_at IS NULL
       AND EXISTS (SELECT 1 FROM openwacht.users u WHERE u.id = p_user AND u.totp_enabled);
    IF NOT FOUND THEN
        RETURN -1;
    END IF;
    RETURN (SELECT count(*) FROM openwacht.recovery_codes WHERE user_id = p_user AND used_at IS NULL);
END
$$;

CREATE FUNCTION openwacht.auth_recovery_left(p_user uuid) RETURNS integer
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    PERFORM openwacht.require_self(p_user);
    RETURN (SELECT count(*) FROM openwacht.recovery_codes WHERE user_id = p_user AND used_at IS NULL);
END
$$;

-- Zwei-Faktor eines Kontos zurücksetzen (nur Eigentümer, Befehl
-- zweifaktor-zuruecksetzen). Beendet alle Sitzungen; bei der nächsten
-- Anmeldung richtet das Konto 2FA neu ein, wenn sie Pflicht ist.
CREATE FUNCTION openwacht.auth_2fa_reset(p_email text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_user   uuid;
    v_tenant uuid;
    v_had    boolean;
BEGIN
    SELECT u.id, u.tenant_id, u.totp_enabled INTO v_user, v_tenant, v_had
      FROM openwacht.users u WHERE u.email = lower(btrim(p_email)) AND u.auth_source <> 'token';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    UPDATE openwacht.users SET totp_secret_enc = NULL, totp_enabled = false WHERE id = v_user;
    DELETE FROM openwacht.recovery_codes WHERE user_id = v_user;
    DELETE FROM openwacht.sessions WHERE user_id = v_user;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, 'zweifaktor.zurueckgesetzt', jsonb_build_object('benutzer', v_user, 'email', lower(btrim(p_email)),
                                                                      'quelle', 'shell', 'war_aktiv', v_had));
    RETURN v_had;
END
$$;
REVOKE ALL ON FUNCTION openwacht.auth_2fa_reset(text) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- M1: Anmelde-Domänen und NetBIOS-Namen nur nach Freigabe
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.directory_domains
    ADD COLUMN status text NOT NULL DEFAULT 'freigegeben' CHECK (status IN ('beantragt', 'freigegeben', 'abgelehnt')),
    ADD COLUMN requested_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN decided_at timestamptz;
-- Eine Domäne darf mehrfach beantragt, aber nur einmal freigegeben sein.
-- Ein Antrag sperrt sie damit nicht mehr für die echte Anbindung.
ALTER TABLE openwacht.directory_domains DROP CONSTRAINT directory_domains_pkey;
ALTER TABLE openwacht.directory_domains ADD PRIMARY KEY (domain, directory_id);
CREATE UNIQUE INDEX directory_domains_approved ON openwacht.directory_domains (domain) WHERE status = 'freigegeben';
GRANT SELECT (status, requested_at, decided_at) ON openwacht.directory_domains TO openwacht_app;
-- Die Anwendung schreibt nur Domäne, Anbindung und Mandant; den Zustand
-- setzen Trigger und Betreiber-Funktion.
REVOKE INSERT ON openwacht.directory_domains FROM openwacht_app;
GRANT INSERT (domain, directory_id, tenant_id) ON openwacht.directory_domains TO openwacht_app;

ALTER TABLE openwacht.directories
    ADD COLUMN netbios_status text NOT NULL DEFAULT 'freigegeben'
        CHECK (netbios_status IN ('beantragt', 'freigegeben', 'abgelehnt'));
DROP INDEX openwacht.directories_netbios;
CREATE UNIQUE INDEX directories_netbios ON openwacht.directories (upper(netbios))
    WHERE netbios IS NOT NULL AND netbios_status = 'freigegeben';
GRANT SELECT (netbios_status) ON openwacht.directories TO openwacht_app;

-- Neue Domäne: im Hauptmandanten sofort frei, sonst beantragt (mit Audit).
CREATE FUNCTION openwacht.directory_domains_claim() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    NEW.requested_at := now();
    NEW.decided_at := NULL;
    IF (SELECT t.parent_id FROM openwacht.tenants t WHERE t.id = NEW.tenant_id) IS NULL THEN
        NEW.status := 'freigegeben';
        NEW.decided_at := now();
    ELSE
        NEW.status := 'beantragt';
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NEW.tenant_id, 'domaene.beantragt', jsonb_build_object('verzeichnis', NEW.directory_id, 'domaene', NEW.domain));
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER directory_domains_claim BEFORE INSERT ON openwacht.directory_domains
    FOR EACH ROW EXECUTE FUNCTION openwacht.directory_domains_claim();

-- Neuer oder geänderter NetBIOS-Name: ebenso.
CREATE FUNCTION openwacht.directories_netbios_claim() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    -- Name unverändert: Zustand bleibt. Die Anwendung darf netbios_status nicht
    -- schreiben (Spaltenrechte); ändern kann ihn nur login_claim_decide.
    IF TG_OP = 'UPDATE' AND upper(NEW.netbios) IS NOT DISTINCT FROM upper(OLD.netbios) THEN
        RETURN NEW;
    END IF;
    IF NEW.netbios IS NULL OR (SELECT t.parent_id FROM openwacht.tenants t WHERE t.id = NEW.tenant_id) IS NULL THEN
        NEW.netbios_status := 'freigegeben';
    ELSE
        NEW.netbios_status := 'beantragt';
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NEW.tenant_id, 'netbios.beantragt', jsonb_build_object('verzeichnis', NEW.id, 'netbios', NEW.netbios));
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER directories_netbios_claim BEFORE INSERT OR UPDATE ON openwacht.directories
    FOR EACH ROW EXECUTE FUNCTION openwacht.directories_netbios_claim();

-- Anmeldung: nur freigegebene Domänen und NetBIOS-Namen.
CREATE OR REPLACE FUNCTION openwacht.directory_for_login(p_domain text, p_netbios text)
    RETURNS TABLE (id uuid, tenant_id uuid, url text, ca_pem text, bind_dn text, bind_pass_enc bytea, base_dn text,
                   nested_groups boolean, kind text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.id, d.tenant_id, d.url, d.ca_pem, d.bind_dn, d.bind_pass_enc, d.base_dn, d.nested_groups, d.kind
      FROM openwacht.directories d
     WHERE d.enabled
       AND ((p_domain IS NOT NULL AND d.id = (SELECT dd.directory_id FROM openwacht.directory_domains dd
                                               WHERE dd.domain = lower(p_domain) AND dd.status = 'freigegeben'))
         OR (p_netbios IS NOT NULL AND upper(d.netbios) = upper(p_netbios) AND d.netbios_status = 'freigegeben'))
     LIMIT 1
$$;

-- Adressen von Konten nur aus freigegebenen Domänen.
CREATE OR REPLACE FUNCTION openwacht.directory_domain_list(p_directory uuid) RETURNS SETOF text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT dd.domain FROM openwacht.directory_domains dd WHERE dd.directory_id = p_directory AND dd.status = 'freigegeben'
$$;

-- Anträge für den Betreiber (alle Mandanten).
CREATE FUNCTION openwacht.login_claims()
    RETURNS TABLE (directory_id uuid, directory_name text, tenant_name text, kind text, value text,
                   status text, requested_at timestamptz, conflict boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur der Betreiber' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT d.id, d.name, t.name, 'domaene'::text, dd.domain, dd.status, dd.requested_at,
           EXISTS (SELECT 1 FROM openwacht.directory_domains x
                    WHERE x.domain = dd.domain AND x.status = 'freigegeben' AND x.directory_id <> dd.directory_id)
      FROM openwacht.directory_domains dd
      JOIN openwacht.directories d ON d.id = dd.directory_id
      JOIN openwacht.tenants t ON t.id = d.tenant_id
     WHERE dd.status <> 'freigegeben' OR t.parent_id IS NOT NULL
    UNION ALL
    SELECT d.id, d.name, t.name, 'netbios'::text, d.netbios, d.netbios_status, d.updated_at,
           EXISTS (SELECT 1 FROM openwacht.directories x
                    WHERE upper(x.netbios) = upper(d.netbios) AND x.netbios_status = 'freigegeben' AND x.id <> d.id)
      FROM openwacht.directories d
      JOIN openwacht.tenants t ON t.id = d.tenant_id
     WHERE d.netbios IS NOT NULL AND (d.netbios_status <> 'freigegeben' OR t.parent_id IS NOT NULL)
     ORDER BY 6, 3, 2, 5;
END
$$;

-- Antrag freigeben oder ablehnen (Betreiber). Freigeben scheitert, wenn die
-- Domäne bzw. der Name schon für eine andere Anbindung frei ist.
CREATE FUNCTION openwacht.login_claim_decide(p_directory uuid, p_kind text, p_value text, p_approve boolean) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
    v_status text := CASE WHEN p_approve THEN 'freigegeben' ELSE 'abgelehnt' END;
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur der Betreiber' USING ERRCODE = '42501';
    END IF;
    IF p_kind = 'domaene' THEN
        UPDATE openwacht.directory_domains SET status = v_status, decided_at = now()
         WHERE directory_id = p_directory AND domain = lower(p_value)
        RETURNING tenant_id INTO v_tenant;
    ELSIF p_kind = 'netbios' THEN
        UPDATE openwacht.directories SET netbios_status = v_status
         WHERE id = p_directory AND upper(netbios) = upper(p_value)
        RETURNING tenant_id INTO v_tenant;
    ELSE
        RAISE EXCEPTION 'Art: domaene oder netbios' USING ERRCODE = '22023';
    END IF;
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'Antrag nicht gefunden' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (v_tenant, CASE WHEN p_kind = 'domaene' THEN 'domaene.' ELSE 'netbios.' END
                      || CASE WHEN p_approve THEN 'freigegeben' ELSE 'abgelehnt' END,
            jsonb_build_object('verzeichnis', p_directory, 'wert', p_value));
    -- Auch im Mandanten des Betreibers nachvollziehbar
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    SELECT u.tenant_id, 'anmeldedomaene.entschieden',
           jsonb_build_object('verzeichnis', p_directory, 'art', p_kind, 'wert', p_value, 'freigegeben', p_approve)
      FROM openwacht.users u WHERE u.id = openwacht.current_user_id() AND u.tenant_id IS DISTINCT FROM v_tenant;
END
$$;

-- ---------------------------------------------------------------------------
-- I2: Höchstdauer der Sitzung je Anbindung
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.directories
    ADD COLUMN session_hours integer CHECK (session_hours BETWEEN 1 AND 12);
GRANT SELECT (session_hours), INSERT (session_hours), UPDATE (session_hours) ON openwacht.directories TO openwacht_app;

-- Höchstdauer für ein Konto (NULL = Standard der Zentrale).
CREATE FUNCTION openwacht.session_max_for(p_user uuid) RETURNS interval
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT interval '1 hour' * d.session_hours
      FROM openwacht.users u JOIN openwacht.directories d ON d.id = u.directory_id
     WHERE u.id = p_user AND d.session_hours IS NOT NULL
$$;

-- ---------------------------------------------------------------------------
-- Rechte
-- ---------------------------------------------------------------------------

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['auth_login_gate(uuid, bytea)', 'auth_source_locked(uuid, bytea)',
        'auth_login_failed(uuid, bytea)', 'auth_login_succeeded(uuid, bytea)',
        'auth_recovery_set(uuid, bytea[])', 'auth_recovery_use(uuid, bytea)', 'auth_recovery_left(uuid)',
        'login_claims()', 'login_claim_decide(uuid, text, text, boolean)', 'session_max_for(uuid)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;
