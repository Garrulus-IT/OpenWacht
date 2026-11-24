// SPDX-License-Identifier: AGPL-3.0-only

import { LizenzHinweis } from "./Lizenz";
import { useState, type FormEvent } from "react";
import { api, ApiError, setCsrf } from "./api";
import { Wortmarke } from "./Wortmarke";
import { Siegel } from "./Zeichen";
import { passkeyFehler, passkeyMoeglich, passkeyNutzen, type AnmeldeOptionen } from "./passkey";

interface Props {
  onAngemeldet: () => void;
}

// Rückkehr vom Firmen-Login (SSO, Etappe 22b): feste Codes, keine Texte vom IdP.
const ssoMeldung: Record<string, string> = {
  abgelaufen: "Die Anmeldung über den Firmen-Login ist abgelaufen. Bitte erneut versuchen.",
  abgebrochen: "Die Anmeldung über den Firmen-Login wurde abgebrochen.",
  abgelehnt: "Der Firmen-Login hat die Anmeldung nicht bestätigt.",
  "keine-rechte": "Dein Konto hat in OpenWacht keine Rechte. Bitte wende dich an deine IT.",
  "nicht-erreichbar": "Der Firmen-Login ist gerade nicht erreichbar.",
  "zu-viele": "Zu viele Anmeldeversuche. Bitte kurz warten.",
  fehler: "Die Anmeldung ist fehlgeschlagen. Bitte erneut versuchen.",
};

function ssoAusAdresse(): string {
  const v = new URLSearchParams(window.location.search).get("sso") ?? "";
  if (v) window.history.replaceState(null, "", window.location.pathname);
  return v;
}

export function Anmeldung({ onAngemeldet }: Props) {
  const [sso] = useState(ssoAusAdresse);
  const [schritt, setSchritt] = useState<"passwort" | "code">(sso === "zweiter-faktor" ? "code" : "passwort");
  const [email, setEmail] = useState("");
  const [passwort, setPasswort] = useState("");
  const [code, setCode] = useState("");
  // Wiederherstellungscode statt Code aus der App (Etappe 30)
  const [mitNotfallcode, setMitNotfallcode] = useState(false);
  const [fehler, setFehler] = useState(ssoMeldung[sso] ?? "");
  const [arbeitet, setArbeitet] = useState(false);
  // Passkey als zweiter Faktor (Etappe 36), wenn das Konto einen hat
  const [passkey, setPasskey] = useState(false);

  const mitPasskey = async () => {
    setFehler("");
    setArbeitet(true);
    try {
      const o = await api<AnmeldeOptionen>("POST", "/api/v1/sitzung/passkey/optionen");
      const antwort = await passkeyNutzen(o);
      const r = await api<{ csrf: string }>("POST", "/api/v1/sitzung/passkey", antwort);
      setCsrf(r.csrf);
      onAngemeldet();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && /abgelaufen/.test(err.message)) {
        setSchritt("passwort");
      }
      setFehler(err instanceof ApiError ? err.message : passkeyFehler(err));
    } finally {
      setArbeitet(false);
    }
  };

  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setArbeitet(true);
    try {
      if (schritt === "passwort") {
        const r = await api<{ csrf?: string; zweiter_faktor?: boolean; passkey?: boolean }>("POST", "/api/v1/sitzung", { email, passwort });
        setPasswort("");
        if (r.zweiter_faktor) {
          setPasskey(!!r.passkey && passkeyMoeglich());
          setSchritt("code");
          return;
        }
        setCsrf(r.csrf);
      } else {
        const r = await api<{ csrf: string }>("POST", "/api/v1/sitzung/zweiter-faktor", { code });
        setCsrf(r.csrf);
      }
      onAngemeldet();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && schritt === "code" && /abgelaufen/.test(err.message)) {
        setSchritt("passwort");
      }
      setCode("");
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  const firmenLogin = async () => {
    setFehler("");
    if (!email.includes("@")) {
      setFehler("Für den Firmen-Login bitte die E-Mail-Adresse eingeben.");
      return;
    }
    setArbeitet(true);
    try {
      const r = await api<{ weiterleitung: string }>("POST", "/api/v1/sitzung/sso", { email });
      window.location.assign(r.weiterleitung);
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
      setArbeitet(false);
    }
  };

  return (
    <main className="seite-mittig anmeldung">
      <form className="tafel" onSubmit={senden} noValidate>
        <Wortmarke />
        {schritt === "passwort" ? (
          <>
            <label className="feld">
              <span>E-Mail-Adresse oder AD-Anmeldename</span>
              <input
                type="text"
                spellCheck={false}
                autoCapitalize="none"
                autoComplete="username"
                required
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>
            <label className="feld">
              <span>Passwort</span>
              <input
                type="password"
                autoComplete="current-password"
                required
                value={passwort}
                onChange={(e) => setPasswort(e.target.value)}
              />
            </label>
          </>
        ) : (
          <>
            {passkey && !mitNotfallcode && (
              <>
                <button type="button" className="knopf knopf-haupt" disabled={arbeitet} onClick={() => void mitPasskey()}>
                  Mit Passkey anmelden
                </button>
                <p className="klein trenner-text">oder mit dem Code aus der App</p>
              </>
            )}
            {mitNotfallcode ? (
              <>
                <p className="hinweis">
                  Gib einen deiner Wiederherstellungscodes ein (Form xxxxx-xxxxx). Jeder Code gilt nur einmal; erzeuge danach neue Codes.
                </p>
                <label className="feld">
                  <span>Wiederherstellungscode</span>
                  <input
                    className="code-eingabe"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    maxLength={20}
                    required
                    autoFocus
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/[^A-Za-z0-9 -]/g, ""))}
                  />
                </label>
              </>
            ) : (
              <>
                <p className="hinweis">Gib den sechsstelligen Code aus deiner Authenticator-App ein.</p>
                <label className="feld">
                  <span>Code</span>
                  <input
                    className="code-eingabe"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    required
                    autoFocus={!passkey}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  />
                </label>
              </>
            )}
          </>
        )}
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
        <button className={passkey && schritt === "code" ? "knopf" : "knopf knopf-haupt"} type="submit" disabled={arbeitet}>
          {schritt === "passwort" ? "Anmelden" : "Code bestätigen"}
        </button>
        {schritt === "passwort" && (
          <button type="button" className="knopf" disabled={arbeitet} onClick={() => void firmenLogin()}>
            Mit Firmen-Login anmelden (SSO)
          </button>
        )}
        {schritt === "code" && (
          <button
            type="button"
            className="knopf-text"
            onClick={() => {
              setMitNotfallcode(!mitNotfallcode);
              setCode("");
              setFehler("");
            }}
          >
            {mitNotfallcode ? "Code aus der App verwenden" : "Gerät verloren? Wiederherstellungscode verwenden"}
          </button>
        )}
        {schritt === "code" && (
          <button
            type="button"
            className="knopf-text"
            onClick={() => {
              setSchritt("passwort");
              setFehler("");
            }}
          >
            Mit anderem Konto anmelden
          </button>
        )}
      </form>
      <Siegel />
      <LizenzHinweis />
    </main>
  );
}
