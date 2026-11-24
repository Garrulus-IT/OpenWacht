// SPDX-License-Identifier: AGPL-3.0-only

// Verwaltung › API-Tokens (Etappe 22b): Zugriff für Skripte und andere
// Werkzeuge (z. B. Grafana) per „Authorization: Bearer owt1.…“. Rolle Leser
// oder Operator, höchstens ein Jahr gültig. Das Token zeigt die Oberfläche nur
// einmal; gespeichert ist nur sein Hash.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type Mandant } from "./api";
import { bestaetigungFertig, CodeFeld } from "./Bestaetigung";
import { vor } from "./zeit";

interface Token {
  id: string;
  mandant: string;
  mandant_name: string;
  name: string;
  rolle: "leser" | "operator";
  ablauf: string;
  angelegt: string;
  zuletzt: string | null;
  widerrufen: string | null;
  von: string;
  gueltig: boolean;
}

const datum = (s: string) => new Date(s).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });

export function ApiTokens(props: { mandant: Mandant; melden: (e: unknown) => void }) {
  const { mandant, melden } = props;
  const admin = mandant.rolle === "admin";
  const [liste, setListe] = useState<Token[] | null>(null);
  const [neu, setNeu] = useState(false);
  const [frisch, setFrisch] = useState<{ token: string; name: string } | null>(null);

  const laden = useCallback(async () => {
    try {
      const r = await api<{ tokens: Token[] }>("GET", "/api/v1/api-tokens");
      setListe(r.tokens);
    } catch (e) {
      melden(e);
    }
  }, [melden]);
  useEffect(() => {
    void laden();
  }, [laden]);

  return (
    <>
      <div className="abschnitt-kopf">
        <h2 className="abschnitt">API-Tokens</h2>
        {admin && !neu && (
          <button className="knopf" onClick={() => setNeu(true)}>
            Token anlegen
          </button>
        )}
      </div>
      <p className="klein">
        Für Skripte und andere Werkzeuge: Anfragen an <code>/api/v1/…</code> mit dem Kopf <code>Authorization: Bearer owt1.…</code>. Ein
        Token sieht und darf, was seine Rolle im Mandanten und darunter erlaubt; Verwaltung und Einstellungen gehen damit nicht.
      </p>
      {!admin && <p className="leer">Nur Admins des Mandanten legen API-Tokens an.</p>}
      {frisch && (
        <div className="meldung meldung-ok" role="status">
          <p>Token „{frisch.name}“ – jetzt kopieren, es wird nicht noch einmal angezeigt:</p>
          <pre className="befehl">{frisch.token}</pre>
          <div className="aktionen">
            <button className="knopf" onClick={() => void navigator.clipboard?.writeText(frisch.token)}>
              Kopieren
            </button>
            <button className="knopf" onClick={() => setFrisch(null)}>
              Fertig
            </button>
          </div>
        </div>
      )}
      {neu && (
        <TokenFormular
          mandant={mandant}
          onFertig={(t) => {
            setNeu(false);
            setFrisch(t);
            void laden();
          }}
          onAbbrechen={() => setNeu(false)}
          melden={melden}
        />
      )}
      {liste === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : liste.length === 0 ? (
        admin && <p className="leer">Noch keine API-Tokens.</p>
      ) : (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Mandant</th>
              <th scope="col">Rolle</th>
              <th scope="col">Gültig bis</th>
              <th scope="col">Zuletzt benutzt</th>
              <th scope="col">Aktionen</th>
            </tr>
          </thead>
          <tbody>
            {liste.map((t) => (
              <tr key={t.id} className={t.gueltig ? undefined : "zeile-aus"}>
                <td>
                  <div className="name">{t.name}</div>
                  <div className="klein">
                    angelegt {datum(t.angelegt)}
                    {t.von ? ` von ${t.von}` : ""}
                  </div>
                </td>
                <td>{t.mandant_name}</td>
                <td>{t.rolle === "operator" ? "Operator" : "Leser"}</td>
                <td>{t.widerrufen ? "widerrufen" : t.gueltig ? datum(t.ablauf) : "abgelaufen"}</td>
                <td>{t.zuletzt ? vor(t.zuletzt, Date.now()) : "nie"}</td>
                <td>
                  {t.gueltig && (
                    <button
                      className="knopf knopf-gefahr"
                      onClick={async () => {
                        try {
                          await api("DELETE", `/api/v1/api-tokens/${t.id}`);
                          void laden();
                        } catch (e) {
                          melden(e);
                        }
                      }}
                    >
                      Widerrufen
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function TokenFormular(props: {
  mandant: Mandant;
  onFertig: (t: { token: string; name: string }) => void;
  onAbbrechen: () => void;
  melden: (e: unknown) => void;
}) {
  const [name, setName] = useState("");
  const [rolle, setRolle] = useState("leser");
  const [tage, setTage] = useState("90");
  const [code, setCode] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      const r = await api<{ token: string }>("POST", "/api/v1/api-tokens", {
        mandant: props.mandant.id,
        name: name.trim(),
        rolle,
        tage: Number(tage),
        code,
      });
      props.onFertig({ token: r.token, name: name.trim() });
    } catch (err) {
      setCode("");
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <form className="panel formular" onSubmit={senden} aria-label="API-Token anlegen">
      <div className="panel-inhalt">
        <label className="feld">
          <span>Name (wofür?)</span>
          <input required maxLength={100} placeholder="Grafana" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="feld">
          <span>Rolle in {props.mandant.name}</span>
          <select value={rolle} onChange={(e) => setRolle(e.target.value)}>
            <option value="leser">Leser (nur lesen)</option>
            <option value="operator">Operator (Sensoren, Geräte, Alarme pflegen)</option>
          </select>
        </label>
        <label className="feld">
          <span>Gültig (Tage, höchstens 365)</span>
          <input type="number" min={1} max={365} required value={tage} onChange={(e) => setTage(e.target.value)} />
        </label>
        <CodeFeld wert={code} setWert={setCode} id="api-token-code" />
        <div className="knopf-reihe">
          <button type="button" className="knopf" onClick={props.onAbbrechen}>
            Abbrechen
          </button>
          <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim() || !bestaetigungFertig(code)}>
            Token anlegen
          </button>
        </div>
      </div>
    </form>
  );
}
