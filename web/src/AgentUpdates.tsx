// SPDX-License-Identifier: AGPL-3.0-only

// Verwaltung › Agent-Updates (Etappe 23): signierte Agent-Versionen. Der
// Betreiber lädt Pakete hoch (Binary + .sig aus tools/signieren), Admins geben
// sie je Agent frei. Der Agent prüft die Offline-Signatur selbst; ohne
// Schlüssel im Build sind Updates aus.

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { api, type Ich, type Mandant } from "./api";
import type { Bereich } from "./bereich";
import { vor } from "./zeit";

interface Paket {
  id: string;
  version: string;
  plattform: string;
  sha256: string;
  groesse: number;
  hochgeladen: string;
}

interface AgentZeile {
  id: string;
  mandant: string;
  hostname: string;
  version: string;
  plattform: string;
  fehler: string;
  zuletzt: string | null;
  freigegeben: string | null;
}

interface Schluessel {
  kennung: string;
  zustand: "aktiv" | "reserve" | "auslaufend" | "widerrufen";
}

interface Widerruf {
  kennung: string;
  durch: string;
  version: string;
  am: string;
}

interface Antwort {
  schluessel: string;
  schluesselbund: Schluessel[];
  widerrufen: Widerruf[];
  pakete: Paket[];
  agents: AgentZeile[];
}

const mb = (n: number) => (n / 1048576).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " MB";

function neuer(a: string, b: string): boolean {
  const p = (v: string) => v.split(".").map((x) => Number(x));
  const x = p(a);
  const y = p(b);
  if (x.length !== 3 || x.some(isNaN)) return false;
  if (y.length !== 3 || y.some(isNaN)) return true;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

export function AgentUpdates(props: { ich: Ich; mandant: Mandant; bereich: Bereich; melden: (e: unknown) => void }) {
  const { ich, bereich, melden } = props;
  const [d, setD] = useState<Antwort | null>(null);
  const [auswahl, setAuswahl] = useState<Set<string>>(new Set());
  const [ziel, setZiel] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const laden = useCallback(async () => {
    try {
      setD(await api<Antwort>("GET", "/api/v1/agent-updates"));
    } catch (e) {
      melden(e);
    }
  }, [melden]);
  useEffect(() => {
    void laden();
  }, [laden]);

  const versionen = useMemo(() => [...new Set((d?.pakete ?? []).map((p) => p.version))], [d]);
  useEffect(() => {
    if (!ziel && versionen[0]) setZiel(versionen[0]);
  }, [versionen, ziel]);
  const agents = (d?.agents ?? []).filter((a) => bereich.ids.has(a.mandant));
  const admin = (a: AgentZeile) => bereich.nachId.get(a.mandant)?.rolle === "admin";

  const fuerAlle = async (aktion: "freigeben" | "zuruecknehmen") => {
    setArbeitet(true);
    try {
      for (const id of auswahl) {
        if (aktion === "freigeben") await api("PUT", `/api/v1/agents/${id}/update`, { version: ziel });
        else await api("DELETE", `/api/v1/agents/${id}/update`);
      }
      setAuswahl(new Set());
      await laden();
    } catch (e) {
      melden(e);
    } finally {
      setArbeitet(false);
    }
  };

  if (!d) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }
  return (
    <>
      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Agent-Updates</h2>
      </div>
      <p className="klein">
        Agents installieren nur Versionen, die mit dem Offline-Schlüssel signiert sind, und nur nach Freigabe hier.{" "}
        {d.schluesselbund.length > 0 ? (
          <>
            Schlüssel dieses Builds:{" "}
            {d.schluesselbund.map((k, i) => (
              <span key={k.kennung}>
                {i > 0 && ", "}
                <code>{k.kennung}</code> ({k.zustand})
              </span>
            ))}
            .
          </>
        ) : (
          <strong>In diesem Build ist kein Update-Schlüssel eingetragen: Agent-Updates sind aus.</strong>
        )}{" "}
        Agents vor 0.23 brauchen einmal <code>openwacht-agent updates-einrichten</code> (root bzw. Administrator).
      </p>
      {d.widerrufen.length > 0 && (
        <p className="klein" role="note">
          Widerrufen:{" "}
          {d.widerrufen.map((w, i) => (
            <span key={w.kennung}>
              {i > 0 && "; "}
              <code>{w.kennung}</code> durch <code>{w.durch}</code> mit Version {w.version} am {new Date(w.am).toLocaleDateString("de-DE")}
            </span>
          ))}
          . Pakete dieser Schlüssel werden nicht mehr angeboten.
        </p>
      )}
      {ich.betreiber && <PaketVerwaltung d={d} onGeaendert={laden} melden={melden} />}
      {agents.length === 0 ? (
        <p className="leer">Keine Agents in diesem Bereich.</p>
      ) : (
        <>
          <div className="aktionen formular-zeile">
            <label className="feld">
              <span>Version</span>
              <select value={ziel} onChange={(e) => setZiel(e.target.value)} disabled={versionen.length === 0}>
                {versionen.length === 0 && <option value="">kein Paket hochgeladen</option>}
                {versionen.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="knopf knopf-haupt"
              disabled={arbeitet || !ziel || auswahl.size === 0}
              onClick={() => void fuerAlle("freigeben")}
            >
              Für {auswahl.size} {auswahl.size === 1 ? "Agent" : "Agents"} freigeben
            </button>
            <button className="knopf" disabled={arbeitet || auswahl.size === 0} onClick={() => void fuerAlle("zuruecknehmen")}>
              Freigabe zurücknehmen
            </button>
          </div>
          <table className="tabelle">
            <thead>
              <tr>
                <th scope="col">
                  <input
                    type="checkbox"
                    aria-label="Alle auswählen"
                    checked={auswahl.size > 0 && auswahl.size === agents.filter(admin).length}
                    onChange={(e) => setAuswahl(new Set(e.target.checked ? agents.filter(admin).map((a) => a.id) : []))}
                  />
                </th>
                <th scope="col">Rechner</th>
                <th scope="col">Version</th>
                <th scope="col">Freigegeben</th>
                <th scope="col">Zustand</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id}>
                  <td>
                    {admin(a) && (
                      <input
                        type="checkbox"
                        aria-label={`${a.hostname} auswählen`}
                        checked={auswahl.has(a.id)}
                        onChange={(e) => {
                          const n = new Set(auswahl);
                          if (e.target.checked) n.add(a.id);
                          else n.delete(a.id);
                          setAuswahl(n);
                        }}
                      />
                    )}
                  </td>
                  <td>
                    <div className="name">{a.hostname}</div>
                    <div className="klein">
                      {bereich.mehrere ? (bereich.nachId.get(a.mandant)?.name ?? "") + " · " : ""}
                      {a.plattform || "Plattform unbekannt (Agent vor 0.23)"}
                    </div>
                  </td>
                  <td className="mono">{a.version || "–"}</td>
                  <td className="mono">{a.freigegeben ?? "–"}</td>
                  <td>
                    {a.fehler ? (
                      <span className="text-warn">{a.fehler}</span>
                    ) : a.freigegeben && neuer(a.freigegeben, a.version) ? (
                      "wird beim nächsten Melden aktualisiert"
                    ) : a.freigegeben ? (
                      "aktuell"
                    ) : (
                      ""
                    )}
                    {a.zuletzt && <div className="klein">gemeldet {vor(a.zuletzt, Date.now())}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}

function PaketVerwaltung(props: { d: Antwort; onGeaendert: () => Promise<void>; melden: (e: unknown) => void }) {
  const [bin, setBin] = useState<File | null>(null);
  const [sig, setSig] = useState<File | null>(null);
  const [arbeitet, setArbeitet] = useState(false);
  const hochladen = async (e: FormEvent) => {
    e.preventDefault();
    if (!bin || !sig) return;
    setArbeitet(true);
    try {
      const sigText = await sig.text();
      const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(sigText)));
      await api("POST", "/api/v1/agent-updates", undefined, {
        raw: bin,
        headers: { "Content-Type": "application/octet-stream", "X-OpenWacht-Signatur": b64 },
      });
      setBin(null);
      setSig(null);
      (e.target as HTMLFormElement).reset();
      await props.onGeaendert();
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <section className="panel" aria-label="Pakete">
      <div className="panel-kopf">
        <h3 className="panel-titel">Pakete (Betreiber)</h3>
      </div>
      <div className="panel-inhalt">
        {props.d.schluesselbund.some((k) => k.zustand !== "widerrufen") && (
          <form className="formular-zeile" onSubmit={hochladen}>
            <label className="feld">
              <span>Agent-Binary</span>
              <input type="file" required onChange={(e) => setBin(e.target.files?.[0] ?? null)} />
            </label>
            <label className="feld">
              <span>Signatur (.sig)</span>
              <input type="file" accept=".sig" required onChange={(e) => setSig(e.target.files?.[0] ?? null)} />
            </label>
            <button className="knopf knopf-haupt" disabled={arbeitet || !bin || !sig}>
              {arbeitet ? "Prüft …" : "Hochladen"}
            </button>
          </form>
        )}
        {props.d.pakete.length === 0 ? (
          <p className="leer">Noch keine Pakete.</p>
        ) : (
          <table className="tabelle">
            <thead>
              <tr>
                <th scope="col">Version</th>
                <th scope="col">Plattform</th>
                <th scope="col">Größe</th>
                <th scope="col">SHA-256</th>
                <th scope="col">Aktionen</th>
              </tr>
            </thead>
            <tbody>
              {props.d.pakete.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.version}</td>
                  <td>{p.plattform}</td>
                  <td>{mb(p.groesse)}</td>
                  <td className="mono klein">{p.sha256.slice(0, 16)}…</td>
                  <td>
                    <button
                      className="knopf knopf-gefahr"
                      onClick={async () => {
                        try {
                          await api("DELETE", `/api/v1/agent-updates/${p.id}`);
                          await props.onGeaendert();
                        } catch (e) {
                          props.melden(e);
                        }
                      }}
                    >
                      Löschen
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
