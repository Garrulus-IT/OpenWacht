// SPDX-License-Identifier: AGPL-3.0-only

// Verwaltung › Agent-Updates (Etappe 23): signierte Agent-Versionen. Der
// Betreiber lädt Pakete hoch (Binary + .sig aus tools/signieren), Admins geben
// sie je Agent frei. Der Agent prüft die Offline-Signatur selbst; ohne
// Schlüssel im Build sind Updates aus.

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { api, type Gruppe, type Ich, type Mandant } from "./api";
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
  // nach der Regel des Mandanten eingetragen (1.0.4)
  automatisch?: boolean;
}

// Regel „automatisch übernehmen“ je Mandant (1.0.4)
interface AutoRegel {
  mandant_id: string;
  aktiv: boolean;
  pilotgruppe: string | null;
  wartezeit_stunden: number;
  tage: number[]; // 1 = Montag … 7 = Sonntag
  von: number;
  bis: number;
}

const TAGE = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];
const AUTO_VORGABE = (m: string): AutoRegel => ({ mandant_id: m, aktiv: false, pilotgruppe: null, wartezeit_stunden: 24, tage: [1, 2, 3, 4, 5, 6, 7], von: 0, bis: 0 });

// Pfad einer Gruppe für die Auswahl („Server / Pilot“)
function gruppenPfade(gruppen: Gruppe[], mandant: string): { id: string; pfad: string }[] {
  const nachId = new Map(gruppen.map((g) => [g.id, g]));
  const pfad = (g: Gruppe): string => (g.eltern_id && nachId.get(g.eltern_id) ? pfad(nachId.get(g.eltern_id)!) + " / " : "") + g.name;
  return gruppen
    .filter((g) => g.mandant_id === mandant)
    .map((g) => ({ id: g.id, pfad: pfad(g) }))
    .sort((a, b) => a.pfad.localeCompare(b.pfad, "de"));
}

function Automatik(props: { mandant: Mandant; melden: (e: unknown) => void }) {
  const { mandant, melden } = props;
  const [r, setR] = useState<AutoRegel | null>(null);
  const [gruppen, setGruppen] = useState<Gruppe[]>([]);
  const [stand, setStand] = useState("");
  const darf = mandant.rolle === "admin";
  useEffect(() => {
    Promise.all([api<{ regeln: AutoRegel[] }>("GET", "/api/v1/agent-updates/automatik"), api<{ gruppen: Gruppe[] }>("GET", "/api/v1/gruppen")])
      .then(([a, g]) => {
        setR(a.regeln.find((x) => x.mandant_id === mandant.id) ?? AUTO_VORGABE(mandant.id));
        setGruppen(g.gruppen);
      })
      .catch(melden);
  }, [mandant.id, melden]);
  if (!r) return null;
  const pfade = gruppenPfade(gruppen, mandant.id);
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setStand("");
    try {
      setR(await api<AutoRegel>("PUT", `/api/v1/mandanten/${mandant.id}/agent-updates/automatik`, r));
      setStand("Gespeichert.");
    } catch (err) {
      setStand(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <form className="formular formular-flach auto-regel" onSubmit={speichern}>
      <fieldset className="feld-gruppe formular-voll" disabled={!darf}>
        <legend>Automatisch übernehmen ({mandant.name})</legend>
        <p className="klein">
          Neue signierte Versionen gehen zuerst an die Agents der Pilotgruppe, nach der Wartezeit an alle übrigen dieses
          Mandanten, aber nur, wenn kein Pilot einen Fehler meldet und mindestens ein Pilot die neue Version schon fährt.
          Installiert wird nur im Zeitfenster. Eine Freigabe von Hand geht immer vor.
        </p>
        <label className="haken">
          <input type="checkbox" checked={r.aktiv} onChange={(e) => setR({ ...r, aktiv: e.target.checked })} />
          <span>Neue Versionen automatisch übernehmen</span>
        </label>
        <div className="formular-zeile">
          <label className="feld">
            <span>Pilotgruppe</span>
            <select value={r.pilotgruppe ?? ""} onChange={(e) => setR({ ...r, pilotgruppe: e.target.value || null })}>
              <option value="">keine (alle nach der Wartezeit)</option>
              {pfade.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.pfad}
                </option>
              ))}
            </select>
          </label>
          <label className="feld feld-schmal">
            <span>Wartezeit (Stunden)</span>
            <input
              type="number"
              min={0}
              max={720}
              value={r.wartezeit_stunden}
              onChange={(e) => setR({ ...r, wartezeit_stunden: Math.max(0, Math.min(720, Number(e.target.value) || 0)) })}
            />
          </label>
        </div>
        <div className="tage" role="group" aria-label="Wochentage">
          {TAGE.map((t, i) => (
            <label key={t} className="haken">
              <input
                type="checkbox"
                checked={r.tage.includes(i + 1)}
                onChange={(e) => setR({ ...r, tage: e.target.checked ? [...r.tage, i + 1].sort() : r.tage.filter((x) => x !== i + 1) })}
              />
              <span>{t}</span>
            </label>
          ))}
        </div>
        <div className="formular-zeile">
          <label className="feld feld-schmal">
            <span>von (Uhr)</span>
            <select value={r.von} onChange={(e) => setR({ ...r, von: Number(e.target.value) })}>
              {Array.from({ length: 24 }, (_, h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, "0")}:00
                </option>
              ))}
            </select>
          </label>
          <label className="feld feld-schmal">
            <span>bis (Uhr)</span>
            <select value={r.bis} onChange={(e) => setR({ ...r, bis: Number(e.target.value) })}>
              {Array.from({ length: 24 }, (_, h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, "0")}:00
                </option>
              ))}
            </select>
          </label>
          <p className="klein">{r.von === r.bis ? "ganzer Tag" : r.von > r.bis ? "über Mitternacht" : ""}</p>
        </div>
        {darf && (
          <div className="aktionen">
            <button className="knopf knopf-haupt" disabled={r.tage.length === 0}>
              Speichern
            </button>
            {stand && <span className="klein">{stand}</span>}
          </div>
        )}
        {!darf && <p className="klein">Ändern können Admins dieses Mandanten.</p>}
      </fieldset>
    </form>
  );
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
      <Automatik mandant={props.mandant} melden={melden} />
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
                  <td className="mono">
                    {a.freigegeben ?? "–"}
                    {a.freigegeben && a.automatisch && <div className="klein">automatisch</div>}
                  </td>
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
