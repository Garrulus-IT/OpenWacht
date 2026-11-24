// SPDX-License-Identifier: AGPL-3.0-only

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type Mandant } from "./api";

// Anträge auf neue Untermandanten (Etappe 36): Admins eines Untermandanten
// beantragen, Admins des Hauptmandanten geben frei oder lehnen ab.

interface Antrag {
  id: string;
  mandant_id: string;
  mandant: string;
  name: string;
  begruendung: string;
  zustand: "beantragt" | "freigegeben" | "abgelehnt";
  beantragt_von: string;
  beantragt_am: string;
  entschieden_von: string;
  entschieden_am: string | null;
  notiz: string;
  darf_entscheiden: boolean;
}

const zustandText = { beantragt: "offen", freigegeben: "freigegeben", abgelehnt: "abgelehnt" } as const;
const tag = (s: string | null) => (s ? new Date(s).toLocaleDateString("de-DE") : "");

export function AntragFormular(props: { mandant: Mandant; onFertig: () => void; onAbbrechen: () => void; melden: (e: unknown) => void }) {
  const [name, setName] = useState("");
  const [grund, setGrund] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      await api("POST", `/api/v1/mandanten/${props.mandant.id}/antraege`, { name: name.trim(), begruendung: grund.trim() });
      props.onFertig();
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <form className="formular-zeile" onSubmit={senden} aria-label="Untermandant beantragen">
      <label className="feld">
        <span>Name des neuen Mandanten unter {props.mandant.name}</span>
        <input autoFocus maxLength={100} required value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="feld feld-breit">
        <span>Begründung (optional)</span>
        <input maxLength={500} value={grund} onChange={(e) => setGrund(e.target.value)} />
      </label>
      <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim()}>
        Beantragen
      </button>
      <button type="button" className="knopf" onClick={props.onAbbrechen}>
        Abbrechen
      </button>
    </form>
  );
}

export function AntraegeListe(props: { stand: number; onGeaendert: () => Promise<void>; melden: (e: unknown) => void }) {
  const { melden, onGeaendert } = props;
  const [liste, setListe] = useState<Antrag[] | null>(null);
  const [notiz, setNotiz] = useState<Record<string, string>>({});

  const laden = useCallback(async () => {
    try {
      const r = await api<{ antraege: Antrag[] }>("GET", "/api/v1/mandanten-antraege");
      setListe(r.antraege);
    } catch (e) {
      melden(e);
    }
  }, [melden]);
  useEffect(() => {
    void laden();
  }, [laden, props.stand]);

  const entscheiden = async (a: Antrag, freigeben: boolean) => {
    try {
      await api("POST", `/api/v1/mandanten-antraege/${a.id}/${freigeben ? "freigeben" : "ablehnen"}`, { notiz: notiz[a.id] ?? "" });
      await laden();
      if (freigeben) await onGeaendert();
    } catch (e) {
      melden(e);
    }
  };

  if (!liste || liste.length === 0) return null;
  return (
    <section className="antraege" aria-labelledby="antraege-titel">
      <h3 id="antraege-titel" className="abschnitt">
        Anträge auf Untermandanten
      </h3>
      <table className="tabelle">
        <thead>
          <tr>
            <th scope="col">Neuer Mandant</th>
            <th scope="col">Unter</th>
            <th scope="col">Beantragt</th>
            <th scope="col">Zustand</th>
            <th scope="col">
              <span className="sr-only">Entscheidung</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {liste.map((a) => (
            <tr key={a.id}>
              <td>
                {a.name}
                {a.begruendung && <div className="klein">{a.begruendung}</div>}
              </td>
              <td>{a.mandant}</td>
              <td>
                {a.beantragt_von} · {tag(a.beantragt_am)}
              </td>
              <td>
                {zustandText[a.zustand]}
                {a.entschieden_von && (
                  <div className="klein">
                    {a.entschieden_von} · {tag(a.entschieden_am)}
                    {a.notiz && ` · ${a.notiz}`}
                  </div>
                )}
              </td>
              <td>
                {a.darf_entscheiden && (
                  <div className="aktionen">
                    <label className="feld">
                      <span className="sr-only">Notiz zum Antrag {a.name}</span>
                      <input
                        placeholder="Notiz (optional)"
                        maxLength={500}
                        value={notiz[a.id] ?? ""}
                        onChange={(e) => setNotiz({ ...notiz, [a.id]: e.target.value })}
                      />
                    </label>
                    <button className="knopf knopf-haupt" onClick={() => void entscheiden(a, true)} aria-label={`${a.name} freigeben`}>
                      Freigeben
                    </button>
                    <button className="knopf knopf-gefahr" onClick={() => void entscheiden(a, false)} aria-label={`${a.name} ablehnen`}>
                      Ablehnen
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
