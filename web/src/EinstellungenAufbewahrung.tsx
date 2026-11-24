// SPDX-License-Identifier: AGPL-3.0-only

// Aufbewahrung der Messwerte (Etappe 35): global für Rohwerte,
// 5-Minuten- und Stundenwerte, je Mandant für die beiden verdichteten
// Stufen (Untermandanten erben). Kürzer stellen löscht ältere Werte beim
// nächsten Wartungslauf und verlangt deshalb einen frischen Code (der
// Betreiber hat immer 2FA; das Feld ist nur Pflicht, wenn es kürzer wird).

import { Fragment, useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { api } from "./api";

type Stufe = "roh_tage" | "fuenf_min_tage" | "stunden_tage";

interface MandantAufbewahrung {
  id: string;
  name: string;
  eltern: string | null;
  fuenf_min_tage: number | null;
  stunden_tage: number | null;
  wirksam: [number, number];
}

interface Antwort {
  global: Record<Stufe, number | null>;
  standard: Record<Stufe, number>;
  grenzen: Record<Stufe, [number, number]>;
  mandanten: MandantAufbewahrung[];
  groesse_bytes: Record<string, number>;
}

const stufen: { id: Stufe; text: string }[] = [
  { id: "roh_tage", text: "Rohwerte" },
  { id: "fuenf_min_tage", text: "5-Minuten-Werte" },
  { id: "stunden_tage", text: "Stundenwerte" },
];

function mb(b?: number) {
  if (b === undefined) return "–";
  return b >= 1 << 30 ? `${(b / (1 << 30)).toFixed(1)} GiB` : `${Math.max(0.1, b / (1 << 20)).toFixed(1)} MiB`;
}

function zahl(s: string): number | null {
  const t = s.trim();
  return t === "" ? null : Number(t);
}

export function AufbewahrungPanel(props: {
  Panel: (p: { titel: string; id: string; rechts?: ReactNode; children: ReactNode }) => ReactNode;
}) {
  const { Panel } = props;
  const [d, setD] = useState<Antwort | null>(null);
  const [fehler, setFehler] = useState("");
  const [form, setForm] = useState<"" | "global" | string>("");
  const [werte, setWerte] = useState<Record<string, string>>({});
  const [code, setCode] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const laden = useCallback(async () => {
    try {
      setD(await api<Antwort>("GET", "/api/v1/einstellungen/aufbewahrung"));
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void laden();
  }, [laden]);

  const reihe = useMemo(() => {
    if (!d) return [];
    const ids = new Set(d.mandanten.map((m) => m.id));
    const kinder = new Map<string | null, MandantAufbewahrung[]>();
    for (const m of d.mandanten) {
      const k = m.eltern && ids.has(m.eltern) ? m.eltern : null;
      kinder.set(k, [...(kinder.get(k) ?? []), m]);
    }
    const out: { m: MandantAufbewahrung; tiefe: number }[] = [];
    const geh = (id: string | null, tiefe: number) => {
      for (const m of kinder.get(id) ?? []) {
        out.push({ m, tiefe });
        if (tiefe < 20) geh(m.id, tiefe + 1);
      }
    };
    geh(null, 0);
    return out;
  }, [d]);

  if (!d) {
    return (
      <Panel id="einst-aufbewahrung" titel="Aufbewahrung der Messwerte">
        {fehler ? <p className="meldung meldung-fehler">{fehler}</p> : <p className="klein">Lädt …</p>}
      </Panel>
    );
  }
  const wirksamGlobal = (s: Stufe) => d.global[s] ?? d.standard[s];
  const oeffnen = (ziel: string) => {
    setFehler("");
    setCode("");
    if (ziel === "global") {
      setWerte(Object.fromEntries(stufen.map((s) => [s.id, d.global[s.id]?.toString() ?? ""])));
    } else {
      const m = d.mandanten.find((x) => x.id === ziel);
      setWerte({ fuenf_min_tage: m?.fuenf_min_tage?.toString() ?? "", stunden_tage: m?.stunden_tage?.toString() ?? "" });
    }
    setForm(ziel);
  };
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    setFehler("");
    try {
      const body: Record<string, unknown> = { code };
      for (const [k, v] of Object.entries(werte)) {
        const n = zahl(v);
        if (n !== null) body[k] = n;
      }
      await api(
        "PUT",
        form === "global" ? "/api/v1/einstellungen/aufbewahrung" : `/api/v1/einstellungen/mandanten/${form}/aufbewahrung`,
        body,
      );
      setForm("");
      await laden();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };
  const felder = (liste: { id: Stufe; text: string }[], erbt: (s: Stufe) => number) => (
    <form className="formular" onSubmit={speichern}>
      <div className="schwellen-felder">
        {liste.map((s) => (
          <label key={s.id} className="feld" htmlFor={`aufb-${s.id}`}>
            <span>
              {s.text} (Tage, {d.grenzen[s.id][0]}–{d.grenzen[s.id][1]})
            </span>
            <input
              id={`aufb-${s.id}`}
              type="number"
              inputMode="numeric"
              min={d.grenzen[s.id][0]}
              max={d.grenzen[s.id][1]}
              placeholder={`leer = ${erbt(s.id)}`}
              value={werte[s.id] ?? ""}
              onChange={(e) => setWerte({ ...werte, [s.id]: e.target.value })}
            />
          </label>
        ))}
      </div>
      <label className="feld code-feld" htmlFor="aufb-code">
        <span>Code aus der Authenticator-App (nur beim Verkürzen)</span>
        <input
          id="aufb-code"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
        />
      </label>
      <p className="hinweis klein">
        Der Code ist nur nötig, wenn eine Stufe kürzer wird: Dann löscht die Wartung ältere Werte innerhalb von 5 Minuten, unwiderruflich.
      </p>
      {fehler && (
        <p className="meldung meldung-fehler" role="alert">
          {fehler}
        </p>
      )}
      <div className="aktionen">
        <button className="knopf knopf-haupt" type="submit" disabled={arbeitet}>
          Speichern
        </button>
        <button className="knopf" type="button" onClick={() => setForm("")}>
          Abbrechen
        </button>
      </div>
    </form>
  );

  return (
    <Panel
      id="einst-aufbewahrung"
      titel="Aufbewahrung der Messwerte"
      rechts={
        form !== "global" && (
          <button className="knopf knopf-klein" onClick={() => oeffnen("global")}>
            Ändern
          </button>
        )
      }
    >
      {form === "global" ? (
        felder(stufen, (s) => d.standard[s])
      ) : (
        <dl className="zusammenfassung">
          {stufen.map((s) => (
            <Fragment key={s.id}>
              <dt>{s.text}</dt>
              <dd>
                {wirksamGlobal(s.id)} Tage {d.global[s.id] === null && "(Standard)"} · belegt{" "}
                {mb(d.groesse_bytes[s.id === "roh_tage" ? "roh" : s.id === "fuenf_min_tage" ? "5m" : "1h"])}
              </dd>
            </Fragment>
          ))}
        </dl>
      )}
      <p className="klein">
        Rohwerte gelten für alle Mandanten gemeinsam. 5-Minuten- und Stundenwerte lassen sich je Mandant kürzer oder länger halten;
        Untermandanten erben den Wert des nächsten Mandanten darüber.
      </p>
      <table className="tabelle">
        <thead>
          <tr>
            <th scope="col">Mandant</th>
            <th scope="col">5-Minuten-Werte</th>
            <th scope="col">Stundenwerte</th>
            <th scope="col">
              <span className="sr-only">Aktion</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {reihe.map(({ m, tiefe }) => (
            <tr key={m.id}>
              <th scope="row" style={{ paddingLeft: `${0.5 + tiefe}rem` }}>
                {m.name}
              </th>
              <td>
                {m.wirksam[0]} Tage {m.fuenf_min_tage === null && <span className="klein">(erbt)</span>}
              </td>
              <td>
                {m.wirksam[1]} Tage {m.stunden_tage === null && <span className="klein">(erbt)</span>}
              </td>
              <td>
                {form === m.id ? null : (
                  <button className="knopf knopf-klein" onClick={() => oeffnen(m.id)} aria-label={`Aufbewahrung für ${m.name} ändern`}>
                    Ändern
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {form !== "" && form !== "global" && (
        <>
          <h3 className="klein">Aufbewahrung für {d.mandanten.find((m) => m.id === form)?.name}</h3>
          {felder(stufen.slice(1), (s) => {
            const m = d.mandanten.find((x) => x.id === form);
            const p = m?.eltern ? d.mandanten.find((x) => x.id === m.eltern) : undefined;
            return p ? p.wirksam[s === "fuenf_min_tage" ? 0 : 1] : wirksamGlobal(s);
          })}
        </>
      )}
    </Panel>
  );
}
