// SPDX-License-Identifier: AGPL-3.0-only

// Berichte (Etappe 25): Verfügbarkeit und SLA-Ziel je Gerät und Mandant,
// Alarme und Kapazität für einen Monat, als Ansicht und als PDF. Den
// Monatsbericht per Mail stellen Admins am Mail-Kanal ein.

import { useEffect, useState, type FormEvent } from "react";
import { api } from "./api";
import { rolleIn, type Bereich } from "./bereich";
import { mitBasis } from "./basis";

interface Bericht {
  mandant: string;
  monat: string;
  erstellt: string;
  mandanten: { id: string; name: string; geraete: number; verfuegbarkeit: number; ziel: number; erfuellt: boolean }[];
  geraete: {
    id: string;
    name: string;
    mandant: string;
    verfuegbarkeit: number;
    ausfall_minuten: number;
    ausfaelle: number;
    ziel: number;
    erfuellt: boolean;
  }[];
  alarme: number;
  kritisch: number;
  warnungen: number;
  bestaetigt: number;
  laengste: { name: string; mandant: string; schwere: string; beginn: string; minuten: number; offen: boolean }[];
  prognose: { geraet: string; platte: string; belegt: number; tage: number }[];
}

const prozent = (f: number) => f.toLocaleString("de-DE", { minimumFractionDigits: 3, maximumFractionDigits: 3 }) + " %";
const dauer = (m: number) => (m < 60 ? `${m} Min.` : `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")} Std.`);

function monate(): string[] {
  const out: string[] = [];
  const d = new Date();
  for (let i = 0; i < 13; i++) {
    const x = new Date(d.getFullYear(), d.getMonth() - i, 1);
    out.push(`${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, "0")}`);
  }
  return out;
}

const monatName = (m: string) => {
  const [y, mo] = m.split("-").map(Number);
  return new Date(y ?? 2000, (mo ?? 1) - 1, 1).toLocaleDateString("de-DE", { month: "long", year: "numeric" });
};

export function Berichte(props: { bereich: Bereich; mitUnter: boolean; melden: (e: unknown) => void }) {
  const { bereich, melden } = props;
  const liste = monate();
  const [monat, setMonat] = useState(liste[1] ?? "");
  const [b, setB] = useState<Bericht | null>(null);
  const admin = rolleIn(bereich, bereich.mandant.id) === "admin";
  const q = `mandant=${bereich.mandant.id}&monat=${monat}&untermandanten=${props.mitUnter ? "1" : "0"}`;

  useEffect(() => {
    setB(null);
    api<Bericht>("GET", `/api/v1/berichte?${q}`).then(setB, melden);
  }, [q, melden]);

  return (
    <section className="ansicht" aria-labelledby="berichte-titel">
      <div className="abschnitt-kopf">
        <h1 id="berichte-titel" className="titel-gross">
          Bericht {monatName(monat)}
        </h1>
        <div className="aktionen formular-zeile">
          <label className="feld">
            <span>Monat</span>
            <select value={monat} onChange={(e) => setMonat(e.target.value)}>
              {liste.map((m) => (
                <option key={m} value={m}>
                  {monatName(m)}
                </option>
              ))}
            </select>
          </label>
          <a className="knopf knopf-haupt" href={mitBasis(`/api/v1/berichte/pdf?${q}`)} download>
            Als PDF
          </a>
        </div>
      </div>
      <p className="klein">
        Verfügbarkeit: Anteil der Zeit ohne offenen kritischen Alarm zu Ping, Agent oder Abfragequelle; Wartungen zählen nicht als Ausfall.
        Den Bericht per Mail am Monatsanfang stellst du am Mail-Kanal ein (Alarme › Kanäle › Bereitschaft und Eskalation).
      </p>
      {admin && <SlaZiel bereich={bereich} melden={melden} />}
      {!b ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : (
        <>
          <div className="kennzahlen">
            <div className="panel kennzahl">
              <span className="klein">Geräte</span>
              <strong>{b.geraete.length}</strong>
            </div>
            <div className="panel kennzahl">
              <span className="klein">Alarme</span>
              <strong>{b.alarme}</strong>
            </div>
            <div className="panel kennzahl">
              <span className="klein">davon kritisch</span>
              <strong>{b.kritisch}</strong>
            </div>
            <div className="panel kennzahl">
              <span className="klein">Platten bald voll</span>
              <strong>{b.prognose.length}</strong>
            </div>
          </div>
          <h2 className="abschnitt">Verfügbarkeit je Mandant</h2>
          <table className="tabelle">
            <thead>
              <tr>
                <th scope="col">Mandant</th>
                <th scope="col">Geräte</th>
                <th scope="col">Verfügbar</th>
                <th scope="col">Ziel</th>
              </tr>
            </thead>
            <tbody>
              {b.mandanten.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>{t.geraete}</td>
                  <td className={t.erfuellt ? "text-ok" : "text-fehler"}>{prozent(t.verfuegbarkeit)}</td>
                  <td>
                    {prozent(t.ziel)} {t.erfuellt ? "erreicht" : "verfehlt"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <h2 className="abschnitt">Verfügbarkeit je Gerät</h2>
          {b.geraete.length === 0 ? (
            <p className="leer">Keine Geräte.</p>
          ) : (
            <table className="tabelle">
              <thead>
                <tr>
                  <th scope="col">Gerät</th>
                  <th scope="col">Verfügbar</th>
                  <th scope="col">Ausfall</th>
                  <th scope="col">Ziel</th>
                </tr>
              </thead>
              <tbody>
                {b.geraete.map((g) => (
                  <tr key={g.id}>
                    <td>
                      <div className="name">{g.name}</div>
                      <div className="klein">{g.mandant}</div>
                    </td>
                    <td className={g.erfuellt ? "text-ok" : "text-fehler"}>{prozent(g.verfuegbarkeit)}</td>
                    <td>{g.ausfall_minuten > 0 ? `${dauer(g.ausfall_minuten)} (${g.ausfaelle}×)` : "–"}</td>
                    <td>{g.erfuellt ? "erreicht" : "verfehlt"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <h2 className="abschnitt">Alarme</h2>
          <p>
            {b.alarme} Alarme begonnen, davon {b.kritisch} kritisch und {b.warnungen} Warnungen; {b.bestaetigt} bestätigt.
          </p>
          {b.laengste.length > 0 && (
            <table className="tabelle">
              <thead>
                <tr>
                  <th scope="col">Längste Alarme</th>
                  <th scope="col">Beginn</th>
                  <th scope="col">Dauer</th>
                </tr>
              </thead>
              <tbody>
                {b.laengste.map((a, i) => (
                  <tr key={i}>
                    <td>
                      <span className={a.schwere === "crit" ? "text-fehler" : "text-warn"}>●</span> {a.name}
                      <div className="klein">{a.mandant}</div>
                    </td>
                    <td>{new Date(a.beginn).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}</td>
                    <td>
                      {dauer(a.minuten)}
                      {a.offen ? " (offen)" : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <h2 className="abschnitt">Kapazität</h2>
          {b.prognose.length === 0 ? (
            <p className="leer">Keine Platte läuft in den nächsten 90 Tagen voll.</p>
          ) : (
            <ul>
              {b.prognose.map((p, i) => (
                <li key={i}>
                  {p.geraet} · {p.platte}: {p.belegt.toLocaleString("de-DE")} % belegt, voll in {p.tage} Tagen
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

function SlaZiel(props: { bereich: Bereich; melden: (e: unknown) => void }) {
  const [ziel, setZiel] = useState("");
  const [gespeichert, setGespeichert] = useState("");
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const wert = ziel.trim() === "" ? null : Number(ziel.replace(",", "."));
      await api("PUT", `/api/v1/mandanten/${props.bereich.mandant.id}/sla`, { ziel: wert });
      setGespeichert(wert === null ? "Ziel zurückgesetzt (erbt vom übergeordneten Mandanten bzw. 99,5 %)." : "Gespeichert.");
    } catch (err) {
      props.melden(err);
    }
  };
  return (
    <form className="formular-zeile" onSubmit={speichern} aria-label="SLA-Ziel">
      <label className="feld">
        <span>SLA-Ziel für {props.bereich.mandant.name} in % (leer = erben)</span>
        <input inputMode="decimal" placeholder="99,5" value={ziel} onChange={(e) => setZiel(e.target.value)} />
      </label>
      <button className="knopf">Ziel speichern</button>
      {gespeichert && (
        <span className="klein" role="status">
          {gespeichert}
        </span>
      )}
    </form>
  );
}
