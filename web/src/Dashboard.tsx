// SPDX-License-Identifier: AGPL-3.0-only

// Bausteine der Widgets (seit Etappe 17, vorher Graphen der Übersicht):
// die vollsten Platten, Alarme je Tag und die Verfügbarkeit, dazu die
// Antworttypen der Dashboard-Endpunkte. Alle Werte kommen gefiltert auf den
// Bereich; die Zentrale zeigt ohnehin nur, was der Benutzer sehen darf.

import { useState } from "react";
import { mandantName, type Bereich } from "./bereich";
import { Pegel } from "./Pegel";
import { bereichFilter, prognoseText, prognoseTitel, type PlattenPrognose } from "./Prognose";

export type Punkt = [number, number, number, number];

export interface FlottenLinie {
  art: "host" | "snmp";
  quelle_id: string;
  geraet_id: string;
  geraet: string;
  mandant_id: string;
  punkte: Punkt[];
}

export interface FlottenVerlauf {
  spanne_s: number;
  schritt_s: number;
  cpu: { gesamt: number; linien: FlottenLinie[] };
  speicher: { gesamt: number; linien: FlottenLinie[] };
}

export interface Kennzahlen {
  alarme_je_stunde: { t: number; warn: number; crit: number; unknown: number }[];
  checks: {
    id: string;
    name: string;
    mandant_id: string;
    geraet_id: string;
    geraet: string;
    tage7: number | null;
    tage30: number | null;
  }[];
  erreichbarkeit: {
    art: "host" | "snmp";
    quelle_id: string;
    mandant_id: string;
    geraet_id: string;
    geraet: string;
    tage7: number | null;
    tage30: number | null;
  }[];
  gekuerzt: boolean;
}

const zahl = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });

export function mitFilter(pfad: string, bereich: Bereich) {
  const f = bereichFilter(bereich);
  return f ? `${pfad}${pfad.includes("?") ? "&" : "?"}${f.slice(1)}` : pfad;
}

// --- Top 5 Platten ---------------------------------------------------------------------

export function VollstePlatten(props: { liste: PlattenPrognose[]; bereich: Bereich; onGeraet: (mandant: string, geraet: string) => void }) {
  const top = [...props.liste].sort((a, b) => b.belegt - a.belegt).slice(0, 5);
  if (top.length === 0) return <p className="leer">Keine Platten im Bereich.</p>;
  return (
    <>
      <table className="tabelle tabelle-kompakt top-platten">
        <thead>
          <tr>
            <th scope="col">Gerät und Platte</th>
            <th scope="col">Belegt</th>
            <th scope="col">Prognose</th>
          </tr>
        </thead>
        <tbody>
          {top.map((p) => (
            <tr key={`${p.art}:${p.quelle_id}:${p.platte}`}>
              <td>
                <button className="knopf-text" onClick={() => props.onGeraet(p.mandant_id, p.geraet_id)}>
                  {p.geraet}
                </button>{" "}
                <span className="mono">{p.platte}</span>
                {props.bereich.mehrere && <span className="mandant-marke">{mandantName(props.bereich, p.mandant_id)}</span>}
              </td>
              <td>
                <Pegel wert={p.belegt} titel={`Mittel der letzten Stunde`} />
              </td>
              <td className="klein" title={prognoseTitel(p)}>
                {prognoseText(p)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

// --- Alarme je Tag ------------------------------------------------------------------------

const TB = 640;
const TH = 120;

function tagSchluessel(d: Date) {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

export function AlarmeJeTag(props: { stunden: Kennzahlen["alarme_je_stunde"] }) {
  const [zeiger, setZeiger] = useState<number | null>(null);
  // Die letzten 30 Tage in der Zeitzone des Browsers, ältester zuerst.
  const tage: { d: Date; warn: number; crit: number; unknown: number }[] = [];
  const heute = new Date();
  heute.setHours(0, 0, 0, 0);
  for (let i = 29; i >= 0; i--) {
    const d = new Date(heute);
    d.setDate(d.getDate() - i);
    tage.push({ d, warn: 0, crit: 0, unknown: 0 });
  }
  const nach = new Map(tage.map((t) => [tagSchluessel(t.d), t]));
  for (const s of props.stunden) {
    const t = nach.get(tagSchluessel(new Date(s.t * 1000)));
    if (t) {
      t.warn += s.warn;
      t.crit += s.crit;
      t.unknown += s.unknown;
    }
  }
  const summe = (t: (typeof tage)[number]) => t.warn + t.crit + t.unknown;
  const gesamt = tage.reduce((n, t) => n + summe(t), 0);
  const max = Math.max(1, ...tage.map(summe));
  // Obergrenze 1, 2, 5, 10 … und ganze Zahlen an der Achse
  const p = Math.pow(10, Math.floor(Math.log10(max)));
  const yMax = [1, 2, 5, 10].map((f) => f * p).find((x) => x >= max)!;
  const l = 28;
  const breite = (TB - l - 6) / tage.length;
  const h = TH - 22;
  const y = (v: number) => 6 + h - (v / yMax) * h;
  const datum = (d: Date) => d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" });
  const z = zeiger !== null ? tage[zeiger] : null;
  return (
    <>
      <figure className="graph">
        <figcaption className="graph-kopf">
          <span className="graph-titel">Begonnene Alarme, letzte 30 Tage</span>
          <span className="graph-wert" aria-live="polite">
            {z
              ? `${z.d.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" })}: ${summe(z)} (${z.crit} Fehler, ${
                  z.warn
                } Warnungen${z.unknown ? `, ${z.unknown} unbekannt` : ""})`
              : `${gesamt} insgesamt`}
          </span>
        </figcaption>
        <svg
          className="graph-flaeche"
          viewBox={`0 0 ${TB} ${TH}`}
          role="img"
          aria-label={`Alarme je Tag, letzte 30 Tage: ${gesamt} insgesamt, höchstens ${max} an einem Tag`}
          onPointerLeave={() => setZeiger(null)}
        >
          {[0, 0.5, 1].map((f) =>
            // Mitte nur, wenn sie eine ganze Zahl ist (bei 5 stünde sonst „3“ in der Mitte).
            f === 0.5 && !Number.isInteger(yMax / 2) ? null : (
              <g key={f}>
                <line className="graph-gitter" x1={l} x2={TB - 6} y1={y(yMax * f)} y2={y(yMax * f)} />
                <text className="graph-achse" x={l - 6} y={y(yMax * f) + 4} textAnchor="end">
                  {Math.round(yMax * f)}
                </text>
              </g>
            ),
          )}
          {tage.map((t, i) => {
            const x = l + i * breite + 1;
            const w = Math.max(1, breite - 2);
            let unten = y(0);
            const teile: [string, number][] = [
              ["crit", t.crit],
              ["warn", t.warn],
              ["unknown", t.unknown],
            ];
            return (
              <g key={i} onPointerEnter={() => setZeiger(i)}>
                <rect x={l + i * breite} y={6} width={breite} height={h} fill="transparent" />
                {teile.map(([art, n]) => {
                  if (!n) return null;
                  const oben = y(0) - (n / yMax) * h;
                  const r = <rect key={art} className={`streifen-${art}`} x={x} width={w} y={unten - (y(0) - oben)} height={y(0) - oben} />;
                  unten -= y(0) - oben;
                  return r;
                })}
              </g>
            );
          })}
          {[0, 14, 29].map((i) => (
            <text
              key={i}
              className="graph-achse"
              x={l + i * breite + breite / 2}
              y={TH - 4}
              textAnchor={i === 0 ? "start" : i === 29 ? "end" : "middle"}
            >
              {datum(tage[i]!.d)}
            </text>
          ))}
        </svg>
      </figure>
    </>
  );
}

// --- Verfügbarkeit ---------------------------------------------------------------------------

function prozentText(v: number | null) {
  return v === null ? "–" : `${zahl.format(v)} %`;
}

export function Verfuegbarkeit(props: { k: Kennzahlen; bereich: Bereich; onGeraet: (mandant: string, geraet: string) => void }) {
  const [alle, setAlle] = useState(false);
  const drin = (x: { mandant_id: string }) => props.bereich.ids.has(x.mandant_id);
  const zeilen = [
    ...props.k.erreichbarkeit.filter(drin).map((r) => ({
      key: `${r.art}:${r.quelle_id}`,
      geraet: r.geraet,
      geraet_id: r.geraet_id,
      mandant_id: r.mandant_id,
      was: r.art === "host" ? "Agent meldet sich" : "SNMP antwortet",
      tage7: r.tage7,
      tage30: r.tage30,
    })),
    ...props.k.checks.filter(drin).map((c) => ({
      key: `c:${c.id}`,
      geraet: c.geraet,
      geraet_id: c.geraet_id,
      mandant_id: c.mandant_id,
      was: c.name,
      tage7: c.tage7,
      tage30: c.tage30,
    })),
  ].sort((a, b) => (a.tage7 ?? 101) - (b.tage7 ?? 101) || (a.tage30 ?? 101) - (b.tage30 ?? 101) || a.geraet.localeCompare(b.geraet, "de"));
  if (zeilen.length === 0) return <p className="leer">Noch keine Werte.</p>;
  const gezeigt = alle ? zeilen : zeilen.slice(0, 10);
  const klasse = (v: number | null) => (v === null ? undefined : v < 95 ? "text-crit" : v < 99 ? "text-warn" : undefined);
  return (
    <>
      <p className="klein">schlechteste zuerst; Agents und SNMP: Zeit mit Messwerten, Checks: erfolgreiche Prüfungen</p>
      <table className="tabelle tabelle-kompakt verfuegbarkeit">
        <thead>
          <tr>
            <th scope="col">Gerät</th>
            <th scope="col">Was</th>
            <th scope="col">7 Tage</th>
            <th scope="col">30 Tage</th>
          </tr>
        </thead>
        <tbody>
          {gezeigt.map((z) => (
            <tr key={z.key}>
              <td>
                <button className="knopf-text" onClick={() => props.onGeraet(z.mandant_id, z.geraet_id)}>
                  {z.geraet}
                </button>
                {props.bereich.mehrere && <span className="mandant-marke">{mandantName(props.bereich, z.mandant_id)}</span>}
              </td>
              <td>{z.was}</td>
              <td className={klasse(z.tage7)}>{prozentText(z.tage7)}</td>
              <td className={klasse(z.tage30)}>{prozentText(z.tage30)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {zeilen.length > 10 && (
        <button className="knopf-text" onClick={() => setAlle(!alle)}>
          {alle ? "Nur die zehn schlechtesten zeigen" : `Alle ${zeilen.length} zeigen`}
        </button>
      )}
      {props.k.gekuerzt && <p className="klein">Gekürzt: Es gibt mehr als 1000 Einträge.</p>}
    </>
  );
}
