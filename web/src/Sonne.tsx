// SPDX-License-Identifier: AGPL-3.0-only

// Sonnendiagramm der Wandanzeige: innen der Mandant, nach außen
// Untermandanten, Gruppen (auch verschachtelt) und Geräte. Jedes Gerät
// trägt den schlimmsten Zustand seiner Sensoren, jeder Ring den schlimmsten
// Zustand darunter. Jedes Gerät ist gleich breit. Nur Namen und Farben.

import { useId, type CSSProperties } from "react";
import { schriftAuf } from "./kennfarbe";
import type { AnzeigeKnoten, AnzeigeStatus } from "./api";
import { Zeichen } from "./Zeichen";

// Koordinatensystem: viewBox -500 … 500, Winkel im Bogenmaß ab 12 Uhr im Uhrzeigersinn.
// 1.0.2 (nach der Klick-Demo): Alle Geräte enden am selben Außenrand AUSSEN;
// Geräte mit Problem treten um VOR hervor. Zwischen den Ringen liegt eine
// dunkle Fuge (FUGE), die Mitte ist eine dunkle Scheibe mit dem Zeichen.
const R = 492;
const VOR = 34;
const AUSSEN = R - VOR;
const LOCH = 0.27 * R;
const FUGE = 7;
const vortreten = new Set<AnzeigeStatus>(["warn", "crit", "quittiert", "unknown"]);

export const statusText: Record<AnzeigeStatus, string> = {
  ok: "OK",
  warn: "Warnung",
  crit: "Kritisch",
  quittiert: "Bestätigt",
  unknown: "Unbekannt",
  wartung: "Wartung oder pausiert",
};

export interface Segment {
  schluessel: string; // Pfad der Namen, eindeutig genug für die Hervorhebung
  pfad: string[];
  name: string;
  art: AnzeigeKnoten["art"];
  status: AnzeigeStatus;
  tiefe: number;
  a0: number;
  a1: number;
  blatt: boolean;
  farbe?: string;
  kennfarbe?: string;
}

const HEX = /^#[0-9a-f]{6}$/i;

// Kennfarbe eines Segments als CSS-Variablen (Wert von der Zentrale geprüft).
export function segmentStil(farbe: string | undefined): { kenn: string; style?: CSSProperties } {
  if (!farbe || !HEX.test(farbe)) return { kenn: "" };
  return { kenn: " kenn", style: { "--kenn": farbe, "--auf-kenn": schriftAuf(farbe) } as CSSProperties };
}

function blaetter(k: AnzeigeKnoten): number {
  if (!k.kinder || k.kinder.length === 0) return 1;
  return k.kinder.reduce((n, c) => n + blaetter(c), 0);
}

// zerlegen: Segmente aller Ebenen unterhalb der Wurzel.
export function zerlegen(wurzel: AnzeigeKnoten): { segmente: Segment[]; tiefe: number } {
  const segmente: Segment[] = [];
  let tiefe = 0;
  const gehe = (k: AnzeigeKnoten, pfad: string[], t: number, a0: number, a1: number) => {
    tiefe = Math.max(tiefe, t);
    const kinder = k.kinder ?? [];
    if (t > 0) {
      segmente.push({
        schluessel: pfad.join("\u0000") + "\u0000" + t,
        pfad,
        name: k.name,
        art: k.art,
        status: k.status,
        tiefe: t,
        a0,
        a1,
        blatt: kinder.length === 0,
        farbe: k.farbe,
        kennfarbe: k.kennfarbe,
      });
    }
    const gesamt = blaetter(k);
    let a = a0;
    for (const c of kinder) {
      const b = a + ((a1 - a0) * blaetter(c)) / gesamt;
      gehe(c, [...pfad, c.name], t + 1, a, b);
      a = b;
    }
  };
  gehe(wurzel, [wurzel.name], 0, 0, 2 * Math.PI);
  return { segmente, tiefe };
}

// Radien der Ringe: Ring 0 (Mandant) schmal, der äußerste breiter für
// die radial geschriebenen Gerätenamen.
export function radien(tiefe: number): number[] {
  const gewicht = (t: number) => (t === 0 ? 0.45 : t === tiefe && tiefe >= 2 ? 1.6 : 1);
  let summe = 0;
  for (let t = 0; t <= tiefe; t++) summe += gewicht(t);
  const r = [LOCH];
  let innen = LOCH;
  for (let t = 0; t <= tiefe; t++) {
    innen += ((AUSSEN - LOCH) * gewicht(t)) / summe;
    r.push(innen);
  }
  return r; // Ring t liegt zwischen r[t] und r[t+1]
}

function ring(r: number[], t: number): [number, number] {
  return [r[t] ?? LOCH, r[t + 1] ?? AUSSEN];
}

// band: Radien eines Segments mit Fugen. Ein Gerät (Blatt) reicht immer bis
// zum Außenrand, auch wenn es weiter innen im Baum hängt; mit Problem tritt
// es hervor.
export function band(r: number[], s: { tiefe: number; blatt: boolean; status: AnzeigeStatus }): [number, number] {
  const [r0] = ring(r, s.tiefe);
  let r1 = s.blatt ? AUSSEN : ring(r, s.tiefe)[1];
  if (s.blatt && vortreten.has(s.status)) r1 = R;
  return [r0 + FUGE / 2, r1 - FUGE / 2];
}

function punkt(r: number, a: number): string {
  return `${(r * Math.sin(a)).toFixed(2)} ${(-r * Math.cos(a)).toFixed(2)}`;
}

function sektor(r0: number, r1: number, a0: number, a1: number): string {
  if (a1 - a0 >= 2 * Math.PI - 1e-6) {
    // voller Ring: zwei Kreise, das Loch über evenodd
    return (
      `M ${punkt(r1, 0)} A ${r1} ${r1} 0 1 1 ${punkt(r1, Math.PI)} A ${r1} ${r1} 0 1 1 ${punkt(r1, 0)} Z ` +
      `M ${punkt(r0, 0)} A ${r0} ${r0} 0 1 1 ${punkt(r0, Math.PI)} A ${r0} ${r0} 0 1 1 ${punkt(r0, 0)} Z`
    );
  }
  const gross = a1 - a0 > Math.PI ? 1 : 0;
  return (
    `M ${punkt(r0, a0)} L ${punkt(r1, a0)} A ${r1} ${r1} 0 ${gross} 1 ${punkt(r1, a1)} ` +
    `L ${punkt(r0, a1)} A ${r0} ${r0} 0 ${gross} 0 ${punkt(r0, a0)} Z`
  );
}

// Beschriftung: tangential (entlang des Rings) oder radial, je nachdem, wo
// mehr vom Namen lesbar ist. Gibt null zurück, wenn nichts Sinnvolles passt.
const ZEICHEN = 0.56; // mittlere Zeichenbreite in em
const MAX_SCHRIFT = 19;
const MIN_SCHRIFT = 6.5;
// Ansicht „Namen“ der Wandanzeige (1.0.6): Schrift darf kleiner werden, damit
// jedes Gerät beschriftet ist (aus der Nähe lesbar, am Bildschirm im Vollbild).
const MIN_SCHRIFT_NAMEN = 3.2;

export interface Beschriftung {
  art: "tangential" | "radial";
  text: string;
  schrift: number;
}

// Fehlen dem Namen nur wenige Zeichen, wird die Schrift um bis zu ein Fünftel
// kleiner, statt zu kürzen (1.0.7): „Garage Feuerwe…“ spart gegenüber „Garage
// Feuerwehr“ keinen Platz, die drei Punkte sind so breit wie die zwei Buchstaben.
const SCHRUMPFEN = 0.8;

function kuerzen(name: string, platz: number, schrift: number, min: number): { text: string; schrift: number } | null {
  const n = Math.floor(platz / (schrift * ZEICHEN));
  if (n >= name.length) return { text: name, schrift };
  const passend = platz / (name.length * ZEICHEN);
  if (passend >= Math.max(min, schrift * SCHRUMPFEN)) return { text: name, schrift: passend };
  if (n < 3) return null;
  return { text: name.slice(0, n - 1).trimEnd() + "…", schrift };
}

export function beschriftung(name: string, r0: number, r1: number, a0: number, a1: number, min = MIN_SCHRIFT): Beschriftung | null {
  const dicke = r1 - r0;
  const mitte = (r0 + r1) / 2;
  const spanne = Math.min(a1 - a0, Math.PI);
  const bogen = mitte * spanne;
  const innenBogen = r0 * spanne;
  const kandidaten: Beschriftung[] = [];
  // tangential: Schrifthöhe durch die Ringdicke begrenzt
  {
    const schrift = Math.min(MAX_SCHRIFT, dicke * 0.5);
    if (schrift >= min) {
      const t = kuerzen(name, bogen * 0.88, schrift, min);
      if (t) kandidaten.push({ art: "tangential", ...t });
    }
  }
  // radial: Schrifthöhe durch die Bogenbreite am Innenrand begrenzt
  {
    const schrift = Math.min(MAX_SCHRIFT, innenBogen * 0.8);
    if (schrift >= min) {
      const t = kuerzen(name, dicke * 0.9, schrift, min);
      if (t) kandidaten.push({ art: "radial", ...t });
    }
  }
  // mehr sichtbare Zeichen gewinnt, bei Gleichstand die größere Schrift
  kandidaten.sort((x, y) => sichtbar(y) - sichtbar(x) || y.schrift - x.schrift);
  return kandidaten[0] ?? null;
}

function sichtbar(b: Beschriftung): number {
  return b.text.endsWith("…") ? b.text.length - 1 : b.text.length + 0.5;
}

function grad(a: number) {
  return (a * 180) / Math.PI;
}

// mitte: "name" zeigt den Mandanten (Dashboard-Widget), "marke" Bildzeichen
// und Wortmarke (Wandanzeige, Corporate Design). alleNamen: auch kleine
// Segmente beschriften (Ansicht „Namen“ der Wandanzeige).
export function Sonne(props: { baum: AnzeigeKnoten; neu: Set<string>; titel: string; mitte?: "name" | "marke"; alleNamen?: boolean }) {
  const id = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const { segmente, tiefe } = zerlegen(props.baum);
  const r = radien(tiefe);
  const wurzel = props.baum;
  const wStil = segmentStil(wurzel.farbe);

  const [w0, w1] = ring(r, 0);
  const mitteText = kuerzen(wurzel.name, LOCH * 1.8, 26, 26 * SCHRUMPFEN);
  return (
    <svg className="sonne" viewBox="-500 -500 1000 1000" role="img" aria-label={props.titel}>
      <title>{props.titel}</title>
      <circle className="sonne-grund" cx="0" cy="0" r={AUSSEN + FUGE} />
      <circle className="sonne-scheibe" cx="0" cy="0" r={LOCH - FUGE / 2} />
      <path
        className={`sonne-seg sonne-${wurzel.status}${wStil.kenn}`}
        style={wStil.style}
        d={sektor(w0 + FUGE / 2, w1 - FUGE / 2, 0, 2 * Math.PI)}
        fillRule="evenodd"
      >
        <title>{`${wurzel.name}: ${statusText[wurzel.status]}${wurzel.kennfarbe ? ` · ${wurzel.kennfarbe}` : ""}`}</title>
      </path>
      {props.mitte === "marke" ? (
        <g aria-hidden="true">
          <Zeichen x={-55} y={-58} width={110} height={62} />
          <text className="sonne-mitte sonne-wortmarke" x="0" y="34" textAnchor="middle" dominantBaseline="middle">
            <tspan className="sonne-wortmarke-open">Open</tspan>Wacht
          </text>
        </g>
      ) : (
        <text className="sonne-mitte" x="0" y="0" textAnchor="middle" dominantBaseline="middle"
          style={mitteText && mitteText.schrift < 26 ? { fontSize: `${mitteText.schrift.toFixed(1)}px` } : undefined}
        >
          {mitteText?.text ?? ""}
        </text>
      )}
      {segmente.map((s, i) => {
        const [r0, r1] = band(r, s);
        const neu = props.neu.has(s.schluessel);
        const st = segmentStil(s.farbe);
        return (
          <path
            key={s.schluessel + i}
            className={`sonne-seg sonne-${s.status}${neu ? " sonne-neu" : ""}${st.kenn}`}
            style={st.style}
            d={sektor(r0, r1, s.a0, s.a1)}
            fillRule="evenodd"
          >
            <title>{`${s.pfad.slice(1).join(" › ")}: ${statusText[s.status]}${s.kennfarbe ? ` · ${s.kennfarbe}` : ""}`}</title>
          </path>
        );
      })}
      <g className="sonne-texte" aria-hidden="true">
        {segmente.map((s, i) => {
          const [r0, r1] = band(r, s);
          const b = beschriftung(s.name, r0, r1, s.a0, s.a1, props.alleNamen ? MIN_SCHRIFT_NAMEN : MIN_SCHRIFT);
          if (!b) return null;
          const mitte = (r0 + r1) / 2;
          const am = (s.a0 + s.a1) / 2;
          const st = segmentStil(s.farbe);
          const cls = `sonne-text sonne-text-${s.status}${st.kenn}`;
          if (b.art === "radial") {
            const links = am > Math.PI;
            const drehung = grad(am) + (links ? 90 : -90);
            const [x, y] = punkt(mitte, am).split(" ");
            return (
              <text
                key={s.schluessel + i}
                className={cls}
                style={st.style}
                fontSize={b.schrift.toFixed(1)}
                textAnchor="middle"
                dy="0.35em"
                transform={`translate(${x} ${y}) rotate(${drehung.toFixed(2)})`}
              >
                {b.text}
              </text>
            );
          }
          // tangential: Bogen in Leserichtung, unten rückwärts
          const halb = Math.min(s.a1 - s.a0, Math.PI) / 2;
          const unten = am > Math.PI / 2 && am < (3 * Math.PI) / 2;
          const von = unten ? am + halb : am - halb;
          const bis = unten ? am - halb : am + halb;
          const pid = `${id}-b${i}`;
          return (
            <g key={s.schluessel + i}>
              <path id={pid} d={`M ${punkt(mitte, von)} A ${mitte} ${mitte} 0 0 ${unten ? 0 : 1} ${punkt(mitte, bis)}`} fill="none" />
              <text className={cls} style={st.style} fontSize={b.schrift.toFixed(1)} dy="0.35em">
                <textPath href={`#${pid}`} startOffset="50%" textAnchor="middle">
                  {b.text}
                </textPath>
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}
