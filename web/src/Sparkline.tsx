// SPDX-License-Identifier: AGPL-3.0-only

// Kleine Verläufe je Sensor eines Geräts (24 Stunden, 30-Minuten-Schritte).
// Ein Klick auf den Sensor öffnet darunter den ausführlichen Verlauf.

import { useCallback, useEffect, useState } from "react";
import { api, meldungMitWert, type Sensor } from "./api";
import { bitrate } from "./Pegel";
import { CheckVerlauf, ReihenVerlauf } from "./Verlauf";

type Punkt = [number, number, number, number];

interface Reihe {
  name: string;
  punkte: Punkt[];
}

interface CheckPunkt {
  t: number;
  n: number;
  ok: number;
  schlechtester: string;
  ms: number | null;
}

export interface SparkDaten {
  spanne_s: number;
  schritt_s: number;
  agent: { id: string; reihen: Reihe[] } | null;
  snmp: { id: string; reihen: Reihe[] } | null;
  checks: { id: string; punkte: CheckPunkt[] }[];
}

// Lädt die Sparklines eines Geräts, solange es aufgeklappt ist (jede Minute neu).
export function useSparklines(geraetId: string, aktiv: boolean) {
  const [daten, setDaten] = useState<SparkDaten | null>(null);
  const laden = useCallback(async () => {
    try {
      setDaten(await api<SparkDaten>("GET", `/api/v1/geraete/${geraetId}/sparklines`));
    } catch {
      // ohne Sparklines geht es auch
    }
  }, [geraetId]);
  useEffect(() => {
    if (!aktiv) return;
    void laden();
    const t = setInterval(() => {
      if (!document.hidden) void laden();
    }, 60_000);
    return () => clearInterval(t);
  }, [aktiv, laden]);
  return daten;
}

const SB = 96;
const SH = 24;
// Zwei Linien: Farben aus den CSS-Variablen der Graphen (hell und dunkel).
const sparkFarben = ["var(--reihe-1)", "var(--reihe-2)"];

// Sparkline: eine oder zwei Linien (Mittelwerte), Lücken reißen ab.
export function Sparkline(props: { linien: [number, number][][]; spanne: number; schritt: number; prozent?: boolean; titel: string }) {
  const bis = Date.now() / 1000;
  const von = bis - props.spanne;
  const alle = props.linien.flat();
  if (alle.length === 0) return <span className="sparkline sparkline-leer" aria-hidden="true" />;
  const werte = alle.map((p) => p[1]);
  const lo = props.prozent ? 0 : Math.min(...werte);
  let hi = props.prozent ? 100 : Math.max(...werte);
  if (hi - lo < 1e-9) hi = lo + 1;
  const x = (t: number) => ((t + props.schritt / 2 - von) / props.spanne) * SB;
  const y = (v: number) => 2 + (SH - 4) * (1 - (Math.min(Math.max(v, lo), hi) - lo) / (hi - lo));
  const pfade = props.linien.map((pts) => {
    let d = "";
    let letzte = -Infinity;
    for (const [t, v] of pts) {
      d += `${t - letzte > props.schritt * 2 ? "M" : "L"}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
      letzte = t;
    }
    return d;
  });
  return (
    <svg className="sparkline" viewBox={`0 0 ${SB} ${SH}`} role="img" aria-label={props.titel} preserveAspectRatio="none">
      {props.prozent && <line className="sparkline-grund" x1={0} x2={SB} y1={y(0)} y2={y(0)} />}
      {pfade.map((d, i) => (
        <path key={i} d={d} className="sparkline-linie" style={{ stroke: sparkFarben[i % sparkFarben.length] }} />
      ))}
    </svg>
  );
}

// Verfügbarkeit eines Checks als Streifen (schlechtester Zustand je Schritt).
function CheckStreifen(props: { punkte: CheckPunkt[]; spanne: number; schritt: number; titel: string }) {
  const bis = Date.now() / 1000;
  const von = bis - props.spanne;
  if (props.punkte.length === 0) return <span className="sparkline sparkline-leer" aria-hidden="true" />;
  const breite = Math.max(1, (props.schritt / props.spanne) * SB);
  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${SB} ${SH}`}
      role="img"
      aria-label={props.titel}
      preserveAspectRatio="none"
      shapeRendering="crispEdges"
    >
      {props.punkte.map((p) => (
        <rect
          key={p.t}
          className={`streifen-${p.schlechtester}`}
          x={((p.t - von) / props.spanne) * SB}
          width={breite + 0.4}
          y={6}
          height={SH - 12}
        />
      ))}
    </svg>
  );
}

// Welche Reihen gehören zu einem Sensor? null = kein Verlauf (z. B. Erreichbarkeit).
export interface SensorReihen {
  quelle: "agent" | "snmp";
  reihen: { name: string; text: string }[];
  einheit: string;
  prozent: boolean;
  format?: (v: number) => string;
}

export function sensorReihen(s: Sensor): SensorReihen | null {
  if (s.art === "check") return null;
  const quelle = s.art === "host" ? "agent" : "snmp";
  const g = s.gegenstand;
  const prozent = (name: string, text: string): SensorReihen => ({ quelle, reihen: [{ name, text }], einheit: "%", prozent: true });
  if (g === "cpu") return prozent("cpu", "CPU");
  if (g === "speicher") return prozent("speicher", "Arbeitsspeicher");
  if (g.startsWith("platte:")) return prozent(g, g.slice(7));
  if (s.art !== "snmp") return null;
  if (g === "temperatur") return { quelle, reihen: [{ name: "temperatur", text: "Temperatur" }], einheit: "°C", prozent: false };
  if (g === "usv") return prozent("usv_ladung", "Ladung");
  if (g.startsWith("toner:")) return prozent(g, g.slice(6));
  if (g.startsWith("if:")) {
    const n = g.slice(3);
    return {
      quelle,
      reihen: [
        { name: "if_ein:" + n, text: "ein" },
        { name: "if_aus:" + n, text: "aus" },
      ],
      einheit: "",
      prozent: false,
      format: bitrate,
    };
  }
  return null;
}

function punkteVon(d: SparkDaten, quelle: "agent" | "snmp", name: string): [number, number][] {
  return (d[quelle]?.reihen.find((r) => r.name === name)?.punkte ?? []).map((p) => [p[0], p[1]]);
}

export function SparkReihen(props: { d: SparkDaten | null; quelle: "agent" | "snmp"; namen: string[]; prozent?: boolean; titel: string }) {
  if (!props.d) return <span className="sparkline sparkline-leer" aria-hidden="true" />;
  return (
    <Sparkline
      linien={props.namen.map((n) => punkteVon(props.d!, props.quelle, n))}
      spanne={props.d.spanne_s}
      schritt={props.d.schritt_s}
      prozent={props.prozent}
      titel={props.titel}
    />
  );
}

// Sensoren eines Geräts mit Sparkline; Klick öffnet den Verlauf darunter.
export function GeraetSensoren(props: { sensoren: Sensor[]; d: SparkDaten | null; misstZeit: (checkId: string) => boolean }) {
  const [offen, setOffen] = useState("");
  if (props.sensoren.length === 0) return null;
  return (
    <div className="geraet-sensoren">
      <h3 className="klein-titel">Sensoren, letzte 24 Stunden</h3>
      <ul className="sparkliste">
        {props.sensoren.map((s) => {
          const r = sensorReihen(s);
          const check = s.art === "check" ? props.d?.checks.find((c) => c.id === s.quelle_id) : undefined;
          const hatVerlauf = !!r || s.art === "check";
          const istOffen = offen === s.schluessel;
          const inhalt = (
            <>
              <span className={`signal signal-${s.status}`} aria-hidden="true" />
              <span className="sparkzeile-text">
                <span className="name">{s.name}</span>
                <span className="klein">{meldungMitWert(s)}</span>
              </span>
              {r ? (
                <SparkReihen
                  d={props.d}
                  quelle={r.quelle}
                  namen={r.reihen.map((x) => x.name)}
                  prozent={r.prozent}
                  titel={`${s.name}, 24 Stunden`}
                />
              ) : check ? (
                <CheckStreifen
                  punkte={check.punkte}
                  spanne={props.d!.spanne_s}
                  schritt={props.d!.schritt_s}
                  titel={`${s.name}, 24 Stunden`}
                />
              ) : (
                <span className="sparkline sparkline-leer" aria-hidden="true" />
              )}
            </>
          );
          return (
            <li key={s.schluessel} className={`sparkzeile${istOffen ? " sparkzeile-offen" : ""}`}>
              {hatVerlauf ? (
                <button
                  type="button"
                  className="sparkzeile-knopf"
                  aria-expanded={istOffen}
                  title={istOffen ? "Verlauf schließen" : "Verlauf öffnen"}
                  onClick={() => setOffen(istOffen ? "" : s.schluessel)}
                >
                  {inhalt}
                </button>
              ) : (
                <div className="sparkzeile-knopf">{inhalt}</div>
              )}
              {istOffen && s.art === "check" && <CheckVerlauf checkId={s.quelle_id} misstZeit={props.misstZeit(s.quelle_id)} />}
              {istOffen && r && (
                <ReihenVerlauf
                  pfad={r.quelle === "agent" ? `/api/v1/agents/${s.quelle_id}/verlauf` : `/api/v1/snmp/${s.quelle_id}/verlauf`}
                  titel={s.name}
                  reihen={r.reihen}
                  einheit={r.einheit}
                  prozent={r.prozent}
                  format={r.format}
                />
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
