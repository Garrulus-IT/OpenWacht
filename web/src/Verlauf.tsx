// SPDX-License-Identifier: AGPL-3.0-only

// Verlauf der Messwerte als schlichte SVG-Linien, ohne Diagramm-Bibliothek.
//
// Die Zentrale liefert je Reihe Punkte [Zeit, Mittel, Minimum, Maximum] in
// festen Schritten. Fehlt ein Punkt (Agent still, Zentrale aus), reißt die
// Linie ab, statt eine Lücke zu überbrücken.

import { bitrate } from "./Pegel";
import { bytes } from "./zeit";
import { useCallback, useEffect, useId, useRef, useState, type PointerEvent } from "react";
import { api, type CheckStatus } from "./api";

export type Zeitraum = "1h" | "24h" | "7t" | "30t";
const zeitraeume: { wert: Zeitraum; text: string }[] = [
  { wert: "1h", text: "1 Std." },
  { wert: "24h", text: "24 Std." },
  { wert: "7t", text: "7 Tage" },
  { wert: "30t", text: "30 Tage" },
];

// Zuletzt gewählter Zeitraum, damit der nächste aufgeklappte Eintrag ihn übernimmt.
let letzterZeitraum: Zeitraum = "24h";

type Punkt = [number, number, number, number];

interface HostVerlaufAntwort {
  spanne_s: number;
  schritt_s: number;
  reihen: { name: string; punkte: Punkt[] }[];
}

interface CheckPunkt {
  t: number;
  n: number;
  ok: number;
  schlechtester: CheckStatus;
  ms: number | null;
  ms_min: number | null;
  ms_max: number | null;
}

interface CheckVerlaufAntwort {
  spanne_s: number;
  schritt_s: number;
  punkte: CheckPunkt[];
  wechsel: { zeit: string; von: CheckStatus | null; nach: CheckStatus; meldung: string | null }[];
}

const zahl = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });

// Farben für mehrere Linien in einem Graphen: vier Farben (--reihe-1 … 4),
// Reihe 5–8 in denselben Farben gestrichelt (Corporate Design). Die Farben
// folgen dem hellen und dunklen Modus; Zustandsfarben bleiben Zuständen
// vorbehalten.
const linienFarbe = (i: number) => `var(--reihe-${(i % 4) + 1})`;
const gestrichelt = (i: number) => i % 8 >= 4;

function uhrzeit(t: number, spanne: number) {
  const d = new Date(t * 1000);
  if (spanne <= 86400) return d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
  if (spanne <= 7 * 86400) return d.toLocaleString("de-DE", { weekday: "short", hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" });
}

function zeitpunkt(t: number) {
  return new Date(t * 1000).toLocaleString("de-DE", {
    weekday: "short",
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Obergrenze der y-Achse: 1, 2 oder 5 mal einer Zehnerpotenz.
function runde(max: number) {
  if (max <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(max)));
  for (const f of [1, 2, 5, 10]) if (f * p >= max) return f * p;
  return 10 * p;
}

export function ZeitraumWahl({ wert, onWahl }: { wert: Zeitraum; onWahl: (z: Zeitraum) => void }) {
  return (
    <div className="umschalter" role="group" aria-label="Zeitraum">
      {zeitraeume.map((z) => (
        <button
          key={z.wert}
          type="button"
          className="umschalter-knopf"
          aria-pressed={wert === z.wert}
          onClick={() => {
            letzterZeitraum = z.wert;
            onWahl(z.wert);
          }}
        >
          {z.text}
        </button>
      ))}
    </div>
  );
}

// Lädt den Verlauf und lädt ihn jede Minute neu, solange er angezeigt wird.
function useVerlauf<T>(pfad: string) {
  const [zeitraum, setZeitraum] = useState<Zeitraum>(letzterZeitraum);
  const [daten, setDaten] = useState<T | null>(null);
  const [fehler, setFehler] = useState("");
  const laden = useCallback(async () => {
    try {
      setDaten(await api<T>("GET", `${pfad}?zeitraum=${zeitraum}`));
      setFehler("");
    } catch (e) {
      setFehler(e instanceof Error ? e.message : "Verlauf nicht ladbar.");
    }
  }, [pfad, zeitraum]);
  useEffect(() => {
    setDaten(null);
    laden();
    const t = setInterval(laden, 60_000);
    return () => clearInterval(t);
  }, [laden]);
  return { zeitraum, setZeitraum, daten, fehler };
}

// --- Graph ----------------------------------------------------------------------

interface Linie {
  name: string;
  punkte: Punkt[];
}

const B = 640;
const H = 150;
const rand = { l: 44, r: 10, o: 10, u: 22 };

export function Graph(props: {
  titel: string;
  linien: Linie[];
  spanne: number;
  schritt: number;
  einheit: string;
  prozent?: boolean;
  // waagerechte Bezugslinie, z. B. die Zahl der Kerne bei der Last
  bezug?: { wert: number; text: string };
  // Ende des Zeitraums (Unix-Sekunden), Standard: jetzt
  bis?: number;
  // eigene Schreibweise der Werte (z. B. Bit/s); ersetzt einheit
  format?: (v: number) => string;
}) {
  const { linien, spanne, schritt, einheit } = props;
  const [zeiger, setZeiger] = useState<number | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const bis = props.bis ?? Date.now() / 1000;
  const von = bis - spanne;
  const alle = linien.flatMap((l) => l.punkte);
  const yMax = props.prozent ? 100 : runde(Math.max(0, props.bezug?.wert ?? 0, ...alle.map((p) => p[3])) * 1.1);
  // Genug Nachkommastellen für den halben Höchstwert, sonst stehen bei
  // kleinen Werten (Last 0,05) zwei gleiche Beschriftungen an der Achse.
  const achsenZahl = new Intl.NumberFormat("de-DE", {
    maximumFractionDigits: Math.min(4, Math.max(1, 1 - Math.floor(Math.log10(yMax / 2)))),
  });
  const achsenText = (f: number) => (props.format ? (f === 0 ? "0" : props.format(yMax * f)) : achsenZahl.format(yMax * f));
  // Linker Rand nach der längsten Beschriftung: Lange Texte wie „20 kbit/s“
  // wurden sonst links abgeschnitten und sahen aus wie „0 kbit/s“ (doppelt).
  const links = Math.max(rand.l, Math.ceil(Math.max(...[0, 0.5, 1].map((f) => achsenText(f).length)) * 6.6) + 10);
  const breite = B - links - rand.r;
  const hoehe = H - rand.o - rand.u;
  const x = (t: number) => links + ((t + schritt / 2 - von) / spanne) * breite;
  const y = (v: number) => rand.o + hoehe - (Math.min(Math.max(v, 0), yMax) / yMax) * hoehe;

  // Zusammenhängende Abschnitte: Eine Lücke von mehr als zwei Schritten trennt.
  const abschnitte = (pts: Punkt[]) => {
    const out: Punkt[][] = [];
    for (const p of pts) {
      const last = out[out.length - 1];
      if (last && p[0] - last[last.length - 1]![0] <= schritt * 2) last.push(p);
      else out.push([p]);
    }
    return out;
  };
  const pfad = (pts: Punkt[], i: 1 | 2 | 3) => pts.map((p, k) => `${k ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[i]).toFixed(1)}`).join("");
  const band = (pts: Punkt[]) =>
    pts.map((p, k) => `${k ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[3]).toFixed(1)}`).join("") +
    [...pts]
      .reverse()
      .map((p) => `L${x(p[0]).toFixed(1)},${y(p[2]).toFixed(1)}`)
      .join("") +
    "Z";

  const zeiten = [...new Set(alle.map((p) => p[0]))].sort((a, b) => a - b);
  const bewegen = (e: PointerEvent<SVGSVGElement>) => {
    const r = svg.current?.getBoundingClientRect();
    if (!r || zeiten.length === 0) return;
    const t = von + (((e.clientX - r.left) / r.width) * B - links) * (spanne / breite) - schritt / 2;
    let best = zeiten[0]!;
    for (const z of zeiten) if (Math.abs(z - t) < Math.abs(best - t)) best = z;
    setZeiger(best);
  };

  // Werte eine Stelle genauer als die Achse: Eine Last von 0,03 hieß sonst „0“.
  const wertZahl = new Intl.NumberFormat("de-DE", {
    maximumFractionDigits: Math.min(4, Math.max(1, 2 - Math.floor(Math.log10(yMax / 2)))),
  });
  const fmt = props.format ?? ((v: number) => `${wertZahl.format(v)}${einheit ? " " + einheit : ""}`);
  // Mittel und Spitze je Linie; über mehrere Platten gemittelt sagt der Wert nichts.
  const kennwerte = (pts: Punkt[]) => ({
    mittel: pts.length ? pts.reduce((s, p) => s + p[1], 0) / pts.length : 0,
    spitze: pts.length ? Math.max(...pts.map((p) => p[3])) : 0,
  });
  const einzeln = linien.length === 1;
  const gesamt = kennwerte(einzeln ? linien[0]!.punkte : []);
  const kennText = (k: { mittel: number; spitze: number }) => `Mittel ${fmt(k.mittel)}, Spitze ${fmt(k.spitze)}`;

  return (
    <figure className="graph">
      <figcaption className="graph-kopf">
        <span className="graph-titel">{props.titel}</span>
        <span className="graph-wert" aria-live="polite">
          {zeiger === null
            ? einzeln && alle.length
              ? kennText(gesamt)
              : ""
            : `${zeitpunkt(zeiger)}: ` +
              linien
                .map((l) => {
                  const p = l.punkte.find((q) => q[0] === zeiger);
                  return p ? `${einzeln ? "" : l.name + " "}${fmt(p[1])}${p[3] > p[1] ? ` (bis ${fmt(p[3])})` : ""}` : null;
                })
                .filter(Boolean)
                .join(" · ")}
        </span>
      </figcaption>
      {alle.length === 0 ? (
        <p className="klein graph-leer">Für diesen Zeitraum liegen noch keine Werte vor.</p>
      ) : (
        <svg
          ref={svg}
          className="graph-flaeche"
          viewBox={`0 0 ${B} ${H}`}
          role="img"
          aria-label={`${props.titel}, ${linien
            .filter((l) => l.punkte.length)
            .map((l) => (einzeln ? "" : l.name + " ") + kennText(kennwerte(l.punkte)))
            .join("; ")}`}
          onPointerMove={bewegen}
          onPointerLeave={() => setZeiger(null)}
        >
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line className="graph-gitter" x1={links} x2={B - rand.r} y1={y(yMax * f)} y2={y(yMax * f)} />
              <text className="graph-achse" x={links - 6} y={y(yMax * f) + 4} textAnchor="end">
                {achsenText(f)}
              </text>
            </g>
          ))}
          {props.bezug && props.bezug.wert > 0 && (
            <g>
              <line className="graph-bezug" x1={links} x2={B - rand.r} y1={y(props.bezug.wert)} y2={y(props.bezug.wert)} />
              <text className="graph-achse" x={B - rand.r - 4} y={y(props.bezug.wert) - 4} textAnchor="end">
                {props.bezug.text}
              </text>
            </g>
          )}
          {[0, 0.5, 1].map((f) => (
            <text
              key={f}
              className="graph-achse"
              x={links + breite * f}
              y={H - 6}
              textAnchor={f === 0 ? "start" : f === 1 ? "end" : "middle"}
            >
              {uhrzeit(von + spanne * f, spanne)}
            </text>
          ))}
          {linien.map((l, i) =>
            abschnitte(l.punkte).map((a, k) => (
              <g key={`${l.name}-${k}`}>
                {einzeln && a.length > 1 && <path className="graph-band" d={band(a)} />}
                {a.length === 1 ? (
                  <circle cx={x(a[0]![0])} cy={y(a[0]![1])} r={2} style={{ fill: linienFarbe(i) }} />
                ) : (
                  <path className="graph-linie" d={pfad(a, 1)} style={{ stroke: linienFarbe(i), strokeDasharray: gestrichelt(i) ? "var(--reihe-strich)" : undefined }} />
                )}
              </g>
            )),
          )}
          {zeiger !== null && <line className="graph-zeiger" x1={x(zeiger)} x2={x(zeiger)} y1={rand.o} y2={rand.o + hoehe} />}
        </svg>
      )}
      {!einzeln && alle.length > 0 && (
        <ul className="graph-legende">
          {linien.map((l, i) => (
            <li key={l.name}>
              <span className={gestrichelt(i) ? "graph-farbe graph-farbe-strich" : "graph-farbe"} style={{ color: linienFarbe(i) }} aria-hidden="true" />
              <span className="mono">{l.name}</span>
              {l.punkte.length > 0 && <span className="klein graph-kennwerte">{kennText(kennwerte(l.punkte))}</span>}
            </li>
          ))}
        </ul>
      )}
    </figure>
  );
}

// --- Hosts ------------------------------------------------------------------------

export function HostVerlauf({ agentId, ohneLast, kerne }: { agentId: string; ohneLast: boolean; kerne: number }) {
  const { zeitraum, setZeitraum, daten, fehler } = useVerlauf<HostVerlaufAntwort>(`/api/v1/agents/${agentId}/verlauf`);
  const titelId = useId();
  const reihe = (name: string) => daten?.reihen.find((r) => r.name === name)?.punkte ?? [];
  const platten = (daten?.reihen ?? [])
    .filter((r) => r.name.startsWith("platte:"))
    .map((r) => ({ name: r.name.slice(7), punkte: r.punkte }));
  const speicher: Linie[] = [{ name: "Arbeitsspeicher", punkte: reihe("speicher") }];
  if (reihe("swap").length) speicher.push({ name: ohneLast ? "Auslagerung" : "Swap", punkte: reihe("swap") });
  return (
    <section className="verlauf" aria-labelledby={titelId}>
      <div className="verlauf-kopf">
        <h3 className="verlauf-titel" id={titelId}>
          Verlauf
        </h3>
        <ZeitraumWahl wert={zeitraum} onWahl={setZeitraum} />
      </div>
      {fehler && <p className="meldung meldung-fehler">{fehler}</p>}
      {!daten && !fehler && (
        <p className="klein" aria-busy="true">
          Verlauf wird geladen …
        </p>
      )}
      {daten && (
        <div className="graphen">
          <Graph
            titel="CPU-Auslastung"
            linien={[{ name: "CPU", punkte: reihe("cpu") }]}
            spanne={daten.spanne_s}
            schritt={daten.schritt_s}
            einheit="%"
            prozent
          />
          <Graph titel="Arbeitsspeicher belegt" linien={speicher} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="%" prozent />
          <Graph
            titel={ohneLast ? "Laufwerke belegt" : "Platten belegt"}
            linien={platten}
            spanne={daten.spanne_s}
            schritt={daten.schritt_s}
            einheit="%"
            prozent
          />
          {!ohneLast && (
            <Graph
              titel="Last (1 Min.)"
              linien={[{ name: "Last", punkte: reihe("last1") }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit=""
              bezug={{ wert: kerne, text: `${kerne} Kerne` }}
            />
          )}
        </div>
      )}
    </section>
  );
}

// --- SNMP ----------------------------------------------------------------------------

// Verlauf einer SNMP-Quelle: CPU, Speicher, Platten, Temperatur, USV,
// Verbrauchsmaterial und der Verkehr der Schnittstellen mit Werten.
export function SnmpVerlauf({ snmpId, schnittstellen }: { snmpId: string; schnittstellen: string[] }) {
  const { zeitraum, setZeitraum, daten, fehler } = useVerlauf<HostVerlaufAntwort>(`/api/v1/snmp/${snmpId}/verlauf`);
  const titelId = useId();
  const reihen = daten?.reihen ?? [];
  const reihe = (name: string) => reihen.find((r) => r.name === name)?.punkte ?? [];
  const mit = (prefix: string) =>
    reihen.filter((r) => r.name.startsWith(prefix)).map((r) => ({ name: r.name.slice(prefix.length), punkte: r.punkte }));
  const verkehr = schnittstellen
    .map((n) => ({ n, ein: reihe("if_ein:" + n), aus: reihe("if_aus:" + n) }))
    .filter((x) => x.ein.length || x.aus.length);
  return (
    <section className="verlauf" aria-labelledby={titelId}>
      <div className="verlauf-kopf">
        <h3 className="verlauf-titel" id={titelId}>
          Verlauf
        </h3>
        <ZeitraumWahl wert={zeitraum} onWahl={setZeitraum} />
      </div>
      {fehler && <p className="meldung meldung-fehler">{fehler}</p>}
      {!daten && !fehler && (
        <p className="klein" aria-busy="true">
          Verlauf wird geladen …
        </p>
      )}
      {daten && (
        <div className="graphen">
          {reihe("cpu").length > 0 && (
            <Graph
              titel="CPU-Auslastung"
              linien={[{ name: "CPU", punkte: reihe("cpu") }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="%"
              prozent
            />
          )}
          {reihe("speicher").length > 0 && (
            <Graph
              titel="Arbeitsspeicher belegt"
              linien={[{ name: "Arbeitsspeicher", punkte: reihe("speicher") }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="%"
              prozent
            />
          )}
          {mit("platte:").length > 0 && (
            <Graph titel="Speicher belegt" linien={mit("platte:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="%" prozent />
          )}
          {mit("iops:").length > 0 && (
            <Graph titel="IOPS je Aggregat" linien={mit("iops:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="IOPS" />
          )}
          {mit("latenz:").length > 0 && (
            <Graph titel="Latenz je Aggregat" linien={mit("latenz:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="ms" />
          )}
          {mit("xcpu:").length > 0 && (
            <Graph titel="CPU je Host" linien={mit("xcpu:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="%" prozent />
          )}
          {mit("xram:").length > 0 && (
            <Graph titel="RAM je Host" linien={mit("xram:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="%" prozent />
          )}
          {mit("vmcpu:").length > 0 && (
            <Graph titel="CPU je VM" linien={mit("vmcpu:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="%" prozent />
          )}
          {mit("vmram:").length > 0 && (
            <Graph titel="RAM je VM" linien={mit("vmram:")} spanne={daten.spanne_s} schritt={daten.schritt_s} einheit="" format={bytes} />
          )}
          {mit("meta:").length > 0 && (
            <Graph
              titel="Thin-Pool-Metadaten belegt"
              linien={mit("meta:")}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="%"
              prozent
            />
          )}
          {reihe("temperatur").length > 0 && (
            <Graph
              titel="Systemtemperatur"
              linien={[{ name: "Temperatur", punkte: reihe("temperatur") }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="°C"
            />
          )}
          {reihe("usv_ladung").length > 0 && (
            <Graph
              titel="USV-Ladung"
              linien={[{ name: "Ladung", punkte: reihe("usv_ladung") }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="%"
              prozent
            />
          )}
          {mit("toner:").length > 0 && (
            <Graph
              titel="Verbrauchsmaterial übrig"
              linien={mit("toner:")}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="%"
              prozent
            />
          )}
          {verkehr.map((x) => (
            <Graph
              key={x.n}
              titel={`Verkehr ${x.n}`}
              linien={[
                { name: "ein", punkte: x.ein },
                { name: "aus", punkte: x.aus },
              ]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit=""
              format={bitrate}
            />
          ))}
          {(reihe("dsl_ab").length > 0 || reihe("dsl_auf").length > 0) && (
            <Graph
              titel="DSL-Synchronrate"
              linien={[
                { name: "ab", punkte: reihe("dsl_ab") },
                { name: "auf", punkte: reihe("dsl_auf") },
              ]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit=""
              format={bitrate}
            />
          )}
          {reihen.length === 0 && <p className="klein">Für diesen Zeitraum liegen noch keine Werte vor.</p>}
        </div>
      )}
    </section>
  );
}

// --- Checks -------------------------------------------------------------------------

const statusText: Record<CheckStatus, string> = { ok: "OK", warn: "Warnung", crit: "Kritisch", unknown: "Unbekannt" };

export function CheckVerlauf({ checkId, misstZeit }: { checkId: string; misstZeit: boolean }) {
  const { zeitraum, setZeitraum, daten, fehler } = useVerlauf<CheckVerlaufAntwort>(`/api/v1/checks/${checkId}/verlauf`);
  const titelId = useId();
  const punkte = daten?.punkte ?? [];
  const n = punkte.reduce((s, p) => s + p.n, 0);
  const ok = punkte.reduce((s, p) => s + p.ok, 0);
  const ms: Punkt[] = punkte.filter((p) => p.ms !== null).map((p) => [p.t, p.ms!, p.ms_min!, p.ms_max!]);
  const bis = Date.now() / 1000;
  return (
    <section className="verlauf" aria-labelledby={titelId}>
      <div className="verlauf-kopf">
        <h3 className="verlauf-titel" id={titelId}>
          Verlauf
        </h3>
        <ZeitraumWahl wert={zeitraum} onWahl={setZeitraum} />
      </div>
      {fehler && <p className="meldung meldung-fehler">{fehler}</p>}
      {!daten && !fehler && (
        <p className="klein" aria-busy="true">
          Verlauf wird geladen …
        </p>
      )}
      {daten && (
        <div className="graphen">
          <figure className="graph">
            <figcaption className="graph-kopf">
              <span className="graph-titel">Verfügbarkeit</span>
              <span className="graph-wert">
                {n ? `${zahl.format((ok / n) * 100)} % OK (${ok} von ${n} Prüfungen)` : "noch keine Prüfungen"}
              </span>
            </figcaption>
            {n > 0 && (
              <svg
                className="graph-streifen"
                shapeRendering="crispEdges"
                viewBox={`0 0 ${B} 14`}
                preserveAspectRatio="none"
                aria-hidden="true"
              >
                {punkte.map((p) => (
                  <rect
                    key={p.t}
                    className={`streifen-${p.schlechtester}`}
                    x={((p.t - (bis - daten.spanne_s)) / daten.spanne_s) * B}
                    width={Math.max(1, (daten.schritt_s / daten.spanne_s) * B) + 0.6}
                    y={0}
                    height={14}
                  >
                    <title>{`${zeitpunkt(p.t)}: ${statusText[p.schlechtester]}`}</title>
                  </rect>
                ))}
              </svg>
            )}
          </figure>
          {misstZeit && (
            <Graph
              titel="Antwortzeit"
              linien={[{ name: "Antwortzeit", punkte: ms }]}
              spanne={daten.spanne_s}
              schritt={daten.schritt_s}
              einheit="ms"
              bis={bis}
            />
          )}
          <div className="wechsel">
            <h4 className="graph-titel">Zustandswechsel</h4>
            {daten.wechsel.length === 0 ? (
              <p className="klein">Keine im gewählten Zeitraum.</p>
            ) : (
              <ol className="wechsel-liste">
                {[...daten.wechsel]
                  .reverse()
                  .slice(0, 10)
                  .map((w) => (
                    <li key={w.zeit + w.nach}>
                      <time dateTime={w.zeit} className="klein">
                        {zeitpunkt(Date.parse(w.zeit) / 1000)}
                      </time>
                      <span>
                        {w.von ? `${statusText[w.von]} → ${statusText[w.nach]}` : `erstes Ergebnis: ${statusText[w.nach]}`}
                        {w.meldung && w.nach !== "ok" ? `, ${w.meldung}` : ""}
                      </span>
                    </li>
                  ))}
              </ol>
            )}
            {daten.wechsel.length > 10 && <p className="klein">… und {daten.wechsel.length - 10} ältere.</p>}
          </div>
        </div>
      )}
    </section>
  );
}

// --- Einzelne Reihen (Klick auf einen Sensor) ------------------------------------------

// Verlauf ausgewählter Reihen einer Quelle (Agent oder SNMP), z. B. nur eine
// Platte oder der Verkehr einer Schnittstelle.
export function ReihenVerlauf(props: {
  pfad: string;
  titel: string;
  reihen: { name: string; text: string }[];
  einheit: string;
  prozent?: boolean;
  format?: (v: number) => string;
}) {
  const { zeitraum, setZeitraum, daten, fehler } = useVerlauf<HostVerlaufAntwort>(props.pfad);
  const titelId = useId();
  const linien = props.reihen.map((r) => ({ name: r.text, punkte: daten?.reihen.find((x) => x.name === r.name)?.punkte ?? [] }));
  return (
    <section className="verlauf verlauf-einzeln" aria-labelledby={titelId}>
      <div className="verlauf-kopf">
        <h4 className="verlauf-titel" id={titelId}>
          Verlauf {props.titel}
        </h4>
        <ZeitraumWahl wert={zeitraum} onWahl={setZeitraum} />
      </div>
      {fehler && <p className="meldung meldung-fehler">{fehler}</p>}
      {!daten && !fehler && (
        <p className="klein" aria-busy="true">
          Verlauf wird geladen …
        </p>
      )}
      {daten && (
        <Graph
          titel={props.titel}
          linien={linien}
          spanne={daten.spanne_s}
          schritt={daten.schritt_s}
          einheit={props.einheit}
          prozent={props.prozent}
          format={props.format}
        />
      )}
    </section>
  );
}
