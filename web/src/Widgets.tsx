// SPDX-License-Identifier: AGPL-3.0-only

// Inhalte der Dashboard-Widgets (Etappe 17). Jedes Widget bekommt seinen
// Bereich (fester Mandant oder der aus der Seitenleiste) und grenzt die Daten
// darauf ein; die Zentrale liefert ohnehin nur, was der Benutzer sehen darf.
// Alle Texte von Agents und Geräten erscheinen nur als Text (React escapt).

import { useEffect, useState, type ReactNode } from "react";
import type { Agent, Alarm, AnzeigeKnoten, AnzeigeStatus, Check, Geraet, Gruppe as GeraeteGruppe, Mandant, Sensor, Snmp } from "./api";
import { kinderVon, mandantName, type Bereich } from "./bereich";
import { AlarmeJeTag, mitFilter, Verfuegbarkeit, VollstePlatten, type FlottenVerlauf, type Kennzahlen } from "./Dashboard";
import { BaldVoll, bereichFilter, type PrognoseAntwort } from "./Prognose";
import { Graph } from "./Verlauf";
import { Pegel } from "./Pegel";
import { Sonne } from "./Sonne";
import { kennStil, kennTitel, type Kennfarbe } from "./kennfarbe";
import { gruppe, gruppen, rang, sensorTitel, statusText, type Gruppe } from "./AlarmeSeite";
import { useQuelle } from "./quelle";
import { vor } from "./zeit";
import { lesen, restText } from "./Zertifikate";
import type { Ort } from "./navigation";
import type { Widget } from "./widgets";

export const Q = {
  sensoren: "/api/v1/sensoren",
  alarme: "/api/v1/alarme?limit=500",
  agents: "/api/v1/agents",
  geraete: "/api/v1/geraete",
  gruppen: "/api/v1/gruppen",
  snmp: "/api/v1/snmp",
};

export interface WidgetProps {
  w: Widget;
  bereich: Bereich;
  mandanten: Mandant[];
  gehe: (o: Partial<Ort>) => void;
}

function Laedt({ fehler }: { fehler: string }) {
  if (fehler) return <p className="meldung meldung-fehler">{fehler}</p>;
  return (
    <p className="klein" aria-busy="true">
      Lädt …
    </p>
  );
}

function useSensoren(b: Bereich) {
  const q = useQuelle<{ sensoren: Sensor[] }>(Q.sensoren, 15_000);
  return { liste: q.daten ? q.daten.sensoren.filter((s) => b.ids.has(s.mandant_id)) : null, fehler: q.fehler };
}

function zumGeraet(gehe: WidgetProps["gehe"], mandant: string, geraet: string) {
  gehe({ reiter: "hosts", mandant, mitUnter: false, geraet });
}

// Kürzel für die vollflächigen Zustandszellen (Entwurf A)
const kurz: Record<string, string> = {
  crit: "Kritisch",
  warn: "Warnung",
  unknown: "Unbekannt",
  neu: "Neu",
  ok: "OK",
  pause: "Pausiert",
  wartung: "Wartung",
};

export function Zustandszelle({ status, bestaetigt, kennfarbe }: { status: string; bestaetigt?: boolean; kennfarbe?: Kennfarbe | null }) {
  const k = kennStil(kennfarbe, status);
  const titel = (bestaetigt ? "bestätigt" : "") + kennTitel(kennfarbe, status);
  return (
    <span
      className={`zst zst-${status}${bestaetigt ? " zst-bestaetigt" : ""}${k.className}`}
      style={k.style}
      title={titel.replace(/^ · /, "") || undefined}
    >
      {kurz[status] ?? status}
      {bestaetigt && <span className="sr-only"> bestätigt</span>}
    </span>
  );
}

// --- Zustand: Probleme zuerst (1.0.6, ersetzt die Sechsecke) -------------------------
//
// Probleme stehen als große Zahlen vorn, immer sichtbar, auch wenn sie unter
// Tausenden OK-Sensoren nur einen winzigen Anteil haben. Der Balken darunter
// zeigt die Verteilung; jedes Problem-Segment ist mindestens so breit, dass es
// zu sehen ist (die Breite ist dann bewusst nicht maßstabsgetreu).

const reihenfolge: Gruppe[] = ["crit", "warn", "unknown", "ok", "wartung", "pause"];
const problem: Gruppe[] = ["crit", "warn", "unknown"];
const farbe: Record<Gruppe, string> = {
  crit: "var(--krit)",
  warn: "var(--warn)",
  unknown: "var(--leise)",
  ok: "var(--ok)",
  wartung: "var(--wartung)",
  pause: "var(--linie)",
};
const text: Record<Gruppe, string> = Object.fromEntries(gruppen.map((g) => [g.id, g.text])) as Record<Gruppe, string>;

// Breiten in Prozent; Probleme mindestens 6 %, der Rest teilt sich, was bleibt.
export function balkenBreiten(zahl: Record<Gruppe, number>): Record<Gruppe, number> {
  const gesamt = reihenfolge.reduce((n, g) => n + zahl[g], 0);
  const out = { crit: 0, warn: 0, unknown: 0, ok: 0, wartung: 0, pause: 0 } as Record<Gruppe, number>;
  if (!gesamt) return out;
  let fest = 0;
  for (const g of problem) {
    if (zahl[g]) {
      out[g] = Math.max(6, (zahl[g] / gesamt) * 100);
      fest += out[g];
    }
  }
  const rest = reihenfolge.filter((g) => !problem.includes(g));
  const restZahl = rest.reduce((n, g) => n + zahl[g], 0);
  const frei = Math.max(0, 100 - fest);
  for (const g of rest) out[g] = restZahl ? (zahl[g] / restZahl) * frei : 0;
  if (!restZahl && fest) for (const g of problem) out[g] = (out[g] / fest) * 100;
  return out;
}

// Eine Zeile je Einheit (Geräte, Sensoren): Zahlen je Zustand, darunter der Balken.
function ZustandsZeile({ zahl, einheit, titel, onClick }: { zahl: Record<Gruppe, number>; einheit: string; titel: string; onClick: () => void }) {
  const breite = balkenBreiten(zahl);
  const probleme = problem.reduce((n, g) => n + zahl[g], 0);
  const gesamt = reihenfolge.reduce((n, g) => n + zahl[g], 0);
  return (
    <>
      <tr className="zustand-zeile" title={titel}>
        <th scope="row">
          <button type="button" className="knopf-text" onClick={onClick}>
            {einheit}
          </button>
          <span className="klein"> {gesamt}</span>
        </th>
        {problem.map((g) => (
          <td key={g} className={zahl[g] ? `zustand-wert zustand-wert-${g}` : "zustand-wert zustand-wert-null"}>
            {zahl[g]}
          </td>
        ))}
        <td className="zustand-wert zustand-wert-ruhig">{zahl.ok}</td>
        <td className="zustand-wert zustand-wert-ruhig">{zahl.wartung + zahl.pause}</td>
      </tr>
      <tr className="zustand-balken-zeile">
        <td colSpan={6}>
          <span
            className="zustand-balken"
            role="img"
            aria-label={probleme ? `${einheit}: ${probleme} mit Problemen von ${gesamt}` : `${einheit}: alle ${gesamt} ohne Problem`}
          >
            {reihenfolge.map((g) =>
              zahl[g] ? <span key={g} className="zustand-segment" style={{ width: `${breite[g]}%`, background: farbe[g] }} /> : null,
            )}
          </span>
        </td>
      </tr>
    </>
  );
}

function leer(): Record<Gruppe, number> {
  return { crit: 0, warn: 0, unknown: 0, ok: 0, wartung: 0, pause: 0 };
}

function ZustandWidget({ bereich, gehe }: WidgetProps) {
  const s = useSensoren(bereich);
  if (!s.liste) return <Laedt fehler={s.fehler} />;
  const sensoren = leer();
  const jeGeraet = new Map<string, Gruppe>();
  for (const x of s.liste) {
    const g = gruppe(x);
    sensoren[g]++;
    const alt = jeGeraet.get(x.geraet_id);
    if (alt === undefined || rang[g] < rang[alt]) jeGeraet.set(x.geraet_id, g);
  }
  const geraete = leer();
  for (const g of jeGeraet.values()) geraete[g]++;
  return (
    <table className="zustand-tabelle">
      <thead>
        <tr>
          <th scope="col">
            <span className="sr-only">Einheit</span>
          </th>
          {problem.map((g) => (
            <th key={g} scope="col">
              <span className={`signal signal-${g}`} aria-hidden="true" /> {text[g]}
            </th>
          ))}
          <th scope="col">OK</th>
          <th scope="col">Wartung/Pause</th>
        </tr>
      </thead>
      <tbody>
        <ZustandsZeile zahl={geraete} einheit="Geräte" titel="Geräte nach ihrem schlimmsten Sensor – zu den Hosts" onClick={() => gehe({ reiter: "hosts" })} />
        <ZustandsZeile zahl={sensoren} einheit="Sensoren" titel="Sensoren nach Zustand – zu den Alarmen" onClick={() => gehe({ reiter: "alarme", alarm: "aktiv" })} />
      </tbody>
    </table>
  );
}

// --- Aktive Alarme: Tabelle mit farbigen Zustandszellen ----------------------------------

function AlarmeWidget({ bereich, gehe }: WidgetProps) {
  const s = useSensoren(bereich);
  if (!s.liste) return <Laedt fehler={s.fehler} />;
  const jetzt = Date.now();
  const offen = s.liste
    .filter((x) => x.alarm && !x.alarm.ende)
    .sort(
      (a, b) =>
        Number(!!a.alarm!.bestaetigt_am) - Number(!!b.alarm!.bestaetigt_am) ||
        rang[gruppe(a)] - rang[gruppe(b)] ||
        Date.parse(b.alarm!.beginn) - Date.parse(a.alarm!.beginn),
    );
  if (offen.length === 0) return <p className="leer">Keine aktiven Alarme.</p>;
  return (
    <table className="tabelle tabelle-kompakt widget-tabelle">
      <thead>
        <tr>
          <th scope="col">Zustand</th>
          <th scope="col">Host</th>
          <th scope="col">Sensor</th>
          <th scope="col" className="nur-breit">
            Meldung
          </th>
          <th scope="col">seit</th>
        </tr>
      </thead>
      <tbody>
        {offen.map((x) => (
          <tr key={x.schluessel}>
            <td className="zelle-zst">
              <Zustandszelle status={x.wartung ? "wartung" : x.status} bestaetigt={!!x.alarm!.bestaetigt_am} kennfarbe={x.kennfarbe} />
            </td>
            <td>
              <button className="knopf-text" onClick={() => zumGeraet(gehe, x.mandant_id, x.geraet_id)}>
                {x.host ?? "–"}
              </button>
              {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, x.mandant_id)}</span>}
            </td>
            <td>{x.name}</td>
            <td className="nur-breit klein">{x.meldung}</td>
            <td className="klein nowrap">{vor(x.alarm!.beginn, jetzt)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- Sensoren nicht OK ------------------------------------------------------------------

function SensorenWidget({ bereich, gehe }: WidgetProps) {
  const s = useSensoren(bereich);
  if (!s.liste) return <Laedt fehler={s.fehler} />;
  const liste = s.liste
    .filter((x) => !["ok", "pause", "wartung"].includes(gruppe(x)))
    .sort((a, b) => rang[gruppe(a)] - rang[gruppe(b)] || sensorTitel(a).localeCompare(sensorTitel(b), "de"));
  if (liste.length === 0) return <p className="leer">Alle Sensoren sind OK.</p>;
  return (
    <ul className="kurzliste">
      {liste.map((x) => (
        <li key={x.schluessel}>
          <span
            className={`signal signal-${x.status}${kennStil(x.kennfarbe, x.status).className}`}
            style={kennStil(x.kennfarbe, x.status).style}
            aria-hidden="true"
          />
          <span className="sr-only">{statusText[x.status]}: </span>
          <button className="knopf-text kurzliste-name" onClick={() => zumGeraet(gehe, x.mandant_id, x.geraet_id)}>
            {x.host ?? x.name}
          </button>
          <span className="klein kurzliste-text" title={x.meldung}>
            {x.host ? x.name : x.meldung}
          </span>
        </li>
      ))}
    </ul>
  );
}

// --- CPU und RAM: aktuelle Werte als Balken --------------------------------------------

const prozent = (teil: number, ganz: number) => (ganz > 0 ? (teil / ganz) * 100 : 0);

function AuslastungWidget({ bereich, gehe }: WidgetProps) {
  const a = useQuelle<{ agents: Agent[]; intervall_sekunden: number }>(Q.agents, 30_000);
  const q = useQuelle<{ snmp: Snmp[] }>(Q.snmp, 60_000);
  const g = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);
  if (!a.daten || !g.daten) return <Laedt fehler={a.fehler || g.fehler} />;
  const jetzt = Date.now();
  const frisch = (t: string | null | undefined, intervall: number) => !!t && jetzt - Date.parse(t) < Math.max(3 * intervall, 180) * 1000;
  const namen = new Map(g.daten.geraete.map((x) => [x.id, x.name]));
  const zeilen: { geraet: string; mandant: string; name: string; cpu: number | null; ram: number | null }[] = [];
  for (const x of a.daten.agents) {
    if (x.gesperrt || !bereich.ids.has(x.mandant_id) || !x.messwerte || !frisch(x.zuletzt_gesehen, a.daten.intervall_sekunden)) continue;
    const m = x.messwerte;
    zeilen.push({
      geraet: x.geraet_id,
      mandant: x.mandant_id,
      name: namen.get(x.geraet_id) ?? x.hostname,
      cpu: m.cpu.auslastung_prozent,
      ram: prozent(m.speicher.gesamt - m.speicher.verfuegbar, m.speicher.gesamt),
    });
  }
  const mitAgent = new Set(zeilen.map((z) => z.geraet));
  for (const s of q.daten?.snmp ?? []) {
    const m = s.messwerte;
    if (!bereich.ids.has(s.mandant_id) || !m || mitAgent.has(s.geraet_id) || !frisch(m.erfasst, s.intervall_sekunden)) continue;
    if (!m.cpu && !(m.speicher && m.speicher.gesamt > 0)) continue;
    zeilen.push({
      geraet: s.geraet_id,
      mandant: s.mandant_id,
      name: namen.get(s.geraet_id) ?? s.adresse,
      cpu: m.cpu ? m.cpu.auslastung_prozent : null,
      ram: m.speicher && m.speicher.gesamt > 0 ? prozent(m.speicher.gesamt - m.speicher.verfuegbar, m.speicher.gesamt) : null,
    });
  }
  if (zeilen.length === 0) return <p className="leer">Keine aktuellen Messwerte im Bereich.</p>;
  const teil = (titel: string, wert: "cpu" | "ram") => {
    const liste = zeilen
      .filter((z) => z[wert] !== null)
      .sort((x, y) => y[wert]! - x[wert]! || x.name.localeCompare(y.name, "de"))
      .slice(0, 8);
    return (
      <div className="auslastung-teil">
        <h3 className="widget-untertitel">{titel}</h3>
        <ul className="balkenliste">
          {liste.map((z) => (
            <li key={z.geraet}>
              <button className="knopf-text balkenliste-name" onClick={() => zumGeraet(gehe, z.mandant, z.geraet)} title={z.name}>
                {z.name}
              </button>
              <Pegel wert={z[wert]!} titel={`${titel} ${z.name}`} />
            </li>
          ))}
        </ul>
      </div>
    );
  };
  return (
    <div className="auslastung">
      {teil("CPU", "cpu")}
      {teil("RAM", "ram")}
    </div>
  );
}

// --- Platten ------------------------------------------------------------------------------

function usePrognose(b: Bereich) {
  const q = useQuelle<PrognoseAntwort>(`/api/v1/prognose/platten${bereichFilter(b)}`, 300_000);
  return { liste: q.daten ? q.daten.platten.filter((p) => b.ids.has(p.mandant_id)) : null, fehler: q.fehler };
}

function PlattenWidget({ bereich, gehe }: WidgetProps) {
  const p = usePrognose(bereich);
  if (!p.liste) return <Laedt fehler={p.fehler} />;
  return <VollstePlatten liste={p.liste} bereich={bereich} onGeraet={(m, g) => zumGeraet(gehe, m, g)} />;
}

function PrognoseWidget({ bereich, gehe }: WidgetProps) {
  const p = usePrognose(bereich);
  if (!p.liste) return <Laedt fehler={p.fehler} />;
  return <BaldVoll liste={p.liste} bereich={bereich} onAnzeigen={(x) => zumGeraet(gehe, x.mandant_id, x.geraet_id)} />;
}

// --- Kennzahlen -----------------------------------------------------------------------------

function useKennzahlen(b: Bereich) {
  return useQuelle<Kennzahlen>(mitFilter("/api/v1/dashboard/kennzahlen", b), 300_000);
}

function AlarmeJeTagWidget({ bereich }: WidgetProps) {
  const k = useKennzahlen(bereich);
  if (!k.daten) return <Laedt fehler={k.fehler} />;
  return <AlarmeJeTag stunden={k.daten.alarme_je_stunde} />;
}

function VerfuegbarkeitWidget({ bereich, gehe }: WidgetProps) {
  const k = useKennzahlen(bereich);
  if (!k.daten) return <Laedt fehler={k.fehler} />;
  return <Verfuegbarkeit k={k.daten} bereich={bereich} onGeraet={(m, g) => zumGeraet(gehe, m, g)} />;
}

// --- Graph ------------------------------------------------------------------------------------

interface HostVerlauf {
  spanne_s: number;
  schritt_s: number;
  reihen: { name: string; punkte: [number, number, number, number][] }[];
}

export function graphTitel(w: Widget, geraete: Geraet[] | null) {
  const was = w.wert === "speicher" ? "RAM" : "CPU";
  if (!w.geraet_id) return `${was}: die höchsten`;
  return `${was}: ${geraete?.find((g) => g.id === w.geraet_id)?.name ?? "Gerät"}`;
}

function GraphWidget({ w, bereich }: WidgetProps) {
  const zeitraum = w.zeitraum ?? "24h";
  const wert = w.wert ?? "cpu";
  const g = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);
  const a = useQuelle<{ agents: Agent[] }>(w.geraet_id ? Q.agents : null, 30_000);
  const geraet = w.geraet_id ? g.daten?.geraete.find((x) => x.id === w.geraet_id) : undefined;
  const agent = w.geraet_id ? a.daten?.agents.find((x) => x.geraet_id === w.geraet_id && !x.gesperrt) : undefined;
  const pfad = !w.geraet_id
    ? mitFilter(`/api/v1/dashboard/verlauf?zeitraum=${zeitraum}`, bereich)
    : agent
      ? `/api/v1/agents/${agent.id}/verlauf?zeitraum=${zeitraum}`
      : geraet?.snmp_id && a.daten
        ? `/api/v1/snmp/${geraet.snmp_id}/verlauf?zeitraum=${zeitraum}`
        : null;
  const v = useQuelle<FlottenVerlauf | HostVerlauf>(pfad, 60_000);
  if (w.geraet_id && g.daten && a.daten && !pfad) {
    return <p className="leer">{geraet ? "Dieses Gerät hat keine Messwerte (kein Agent, kein SNMP)." : "Gerät nicht mehr vorhanden."}</p>;
  }
  if (!v.daten) return <Laedt fehler={v.fehler || g.fehler || a.fehler} />;
  let linien: { name: string; punkte: [number, number, number, number][] }[];
  if ("reihen" in v.daten) {
    linien = [{ name: wert === "cpu" ? "CPU" : "Arbeitsspeicher", punkte: v.daten.reihen.find((r) => r.name === wert)?.punkte ?? [] }];
  } else {
    const teil = wert === "cpu" ? v.daten.cpu : v.daten.speicher;
    linien = teil.linien
      .filter((l) => bereich.ids.has(l.mandant_id))
      .map((l) => ({ name: bereich.mehrere ? `${l.geraet} (${mandantName(bereich, l.mandant_id)})` : l.geraet, punkte: l.punkte }));
  }
  return <Graph titel="" linien={linien} spanne={v.daten.spanne_s} schritt={v.daten.schritt_s} einheit="%" prozent />;
}

// --- Sonnendiagramm ------------------------------------------------------------------------------

const anzeigeRang: Record<AnzeigeStatus, number> = { wartung: 0, ok: 1, warn: 2, unknown: 3, quittiert: 4, crit: 5 };

function anzeigeStatus(s: Sensor): AnzeigeStatus {
  if (s.status === "pause" || s.wartung) return "wartung";
  if (s.status === "neu" || s.status === "unknown") return "unknown";
  if (s.status === "crit") return s.alarm?.bestaetigt_am ? "quittiert" : "crit";
  return s.status === "warn" ? "warn" : "ok";
}

// Baum wie die Wandanzeige: Mandant, Untermandanten, Gruppen, Geräte.
function sonnenBaum(b: Bereich, mandanten: Mandant[], geraete: Geraet[], gruppenListe: GeraeteGruppe[], sensoren: Sensor[]): AnzeigeKnoten {
  const kinder = kinderVon(mandanten);
  const status = new Map<string, AnzeigeStatus>();
  for (const s of sensoren) {
    const st = anzeigeStatus(s);
    const alt = status.get(s.geraet_id);
    if (!alt || anzeigeRang[st] > anzeigeRang[alt]) status.set(s.geraet_id, st);
  }
  const knoten = (m: Mandant): AnzeigeKnoten => {
    const eigene = gruppenListe.filter((g) => g.mandant_id === m.id);
    const gruppe = (eltern: string | null, tiefe: number): AnzeigeKnoten[] =>
      eigene
        .filter((g) => g.eltern_id === eltern)
        .sort((x, y) => x.position - y.position)
        .map((g) => ({
          name: g.name,
          art: "gruppe" as const,
          status: "unknown" as AnzeigeStatus,
          kinder: [
            ...(tiefe < 4 ? gruppe(g.id, tiefe + 1) : []),
            ...geraete.filter((d) => d.gruppe_id === g.id).map((d) => geraetKnoten(d)),
          ],
        }))
        .filter((k) => k.kinder.length > 0);
    const geraetKnoten = (d: Geraet): AnzeigeKnoten => ({ name: d.name, art: "geraet", status: status.get(d.id) ?? "unknown" });
    return {
      name: m.name,
      art: "mandant",
      status: "unknown",
      kinder: [
        ...(kinder.get(m.id) ?? []).filter((k) => b.ids.has(k.id)).map(knoten),
        ...gruppe(null, 1),
        ...geraete.filter((d) => d.mandant_id === m.id && !d.gruppe_id).map(geraetKnoten),
      ],
    };
  };
  const schlimmster = (k: AnzeigeKnoten): AnzeigeStatus => {
    if (!k.kinder || k.kinder.length === 0) return k.status;
    let st: AnzeigeStatus = "wartung";
    for (const c of k.kinder) {
      const x = schlimmster(c);
      if (anzeigeRang[x] > anzeigeRang[st]) st = x;
    }
    k.status = st;
    return st;
  };
  const wurzel = knoten(b.mandant);
  if (!wurzel.kinder?.length) wurzel.status = "unknown";
  else schlimmster(wurzel);
  return wurzel;
}

function SonneWidget({ bereich, mandanten }: WidgetProps) {
  const g = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);
  const gr = useQuelle<{ gruppen: GeraeteGruppe[] }>(Q.gruppen, 60_000);
  const s = useSensoren(bereich);
  if (!g.daten || !gr.daten || !s.liste) return <Laedt fehler={g.fehler || gr.fehler || s.fehler} />;
  const drin = (x: { mandant_id: string }) => bereich.ids.has(x.mandant_id);
  const baum = sonnenBaum(bereich, mandanten, g.daten.geraete.filter(drin), gr.daten.gruppen.filter(drin), s.liste);
  return (
    <div className="sonne-widget">
      <Sonne baum={baum} neu={new Set()} titel={`Zustand von ${bereich.mandant.name}`} />
    </div>
  );
}

// --- Ereignisse der letzten 4 Stunden ------------------------------------------------------------

interface Ereignis {
  zeit: number;
  status: string;
  text: string;
  a: Alarm;
}

const wechselText: Record<string, string> = { crit: "Kritisch", warn: "Warnung", unknown: "Unbekannt" };

function EreignisseWidget({ bereich }: WidgetProps) {
  const q = useQuelle<{ alarme: Alarm[] }>(Q.alarme, 30_000);
  if (!q.daten) return <Laedt fehler={q.fehler} />;
  const jetzt = Date.now();
  const ab = jetzt - 4 * 3600_000;
  const liste: Ereignis[] = [];
  for (const a of q.daten.alarme) {
    if (!bereich.ids.has(a.mandant_id)) continue;
    const beginn = Date.parse(a.beginn);
    if (beginn >= ab) liste.push({ zeit: beginn, status: a.schlimmster, text: `→ ${wechselText[a.schlimmster] ?? a.schlimmster}`, a });
    if (a.ende && Date.parse(a.ende) >= ab) liste.push({ zeit: Date.parse(a.ende), status: "ok", text: "→ OK", a });
    if (a.bestaetigt_am && Date.parse(a.bestaetigt_am) >= ab) {
      liste.push({
        zeit: Date.parse(a.bestaetigt_am),
        status: "bestaetigt",
        text: `bestätigt${a.bestaetigt_von ? ` von ${a.bestaetigt_von}` : ""}`,
        a,
      });
    }
  }
  liste.sort((x, y) => y.zeit - x.zeit);
  if (liste.length === 0) return <p className="leer">Keine Ereignisse in den letzten 4 Stunden.</p>;
  return (
    <table className="tabelle tabelle-kompakt widget-tabelle">
      <tbody>
        {liste.slice(0, 100).map((e, i) => (
          <tr key={`${e.a.id}-${e.status}-${i}`}>
            <td className="zelle-punkt">
              <span
                className={`signal signal-${e.status === "bestaetigt" ? "pause" : e.status}${kennStil(e.a.kennfarbe, e.status === "bestaetigt" ? "" : e.status).className}`}
                style={kennStil(e.a.kennfarbe, e.status === "bestaetigt" ? "" : e.status).style}
                aria-hidden="true"
              />
            </td>
            <td className="klein nowrap">
              <time dateTime={new Date(e.zeit).toISOString()}>{vor(new Date(e.zeit).toISOString(), jetzt)}</time>
            </td>
            <td>
              {e.a.name} <span className="klein">{e.text}</span>
              {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, e.a.mandant_id)}</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- Zertifikate (1.0.7) ------------------------------------------------------------------------

function ZertifikateWidget({ bereich, gehe }: WidgetProps) {
  const q = useQuelle<{ checks: Check[] }>("/api/v1/checks", 60_000);
  const g = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);
  if (!q.daten) return <Laedt fehler={q.fehler} />;
  const heute = new Date();
  const namen = new Map((g.daten?.geraete ?? []).map((x) => [x.id, x.name]));
  const zeilen = q.daten.checks
    .filter((c) => c.typ === "tls" && bereich.ids.has(c.mandant_id))
    .map((c) => lesen(c, heute))
    .sort((a, b) => (a.rest ?? 1e9) - (b.rest ?? 1e9));
  if (zeilen.length === 0) return <p className="leer">Keine Sensoren „TLS-Zertifikat“ im Bereich.</p>;
  return (
    <table className="tabelle tabelle-kompakt widget-tabelle">
      <tbody>
        {zeilen.slice(0, 50).map((z) => (
          <tr key={z.c.id}>
            <td>
              <Zustandszelle status={z.stand} />
            </td>
            <td>
              <button className="knopf-text" onClick={() => zumGeraet(gehe, z.c.mandant_id, z.c.geraet_id)}>
                {z.c.name}
              </button>{" "}
              <span className="klein">{namen.get(z.c.geraet_id) ?? ""}</span>
              {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, z.c.mandant_id)}</span>}
            </td>
            <td className={z.rest !== null && z.rest < 0 ? "text-crit" : z.rest !== null && z.rest <= 14 ? "text-warn" : undefined}>
              {z.problem && z.rest === null ? z.problem : restText(z)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- Wartung (1.0.7) ----------------------------------------------------------------------------

interface WartungAntwort {
  laufend: { id: string; mandant_id: string; geraet: string; sensor: string | null; bis: string; grund: string }[];
  fenster: { id: string; mandant_id: string; name: string; ziel_name: string; aktiv: boolean; naechstes: [string, string] | null }[];
}

const zeitpunkt = new Intl.DateTimeFormat("de-DE", { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });

function WartungWidget({ bereich, gehe }: WidgetProps) {
  const q = useQuelle<WartungAntwort>("/api/v1/wartung", 60_000);
  if (!q.daten) return <Laedt fehler={q.fehler} />;
  const drin = (x: { mandant_id: string }) => bereich.ids.has(x.mandant_id);
  const laufend = q.daten.laufend.filter(drin);
  const kommend = q.daten.fenster
    .filter((f) => drin(f) && f.aktiv && f.naechstes)
    .sort((a, b) => a.naechstes![0].localeCompare(b.naechstes![0]))
    .slice(0, 20);
  if (laufend.length === 0 && kommend.length === 0) return <p className="leer">Keine laufende und keine geplante Wartung.</p>;
  return (
    <>
      <table className="tabelle tabelle-kompakt widget-tabelle">
        <tbody>
          {laufend.map((l) => (
            <tr key={l.id}>
              <td>
                <Zustandszelle status="wartung" />
              </td>
              <td>
                {l.geraet}
                {l.sensor ? ` · ${l.sensor}` : ""} {l.grund && <span className="klein">{l.grund}</span>}
                {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, l.mandant_id)}</span>}
              </td>
              <td className="klein">bis {zeitpunkt.format(new Date(l.bis))}</td>
            </tr>
          ))}
          {kommend.map((f) => (
            <tr key={f.id}>
              <td className="klein">ab {zeitpunkt.format(new Date(f.naechstes![0]))}</td>
              <td>
                {f.name} <span className="klein">{f.ziel_name}</span>
                {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, f.mandant_id)}</span>}
              </td>
              <td className="klein">bis {zeitpunkt.format(new Date(f.naechstes![1]))}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="knopf-text" onClick={() => gehe({ reiter: "wartung" })}>
        Zur Wartung
      </button>
    </>
  );
}

// --- Einzelner Sensor (1.0.7) -------------------------------------------------------------------

function SensorWidget({ w, gehe }: WidgetProps) {
  // Ohne Eingrenzung auf den Bereich: Der Sensor ist fest gewählt; die Zentrale liefert ihn nur, wenn der Benutzer ihn sehen darf.
  const q = useQuelle<{ sensoren: Sensor[] }>(Q.sensoren, 15_000);
  if (!w.sensor) return <p className="leer">Noch kein Sensor gewählt: „✎ Anpassen“ → ⚙.</p>;
  if (!q.daten) return <Laedt fehler={q.fehler} />;
  const s = q.daten.sensoren.find((x) => x.schluessel === w.sensor);
  if (!s) return <p className="leer">Diesen Sensor gibt es nicht mehr, oder er ist für dich nicht sichtbar.</p>;
  const status = s.wartung ? "wartung" : s.status;
  return (
    <div className="sensor-widget">
      <Zustandszelle status={status} bestaetigt={!!s.alarm?.bestaetigt_am} kennfarbe={s.kennfarbe} />
      <div className="sensor-widget-name">
        <button className="knopf-text" onClick={() => zumGeraet(gehe, s.mandant_id, s.geraet_id)}>
          {s.host ?? "Gerät"}
        </button>
        <b>{s.name}</b>
      </div>
      <p className="sensor-widget-meldung">{s.meldung || statusText[status] || ""}</p>
      {s.seit && (
        <p className="klein">
          seit <time dateTime={s.seit}>{vor(s.seit, Date.now())}</time>
        </p>
      )}
    </div>
  );
}

// --- Uhr und Notiz (1.0.7) ----------------------------------------------------------------------

const uhrzeit = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const datum = new Intl.DateTimeFormat("de-DE", { weekday: "long", day: "2-digit", month: "long", year: "numeric" });

function UhrWidget() {
  const [jetzt, setJetzt] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setJetzt(new Date()), 1000);
    return () => window.clearInterval(t);
  }, []);
  return (
    <div className="uhr-widget">
      <time className="uhr-widget-zeit mono" dateTime={jetzt.toISOString()}>
        {uhrzeit.format(jetzt)}
      </time>
      <span className="klein">{datum.format(jetzt)}</span>
    </div>
  );
}

// Der Text stammt vom Benutzer selbst und erscheint nur als Text (React escapt), Zeilenumbrüche bleiben.
function NotizWidget({ w }: WidgetProps) {
  if (!w.text) return <p className="leer">Leere Notiz: „✎ Anpassen“ → ⚙.</p>;
  return <p className="notiz-widget">{w.text}</p>;
}

// --- Verteiler ---------------------------------------------------------------------------------------

export function WidgetInhalt(props: WidgetProps): ReactNode {
  switch (props.w.typ) {
    case "zustand":
      return <ZustandWidget {...props} />;
    case "alarme":
      return <AlarmeWidget {...props} />;
    case "sensoren":
      return <SensorenWidget {...props} />;
    case "auslastung":
      return <AuslastungWidget {...props} />;
    case "platten":
      return <PlattenWidget {...props} />;
    case "prognose":
      return <PrognoseWidget {...props} />;
    case "alarme_je_tag":
      return <AlarmeJeTagWidget {...props} />;
    case "verfuegbarkeit":
      return <VerfuegbarkeitWidget {...props} />;
    case "graph":
      return <GraphWidget {...props} />;
    case "sonne":
      return <SonneWidget {...props} />;
    case "ereignisse":
      return <EreignisseWidget {...props} />;
    case "zertifikate":
      return <ZertifikateWidget {...props} />;
    case "wartung":
      return <WartungWidget {...props} />;
    case "sensor":
      return <SensorWidget {...props} />;
    case "uhr":
      return <UhrWidget />;
    case "notiz":
      return <NotizWidget {...props} />;
  }
}
