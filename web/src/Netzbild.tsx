// SPDX-License-Identifier: AGPL-3.0-only

// Netzbild (1.0.11): die Verbindungen zwischen den Geräten, wie die Geräte
// sie per LLDP melden. Knoten sind Geräte aus OpenWacht mit Zustand (Form und
// Farbe), Linien die gemeldeten Verbindungen mit den Ports an beiden Enden.
// Nachbarn, die kein Gerät in OpenWacht sind (Access Points, Telefone, fremde
// Switches), stehen je Gerät grau und ohne Klick darunter. Die Daten kommen
// aus den SNMP-Abfragen; die Zentrale liefert nur, was der Benutzer sehen darf.

import { useMemo, useState } from "react";
import type { Geraet, Sensor, Snmp } from "./api";
import { Aufnehmen, type Kandidat } from "./Aufnehmen";
import { anzeigeText, rang, type Anzeige } from "./Checks";
import { physischePorts, portNummer } from "./PortBild";

type Stand = Anzeige | "wartung";
const standText: Record<Stand, string> = { ...anzeigeText, wartung: "Wartung" };

// schluessel: Name zum Vergleichen: klein, ohne Domäne („SW-Keller.intern“ → „sw-keller“).
export function schluessel(name: string) {
  const n = name.trim().toLowerCase();
  if (n === "" || /^[0-9.]+$/.test(n) || n.includes(":")) return n;
  return n.split(".")[0] ?? n;
}

export interface Kante {
  a: string;
  b: string;
  // Ports an den beiden Enden; anzahl = Zahl der gemeldeten Verbindungen
  portsA: string[];
  portsB: string[];
  anzahl: number;
}

export interface Fremder {
  name: string;
  port: string;
  adresse?: string;
}

export interface Netz {
  knoten: string[];
  kanten: Kante[];
  fremde: Map<string, Fremder[]>;
}

// netz baut aus den LLDP-Nachbarn der Quellen die Verbindungen. Ein Nachbar
// gilt als Gerät aus OpenWacht, wenn sein Name eindeutig zum Namen eines
// Geräts oder zum Namen passt, den ein Gerät per SNMP von sich meldet.
// finder: ordnet einen LLDP-Namen einem Gerät zu, über den Gerätenamen oder
// den Namen, den das Gerät per SNMP von sich meldet. undefined = unbekannt,
// null = mehrdeutig.
export function finder(geraete: Geraet[], quellen: Snmp[]) {
  const sichtbar = new Set(geraete.map((g) => g.id));
  const nachName = new Map<string, string | null>();
  const merke = (name: string | undefined, id: string) => {
    if (!name) return;
    const k = schluessel(name);
    if (k === "") return;
    const alt = nachName.get(k);
    nachName.set(k, alt === undefined || alt === id ? id : null); // null = mehrdeutig
  };
  for (const g of geraete) merke(g.name, g.id);
  for (const q of quellen) if (sichtbar.has(q.geraet_id)) merke(q.messwerte?.system?.name, q.geraet_id);
  return (name: string | undefined) => (name ? nachName.get(schluessel(name)) : undefined);
}

export function netz(geraete: Geraet[], quellen: Snmp[]): Netz {
  const sichtbar = new Set(geraete.map((g) => g.id));
  const finde = finder(geraete, quellen);

  // Je Gerätepaar: die eigenen Ports, die jede Seite meldet, und wie jede
  // Seite den Port der anderen nennt. Melden beide Seiten, gelten die eigenen
  // Angaben; meldet nur eine, steht am anderen Ende ihre Beschreibung.
  interface Roh {
    a: string;
    b: string;
    eigenA: string[];
    eigenB: string[];
    fernA: string[];
    fernB: string[];
  }
  const roh = new Map<string, Roh>();
  const fremde = new Map<string, Fremder[]>();
  const knoten = new Set<string>();
  for (const q of quellen) {
    const m = q.messwerte;
    if (!m?.lldp || !sichtbar.has(q.geraet_id)) continue;
    const eigen = q.geraet_id;
    for (const n of m.lldp) {
      const i = m.schnittstellen.find((x) => x.index === n.index);
      const nr = portNummer(m.schnittstellen, n.index);
      const hier = nr > 0 ? `Port ${nr}` : (i?.name ?? `Index ${n.index}`);
      const ziel = finde(n.name);
      knoten.add(eigen);
      if (!ziel || ziel === eigen) {
        fremde.set(eigen, [...(fremde.get(eigen) ?? []), { name: n.name || n.port || "unbekannt", port: hier, adresse: n.adresse }]);
        continue;
      }
      knoten.add(ziel);
      const [a, b] = eigen < ziel ? [eigen, ziel] : [ziel, eigen];
      const k = roh.get(`${a}|${b}`) ?? { a, b, eigenA: [], eigenB: [], fernA: [], fernB: [] };
      if (eigen === a) {
        k.eigenA.push(hier);
        if (n.port) k.fernB.push(n.port);
      } else {
        k.eigenB.push(hier);
        if (n.port) k.fernA.push(n.port);
      }
      roh.set(`${a}|${b}`, k);
    }
  }
  const kanten = [...roh.values()].map((k) => ({
    a: k.a,
    b: k.b,
    portsA: k.eigenA.length > 0 ? k.eigenA : k.fernA,
    portsB: k.eigenB.length > 0 ? k.eigenB : k.fernB,
    anzahl: Math.max(k.eigenA.length, k.eigenB.length, 1),
  }));
  return { knoten: [...knoten], kanten, fremde };
}

export interface Platz {
  id: string;
  x: number;
  y: number;
}

const breite = 216;
const hoehe = 68;
const lueckeX = 40;
const lueckeY = 96;

// anordnen: je zusammenhängendem Teil das Gerät mit den meisten Verbindungen
// nach oben, die anderen in Ebenen darunter (Breitensuche). Die Teile stehen
// nebeneinander.
export function anordnen(n: Netz, name: (id: string) => string): { plaetze: Platz[]; w: number; h: number } {
  const nachbarn = new Map<string, Set<string>>();
  for (const id of n.knoten) nachbarn.set(id, new Set());
  for (const k of n.kanten) {
    nachbarn.get(k.a)?.add(k.b);
    nachbarn.get(k.b)?.add(k.a);
  }
  const grad = (id: string) => nachbarn.get(id)?.size ?? 0;
  const offen = new Set(n.knoten);
  const plaetze: Platz[] = [];
  let links = 0;
  let h = 0;
  const reihenfolge = [...n.knoten].sort((a, b) => grad(b) - grad(a) || name(a).localeCompare(name(b), "de"));
  for (const start of reihenfolge) {
    if (!offen.has(start)) continue;
    const ebenen: string[][] = [];
    let aktuell = [start];
    offen.delete(start);
    while (aktuell.length > 0) {
      ebenen.push(aktuell);
      const naechste: string[] = [];
      for (const id of aktuell) {
        for (const x of [...(nachbarn.get(id) ?? [])].sort((a, b) => name(a).localeCompare(name(b), "de"))) {
          if (offen.has(x)) {
            offen.delete(x);
            naechste.push(x);
          }
        }
      }
      aktuell = naechste;
    }
    const max = Math.max(...ebenen.map((e) => e.length));
    const teilBreite = max * breite + (max - 1) * lueckeX;
    ebenen.forEach((e, y) => {
      const b = e.length * breite + (e.length - 1) * lueckeX;
      e.forEach((id, x) => plaetze.push({ id, x: links + (teilBreite - b) / 2 + x * (breite + lueckeX), y: y * (hoehe + lueckeY) }));
    });
    links += teilBreite + lueckeX * 2;
    h = Math.max(h, ebenen.length * hoehe + (ebenen.length - 1) * lueckeY);
  }
  return { plaetze, w: Math.max(0, links - lueckeX * 2), h };
}

function standVon(g: Geraet, sensoren: Sensor[]): Stand {
  if (g.wartung) return "wartung";
  if (sensoren.length === 0) return "neu";
  return sensoren.map((s) => s.status as Anzeige).reduce((a, b) => (rang[b] < rang[a] ? b : a));
}

// kurve: Punkt auf der Verbindungskurve (kubische Bézierkurve mit senkrechten
// Tangenten an beiden Enden) bei t zwischen 0 und 1.
function kurve(x1: number, y1: number, x2: number, y2: number, t: number) {
  const my = (y1 + y2) / 2;
  const u = 1 - t;
  return {
    x: u * u * u * x1 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x2,
    y: u * u * u * y1 + 3 * u * u * t * my + 3 * u * t * t * my + t * t * t * y2,
  };
}

// Schild: Portname auf der Linie, als kleine Marke.
function Schild({ x, y, text }: { x: number; y: number; text: string }) {
  const t = text.length > 22 ? text.slice(0, 21) + "…" : text;
  const w = t.length * 6.3 + 12;
  return (
    <g className="netz-schild">
      <rect x={x - w / 2} y={y - 9} width={w} height={18} rx={9} />
      <text x={x} y={y + 0.5}>
        {t}
      </text>
    </g>
  );
}

export function Netzbild(props: {
  geraete: Geraet[];
  quellen: Snmp[];
  sensoren: Sensor[];
  onOeffnen: (id: string) => void;
  // darf: Geräte im Mandanten anlegen (Operator oder Admin)
  darf: (mandantId: string) => boolean;
  melden: (e: unknown) => void;
}) {
  const { geraete, quellen, sensoren } = props;
  // gerade geöffnetes „Ins Monitoring aufnehmen“: Switch und Nachbar
  const [aufnahme, setAufnahme] = useState<{ sw: string; k: Kandidat } | null>(null);
  // Gerät unter der Maus oder im Fokus: Seine Verbindungen treten hervor.
  const [aktiv, setAktiv] = useState<string | null>(null);
  const bild = useMemo(() => {
    const n = netz(geraete, quellen);
    const nachId = new Map(geraete.map((g) => [g.id, g]));
    const lage = anordnen(n, (id) => nachId.get(id)?.name ?? "");
    const ports = new Map(quellen.filter((q) => q.messwerte).map((q) => [q.geraet_id, physischePorts(q.messwerte!.schnittstellen)]));
    return { n, nachId, lage, ports, ort: new Map(lage.plaetze.map((p) => [p.id, p])) };
  }, [geraete, quellen]);
  const { n, nachId, lage, ort, ports } = bild;
  if (n.knoten.length === 0) return null;
  const jeGeraet = new Map<string, Sensor[]>();
  for (const s of sensoren) jeGeraet.set(s.geraet_id, [...(jeGeraet.get(s.geraet_id) ?? []), s]);
  const mitFremden = [...n.fremde.entries()]
    .map(([id, liste]) => ({ g: nachId.get(id), liste }))
    .filter((x): x is { g: Geraet; liste: Fremder[] } => !!x.g)
    .sort((a, b) => a.g.name.localeCompare(b.g.name, "de"));
  const fremdeGesamt = mitFremden.reduce((s, x) => s + x.liste.length, 0);

  // Linien verlassen ein Gerät verteilt über seine Unter- bzw. Oberkante,
  // sortiert nach der Lage der Gegenseite, damit sich Linien und Portnamen
  // nicht an einem Punkt stapeln.
  const unten = new Map<string, string[]>();
  const oben = new Map<string, string[]>();
  const lagen = n.kanten
    .map((k) => {
      const a = ort.get(k.a);
      const b = ort.get(k.b);
      if (!a || !b) return null;
      const dreh = a.y > b.y || (a.y === b.y && a.x > b.x);
      return dreh ? { k, o: b, u: a, portsO: k.portsB, portsU: k.portsA } : { k, o: a, u: b, portsO: k.portsA, portsU: k.portsB };
    })
    .filter((x): x is NonNullable<typeof x> => x !== null);
  for (const l of lagen) {
    if (l.o.y === l.u.y) continue;
    unten.set(l.o.id, [...(unten.get(l.o.id) ?? []), l.u.id]);
    oben.set(l.u.id, [...(oben.get(l.u.id) ?? []), l.o.id]);
  }
  const anker = (liste: Map<string, string[]>, von: Platz, zu: Platz) => {
    const ziele = (liste.get(von.id) ?? []).slice().sort((x, y) => (ort.get(x)?.x ?? 0) - (ort.get(y)?.x ?? 0));
    return von.x + (breite * (ziele.indexOf(zu.id) + 1)) / (ziele.length + 1);
  };
  const rand = 28;
  return (
    <div className="netzbild">
      <div className="netzbild-rahmen">
        <div className="netzbild-flaeche" style={{ width: lage.w + rand * 2, height: lage.h + rand * 2 }}>
          <svg className="netzbild-linien" width={lage.w + rand * 2} height={lage.h + rand * 2} aria-hidden="true">
            <g transform={`translate(${rand} ${rand})`}>
              {lagen.map(({ k, o, u, portsO, portsU }) => {
                const gleicheEbene = o.y === u.y;
                const x1 = gleicheEbene ? o.x + breite : anker(unten, o, u);
                const x2 = gleicheEbene ? u.x : anker(oben, u, o);
                const y1 = gleicheEbene ? o.y + hoehe / 2 : o.y + hoehe;
                const y2 = gleicheEbene ? u.y + hoehe / 2 : u.y;
                const my = (y1 + y2) / 2;
                const pfad = gleicheEbene ? `M ${x1} ${y1} L ${x2} ${y2}` : `M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`;
                const p1 = gleicheEbene ? { x: x1 + (x2 - x1) * 0.25, y: y1 } : kurve(x1, y1, x2, y2, 0.44);
                const p2 = gleicheEbene ? { x: x1 + (x2 - x1) * 0.75, y: y1 } : kurve(x1, y1, x2, y2, 0.87);
                const hervor = aktiv !== null && (aktiv === k.a || aktiv === k.b);
                const zurueck = aktiv !== null && !hervor;
                return (
                  <g key={`${k.a}|${k.b}`} className={`netz-kante${hervor ? " netz-kante-aktiv" : ""}${zurueck ? " netz-kante-leise" : ""}`}>
                    <path d={pfad} className="netz-linie-schein" />
                    <path d={pfad} className={`netz-linie${k.anzahl > 1 ? " netz-linie-mehrfach" : ""}`} />
                    {k.anzahl > 1 && <path d={pfad} className="netz-linie-kern" />}
                    {portsO.length > 0 && <Schild x={p1.x} y={p1.y} text={portsO.join(", ")} />}
                    {portsU.length > 0 && <Schild x={p2.x} y={p2.y} text={portsU.join(", ")} />}
                  </g>
                );
              })}
            </g>
          </svg>
          {lage.plaetze.map((p) => {
            const g = nachId.get(p.id);
            if (!g) return null;
            const stand = standVon(g, jeGeraet.get(g.id) ?? []);
            const zahl = n.fremde.get(g.id)?.length ?? 0;
            const pp = ports.get(g.id) ?? [];
            const an = pp.filter((i) => i.admin_an && i.status === "up").length;
            const unter = [g.adresse, pp.length >= 4 ? `${an}/${pp.length} Ports` : "", zahl > 0 ? `+${zahl}` : ""].filter(Boolean).join(" · ");
            return (
              <button
                key={g.id}
                type="button"
                className={`netz-knoten netz-${stand}${aktiv === g.id ? " netz-knoten-aktiv" : ""}`}
                style={{ left: p.x + rand, top: p.y + rand, width: breite, height: hoehe }}
                onClick={() => props.onOeffnen(g.id)}
                onMouseEnter={() => setAktiv(g.id)}
                onMouseLeave={() => setAktiv(null)}
                onFocus={() => setAktiv(g.id)}
                onBlur={() => setAktiv(null)}
                title={`${g.name}: ${standText[stand]}${zahl > 0 ? `, ${zahl} ${zahl === 1 ? "weiterer Nachbar" : "weitere Nachbarn"} ohne Gerät in OpenWacht` : ""}`}
              >
                <span className="netz-kopf">
                  <span className={`signal signal-${stand}`} aria-hidden="true" />
                  <span className="netz-name">{g.name}</span>
                </span>
                <span className="netz-unter">
                  <span className="sr-only">{standText[stand]}, </span>
                  {unter || standText[stand]}
                </span>
                {pp.length >= 4 && (
                  <span className="netz-ports" aria-hidden="true">
                    {pp.slice(0, 56).map((i) => (
                      <span key={i.index} className={`netz-port${i.admin_an && i.status === "up" ? " netz-port-an" : ""}`} />
                    ))}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
      <p className="klein netzbild-legende">
        Linien sind Verbindungen, die die Geräte per LLDP melden; die Marken nennen die Ports an beiden Enden, eine doppelte
        Linie steht für mehrere Verbindungen. Die Punktreihe unten in einer Karte zeigt die Ports des Geräts, hell = verbunden.
      </p>
      {mitFremden.length > 0 && (
        <details className="erweitert netzbild-fremde" open={fremdeGesamt <= 30}>
          <summary>Nachbarn, die kein Gerät in OpenWacht sind ({fremdeGesamt})</summary>
          {mitFremden.map(({ g, liste }) => (
            <div key={g.id} className="netzbild-fremde-geraet">
              <button type="button" className="knopf-text" onClick={() => props.onOeffnen(g.id)}>
                {g.name}
              </button>
              <ul className="netzbild-chips">
                {liste
                  .slice()
                  .sort((a, b) => a.port.localeCompare(b.port, "de", { numeric: true }))
                  .map((f, k) => {
                    const offen = aufnahme?.sw === g.id && aufnahme.k.port === f.port && aufnahme.k.name === f.name;
                    return (
                      <li key={k}>
                        {props.darf(g.mandant_id) ? (
                          <button
                            type="button"
                            className={`netzbild-chip netzbild-chip-knopf${offen ? " netzbild-chip-offen" : ""}`}
                            aria-expanded={offen}
                            title={`${f.name} ins Monitoring aufnehmen`}
                            onClick={() => setAufnahme(offen ? null : { sw: g.id, k: { name: f.name, port: f.port, adresse: f.adresse } })}
                          >
                            <span className="netzbild-chip-plus" aria-hidden="true">
                              +
                            </span>
                            {f.name} <span className="klein">{f.port}</span>
                          </button>
                        ) : (
                          <span className="netzbild-chip">
                            {f.name} <span className="klein">{f.port}</span>
                          </span>
                        )}
                      </li>
                    );
                  })}
              </ul>
              {aufnahme?.sw === g.id && (
                <Aufnehmen
                  key={aufnahme.k.port + aufnahme.k.name}
                  k={aufnahme.k}
                  sw={g}
                  melden={props.melden}
                  onAbbrechen={() => setAufnahme(null)}
                  onFertig={(id) => {
                    setAufnahme(null);
                    props.onOeffnen(id);
                  }}
                />
              )}
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
