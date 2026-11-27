// SPDX-License-Identifier: AGPL-3.0-only

// Netzbild (1.0.11): die Verbindungen zwischen den Geräten, wie die Geräte
// sie per LLDP melden. Knoten sind Geräte aus OpenWacht mit Zustand (Form und
// Farbe), Linien die gemeldeten Verbindungen mit den Ports an beiden Enden.
// Nachbarn, die kein Gerät in OpenWacht sind (Access Points, Telefone, fremde
// Switches), stehen je Gerät grau und ohne Klick darunter. Die Daten kommen
// aus den SNMP-Abfragen; die Zentrale liefert nur, was der Benutzer sehen darf.

import { useMemo } from "react";
import type { Geraet, Sensor, Snmp } from "./api";
import { anzeigeText, rang, type Anzeige } from "./Checks";
import { portNummer } from "./PortBild";

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
}

export interface Netz {
  knoten: string[];
  kanten: Kante[];
  fremde: Map<string, Fremder[]>;
}

// netz baut aus den LLDP-Nachbarn der Quellen die Verbindungen. Ein Nachbar
// gilt als Gerät aus OpenWacht, wenn sein Name eindeutig zum Namen eines
// Geräts oder zum Namen passt, den ein Gerät per SNMP von sich meldet.
export function netz(geraete: Geraet[], quellen: Snmp[]): Netz {
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
      const ziel = n.name ? nachName.get(schluessel(n.name)) : undefined;
      knoten.add(eigen);
      if (!ziel || ziel === eigen) {
        fremde.set(eigen, [...(fremde.get(eigen) ?? []), { name: n.name || n.port || "unbekannt", port: hier }]);
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

const breite = 190;
const hoehe = 52;
const lueckeX = 36;
const lueckeY = 84;

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

export function Netzbild(props: { geraete: Geraet[]; quellen: Snmp[]; sensoren: Sensor[]; onOeffnen: (id: string) => void }) {
  const { geraete, quellen, sensoren } = props;
  const bild = useMemo(() => {
    const n = netz(geraete, quellen);
    const nachId = new Map(geraete.map((g) => [g.id, g]));
    const lage = anordnen(n, (id) => nachId.get(id)?.name ?? "");
    return { n, nachId, lage, ort: new Map(lage.plaetze.map((p) => [p.id, p])) };
  }, [geraete, quellen]);
  const { n, nachId, lage, ort } = bild;
  if (n.knoten.length === 0) return null;
  const jeGeraet = new Map<string, Sensor[]>();
  for (const s of sensoren) jeGeraet.set(s.geraet_id, [...(jeGeraet.get(s.geraet_id) ?? []), s]);
  const mitFremden = [...n.fremde.entries()]
    .map(([id, liste]) => ({ g: nachId.get(id), liste }))
    .filter((x): x is { g: Geraet; liste: Fremder[] } => !!x.g)
    .sort((a, b) => a.g.name.localeCompare(b.g.name, "de"));
  return (
    <div className="netzbild">
      <div className="netzbild-rahmen">
        <div className="netzbild-flaeche" style={{ width: lage.w, height: lage.h }}>
          <svg className="netzbild-linien" width={lage.w} height={lage.h} aria-hidden="true">
            {(() => {
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
              const kurz = (t: string) => (t.length > 24 ? t.slice(0, 23) + "…" : t);
              return lagen.map(({ k, o, u, portsO, portsU }) => {
                const gleicheEbene = o.y === u.y;
                const x1 = gleicheEbene ? o.x + breite : anker(unten, o, u);
                const x2 = gleicheEbene ? u.x : anker(oben, u, o);
                const y1 = gleicheEbene ? o.y + hoehe / 2 : o.y + hoehe;
                const y2 = gleicheEbene ? u.y + hoehe / 2 : u.y;
                const bei = (t: number) => ({ x: x1 + (x2 - x1) * t, y: y1 + (y2 - y1) * t });
                const p1 = bei(0.3);
                const p2 = bei(0.82);
                const textO = portsO.join(", ");
                const textU = portsU.join(", ");
                return (
                  <g key={`${k.a}|${k.b}`}>
                    <line x1={x1} y1={y1} x2={x2} y2={y2} className={`netzbild-linie${k.anzahl > 1 ? " netzbild-linie-mehrfach" : ""}`} />
                    {textO && (
                      <text x={p1.x} y={p1.y} className="netzbild-port">
                        {kurz(textO)}
                      </text>
                    )}
                    {textU && (
                      <text x={p2.x} y={p2.y} className="netzbild-port">
                        {kurz(textU)}
                      </text>
                    )}
                  </g>
                );
              });
            })()}
          </svg>
          {lage.plaetze.map((p) => {
            const g = nachId.get(p.id);
            if (!g) return null;
            const stand = standVon(g, jeGeraet.get(g.id) ?? []);
            const zahl = n.fremde.get(g.id)?.length ?? 0;
            return (
              <button
                key={g.id}
                type="button"
                className={`topo-knoten topo-${stand} netzbild-knoten`}
                style={{ left: p.x, top: p.y, width: breite, height: hoehe }}
                onClick={() => props.onOeffnen(g.id)}
                title={`${g.name}: ${standText[stand]}`}
              >
                <span className={`signal signal-${stand}`} aria-hidden="true" />
                <span className="topo-text">
                  <span className="topo-name">{g.name}</span>
                  <span className="topo-unter">
                    <span className="sr-only">{standText[stand]}, </span>
                    {zahl > 0 ? `${zahl} ${zahl === 1 ? "weiterer Nachbar" : "weitere Nachbarn"}` : (g.adresse ?? standText[stand])}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </div>
      {mitFremden.length > 0 && (
        <details className="erweitert netzbild-fremde" open={mitFremden.reduce((s, x) => s + x.liste.length, 0) <= 30}>
          <summary>Nachbarn, die kein Gerät in OpenWacht sind ({mitFremden.reduce((s, x) => s + x.liste.length, 0)})</summary>
          {mitFremden.map(({ g, liste }) => (
            <div key={g.id} className="netzbild-fremde-geraet">
              <button type="button" className="knopf-text" onClick={() => props.onOeffnen(g.id)}>
                {g.name}
              </button>
              <ul className="netzbild-chips">
                {liste
                  .slice()
                  .sort((a, b) => a.port.localeCompare(b.port, "de", { numeric: true }))
                  .map((f, k) => (
                    <li key={k} className="netzbild-chip">
                      {f.name} <span className="klein">{f.port}</span>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
