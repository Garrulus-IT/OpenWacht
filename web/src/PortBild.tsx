// SPDX-License-Identifier: AGPL-3.0-only

// Bild der Ports eines Switches (1.0.10): die physischen Ports in zwei Reihen
// wie auf der Frontplatte, ungerade oben, gerade unten, Uplinks rechts
// abgesetzt. Jeder Port zeigt seinen Zustand als Form und Farbe und, falls
// das Gerät es meldet, ob er per PoE Strom liefert. Ein Klick wählt den Port;
// die Einzelheiten zeigt die aufrufende Ansicht. Geräte mit Karten oder
// Stacks (1.0.13) zeigen je Karte oder Mitglied eine eigene Zeile.

import type { SnmpLldpNachbar, SnmpPoePort, SnmpSchnittstelle } from "./api";
import { bitrate } from "./Pegel";

// ifType der physischen Ports: Ethernet, Fast Ethernet (alt), Gigabit (alt)
const physisch = new Set([6, 62, 69, 117]);

// Ab so vielen physischen Ports gilt ein Gerät als Switch.
const mindestens = 8;

export function physischePorts(ifs: SnmpSchnittstelle[]) {
  return ifs.filter((i) => physisch.has(i.typ)).sort((a, b) => a.index - b.index);
}

// uplinks: Zahl der Ports am Ende, die abgesetzt stehen (24+4, 48+2, 8+2 …).
function uplinks(n: number) {
  const rest = n >= 12 ? n % 12 : n % 8;
  return rest === 2 || rest === 4 ? rest : 0;
}

// poeNachIndex ordnet die PoE-Ports den Schnittstellen zu: PoE-Port n gehört
// zur Schnittstelle mit ifIndex n. Das gilt nur bei einer einzigen PoE-Gruppe;
// bei mehreren siehe poeZuordnung.
export function poeNachIndex(poe: SnmpPoePort[] | undefined) {
  const m = new Map<number, SnmpPoePort>();
  if (!poe || poe.length === 0 || poe.some((p) => p.gruppe !== poe[0]!.gruppe)) return m;
  for (const p of poe) m.set(p.port, p);
  return m;
}

// Module (1.0.13): Geräte mit Steckkarten (Aruba 5400R: Slots A bis F, Ports
// „A1“ … „F24“) oder Stacks (Aruba 2930: „1/1“ … „2/28“) zeigen jede Karte,
// jedes Mitglied als eigene Zeile. Erkannt wird das am Namen der Ports.
export interface Modul {
  // Kennung: „A“, „1“ oder „1/A“ (Stack aus Chassis, VSF)
  kennung: string;
  // Beschriftung: „Slot A“, „Mitglied 1“
  text: string;
  // Ports mit ihrer Nummer auf der Karte
  ports: { i: SnmpSchnittstelle; nr: number }[];
  // Slot ohne Ports zwischen bestückten Slots
  leer?: boolean;
}

const slotMuster = /^([A-L])(\d{1,2})$/;
const stackMuster = /^(\d{1,2})\/(\d{1,3})$/;
const vsfMuster = /^(\d)\/([A-L])(\d{1,2})$/;

function zerlegen(name: string): { kennung: string; text: string; nr: number; art: "slot" | "stack" | "vsf" } | null {
  let m = slotMuster.exec(name);
  if (m) return { kennung: m[1]!, text: `Slot ${m[1]}`, nr: Number(m[2]), art: "slot" };
  m = vsfMuster.exec(name);
  if (m) return { kennung: `${m[1]}/${m[2]}`, text: `Mitglied ${m[1]}, Slot ${m[2]}`, nr: Number(m[3]), art: "vsf" };
  m = stackMuster.exec(name);
  if (m) return { kennung: m[1]!, text: `Mitglied ${m[1]}`, nr: Number(m[2]), art: "stack" };
  return null;
}

// module teilt die physischen Ports in Karten oder Stack-Mitglieder; null,
// wenn das Gerät keine hat (dann eine Frontplatte wie bisher). Es braucht
// mindestens neun von zehn Ports im selben Schema; ein Stack braucht zwei
// Mitglieder, damit „1/1“ eines Einzelgeräts nicht als Stack gilt.
export function module(ports: SnmpSchnittstelle[]): Modul[] | null {
  if (ports.length === 0) return null;
  const teile = ports.map((i) => ({ i, t: zerlegen(i.name.trim()) }));
  const art = teile[0]!.t?.art;
  const passend = teile.filter((x) => x.t && x.t.art === art);
  if (!art || passend.length < ports.length * 0.9) return null;
  const map = new Map<string, Modul>();
  for (const { i, t } of passend) {
    const k = t!.kennung;
    if (!map.has(k)) map.set(k, { kennung: k, text: t!.text, ports: [] });
    map.get(k)!.ports.push({ i, nr: t!.nr });
  }
  if (art === "stack" && map.size < 2) return null;
  const liste = [...map.values()];
  for (const m of liste) m.ports.sort((a, b) => a.nr - b.nr);
  const schluessel = (k: string) => k.split("/").map((t) => (/^\d+$/.test(t) ? t.padStart(3, "0") : t)).join("/");
  liste.sort((a, b) => schluessel(a.kennung).localeCompare(schluessel(b.kennung)));
  // Lücken zwischen bestückten Slots zeigen (A, C → B leer); nicht bei Stacks
  if (art === "slot") {
    const voll: Modul[] = [];
    const von = liste[0]!.kennung.charCodeAt(0);
    const bis = liste[liste.length - 1]!.kennung.charCodeAt(0);
    for (let c = von; c <= bis; c++) {
      const k = String.fromCharCode(c);
      voll.push(map.get(k) ?? { kennung: k, text: `Slot ${k}`, ports: [], leer: true });
    }
    return voll;
  }
  return liste;
}

// poeZuordnung ordnet die PoE-Ports den Schnittstellen zu. Eine PoE-Gruppe:
// PoE-Port n ist ifIndex n. Mehrere Gruppen (1.0.13) nur bei erkannten Modulen:
// Gruppe g ist die g-te Karte (Slot A = 1) oder Stack-Mitglied g, PoE-Port p
// der Port mit Nummer p darauf. Passt das nicht, bleibt PoE im Bild weg.
export function poeZuordnung(ifs: SnmpSchnittstelle[], poe: SnmpPoePort[] | undefined) {
  const einfach = poeNachIndex(poe);
  if (einfach.size > 0 || !poe || poe.length === 0) return einfach;
  const m = new Map<number, SnmpPoePort>();
  const mods = module(physischePorts(ifs));
  if (!mods) return m;
  for (const p of poe) {
    const mod = mods.find((x) =>
      /^[A-L]$/.test(x.kennung) ? x.kennung.charCodeAt(0) - 64 === p.gruppe : x.kennung === String(p.gruppe),
    );
    const port = mod?.ports.find((x) => x.nr === p.port);
    if (port) m.set(port.i.index, p);
  }
  return m;
}

// portBezeichnung: wie der Port im Bild heißt: „A5“ oder „1/5“ bei Modulen,
// sonst die laufende Nummer; "" wenn der Port nicht im Bild ist.
export function portBezeichnung(ifs: SnmpSchnittstelle[], index: number) {
  const ports = physischePorts(ifs);
  const i = ports.find((x) => x.index === index);
  if (!i) return "";
  if (module(ports)) return i.name.trim();
  return String(ports.indexOf(i) + 1);
}

// nachbarText: „sw-keller, Port GigabitEthernet 1/24“
export function nachbarText(n: SnmpLldpNachbar) {
  return [n.name, n.port ? `Port ${n.port}` : ""].filter(Boolean).join(", ");
}

export const poeText: Record<number, string> = {
  1: "aus oder nichts angeschlossen",
  2: "sucht ein Gerät",
  3: "liefert Strom",
  4: "Fehler",
  5: "Test",
  6: "Fehler",
};

// langsam (1.0.11): verbunden, aber mit weniger als 1 Gbit/s ausgehandelt.
// Das ist ein Hinweis, kein Alarm: Drucker und Telefone können oft nur 100 Mbit/s.
export function langsam(i: SnmpSchnittstelle) {
  return i.admin_an && i.status === "up" && i.geschwindigkeit_bps > 0 && i.geschwindigkeit_bps < 1e9;
}

export type PortZustand = "ok" | "crit" | "aus" | "frei";

export function portZustand(i: SnmpSchnittstelle, ueberwacht: boolean): PortZustand {
  if (!i.admin_an) return "aus";
  if (i.status === "up") return "ok";
  return ueberwacht ? "crit" : "frei";
}

const zustandText: Record<PortZustand, string> = {
  ok: "verbunden",
  crit: "nicht verbunden, wird überwacht",
  aus: "abgeschaltet",
  frei: "nicht verbunden",
};

type Props = {
  ifs: SnmpSchnittstelle[];
  poe: SnmpPoePort[] | undefined;
  // LLDP-Nachbarn (1.0.11), nur für den Hinweis am Port
  lldp?: SnmpLldpNachbar[];
  ueberwacht: string[];
  gewaehlt: number | null;
  // Name des Geräts für das Schild links
  name?: string;
  onWahl: (index: number | null) => void;
};

// gruppieren: Ports in Gruppen zu zwölf (sechs Spalten) wie auf einer
// Frontplatte, die Uplinks am Ende abgesetzt.
function gruppieren<T>(ports: T[]) {
  const up = uplinks(ports.length);
  const haupt = ports.slice(0, ports.length - up);
  const gruppen: { ports: T[]; uplink: boolean }[] = [];
  for (let k = 0; k < haupt.length; k += 12) gruppen.push({ ports: haupt.slice(k, k + 12), uplink: false });
  if (up > 0) gruppen.push({ ports: ports.slice(ports.length - up), uplink: true });
  return gruppen;
}

function Port(props: Props & { i: SnmpSchnittstelle; nr: string; oben: boolean; zuordnung: Map<number, SnmpPoePort> }) {
  const { i, nr } = props;
  const z = portZustand(i, props.ueberwacht.includes(i.name));
  const p = props.zuordnung.get(i.index);
  const strom = p?.status === 3;
  const poeFehler = p?.status === 4 || p?.status === 6;
  const nachbarn = (props.lldp ?? []).filter((n) => n.index === i.index);
  const lahm = langsam(i);
  const kopf = nr === i.name.trim() ? `Port ${nr}` : `Port ${nr}, ${i.name}`;
  const text = `${kopf}${i.alias ? ` (${i.alias})` : ""}: ${zustandText[z]}${lahm ? `, langsam (${bitrate(i.geschwindigkeit_bps)})` : ""}${p ? `, PoE ${poeText[p.status] ?? "unbekannt"}` : ""}${nachbarn.length > 0 ? `, Nachbar ${nachbarn.map(nachbarText).join("; ")}` : ""}`;
  const kurz = nr.includes("/") ? nr.slice(nr.lastIndexOf("/") + 1) : nr.replace(/^[A-L]/, "");
  return (
    <button
      type="button"
      className={`port port-${props.oben ? "oben" : "unten"} port-${z}${props.gewaehlt === i.index ? " port-gewaehlt" : ""}`}
      aria-pressed={props.gewaehlt === i.index}
      aria-label={text}
      title={text}
      onClick={() => props.onWahl(props.gewaehlt === i.index ? null : i.index)}
    >
      <span className="port-nr">{kurz}</span>
      <span className="port-buchse" aria-hidden="true">
        <span className={`signal signal-${lahm ? "warn" : z === "ok" ? "ok" : z === "crit" ? "crit" : z === "aus" ? "pause" : "leer"}`} />
        <span className={`port-poe${poeFehler ? " port-poe-fehler" : ""}`}>{strom ? "PoE" : poeFehler ? "PoE!" : ""}</span>
      </span>
    </button>
  );
}

function Gruppen(props: Props & { liste: { i: SnmpSchnittstelle; nr: string }[]; zuordnung: Map<number, SnmpPoePort> }) {
  return (
    <>
      {gruppieren(props.liste).map((gr, b) => (
        <div key={b} className={`port-gruppe${gr.uplink ? " port-gruppe-uplink" : ""}`}>
          {gr.ports.map((x, k) => (
            <Port key={x.i.index} {...props} i={x.i} nr={x.nr} oben={k % 2 === 0} />
          ))}
        </div>
      ))}
    </>
  );
}

export function PortBild(props: Props) {
  const ports = physischePorts(props.ifs);
  if (ports.length < mindestens) return null;
  const poe = poeZuordnung(props.ifs, props.poe);
  const mods = module(ports);
  const verbunden = ports.filter((i) => i.admin_an && i.status === "up").length;
  const slots = mods?.some((m) => /^[A-L]$/.test(m.kennung));
  return (
    <div className="portbild" role="group" aria-label="Ports des Geräts">
      <div className={`geraet-front${mods ? " geraet-front-module" : ""}`}>
        <div className="front-schild">
          <span className="front-name">{props.name ?? "Switch"}</span>
          <span className="front-zahl">
            {verbunden} von {ports.length} verbunden
          </span>
          {mods && (
            <span className="front-zahl">
              {mods.filter((m) => !m.leer).length} {slots ? "Karten" : "Mitglieder"}
            </span>
          )}
        </div>
        {mods ? (
          <div className="front-module">
            {mods.map((m) => {
              const an = m.ports.filter((x) => x.i.admin_an && x.i.status === "up").length;
              return (
                <div key={m.kennung} className={`port-modul${m.leer ? " port-modul-leer" : ""}`} role="group" aria-label={m.leer ? `${m.text}: leer` : `${m.text}: ${an} von ${m.ports.length} verbunden`}>
                  <div className="modul-schild" aria-hidden="true">
                    <span className="modul-kennung">{m.kennung}</span>
                    <span className="modul-zahl">{m.leer ? "leer" : `${an}/${m.ports.length}`}</span>
                  </div>
                  {m.leer ? (
                    <div className="modul-blende">kein Modul gemeldet</div>
                  ) : (
                    <div className="front-ports">
                      <Gruppen {...props} zuordnung={poe} liste={m.ports.map((x) => ({ i: x.i, nr: x.i.name.trim() }))} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="front-ports">
            <Gruppen {...props} zuordnung={poe} liste={ports.map((i, k) => ({ i, nr: String(k + 1) }))} />
          </div>
        )}
      </div>
      <p className="klein portbild-legende">
        <span className="signal signal-ok" aria-hidden="true" /> verbunden · <span className="signal signal-warn" aria-hidden="true" /> verbunden
        unter 1 Gbit/s · <span className="signal signal-leer" aria-hidden="true" /> nicht
        verbunden · <span className="signal signal-crit" aria-hidden="true" /> nicht verbunden und überwacht ·{" "}
        <span className="signal signal-pause" aria-hidden="true" /> abgeschaltet
        {poe.size > 0 ? " · PoE: liefert Strom" : ""}.{" "}
        {mods
          ? slots
            ? "Jede Zeile ist eine Karte im Chassis, die Nummer zählt die Ports auf der Karte."
            : "Jede Zeile ist ein Mitglied des Stacks, die Nummer zählt die Ports des Mitglieds."
          : "Die Nummer zählt die physischen Ports in der Reihenfolge des Geräts."}
      </p>
    </div>
  );
}
