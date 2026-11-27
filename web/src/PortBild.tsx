// SPDX-License-Identifier: AGPL-3.0-only

// Bild der Ports eines Switches (1.0.10): die physischen Ports in zwei Reihen
// wie auf der Frontplatte, ungerade oben, gerade unten, Uplinks rechts
// abgesetzt. Jeder Port zeigt seinen Zustand als Form und Farbe und, falls
// das Gerät es meldet, ob er per PoE Strom liefert. Ein Klick wählt den Port;
// die Einzelheiten zeigt die aufrufende Ansicht.

import type { SnmpLldpNachbar, SnmpPoePort, SnmpSchnittstelle } from "./api";

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
// bei mehreren (Stack) bleibt PoE im Bild weg.
export function poeNachIndex(poe: SnmpPoePort[] | undefined) {
  const m = new Map<number, SnmpPoePort>();
  if (!poe || poe.length === 0 || poe.some((p) => p.gruppe !== poe[0]!.gruppe)) return m;
  for (const p of poe) m.set(p.port, p);
  return m;
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

export function PortBild(props: {
  ifs: SnmpSchnittstelle[];
  poe: SnmpPoePort[] | undefined;
  // LLDP-Nachbarn (1.0.11), nur für den Hinweis am Port
  lldp?: SnmpLldpNachbar[];
  ueberwacht: string[];
  gewaehlt: number | null;
  // Name des Geräts für das Schild links
  name?: string;
  onWahl: (index: number | null) => void;
}) {
  const ports = physischePorts(props.ifs);
  if (ports.length < mindestens) return null;
  const poe = poeNachIndex(props.poe);
  const up = uplinks(ports.length);
  const haupt = ports.slice(0, ports.length - up);
  // Hauptports in Gruppen zu zwölf (sechs Spalten), wie auf einer Frontplatte
  const gruppen: { ports: SnmpSchnittstelle[]; uplink: boolean }[] = [];
  for (let k = 0; k < haupt.length; k += 12) gruppen.push({ ports: haupt.slice(k, k + 12), uplink: false });
  if (up > 0) gruppen.push({ ports: ports.slice(ports.length - up), uplink: true });
  const verbunden = ports.filter((i) => i.admin_an && i.status === "up").length;
  let nr = 0;
  return (
    <div className="portbild" role="group" aria-label="Ports des Geräts">
      <div className="geraet-front">
        <div className="front-schild">
          <span className="front-name">{props.name ?? "Switch"}</span>
          <span className="front-zahl">
            {verbunden} von {ports.length} verbunden
          </span>
        </div>
        <div className="front-ports">
          {gruppen.map((gr, b) => (
            <div key={b} className={`port-gruppe${gr.uplink ? " port-gruppe-uplink" : ""}`}>
              {gr.ports.map((i, k) => {
                nr += 1;
                const z = portZustand(i, props.ueberwacht.includes(i.name));
                const p = poe.get(i.index);
                const strom = p?.status === 3;
                const poeFehler = p?.status === 4 || p?.status === 6;
                const nachbarn = (props.lldp ?? []).filter((n) => n.index === i.index);
                const text = `Port ${nr}, ${i.name}${i.alias ? ` (${i.alias})` : ""}: ${zustandText[z]}${p ? `, PoE ${poeText[p.status] ?? "unbekannt"}` : ""}${nachbarn.length > 0 ? `, Nachbar ${nachbarn.map(nachbarText).join("; ")}` : ""}`;
                return (
                  <button
                    key={i.index}
                    type="button"
                    className={`port port-${k % 2 === 0 ? "oben" : "unten"} port-${z}${props.gewaehlt === i.index ? " port-gewaehlt" : ""}`}
                    aria-pressed={props.gewaehlt === i.index}
                    aria-label={text}
                    title={text}
                    onClick={() => props.onWahl(props.gewaehlt === i.index ? null : i.index)}
                  >
                    <span className="port-nr">{nr}</span>
                    <span className="port-buchse" aria-hidden="true">
                      <span className={`signal signal-${z === "ok" ? "ok" : z === "crit" ? "crit" : z === "aus" ? "pause" : "leer"}`} />
                      <span className={`port-poe${poeFehler ? " port-poe-fehler" : ""}`}>{strom ? "PoE" : poeFehler ? "PoE!" : ""}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>
      <p className="klein portbild-legende">
        <span className="signal signal-ok" aria-hidden="true" /> verbunden · <span className="signal signal-leer" aria-hidden="true" /> nicht
        verbunden · <span className="signal signal-crit" aria-hidden="true" /> nicht verbunden und überwacht ·{" "}
        <span className="signal signal-pause" aria-hidden="true" /> abgeschaltet
        {poe.size > 0 ? " · PoE: liefert Strom" : ""}. Die Nummer zählt die physischen Ports in der Reihenfolge des Geräts.
      </p>
    </div>
  );
}

// portNummer: laufende Nummer eines Ports im Bild (ab 1), 0 = nicht im Bild.
export function portNummer(ifs: SnmpSchnittstelle[], index: number) {
  return physischePorts(ifs).findIndex((i) => i.index === index) + 1;
}
