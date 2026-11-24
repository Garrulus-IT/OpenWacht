// SPDX-License-Identifier: AGPL-3.0-only

// Prognose für Platten: „voll in ~N Tagen“ aus der Steigung der letzten
// 30 Tage (berechnet von der Zentrale). Nur Anzeige, kein Alarm.

import type { Bereich } from "./bereich";
import { mandantName } from "./bereich";

export interface PlattenPrognose {
  art: "host" | "snmp";
  quelle_id: string;
  mandant_id: string;
  geraet_id: string;
  geraet: string;
  platte: string;
  belegt: number;
  pro_tag: number | null;
  stand: "steigt" | "stabil" | "zu_wenig";
  tage: number | null;
  basis_tage: number;
  nach_sprung: boolean;
}

export interface PrognoseAntwort {
  platten: PlattenPrognose[];
  gekuerzt: boolean;
}

// Filter für die Anfrage: die Mandanten des Bereichs (grenzt nur ein).
export function bereichFilter(b: Bereich) {
  return b.ids.size <= 200 ? `?mandanten=${[...b.ids].join(",")}` : "";
}

export const prognoseSchluessel = (art: string, quelle: string, platte: string) => `${art}:${quelle}:${platte}`;

export function prognoseNach(liste: PlattenPrognose[] | null | undefined) {
  return new Map((liste ?? []).map((p) => [prognoseSchluessel(p.art, p.quelle_id, p.platte), p]));
}

// Grob runden: Die Prognose ist eine Schätzung, keine Zusage.
function grob(tage: number) {
  if (tage < 10) return tage;
  if (tage < 100) return Math.round(tage / 5) * 5;
  return Math.round(tage / 10) * 10;
}

export function prognoseText(p: PlattenPrognose): string {
  if (p.stand === "zu_wenig") return p.nach_sprung ? "Prognose nach Löschung erst ab 3 Tagen" : "Prognose ab 3 Tagen Verlauf";
  if (p.stand === "stabil" || p.tage === null) return "wächst nicht";
  if (p.tage < 1) return p.belegt >= 99.5 ? "voll" : "voll in < 1 Tag";
  if (p.tage > 365) return "voll in > 1 Jahr";
  const n = grob(p.tage);
  return `voll in ~${n} ${n === 1 ? "Tag" : "Tagen"}`;
}

const zahl = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 2 });

export function prognoseTitel(p: PlattenPrognose): string {
  const teile = [`Lineare Steigung über ${zahl.format(p.basis_tage)} Tage`];
  if (p.pro_tag !== null) teile.push(`${zahl.format(p.pro_tag)} Prozentpunkte je Tag`);
  if (p.nach_sprung) teile.push("gerechnet ab der letzten Löschung oder Vergrößerung");
  return teile.join(", ");
}

// Kurztext unter dem freien Platz einer Platte.
export function PrognoseZeile({ p }: { p: PlattenPrognose | undefined }) {
  if (!p) return null;
  const bald = p.stand === "steigt" && p.tage !== null && p.tage <= 30;
  return (
    <span className={`klein prognose${bald ? " prognose-bald" : ""}`} title={prognoseTitel(p)}>
      {prognoseText(p)}
    </span>
  );
}

// „Bald voll“: Platten, die in höchstens `tage` Tagen voll sind.
export const baldVollTage = 90;

export function BaldVoll(props: { liste: PlattenPrognose[]; bereich: Bereich; onAnzeigen: (p: PlattenPrognose) => void }) {
  const bald = props.liste
    .filter((p) => p.stand === "steigt" && p.tage !== null && p.tage <= baldVollTage)
    .sort((a, b) => a.tage! - b.tage! || b.belegt - a.belegt);
  if (bald.length === 0) return <p className="leer">Keine Platte läuft in den nächsten {baldVollTage} Tagen voll.</p>;
  return (
    <ul className="sensor-liste">
      {bald.slice(0, 10).map((p) => (
        <li key={prognoseSchluessel(p.art, p.quelle_id, p.platte)} className="sensor">
          <span className={`signal signal-${p.tage! <= 14 ? "warn" : "pause"}`} aria-hidden="true" />
          <span className="sensor-text">
            <span className="name">
              {p.geraet} · <span className="mono">{p.platte}</span>
            </span>
            <span className="klein" title={prognoseTitel(p)}>
              {props.bereich.mehrere && <span className="mandant-marke">{mandantName(props.bereich, p.mandant_id)}</span>}
              {prognoseText(p)}, jetzt {Math.round(p.belegt)} % belegt
            </span>
          </span>
          <button className="knopf-text" onClick={() => props.onAnzeigen(p)}>
            Anzeigen
          </button>
        </li>
      ))}
      {bald.length > 10 && <li className="klein">… und {bald.length - 10} weitere.</li>}
    </ul>
  );
}
