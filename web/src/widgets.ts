// SPDX-License-Identifier: AGPL-3.0-only

// Widgets des Dashboards (Etappe 17): Arten, Startgrößen, Einstellungen und
// das Standard-Layout. Dieselben Regeln prüfen die Zentrale
// (internal/zentrale/dashboard_layout.go) und die Datenbank (Migration 0019);
// hier stehen sie nur, damit die Oberfläche nichts anbietet, was abgelehnt würde.

import type { Zeitraum } from "./Verlauf";

export type WidgetTyp =
  | "zustand"
  | "alarme"
  | "sensoren"
  | "auslastung"
  | "platten"
  | "prognose"
  | "alarme_je_tag"
  | "verfuegbarkeit"
  | "graph"
  | "sonne"
  | "ereignisse";

export type Groesse = "klein" | "breit" | "hoch";
export type GraphWert = "cpu" | "speicher";

export interface Widget {
  id: string;
  typ: WidgetTyp;
  groesse: Groesse;
  // fester Mandant (mit seinen Untermandanten); null = wie in der Seitenleiste
  mandant_id?: string | null;
  // nur Graph: ein Gerät; null = die höchsten im Bereich
  geraet_id?: string | null;
  zeitraum?: Zeitraum | null;
  wert?: GraphWert | null;
}

export const maxWidgets = 30;

export const widgetArten: Record<WidgetTyp, { titel: string; groesse: Groesse; text: string }> = {
  zustand: { titel: "Zustand", groesse: "breit", text: "Sensoren und Geräte nach Zustand" },
  alarme: { titel: "Aktive Alarme", groesse: "breit", text: "Tabelle der offenen Alarme" },
  sensoren: { titel: "Sensoren nicht OK", groesse: "klein", text: "kurze Liste aller Probleme" },
  auslastung: { titel: "CPU und RAM", groesse: "hoch", text: "aktuelle Auslastung der Hosts" },
  platten: { titel: "Vollste Platten", groesse: "klein", text: "die fünf vollsten Platten" },
  prognose: { titel: "Platten-Prognose", groesse: "klein", text: "Platten, die bald voll sind" },
  alarme_je_tag: { titel: "Alarme je Tag", groesse: "klein", text: "begonnene Alarme, 30 Tage" },
  verfuegbarkeit: { titel: "Verfügbarkeit", groesse: "klein", text: "7 und 30 Tage, schlechteste zuerst" },
  graph: { titel: "Graph", groesse: "breit", text: "CPU oder RAM eines Hosts oder der höchsten" },
  sonne: { titel: "Sonnendiagramm", groesse: "klein", text: "Mandanten, Gruppen und Geräte" },
  ereignisse: { titel: "Ereignisse (4 Std.)", groesse: "hoch", text: "Beginn, Ende und Bestätigung von Alarmen" },
};

export const groessen: { id: Groesse; kurz: string; text: string }[] = [
  { id: "klein", kurz: "K", text: "klein" },
  { id: "breit", kurz: "B", text: "breit" },
  { id: "hoch", kurz: "H", text: "hoch" },
];

const standardArten: [WidgetTyp, Groesse][] = [
  ["zustand", "breit"],
  ["sensoren", "klein"],
  ["alarme", "breit"],
  ["auslastung", "hoch"],
  ["ereignisse", "hoch"],
  ["platten", "klein"],
  ["alarme_je_tag", "klein"],
  ["prognose", "klein"],
  ["graph", "breit"],
  ["verfuegbarkeit", "klein"],
];

export function standardLayout(): Widget[] {
  return standardArten.map(([typ, groesse], i) => ({ id: `std${i + 1}`, typ, groesse }));
}

// neueId: 8 Zeichen a–z, 0–9, eindeutig im Layout.
export function neueId(layout: Widget[]): string {
  const zeichen = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (;;) {
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    const id = Array.from(b, (x) => zeichen[x % zeichen.length]).join("");
    if (!layout.some((w) => w.id === id)) return id;
  }
}

// Darf die Art noch hinzugefügt werden? Jede Art gibt es einmal, Graphen mehrfach.
export function verfuegbar(layout: Widget[], typ: WidgetTyp) {
  return layout.length < maxWidgets && (typ === "graph" || !layout.some((w) => w.typ === typ));
}

// fuerSpeichern: nur die Felder, die die Zentrale kennt; leere Einstellungen weglassen.
export function fuerSpeichern(layout: Widget[]) {
  return layout.map((w) => {
    const o: Widget = { id: w.id, typ: w.typ, groesse: w.groesse };
    if (w.mandant_id && !(w.typ === "graph" && w.geraet_id)) o.mandant_id = w.mandant_id;
    if (w.typ === "graph") {
      if (w.geraet_id) o.geraet_id = w.geraet_id;
      if (w.zeitraum) o.zeitraum = w.zeitraum;
      if (w.wert) o.wert = w.wert;
    }
    return o;
  });
}
