// SPDX-License-Identifier: AGPL-3.0-only

// Widgets des Dashboards (Etappe 17, frei anpassbar seit 1.0.7): Arten,
// Startgrößen, Einstellungen und das Standard-Layout. Dieselben Regeln prüfen
// die Zentrale (internal/zentrale/dashboard_layout.go) und die Datenbank
// (Migrationen 0019 und 0062); hier stehen sie nur, damit die Oberfläche
// nichts anbietet, was abgelehnt würde.
//
// Jedes Widget hat eine freie Breite (2 bis 12 Spalten) und Höhe (1 bis 6
// Reihen), optional einen eigenen Titel und eine Seite. Layouts aus der Zeit
// vor 1.0.7 tragen „groesse“ (klein, breit, hoch) und werden beim Laden
// umgerechnet.

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
  | "ereignisse"
  | "zertifikate"
  | "wartung"
  | "sensor"
  | "uhr"
  | "notiz";

export type GraphWert = "cpu" | "speicher";

export interface Widget {
  id: string;
  typ: WidgetTyp;
  // Spalten im 12er-Raster (2–12) und Reihen (1–6)
  breite: number;
  hoehe: number;
  // eigener Titel; leer = der Titel der Art
  titel?: string | null;
  // Seite ab 0
  seite?: number | null;
  // fester Mandant (mit seinen Untermandanten); null = wie in der Seitenleiste
  mandant_id?: string | null;
  // nur Graph: ein Gerät; null = die höchsten im Bereich
  geraet_id?: string | null;
  zeitraum?: Zeitraum | null;
  wert?: GraphWert | null;
  // nur Notiz
  text?: string | null;
  // nur „Einzelner Sensor“: Schlüssel aus /api/v1/sensoren
  sensor?: string | null;
}

// So kommt ein Widget von der Zentrale: alt mit „groesse“ oder neu mit Maßen.
export type WidgetRoh = Omit<Widget, "breite" | "hoehe"> & { groesse?: "klein" | "breit" | "hoch"; breite?: number; hoehe?: number };

export const maxWidgets = 60;
export const maxSeiten = 8;
export const SPALTEN = 12;
export const minBreite = 2;
export const maxHoehe = 6;

const alt: Record<string, [number, number]> = { klein: [4, 1], breit: [8, 1], hoch: [4, 2] };

export function klemmen(n: number, von: number, bis: number) {
  return Math.min(bis, Math.max(von, Math.round(n)));
}

// ausRoh: alte Größe umrechnen, Maße und Seite in die erlaubten Grenzen bringen.
export function ausRoh(w: WidgetRoh, seiten: number): Widget {
  const { groesse, ...rest } = w;
  const [b, h] = w.breite && w.hoehe ? [w.breite, w.hoehe] : (alt[groesse ?? "klein"] ?? alt.klein!);
  const seite = w.seite && w.seite > 0 && w.seite < Math.max(1, seiten) ? w.seite : 0;
  return { ...rest, breite: klemmen(b, minBreite, SPALTEN), hoehe: klemmen(h, 1, maxHoehe), seite };
}

export const widgetArten: Record<WidgetTyp, { titel: string; breite: number; hoehe: number; text: string }> = {
  zustand: { titel: "Zustand", breite: 8, hoehe: 1, text: "Sensoren und Geräte nach Zustand" },
  alarme: { titel: "Aktive Alarme", breite: 8, hoehe: 1, text: "Tabelle der offenen Alarme" },
  sensoren: { titel: "Sensoren nicht OK", breite: 4, hoehe: 1, text: "kurze Liste aller Probleme" },
  auslastung: { titel: "CPU und RAM", breite: 4, hoehe: 2, text: "aktuelle Auslastung der Hosts" },
  platten: { titel: "Vollste Platten", breite: 4, hoehe: 1, text: "die fünf vollsten Platten" },
  prognose: { titel: "Platten-Prognose", breite: 4, hoehe: 1, text: "Platten, die bald voll sind" },
  alarme_je_tag: { titel: "Alarme je Tag", breite: 4, hoehe: 1, text: "begonnene Alarme, 30 Tage" },
  verfuegbarkeit: { titel: "Verfügbarkeit", breite: 4, hoehe: 1, text: "7 und 30 Tage, schlechteste zuerst" },
  graph: { titel: "Graph", breite: 8, hoehe: 1, text: "CPU oder RAM eines Hosts oder der höchsten" },
  sonne: { titel: "Sonnendiagramm", breite: 4, hoehe: 2, text: "Mandanten, Gruppen und Geräte" },
  ereignisse: { titel: "Ereignisse (4 Std.)", breite: 4, hoehe: 2, text: "Beginn, Ende und Bestätigung von Alarmen" },
  zertifikate: { titel: "Zertifikate", breite: 4, hoehe: 1, text: "TLS-Zertifikate, das zuerst ablaufende oben" },
  wartung: { titel: "Wartung", breite: 4, hoehe: 1, text: "laufende und die nächsten Wartungen" },
  sensor: { titel: "Einzelner Sensor", breite: 3, hoehe: 1, text: "ein Sensor groß, mit Zustand und Meldung" },
  uhr: { titel: "Uhr", breite: 2, hoehe: 1, text: "Uhrzeit und Datum, für den Leitstand" },
  notiz: { titel: "Notiz", breite: 3, hoehe: 1, text: "eigener Text, z. B. die Nummer der Bereitschaft" },
};

const standardArten: WidgetTyp[] = [
  "zustand",
  "sensoren",
  "alarme",
  "auslastung",
  "ereignisse",
  "platten",
  "alarme_je_tag",
  "prognose",
  "graph",
  "verfuegbarkeit",
];

export function standardLayout(): Widget[] {
  return standardArten.map((typ, i) => ({ id: `std${i + 1}`, typ, breite: widgetArten[typ].breite, hoehe: widgetArten[typ].hoehe, seite: 0 }));
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

// fuerSpeichern: nur die Felder, die die Zentrale kennt; leere Einstellungen weglassen.
export function fuerSpeichern(layout: Widget[]) {
  return layout.map((w) => {
    const o: Widget = { id: w.id, typ: w.typ, breite: w.breite, hoehe: w.hoehe };
    if (w.titel?.trim()) o.titel = w.titel.trim();
    if (w.seite) o.seite = w.seite;
    if (w.mandant_id && !(w.typ === "graph" && w.geraet_id)) o.mandant_id = w.mandant_id;
    if (w.typ === "graph") {
      if (w.geraet_id) o.geraet_id = w.geraet_id;
      if (w.zeitraum) o.zeitraum = w.zeitraum;
      if (w.wert) o.wert = w.wert;
    }
    if (w.typ === "notiz" && w.text) o.text = w.text;
    if (w.typ === "sensor" && w.sensor) o.sensor = w.sensor;
    return o;
  });
}

// Spalten, die das Raster bei dieser Breite (CSS-Pixel) hat: 12, 6 oder 1.
export function spaltenFuer(breitePx: number): 12 | 6 | 1 {
  return breitePx >= 780 ? 12 : breitePx >= 520 ? 6 : 1;
}

// Spanne eines Widgets im Raster: bei 6 Spalten halb oder ganz, bei einer immer ganz.
export function spanne(w: Widget, spalten: 12 | 6 | 1): number {
  if (spalten === 12) return w.breite;
  if (spalten === 6) return w.breite <= 6 ? 3 : 6;
  return 1;
}

// seiteLoeschen: Widgets der Seite verschwinden, die dahinter rücken auf.
export function seiteLoeschen(layout: Widget[], seite: number): Widget[] {
  return layout.filter((w) => (w.seite ?? 0) !== seite).map((w) => ((w.seite ?? 0) > seite ? { ...w, seite: (w.seite ?? 0) - 1 } : w));
}
