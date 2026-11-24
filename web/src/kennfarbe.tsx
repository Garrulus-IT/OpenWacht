// SPDX-License-Identifier: AGPL-3.0-only

// Kennfarben (0.99.2): Ein Sensor mit Kennfarbe erscheint bei Warnung,
// Kritisch und Bestätigt in dieser Farbe statt in Gelb bzw. Rot. Form und Text
// der Schwere bleiben (Corporate Design: nie nur Farbe). Bei gleicher Schwere
// gewinnt immer der Zustand ohne Kennfarbe („Rot gewinnt immer“).
//
// Die Farbe kommt als „#rrggbb“ von der Zentrale (geprüft) und wird nur als
// CSS-Variable im style-Attribut gesetzt, nie als Markup.

import type { CSSProperties } from "react";

export interface Kennfarbe {
  id: string;
  name: string;
  farbe: string;
}

const HEX = /^#[0-9a-f]{6}$/i;

// Flächen wie in internal/zentrale/kennfarben.go
export const GRUND_HELL = "#ffffff";
export const GRUND_DUNKEL = "#111c29";
export const MIN_KONTRAST = 3;

function kanal(v: number) {
  const x = v / 255;
  return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
}

function leuchtdichte(hex: string) {
  const n = parseInt(hex.slice(1), 16);
  return 0.2126 * kanal((n >> 16) & 255) + 0.7152 * kanal((n >> 8) & 255) + 0.0722 * kanal(n & 255);
}

export function kontrast(a: string, b: string): number {
  const x = leuchtdichte(a);
  const y = leuchtdichte(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

// Schrift auf einer Fläche in der Kennfarbe: die dunkle oder weiße, je nachdem,
// welche mehr Kontrast hat.
export function schriftAuf(hex: string): string {
  return kontrast(hex, "#ffffff") >= kontrast(hex, "#0a121c") ? "#ffffff" : "#0a121c";
}

// Prüfung im Farbwähler, gleich wie in der Zentrale.
export function kennfarbePruefen(hex: string): { hell: number; dunkel: number; fehler: string | null } {
  if (!HEX.test(hex)) return { hell: 0, dunkel: 0, fehler: "Format #rrggbb" };
  const hell = kontrast(hex, GRUND_HELL);
  const dunkel = kontrast(hex, GRUND_DUNKEL);
  const fehler =
    hell < MIN_KONTRAST
      ? "Auf hellem Grund zu blass. Bitte einen dunkleren oder kräftigeren Ton wählen."
      : dunkel < MIN_KONTRAST
        ? "Auf dunklem Grund zu dunkel. Bitte einen helleren Ton wählen."
        : null;
  return { hell, dunkel, fehler };
}

export function zahl(r: number) {
  return (Math.floor(r * 10) / 10).toLocaleString("de-DE", { minimumFractionDigits: 1 });
}

// Gilt die Kennfarbe bei diesem Zustand?
export function kennfarbeGilt(status: string): boolean {
  return status === "warn" || status === "crit" || status === "quittiert" || status === "bestaetigt";
}

// Stil für Zustandsformen und -zellen: setzt --kenn und --auf-kenn, die
// Klasse „kenn“ schaltet die Farben in styles.css um.
export function kennStil(k: Kennfarbe | null | undefined, status: string): { className: string; style?: CSSProperties } {
  if (!k || !HEX.test(k.farbe) || !kennfarbeGilt(status)) return { className: "" };
  return {
    className: " kenn",
    style: { "--kenn": k.farbe, "--auf-kenn": schriftAuf(k.farbe) } as CSSProperties,
  };
}

// Tooltip-Zusatz mit dem Namen der Kennfarbe
export function kennTitel(k: Kennfarbe | null | undefined, status: string): string {
  return k && kennfarbeGilt(status) ? ` · ${k.name}` : "";
}

// Kennfarbe eines Geräts bzw. einer Gruppe: die des schlimmsten Zustands,
// aber nur, wenn kein Zustand gleicher Schwere ohne Kennfarbe dabei ist.
export function kennfarbeVon<T>(
  teile: T[],
  stand: string,
  status: (t: T) => string,
  kenn: (t: T) => Kennfarbe | null | undefined,
): Kennfarbe | null {
  if (!kennfarbeGilt(stand)) return null;
  let erste: Kennfarbe | null = null;
  for (const t of teile) {
    if (status(t) !== stand) continue;
    const k = kenn(t);
    if (!k) return null; // Rot gewinnt immer
    erste ??= k;
  }
  return erste;
}

// Kleine Marke mit Farbfeld und Name, z. B. hinter der Meldung eines Sensors.
export function KennMarke({ k, status, immer }: { k?: Kennfarbe | null; status?: string; immer?: boolean }) {
  if (!k || !HEX.test(k.farbe) || (!immer && !kennfarbeGilt(status ?? ""))) return null;
  return (
    <span className="kenn-marke" style={{ "--kenn": k.farbe } as CSSProperties}>
      {k.name}
    </span>
  );
}
