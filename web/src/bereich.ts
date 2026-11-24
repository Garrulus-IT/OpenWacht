// SPDX-License-Identifier: AGPL-3.0-only

// Der Bereich, den die Reiter Hosts, Checks und Alarmierung zeigen: der im
// Kopf gewählte Mandant und, wenn gewünscht, alle Mandanten darunter.
//
// Die Listen der API liefern ohne Filter alles, was der Benutzer sehen darf
// (Row-Level Security in der Datenbank). Die Oberfläche grenzt das nur noch
// auf den Bereich ein; sie erweitert nie, was die Zentrale herausgibt.

import type { Mandant, Rolle } from "./api";

export interface Bereich {
  // gewählter Mandant; neue Hosts, Checks und Kanäle landen hier
  mandant: Mandant;
  // IDs im Bereich (der gewählte Mandant und ggf. alle darunter)
  ids: Set<string>;
  nachId: Map<string, Mandant>;
  // Mehr als ein Mandant im Bereich: Zeilen zeigen ihren Mandanten.
  mehrere: boolean;
}

export function kinderVon(mandanten: Mandant[]) {
  const k = new Map<string, Mandant[]>();
  for (const m of mandanten) {
    if (!m.uebergeordnet_id) continue;
    const liste = k.get(m.uebergeordnet_id) ?? [];
    liste.push(m);
    k.set(m.uebergeordnet_id, liste);
  }
  for (const liste of k.values()) liste.sort((a, b) => a.name.localeCompare(b.name, "de"));
  return k;
}

// Wurzeln aus Sicht des Benutzers: Knoten, deren Eltern er nicht sieht.
export function wurzeln(ms: Mandant[]) {
  const ids = new Set(ms.map((m) => m.id));
  return ms.filter((m) => m.uebergeordnet_id === null || !ids.has(m.uebergeordnet_id)).sort((a, b) => a.name.localeCompare(b.name, "de"));
}

// Mandanten in Baumreihenfolge mit Tiefe, für Auswahllisten.
export function baumReihe(ms: Mandant[]): { m: Mandant; tiefe: number }[] {
  const kinder = kinderVon(ms);
  const out: { m: Mandant; tiefe: number }[] = [];
  const besuchen = (m: Mandant, tiefe: number) => {
    out.push({ m, tiefe });
    for (const k of kinder.get(m.id) ?? []) besuchen(k, tiefe + 1);
  };
  for (const w of wurzeln(ms)) besuchen(w, 0);
  return out;
}

export function bereichFuer(ms: Mandant[], id: string, mitUnter: boolean): Bereich | null {
  const nachId = new Map(ms.map((m) => [m.id, m]));
  const mandant = nachId.get(id);
  if (!mandant) return null;
  const ids = new Set([id]);
  if (mitUnter) {
    const kinder = kinderVon(ms);
    const offen = [id];
    while (offen.length) {
      for (const k of kinder.get(offen.pop()!) ?? []) {
        if (!ids.has(k.id)) {
          ids.add(k.id);
          offen.push(k.id);
        }
      }
    }
  }
  return { mandant, ids, nachId, mehrere: ids.size > 1 };
}

export function rolleIn(b: Bereich, mandantId: string): Rolle | "" {
  return b.nachId.get(mandantId)?.rolle ?? "";
}

// Hosts und Checks pflegen dürfen Admins und Operatoren.
export function darfPflegen(b: Bereich, mandantId: string) {
  const r = rolleIn(b, mandantId);
  return r === "admin" || r === "operator";
}

export function mandantName(b: Bereich, mandantId: string) {
  return b.nachId.get(mandantId)?.name ?? "";
}
