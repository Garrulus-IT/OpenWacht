// SPDX-License-Identifier: AGPL-3.0-only

// Gemeinsame Datenquellen für die Widgets des Dashboards: Mehrere Widgets mit
// derselben Adresse teilen sich eine Anfrage und ihr Ergebnis. Neu geladen
// wird im Takt der Quelle, solange mindestens ein Widget sie nutzt und das
// Fenster sichtbar ist. Fehler bleiben je Quelle stehen, bis eine Anfrage
// wieder gelingt.

import { useEffect, useState } from "react";
import { api } from "./api";

interface Eintrag {
  daten: unknown;
  fehler: string;
  zeit: number;
  laeuft: Promise<void> | null;
  hoerer: Set<() => void>;
  takt: number;
  timer: number | null;
  // so viele Nutzer wollen auch bei verborgenem Fenster neue Daten (1.0.3:
  // Windows-Benachrichtigungen, wenn OpenWacht im Hintergrund ist)
  verborgen: number;
}

const speicher = new Map<string, Eintrag>();

function holen(pfad: string, e: Eintrag) {
  if (e.laeuft) return e.laeuft;
  e.laeuft = api<unknown>("GET", pfad)
    .then(
      (d) => {
        e.daten = d;
        e.fehler = "";
      },
      (err: unknown) => {
        e.fehler = err instanceof Error ? err.message : "Nicht ladbar.";
      },
    )
    .finally(() => {
      e.zeit = Date.now();
      e.laeuft = null;
      for (const h of e.hoerer) h();
    });
  return e.laeuft;
}

// useQuelle lädt pfad (null = nichts laden) und liefert Daten und Fehler.
// auchVerborgen: auch weiter laden, wenn das Fenster nicht sichtbar ist.
export function useQuelle<T>(pfad: string | null, takt = 30_000, auchVerborgen = false): { daten: T | null; fehler: string } {
  const [, neu] = useState(0);
  useEffect(() => {
    if (!pfad) return;
    let e = speicher.get(pfad);
    if (!e) {
      e = { daten: null, fehler: "", zeit: 0, laeuft: null, hoerer: new Set(), takt, timer: null, verborgen: 0 };
      speicher.set(pfad, e);
    }
    const eintrag = e;
    const hoeren = () => neu((n) => n + 1);
    eintrag.hoerer.add(hoeren);
    if (auchVerborgen) eintrag.verborgen++;
    eintrag.takt = Math.min(eintrag.takt, takt);
    if (Date.now() - eintrag.zeit > eintrag.takt / 2) void holen(pfad, eintrag);
    else hoeren();
    if (eintrag.timer === null) {
      eintrag.timer = window.setInterval(() => {
        if (!document.hidden || eintrag.verborgen > 0) void holen(pfad, eintrag);
      }, eintrag.takt);
    }
    return () => {
      eintrag.hoerer.delete(hoeren);
      if (auchVerborgen) eintrag.verborgen--;
      if (eintrag.hoerer.size === 0 && eintrag.timer !== null) {
        window.clearInterval(eintrag.timer);
        eintrag.timer = null;
      }
    };
  }, [pfad, takt, auchVerborgen]);
  const e = pfad ? speicher.get(pfad) : undefined;
  return { daten: (e?.daten as T | undefined) ?? null, fehler: e?.fehler ?? "" };
}

// leeren verwirft alle zwischengespeicherten Daten (z. B. beim Abmelden).
export function quellenLeeren() {
  for (const e of speicher.values()) if (e.timer !== null) window.clearInterval(e.timer);
  speicher.clear();
}

// auffrischen lädt eine Quelle sofort neu (z. B. nach einer Änderung).
export function auffrischen(pfad: string) {
  const e = speicher.get(pfad);
  if (e) void holen(pfad, e);
}
