// SPDX-License-Identifier: AGPL-3.0-only

// Darstellung: System (Standard), Hell oder Dunkel. Die Wahl liegt nur im
// Browser (localStorage, kein Geheimnis); public/thema.js setzt sie schon vor
// dem ersten Zeichnen. Gilt die Systemeinstellung, folgt die Seite auch einem
// Wechsel des Systems zur Laufzeit (z. B. abends automatisch dunkel).

import { useEffect, useState } from "react";

export type Thema = "system" | "hell" | "dunkel";

const SCHLUESSEL = "openwacht.thema";
const abfrage = "(prefers-color-scheme: dark)";

export function gespeichertesThema(): Thema {
  try {
    const w = window.localStorage.getItem(SCHLUESSEL);
    if (w === "hell" || w === "dunkel") return w;
  } catch {
    /* Speicher gesperrt (privates Fenster, Richtlinie): System */
  }
  return "system";
}

function systemDunkel() {
  return typeof window.matchMedia === "function" && window.matchMedia(abfrage).matches;
}

export function anwenden(t: Thema) {
  const dunkel = t === "dunkel" || (t === "system" && systemDunkel());
  document.documentElement.setAttribute("data-thema", dunkel ? "dunkel" : "hell");
}

function speichern(t: Thema) {
  try {
    if (t === "system") window.localStorage.removeItem(SCHLUESSEL);
    else window.localStorage.setItem(SCHLUESSEL, t);
  } catch {
    /* nicht speicherbar: gilt bis zum Neuladen */
  }
}

export function useThema(): [Thema, (t: Thema) => void] {
  const [thema, setThema] = useState<Thema>(gespeichertesThema);

  useEffect(() => {
    anwenden(thema);
    if (thema !== "system" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(abfrage);
    const folgen = () => anwenden("system");
    mq.addEventListener("change", folgen);
    return () => mq.removeEventListener("change", folgen);
  }, [thema]);

  // Wahl in einem anderen Tab übernehmen.
  useEffect(() => {
    const anderesFenster = (e: StorageEvent) => {
      if (e.key === SCHLUESSEL || e.key === null) setThema(gespeichertesThema());
    };
    window.addEventListener("storage", anderesFenster);
    return () => window.removeEventListener("storage", anderesFenster);
  }, []);

  return [
    thema,
    (t: Thema) => {
      speichern(t);
      setThema(t);
    },
  ];
}
