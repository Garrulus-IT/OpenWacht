// SPDX-License-Identifier: AGPL-3.0-only

// Hinweise (Etappe 31): Zustand der Zentrale (nur für den Betreiber) und
// Geräte, deren Alarme wegen eines ausgefallenen Elterngeräts ruhen (N2).
// Steht auf der Seite Alarme über „Aktiv“ und „Protokoll“.

import { dauer } from "./AlarmeSeite";

export interface Hinweis {
  schluessel: string;
  mandant_id: string | null;
  zustand: "warn" | "crit";
  titel: string;
  text: string;
  seit: string;
}

export interface Unterdrueckt {
  mandant_id: string;
  geraet_id: string;
  geraet: string;
  seit: string | null;
  anzahl: number;
  geraete: string[];
}

export interface HinweisDaten {
  hinweise: Hinweis[];
  unterdrueckt: Unterdrueckt[];
}

function zeit(iso: string) {
  return new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

export function Hinweise(props: { d: HinweisDaten; jetzt: number; drin: (mandant: string) => boolean }) {
  const { d, jetzt, drin } = props;
  // Hinweise zu Unterdrückungen stehen schon in der eigenen Liste darunter.
  const liste = d.hinweise.filter((h) => !h.schluessel.startsWith("unterdrueckt:") && (h.mandant_id === null || drin(h.mandant_id)));
  const ruhen = d.unterdrueckt.filter((u) => drin(u.mandant_id));
  if (liste.length === 0 && ruhen.length === 0) return null;
  return (
    <div className="hinweise" aria-label="Hinweise">
      {liste.map((h) => (
        <div
          key={h.schluessel}
          className={`meldung ${h.zustand === "crit" ? "meldung-fehler" : "meldung-warnung"}`}
          role={h.zustand === "crit" ? "alert" : "status"}
        >
          <strong>
            {h.mandant_id === null ? "Zentrale: " : ""}
            {h.titel}
          </strong>{" "}
          <span className="klein">seit {zeit(h.seit)}</span>
          <div>{h.text}</div>
        </div>
      ))}
      {ruhen.map((u) => {
        const lang = u.seit !== null && jetzt - Date.parse(u.seit) >= 7 * 24 * 3600 * 1000;
        return (
          <div key={u.geraet_id} className={`meldung ${lang ? "meldung-warnung" : "meldung-wartung"}`} role="status">
            <strong>Alarme unterdrückt{u.seit ? ` seit ${zeit(u.seit)} (${dauer(u.seit, jetzt)})` : ""}</strong>
            <div>
              {u.anzahl === 1 ? "Ein Gerät hängt" : `${u.anzahl} Geräte hängen`} von „{u.geraet}“ ab, das nicht erreichbar ist:{" "}
              {u.geraete.join(", ")}
              {u.anzahl > u.geraete.length ? " …" : ""}. Für diese Geräte gehen keine eigenen Alarme raus.
              {lang
                ? " Das dauert schon über 7 Tage; die Alarmkanäle des Mandanten haben einen Hinweis bekommen. Abhängigkeit prüfen oder das Gerät reparieren."
                : " Nach 7 Tagen geht ein Hinweis an die Alarmkanäle des Mandanten."}
            </div>
          </div>
        );
      })}
    </div>
  );
}
