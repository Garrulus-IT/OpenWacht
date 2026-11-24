// SPDX-License-Identifier: AGPL-3.0-only

// Aktionsmenü „Aktionen ▾“ (Etappe 19): fasst die Knöpfe eines Geräts
// zusammen. Einträge sind in Gruppen geordnet, gefährliche stehen rot und
// abgesetzt am Ende. Bedienung mit der Maus, per Tastatur (Pfeiltasten,
// Pos1/Ende, Esc, Tab schließt) und am Handy als Liste von unten.
//
// Es erscheinen nur Einträge, die der Aufrufer übergibt; Rolle und Zustand
// des Geräts prüft die Seite, die API ohnehin noch einmal.

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";

export interface Aktion {
  text: string;
  onWahl: () => void;
  gefahr?: boolean;
  titel?: string;
}

// Gruppen: jede Gruppe ist eine Liste von Aktionen; leere Gruppen fallen weg.
export function Aktionsmenue(props: { gruppen: Aktion[][]; beschriftung?: string; name: string }) {
  const [offen, setOffen] = useState(false);
  const knopf = useRef<HTMLButtonElement>(null);
  const menue = useRef<HTMLDivElement>(null);
  const id = useId();
  const gruppen = props.gruppen.filter((g) => g.length > 0);

  const eintraege = () => Array.from(menue.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? []);
  const fokus = (i: number) => {
    const l = eintraege();
    if (l.length) l[(i + l.length) % l.length]?.focus();
  };
  const schliessen = (zurueck: boolean) => {
    setOffen(false);
    if (zurueck) knopf.current?.focus();
  };

  useEffect(() => {
    if (!offen) return;
    fokus(0);
    const draussen = (e: PointerEvent) => {
      const t = e.target as Node;
      if (!menue.current?.contains(t) && !knopf.current?.contains(t)) setOffen(false);
    };
    document.addEventListener("pointerdown", draussen);
    return () => document.removeEventListener("pointerdown", draussen);
  }, [offen]);

  if (gruppen.length === 0) return null;

  const taste = (e: KeyboardEvent<HTMLDivElement>) => {
    const l = eintraege();
    const i = l.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      fokus(i + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      fokus(i - 1);
    } else if (e.key === "Home") {
      e.preventDefault();
      fokus(0);
    } else if (e.key === "End") {
      e.preventDefault();
      fokus(l.length - 1);
    } else if (e.key === "Escape") {
      e.preventDefault();
      schliessen(true);
    } else if (e.key === "Tab") {
      schliessen(false);
    }
  };

  return (
    <div className="aktionsmenue">
      <button
        ref={knopf}
        type="button"
        className="knopf"
        aria-haspopup="menu"
        aria-expanded={offen}
        aria-controls={offen ? id : undefined}
        aria-label={`${props.beschriftung ?? "Aktionen"} für ${props.name}`}
        onClick={() => setOffen(!offen)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && !offen) {
            e.preventDefault();
            setOffen(true);
          }
        }}
      >
        {props.beschriftung ?? "Aktionen"} <span aria-hidden="true">▾</span>
      </button>
      {offen && (
        <>
          <div className="aktionsmenue-schleier" aria-hidden="true" onClick={() => schliessen(false)} />
          <div ref={menue} id={id} className="aktionsmenue-liste" role="menu" aria-label={`Aktionen für ${props.name}`} onKeyDown={taste}>
            <p className="aktionsmenue-titel" aria-hidden="true">
              {props.name}
            </p>
            {gruppen.map((g, gi) => (
              <div key={gi} role="group" className={`aktionsmenue-gruppe${g.some((a) => a.gefahr) ? " aktionsmenue-gefahr" : ""}`}>
                {g.map((a) => (
                  <button
                    key={a.text}
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    title={a.titel}
                    className={a.gefahr ? "gefahr" : undefined}
                    onClick={() => {
                      schliessen(true);
                      a.onWahl();
                    }}
                  >
                    {a.text}
                  </button>
                ))}
              </div>
            ))}
            <button type="button" className="aktionsmenue-abbrechen" onClick={() => schliessen(true)}>
              Abbrechen
            </button>
          </div>
        </>
      )}
    </div>
  );
}
