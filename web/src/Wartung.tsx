// SPDX-License-Identifier: AGPL-3.0-only

// Wartungsmodus für ein Gerät oder einen Check: Anzeige, Setzen und Beenden.
// Die Wartung eines Geräts gilt für seinen Agent und alle seine Checks.
// In der Wartung laufen Messungen weiter; die Zentrale meldet keine neuen
// Probleme und keine Erinnerungen, Entwarnungen schon.

import { useState, type FormEvent } from "react";
import { api, type Wartung } from "./api";

const dauern: [number, string][] = [
  [30, "30 Minuten"],
  [60, "1 Stunde"],
  [120, "2 Stunden"],
  [480, "8 Stunden"],
];
const maxMinuten = 7 * 24 * 60;

// „bis 14:30“, an einem anderen Tag „bis Fr., 21.11., 14:30“.
export function wartungBis(w: Wartung) {
  const bis = new Date(w.bis);
  const heute = new Date().toDateString() === bis.toDateString();
  return heute
    ? `bis ${bis.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" })}`
    : `bis ${bis.toLocaleString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}`;
}

export function WartungMarke({ w }: { w: Wartung }) {
  return (
    <span className="marke marke-wartung" title={w.grund ? `Wartung: ${w.grund}` : "Wartung"}>
      Wartung {wartungBis(w)}
    </span>
  );
}

// datetime-local erwartet Ortszeit ohne Zone.
function ortszeit(d: Date) {
  const z = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}`;
}

export function WartungSteuerung(props: {
  // API-Pfad des Ziels, z. B. /api/v1/checks/<id>
  pfad: string;
  name: string;
  wartung: Wartung | null;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
  // Gesteuert (Aktionsmenü am Gerät, Etappe 19): nur das Formular, geöffnet
  // von außen; ohne offen zeigt die Steuerung nichts.
  offen?: boolean;
  onSchliessen?: () => void;
}) {
  const w = props.wartung;
  const [eigenOffen, setEigenOffen] = useState(false);
  const gesteuert = props.offen !== undefined;
  const offen = gesteuert ? !!props.offen : eigenOffen;
  const setOffen = (x: boolean) => {
    if (gesteuert) {
      if (!x) props.onSchliessen?.();
    } else setEigenOffen(x);
  };
  const [dauer, setDauer] = useState<number | "frei">(120);
  const [bis, setBis] = useState(() => ortszeit(new Date(Date.now() + 24 * 3600e3)));
  const [grund, setGrund] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const setzen = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    const minuten = dauer === "frei" ? Math.round((new Date(bis).getTime() - Date.now()) / 60000) : dauer;
    if (!Number.isFinite(minuten) || minuten < 1) {
      setFehler("Das Ende muss in der Zukunft liegen.");
      return;
    }
    if (minuten > maxMinuten) {
      setFehler("Eine Wartung dauert höchstens 7 Tage.");
      return;
    }
    setArbeitet(true);
    try {
      await api("PUT", `${props.pfad}/wartung`, { minuten, grund });
      setOffen(false);
      setGrund("");
      props.onGeaendert();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  const beenden = async () => {
    setArbeitet(true);
    try {
      await api("DELETE", `${props.pfad}/wartung`);
      props.onGeaendert();
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };

  if (offen) {
    return (
      <form className="formular-zeile wartung-formular" onSubmit={setzen} aria-label={`Wartung für ${props.name}`}>
        <label className="feld">
          <span>Dauer</span>
          <select autoFocus value={dauer} onChange={(e) => setDauer(e.target.value === "frei" ? "frei" : Number(e.target.value))}>
            {dauern.map(([m, t]) => (
              <option key={m} value={m}>
                {t}
              </option>
            ))}
            <option value="frei">bis …</option>
          </select>
        </label>
        {dauer === "frei" && (
          <label className="feld">
            <span>Ende</span>
            <input
              type="datetime-local"
              required
              value={bis}
              min={ortszeit(new Date())}
              max={ortszeit(new Date(Date.now() + maxMinuten * 60e3))}
              onChange={(e) => setBis(e.target.value)}
            />
          </label>
        )}
        <label className="feld feld-breit">
          <span>Grund (optional)</span>
          <input maxLength={200} value={grund} placeholder="z. B. Firmware-Update" onChange={(e) => setGrund(e.target.value)} />
        </label>
        <button className="knopf knopf-haupt" disabled={arbeitet}>
          {w ? "Wartung neu setzen" : "Wartung starten"}
        </button>
        <button type="button" className="knopf" onClick={() => setOffen(false)}>
          Abbrechen
        </button>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <p className="hinweis klein formular-voll">
          Messungen laufen weiter. Neue Probleme und Erinnerungen werden nicht gemeldet, Entwarnungen schon. Besteht ein Problem nach dem
          Ende noch, kommt sofort ein Alarm.
        </p>
      </form>
    );
  }
  if (gesteuert) return null;
  return w ? (
    <>
      <button className="knopf" disabled={arbeitet} onClick={beenden}>
        Wartung beenden
      </button>
      <button className="knopf" onClick={() => setOffen(true)}>
        Ändern
      </button>
    </>
  ) : (
    <button className="knopf" onClick={() => setOffen(true)} title="Alarme vorübergehend unterdrücken">
      Wartung …
    </button>
  );
}

// Zeile für die Detailansicht: wer, seit wann, warum.
export function WartungHinweis({ w }: { w: Wartung }) {
  return (
    <p className="meldung meldung-wartung">
      {w.ueber_geraet ? "Das Gerät ist in Wartung" : "In Wartung"} {wartungBis(w)}
      {w.von ? `, gesetzt von ${w.von}` : ""}
      {w.grund ? `: ${w.grund}` : ""}. Neue Probleme werden nicht gemeldet.
    </p>
  );
}
