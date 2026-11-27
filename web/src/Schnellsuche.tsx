// SPDX-License-Identifier: AGPL-3.0-only

// Schnellsuche (1.0.6, Idee aus der Klick-Demo): Strg+K bzw. ⌘K öffnet ein
// Feld, das über Geräte, Sensoren, Mandanten und Seiten sucht. Gesucht wird
// nur in dem, was die Zentrale ohnehin liefert (alles Sichtbare); die Daten
// holt der Dialog bei jedem Öffnen frisch und vergisst sie beim Schließen.

import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Geraet, type Mandant, type Sensor, type SensorStatus } from "./api";
import { navGruppen, type Ort, type Reiter } from "./navigation";

type Treffer =
  | { art: "geraet"; id: string; text: string; sub: string; mandant: string; status?: SensorStatus }
  | { art: "sensor"; id: string; text: string; sub: string; mandant: string; geraet: string; status: SensorStatus }
  | { art: "mandant"; id: string; text: string; sub: string }
  | { art: "seite"; id: Reiter; text: string; sub: string };

const ART: Record<Treffer["art"], string> = { geraet: "Gerät", sensor: "Sensor", mandant: "Mandant", seite: "Seite" };
const MAX = 12;
// Schlimmster Zustand zuerst, wenn die Übereinstimmung gleich gut ist.
const RANG: Record<string, number> = { crit: 0, warn: 1, unknown: 2, neu: 3, pause: 4, ok: 5 };
const statusText: Record<string, string> = {
  ok: "OK",
  warn: "Warnung",
  crit: "Kritisch",
  unknown: "Unbekannt",
  pause: "Pause",
  neu: "neu",
};

function schlimmer(a: SensorStatus | undefined, b: SensorStatus): SensorStatus {
  return a === undefined || RANG[b]! < RANG[a]! ? b : a;
}

// Güte einer Übereinstimmung: 0 = Anfang des Namens, 1 = Anfang eines
// Wortes, 2 = irgendwo im Namen, 3 = nur im Zusatz; -1 = kein Treffer.
// Mehrere Wörter müssen alle vorkommen.
export function guete(q: string, text: string, sub: string): number {
  const woerter = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (woerter.length === 0) return 3;
  const t = text.toLowerCase();
  const voll = `${t} ${sub.toLowerCase()}`;
  if (!woerter.every((w) => voll.includes(w))) return -1;
  const w0 = woerter[0]!;
  if (t.startsWith(w0)) return 0;
  if (t.split(/[\s._\-/·›]+/).some((x) => x.startsWith(w0))) return 1;
  if (t.includes(w0)) return 2;
  return 3;
}

export function Schnellsuche(props: {
  mandanten: Mandant[];
  betreiber: boolean;
  onZu: () => void;
  gehe: (o: Partial<Ort>) => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const feld = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  const [auswahl, setAuswahl] = useState(0);
  const [daten, setDaten] = useState<{ geraete: Geraet[]; sensoren: Sensor[] } | null>(null);
  const [fehler, setFehler] = useState("");

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
    feld.current?.focus();
    let weg = false;
    Promise.all([
      api<{ geraete: Geraet[] }>("GET", "/api/v1/geraete"),
      api<{ sensoren: Sensor[] }>("GET", "/api/v1/sensoren"),
    ])
      .then(([g, s]) => {
        if (!weg) setDaten({ geraete: g.geraete, sensoren: s.sensoren });
      })
      .catch((e: unknown) => {
        if (!weg) setFehler(e instanceof Error ? e.message : String(e));
      });
    return () => {
      weg = true;
    };
  }, []);

  const pfad = useMemo(() => {
    const nach = new Map(props.mandanten.map((m) => [m.id, m]));
    return (id: string) => {
      const teile: string[] = [];
      for (let m = nach.get(id); m && teile.length < 8; m = m.uebergeordnet_id ? nach.get(m.uebergeordnet_id) : undefined) teile.unshift(m.name);
      return teile.join(" › ");
    };
  }, [props.mandanten]);

  const alle = useMemo<Treffer[]>(() => {
    const out: Treffer[] = [];
    const zustand = new Map<string, SensorStatus>();
    for (const s of daten?.sensoren ?? []) zustand.set(s.geraet_id, schlimmer(zustand.get(s.geraet_id), s.status));
    for (const g of daten?.geraete ?? []) {
      out.push({
        art: "geraet",
        id: g.id,
        text: g.name,
        sub: [g.adresse, pfad(g.mandant_id)].filter(Boolean).join(" · "),
        mandant: g.mandant_id,
        status: zustand.get(g.id),
      });
    }
    for (const s of daten?.sensoren ?? []) {
      out.push({
        art: "sensor",
        id: s.schluessel,
        text: s.name,
        sub: [s.host, s.status === "ok" ? "" : s.meldung].filter(Boolean).join(" · "),
        mandant: s.mandant_id,
        geraet: s.geraet_id,
        status: s.status,
      });
    }
    for (const m of props.mandanten) out.push({ art: "mandant", id: m.id, text: m.name, sub: pfad(m.id) });
    for (const g of navGruppen)
      for (const p of g.punkte) if (!p.betreiber || props.betreiber) out.push({ art: "seite", id: p.id, text: p.text, sub: g.titel });
    return out;
  }, [daten, props.mandanten, props.betreiber, pfad]);

  const treffer = useMemo(() => {
    const leer = q.trim() === "";
    return alle
      .map((t, i) => ({ t, i, g: leer ? (t.art === "seite" ? 0 : -1) : guete(q, t.text, t.sub) }))
      .filter((x) => x.g >= 0)
      .sort(
        (a, b) =>
          a.g - b.g ||
          (RANG["status" in a.t ? (a.t.status ?? "ok") : "ok"] ?? 9) - (RANG["status" in b.t ? (b.t.status ?? "ok") : "ok"] ?? 9) ||
          a.i - b.i,
      )
      .slice(0, MAX)
      .map((x) => x.t);
  }, [alle, q]);

  useEffect(() => setAuswahl(0), [q]);

  const oeffnen = (t: Treffer) => {
    ref.current?.close();
    switch (t.art) {
      case "geraet":
        props.gehe({ reiter: "hosts", mandant: t.mandant, mitUnter: true, geraet: t.id, geraetReiter: "uebersicht" });
        break;
      case "sensor":
        props.gehe({ reiter: "hosts", mandant: t.mandant, mitUnter: true, geraet: t.geraet, geraetReiter: "sensoren" });
        break;
      case "mandant":
        props.gehe({ mandant: t.id });
        break;
      case "seite":
        props.gehe({ reiter: t.id, unter: "mandanten", alarm: "aktiv", geraet: "" });
        break;
    }
  };

  const taste = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setAuswahl((a) => Math.min(a + 1, treffer.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setAuswahl((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter" && treffer[auswahl]) {
      e.preventDefault();
      oeffnen(treffer[auswahl]);
    }
  };

  const aktiv = treffer[auswahl] ? `such-${auswahl}` : undefined;
  return (
    <dialog ref={ref} className="dialog schnellsuche" aria-label="Schnellsuche" onClose={props.onZu} onCancel={props.onZu}>
      <input
        ref={feld}
        className="such-feld"
        type="search"
        placeholder="Gerät, Sensor, Mandant oder Seite suchen …"
        autoComplete="off"
        spellCheck={false}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={taste}
        role="combobox"
        aria-expanded="true"
        aria-controls="such-liste"
        aria-activedescendant={aktiv}
        aria-label="Suchbegriff"
      />
      {fehler && (
        <p className="meldung meldung-fehler such-meldung" role="alert">
          {fehler}
        </p>
      )}
      <ul className="such-liste" id="such-liste" role="listbox" aria-label="Treffer">
        {treffer.map((t, i) => (
          <li
            key={t.art + t.id}
            id={`such-${i}`}
            role="option"
            aria-selected={i === auswahl}
            className={i === auswahl ? "such-treffer such-aktiv" : "such-treffer"}
            onMouseMove={() => setAuswahl(i)}
            onClick={() => oeffnen(t)}
          >
            {"status" in t && t.status ? (
              <span className={`signal signal-${t.status}`} aria-label={statusText[t.status]} role="img" />
            ) : (
              <span className="such-ohne" aria-hidden="true" />
            )}
            <span className="such-text">
              <span className="such-name">{t.text}</span>
              {t.sub && <span className="such-sub">{t.sub}</span>}
            </span>
            <span className="such-art">{ART[t.art]}</span>
          </li>
        ))}
        {treffer.length === 0 && (
          <li className="such-leer">{daten === null && !fehler ? "Lädt …" : "Nichts gefunden."}</li>
        )}
      </ul>
      <p className="such-fuss">
        <span>
          <kbd>↑</kbd> <kbd>↓</kbd> wählen · <kbd>Enter</kbd> öffnen · <kbd>Esc</kbd> schließen
        </span>
        {daten !== null && q.trim() === "" && (
          <span>
            {daten.geraete.length} Geräte, {daten.sensoren.length} Sensoren
          </span>
        )}
      </p>
    </dialog>
  );
}
