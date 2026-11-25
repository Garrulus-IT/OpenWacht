// SPDX-License-Identifier: AGPL-3.0-only

// Wandanzeige: eigene Seite unter /anzeige, ohne Benutzerkonto.
//
// Der Link enthält den Schlüssel im Fragment (#…). Die Seite schickt ihn
// einmal an die Zentrale, bekommt ein HttpOnly-Cookie und entfernt den
// Schlüssel sofort aus der Adresszeile und dem Verlauf. Danach fragt sie alle
// 30 Sekunden den Zustand ab.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type AnzeigeDaten, type AnzeigeKennfarbe, type AnzeigeKnoten, type AnzeigeStatus } from "./api";
import { segmentStil, Sonne, statusText, zerlegen } from "./Sonne";
import { spielen, tonFreigeben, tonFrei, tonFuer } from "./Ton";

const TAKT_MS = 30_000;
// Ohne frische Daten so lange gilt die Anzeige als veraltet.
const VERALTET_MS = 2 * 60_000;
// So lange bleibt ein neuer Alarm hervorgehoben.
const NEU_MS = 60_000;

type Zustand = { art: "laden" } | { art: "fehler"; text: string } | { art: "da"; daten: AnzeigeDaten; geholt: number };

function uhrzeit(t: number) {
  return new Date(t).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

function datum(t: number) {
  return new Date(t).toLocaleDateString("de-DE", { weekday: "long", day: "numeric", month: "long" });
}

// Uhr mit Sekunden: Bleiben die Sekunden stehen, ist die Seite eingefroren
// (Browser hängt, Bildschirm zeigt ein altes Bild). Eigener Takt je Sekunde.
function Uhr() {
  const [t, setT] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setT(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  return (
    <time className="wand-uhr" dateTime={t.toISOString()}>
      {uhrzeit(t.getTime())}
      <span className="wand-uhr-sek">{String(t.getSeconds()).padStart(2, "0")}</span>
    </time>
  );
}

// Höchstens so viele Geräte in der Liste „Aktuell“; der Rest als Zahl.
const MAX_PROBLEME = 12;
const PROBLEM: AnzeigeStatus[] = ["crit", "quittiert", "warn", "unknown"];

// Legende: Geräte je Zustand, schlimmster zuerst. Die Form trägt den Zustand
// auch ohne Farbe (Corporate Design, Zustandsformen).
const LEGENDE: AnzeigeStatus[] = ["crit", "quittiert", "warn", "unknown", "wartung", "ok"];

function zaehlen(baum: AnzeigeKnoten): Record<AnzeigeStatus, number> {
  const n: Record<AnzeigeStatus, number> = { ok: 0, warn: 0, crit: 0, quittiert: 0, unknown: 0, wartung: 0 };
  const gehe = (k: AnzeigeKnoten) => {
    if (k.art === "geraet") n[k.status] = (n[k.status] ?? 0) + 1;
    for (const c of k.kinder ?? []) gehe(c);
  };
  gehe(baum);
  return n;
}

const kurzText: Record<AnzeigeStatus, string> = { ...statusText, wartung: "Wartung" };

// Zahlen je Zustand als Kacheln; Zustände ohne Gerät treten zurück.
function Zaehler({ baum }: { baum: AnzeigeKnoten }) {
  const n = zaehlen(baum);
  return (
    <ul className="wand-zaehler" aria-label="Geräte nach Zustand">
      {LEGENDE.map((s) => (
        <li key={s} className={n[s] ? `wand-zahl wand-zahl-${s}` : "wand-zahl wand-zahl-leer"}>
          <span className={`signal wand-signal-${s}`} aria-hidden="true" />
          <span className="wand-zahl-wert">{n[s]}</span>
          <span className="wand-zahl-text">{kurzText[s]}</span>
        </li>
      ))}
    </ul>
  );
}

interface Problem {
  name: string;
  pfad: string;
  status: AnzeigeStatus;
  farbe?: string;
  kennfarbe?: string;
}

// Geräte, die nicht OK sind, schlimmste zuerst, mit dem Weg dorthin.
function probleme(baum: AnzeigeKnoten): Problem[] {
  const out: Problem[] = [];
  const gehe = (k: AnzeigeKnoten, pfad: string[]) => {
    if (k.art === "geraet") {
      if (PROBLEM.includes(k.status)) out.push({ name: k.name, pfad: pfad.join(" › "), status: k.status, farbe: k.farbe, kennfarbe: k.kennfarbe });
      return;
    }
    for (const c of k.kinder ?? []) gehe(c, k === baum ? pfad : [...pfad, k.name]);
  };
  gehe(baum, []);
  out.sort((a, b) => PROBLEM.indexOf(a.status) - PROBLEM.indexOf(b.status) || a.name.localeCompare(b.name, "de"));
  return out;
}

function Probleme({ baum, neu }: { baum: AnzeigeKnoten; neu: number }) {
  const liste = probleme(baum);
  return (
    <section className="wand-block" aria-labelledby="wand-aktuell">
      <h2 id="wand-aktuell" className="wand-block-titel">
        Aktuell
      </h2>
      {liste.length === 0 ? (
        <p className="wand-alles-ok">
          <span className="signal wand-signal-ok" aria-hidden="true" />
          Alle Geräte sind OK.
        </p>
      ) : (
        <ul className="wand-probleme">
          {liste.slice(0, MAX_PROBLEME).map((p, i) => {
            const st = segmentStil(p.farbe);
            return (
              <li key={p.pfad + "\u0000" + p.name + i} className={`wand-problem wand-problem-${p.status}${st.kenn}`} style={st.style}>
                <span className={`signal wand-signal-${p.status}${st.kenn}`} style={st.style} aria-hidden="true" />
                <span className="wand-problem-text">
                  <span className="wand-problem-name">{p.name}</span>
                  <span className="wand-problem-pfad">
                    <span className="sr-only">{statusText[p.status]}, </span>
                    {p.kennfarbe ? `${p.kennfarbe} · ` : p.status === "quittiert" ? "bestätigt · " : ""}
                    {p.pfad}
                  </span>
                </span>
              </li>
            );
          })}
          {liste.length > MAX_PROBLEME && <li className="wand-problem-mehr">+ {liste.length - MAX_PROBLEME} weitere</li>}
        </ul>
      )}
      {neu > 0 && <p className="wand-neu">{neu === 1 ? "1 neuer Alarm" : `${neu} neue Alarme`} in der letzten Minute</p>}
    </section>
  );
}

// Legende der Kennfarben: alle, die die Anzeige kennt, mit der Zahl der
// Geräte, die gerade in dieser Farbe stehen.
function KennfarbenLegende({ liste }: { liste: AnzeigeKennfarbe[] }) {
  if (liste.length === 0) return null;
  return (
    <section className="wand-block" aria-labelledby="wand-kennfarben">
      <h2 id="wand-kennfarben" className="wand-block-titel">
        Kennfarben
      </h2>
      <ul className="wand-kennfarben">
        {liste.map((k) => {
          const st = segmentStil(k.farbe);
          return (
            <li key={k.name + k.farbe} className={k.geraete ? "" : "wand-kenn-leer"}>
              <span className="wand-kenn-feld" style={st.style} aria-hidden="true" />
              <span className="wand-kenn-name">{k.name}</span>
              <span className="wand-kenn-zahl">{k.geraete}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// Zahl der Geräte unter den neu hervorgehobenen Segmenten
function neueGeraete(baum: AnzeigeKnoten, hervor: Set<string>): number {
  return zerlegen(baum).segmente.filter((s) => s.art === "geraet" && hervor.has(s.schluessel)).length;
}

// Zustand je Gerät für den Ton (1.0.2): nur Warnung und Kritisch, nicht bestätigt.
function geraeteZustand(baum: AnzeigeKnoten): Map<string, string> {
  return new Map(
    zerlegen(baum)
      .segmente.filter((s) => s.art === "geraet" && (s.status === "crit" || s.status === "warn"))
      .map((s) => [s.schluessel, s.status]),
  );
}

// Schlüssel der Segmente mit Alarm (nicht bestätigt).
function alarme(baum: AnzeigeKnoten): Set<string> {
  return new Set(
    zerlegen(baum)
      .segmente.filter((s) => s.status === "crit")
      .map((s) => s.schluessel),
  );
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// vorschau: ID der Anzeige; dann lädt die Seite in der Sitzung eines Admins
// ohne Anzeige-Schlüssel (/anzeige/vorschau?id=…, 0.99.2).
export function Wandanzeige({ vorschau }: { vorschau?: string } = {}) {
  const [zustand, setZustand] = useState<Zustand>({ art: "laden" });
  const [stoerung, setStoerung] = useState<number | null>(null); // seit wann keine Verbindung
  const [jetzt, setJetzt] = useState(Date.now());
  const [neu, setNeu] = useState<Map<string, number>>(new Map());
  const vorher = useRef<Set<string> | null>(null);
  const vorherTon = useRef<Map<string, string> | null>(null);
  const aus = useRef(false);
  const [tonAn, setTonAn] = useState(false);

  const holen = useCallback(async () => {
    try {
      const d = await api<AnzeigeDaten>("GET", vorschau !== undefined ? `/api/v1/anzeigen/${vorschau}/vorschau` : "/api/v1/anzeige/daten");
      const jetztAlarme = alarme(d.baum);
      const t = Date.now();
      if (vorher.current) {
        const alt = vorher.current;
        setNeu((m) => {
          const n = new Map([...m].filter(([k, seit]) => t - seit < NEU_MS && jetztAlarme.has(k)));
          for (const k of jetztAlarme) if (!alt.has(k) && !n.has(k)) n.set(k, t);
          return n;
        });
      }
      vorher.current = jetztAlarme;
      // Ton: neue oder schlimmer gewordene Geräte, Entwarnung, wenn keins mehr übrig ist.
      const z = geraeteZustand(d.baum);
      const altZ = vorherTon.current;
      vorherTon.current = z;
      if (altZ && d.ton && tonFrei()) {
        let art: "krit" | "warn" | "entwarnung" | null = null;
        for (const [k, st] of z) {
          if (altZ.get(k) === st || altZ.get(k) === "crit") continue;
          const a = tonFuer(d.ton.ton, st);
          if (a === "krit" || (a === "warn" && art === null)) art = a;
        }
        if (!art && d.ton.entwarnung && d.ton.ton !== "aus" && altZ.size > 0 && z.size < altZ.size) art = "entwarnung";
        if (art) spielen(d.ton.klang, d.ton.lautstaerke, art);
      }
      setZustand({ art: "da", daten: d, geholt: t });
      setStoerung(null);
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403 || (vorschau !== undefined && e.status === 404))) {
        aus.current = true;
        setZustand({ art: "fehler", text: e.message });
        return;
      }
      setStoerung((s) => s ?? Date.now());
    }
  }, [vorschau]);

  // Anmelden mit dem Schlüssel aus dem Fragment, dann regelmäßig abfragen.
  useEffect(() => {
    let weg = false;
    let takt: number | undefined;
    const start = async () => {
      if (vorschau !== undefined && !UUID.test(vorschau)) {
        setZustand({ art: "fehler", text: "Vorschau: Anzeige unbekannt." });
        return;
      }
      const schluessel = vorschau !== undefined ? "" : window.location.hash.replace(/^#/, "");
      if (schluessel) {
        // Schlüssel sofort aus Adresszeile und Verlauf entfernen.
        window.history.replaceState(null, "", "/anzeige");
        try {
          await api("POST", "/api/v1/anzeige/anmelden", { schluessel });
        } catch (e) {
          if (!weg) setZustand({ art: "fehler", text: e instanceof Error ? e.message : String(e) });
          return;
        }
      }
      if (weg) return;
      await holen();
      takt = window.setInterval(() => {
        if (!aus.current) void holen();
      }, TAKT_MS);
    };
    void start();
    return () => {
      weg = true;
      window.clearInterval(takt);
    };
  }, [holen, vorschau]);

  // Uhr für „veraltet“ und das Ende der Hervorhebung
  useEffect(() => {
    const t = window.setInterval(() => setJetzt(Date.now()), 5_000);
    return () => window.clearInterval(t);
  }, []);

  // Bildschirm wach halten, wo der Browser das kann.
  useEffect(() => {
    type Sperre = { release: () => Promise<void> };
    const wl = (navigator as Navigator & { wakeLock?: { request: (t: "screen") => Promise<Sperre> } }).wakeLock;
    if (!wl) return;
    let sperre: Sperre | null = null;
    const holenSperre = () => {
      if (document.visibilityState === "visible") {
        wl.request("screen")
          .then((s) => (sperre = s))
          .catch(() => undefined);
      }
    };
    holenSperre();
    document.addEventListener("visibilitychange", holenSperre);
    return () => {
      document.removeEventListener("visibilitychange", holenSperre);
      void sperre?.release().catch(() => undefined);
    };
  }, []);

  if (zustand.art === "laden") {
    return <div className="wand" aria-busy="true" />;
  }
  if (zustand.art === "fehler") {
    return (
      <div className="wand wand-mittig">
        <p className="wand-fehler" role="alert">
          {zustand.text}
        </p>
      </div>
    );
  }
  const { daten, geholt } = zustand;
  const veraltet = jetzt - geholt > VERALTET_MS;
  const hervor = new Set([...neu].filter(([, seit]) => jetzt - seit < NEU_MS).map(([k]) => k));
  return (
    <div className={veraltet ? "wand wand-veraltet" : "wand"}>
      <main className="wand-flaeche">
        <Sonne baum={daten.baum} neu={hervor} titel={`Zustand von ${daten.baum.name}`} mitte="marke" />
      </main>
      <aside className="wand-seite" aria-label="Übersicht">
        {vorschau !== undefined && <p className="wand-vorschau">Vorschau in deiner Sitzung – so sieht es der Bildschirm</p>}
        {vorschau === undefined && daten.ton && daten.ton.ton !== "aus" && !tonAn && (
          <button type="button" className="wand-ton" onClick={() => void tonFreigeben().then(setTonAn)}>
            Ton einschalten
          </button>
        )}
        <header className="wand-kopf">
          <div>
            <p className="wand-name">{daten.anzeige}</p>
            <p className="wand-datum">{datum(jetzt)}</p>
          </div>
          <div className="wand-uhr-block">
            <Uhr />
            <p className="wand-stand">Stand {uhrzeit(geholt)}</p>
          </div>
        </header>
        {stoerung !== null && (
          <p className="wand-stoerung" role="alert">
            Keine Verbindung zur Zentrale seit {uhrzeit(stoerung)}
            {veraltet ? " – die Anzeige ist veraltet" : ""}
          </p>
        )}
        <Zaehler baum={daten.baum} />
        <Probleme baum={daten.baum} neu={neueGeraete(daten.baum, hervor)} />
        <KennfarbenLegende liste={daten.kennfarben ?? []} />
      </aside>
    </div>
  );
}
