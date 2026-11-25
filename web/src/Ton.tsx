// SPDX-License-Identifier: AGPL-3.0-only

// Hinweise am Rand und Ton bei neuen Ereignissen (1.0.2).
//
// Die Klänge erzeugt der Browser mit Web Audio (keine Dateien, nichts von
// außen). Browser spielen Ton erst nach einer Bedienung der Seite ab; in der
// Oberfläche reicht ein beliebiger Klick, die Wandanzeige hat dafür einen Knopf.

import { useEffect, useRef, useState } from "react";
import { api, type Alarm, type HinweiseTon, type Klang, type TonEinstellung, type TonStufe } from "./api";
import { Dialog } from "./Startseite";
import { useQuelle } from "./quelle";
// derselbe Pfad wie Q.alarme in Widgets.tsx: teilt den Zwischenspeicher
const ALARME = "/api/v1/alarme?limit=500";

export const TON_VORGABE: HinweiseTon = { hinweise: true, ton: "aus", klang: "bling", lautstaerke: 60, entwarnung: false };

let ctx: AudioContext | null = null;
let zuletzt = 0;

function audio(): AudioContext | null {
  if (!ctx) {
    const AC = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AC) return null;
    try {
      ctx = new AC();
    } catch {
      return null;
    }
  }
  return ctx;
}

// freigeben: nach einer Bedienung aufrufen, damit der Browser Ton erlaubt.
export function tonFreigeben(): Promise<boolean> {
  const a = audio();
  if (!a) return Promise.resolve(false);
  return a
    .resume()
    .then(() => a.state === "running")
    .catch(() => false);
}

export function tonFrei(): boolean {
  return ctx?.state === "running";
}

// Ein Ton: Sinus mit weichem Anschlag und Ausklang, dazu leise Obertöne.
function glocke(a: AudioContext, ziel: AudioNode, start: number, hz: number, dauer: number, pegel: number, teil: number[]) {
  teil.forEach((faktor, i) => {
    const o = a.createOscillator();
    const g = a.createGain();
    o.type = "sine";
    o.frequency.value = hz * faktor;
    const p = pegel / (i + 1) ** 1.6;
    g.gain.setValueAtTime(0.0001, start);
    g.gain.exponentialRampToValueAtTime(p, start + 0.012);
    g.gain.exponentialRampToValueAtTime(0.0001, start + dauer / (1 + i * 0.6));
    o.connect(g).connect(ziel);
    o.start(start);
    o.stop(start + dauer + 0.05);
  });
}

// art: "krit", "warn" (eine Quarte tiefer, leiser) oder "entwarnung" (fallend, leise)
export function spielen(klang: Klang, lautstaerke: number, art: "krit" | "warn" | "entwarnung" = "krit", sofort = false) {
  const a = audio();
  if (!a || a.state !== "running" || lautstaerke <= 0) return;
  const jetzt = Date.now();
  if (!sofort && jetzt - zuletzt < 3000) return; // nicht stapeln
  zuletzt = jetzt;
  const haupt = a.createGain();
  haupt.gain.value = (Math.min(100, lautstaerke) / 100) ** 2 * (art === "krit" ? 0.5 : 0.32);
  haupt.connect(a.destination);
  const t = a.currentTime + 0.02;
  const f = art === "warn" ? 0.75 : 1;
  if (art === "entwarnung") {
    glocke(a, haupt, t, 880, 0.7, 0.6, [1, 2]);
    glocke(a, haupt, t + 0.16, 659.25, 0.9, 0.6, [1, 2]);
    return;
  }
  switch (klang) {
    case "bling":
      glocke(a, haupt, t, 1318.5 * f, 0.9, 0.8, [1, 2.01, 3]);
      glocke(a, haupt, t + 0.11, 1760 * f, 1.2, 0.8, [1, 2.01, 3]);
      break;
    case "gong":
      glocke(a, haupt, t, 196 * f, 2.6, 1, [1, 1.48, 2.02, 2.74, 3.9]);
      break;
    case "doppel":
      glocke(a, haupt, t, 988 * f, 0.35, 0.9, [1, 2]);
      glocke(a, haupt, t + 0.28, 988 * f, 0.5, 0.9, [1, 2]);
      break;
  }
}

// ernst: Spielt die Stufe für diesen Zustand einen Ton?
export function tonFuer(stufe: TonStufe, status: string): "krit" | "warn" | null {
  if (stufe === "aus") return null;
  if (status === "crit") return "krit";
  if (status === "warn" && stufe === "warn") return "warn";
  return null;
}

// --- Benachrichtigungen des Systems (1.0.3) ------------------------------------
//
// Zusätzlich zu den Hinweisen am Rand kann der Browser eine Benachrichtigung
// des Systems zeigen (unter Windows unten rechts), wenn OpenWacht im
// Hintergrund ist. Ob das gewollt ist, gilt je Browser (Erlaubnis des Browsers
// und ein Merker im localStorage, kein Geheimnis). OpenWacht muss dafür offen
// sein, als Tab oder als installierte App.

const MERKER = "openwacht.benachrichtigung";
const GEAENDERT = "openwacht-benachrichtigung";

export function systemMoeglich(): boolean {
  return typeof window !== "undefined" && "Notification" in window && window.isSecureContext;
}

export function systemAn(): boolean {
  if (!systemMoeglich() || Notification.permission !== "granted") return false;
  try {
    return localStorage.getItem(MERKER) === "an";
  } catch {
    return false;
  }
}

// systemSetzen fragt beim Einschalten nach der Erlaubnis (nur nach einem Klick
// möglich) und liefert, ob die Benachrichtigungen jetzt an sind.
export async function systemSetzen(an: boolean): Promise<boolean> {
  if (an && systemMoeglich() && Notification.permission === "default") {
    try {
      await Notification.requestPermission();
    } catch {
      /* alte Browser: Rückgabe über die Erlaubnis unten */
    }
  }
  try {
    if (an && systemMoeglich() && Notification.permission === "granted") localStorage.setItem(MERKER, "an");
    else localStorage.removeItem(MERKER);
  } catch {
    /* ohne localStorage bleibt es aus */
  }
  window.dispatchEvent(new Event(GEAENDERT));
  return systemAn();
}

function useSystemAn(): boolean {
  const [an, setAn] = useState(systemAn);
  useEffect(() => {
    const neu = () => setAn(systemAn());
    window.addEventListener(GEAENDERT, neu);
    window.addEventListener("focus", neu);
    return () => {
      window.removeEventListener(GEAENDERT, neu);
      window.removeEventListener("focus", neu);
    };
  }, []);
  return an;
}

// Als App installieren: Chrome und Edge bieten das über ein Ereignis an.
type InstallEreignis = Event & { prompt: () => Promise<void> };
let installieren: InstallEreignis | null = null;
if (typeof window !== "undefined") {
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    installieren = e as InstallEreignis;
  });
  window.addEventListener("appinstalled", () => (installieren = null));
}

// --- Hinweise am Rand ---------------------------------------------------------

const RANG: Record<string, number> = { unknown: 1, warn: 2, crit: 3 };
const TEXT: Record<string, string> = { crit: "Kritisch", warn: "Warnung", unknown: "Unbekannt" };
const MAX_HINWEISE = 4;

interface Hinweis {
  schluessel: string;
  art: "neu" | "schlimmer" | "entwarnung";
  alarm: Alarm;
  seit: number;
}

function kopf(h: Hinweis): string {
  const st = h.art === "entwarnung" ? "ok" : h.alarm.status;
  return h.art === "entwarnung" ? "Entwarnung" : h.art === "schlimmer" ? `Jetzt ${TEXT[st] ?? st}` : (TEXT[st] ?? st);
}

function kurz(h: Hinweis): string {
  return `${kopf(h)}: ${h.alarm.name}`;
}

export function RandHinweise({ e, onAlarme }: { e: HinweiseTon; onAlarme: () => void }) {
  const system = useSystemAn();
  const aktiv = e.hinweise || e.ton !== "aus" || system;
  const q = useQuelle<{ alarme: Alarm[] }>(aktiv ? ALARME : null, 15_000, system);
  const vorher = useRef<Map<string, Alarm> | null>(null);
  const [liste, setListe] = useState<Hinweis[]>([]);
  const [halt, setHalt] = useState(false);
  const einst = useRef(e);
  einst.current = e;
  const systemRef = useRef(system);
  systemRef.current = system;
  const zuAlarmen = useRef(onAlarme);
  zuAlarmen.current = onAlarme;

  // Ton nach der ersten Bedienung der Seite freigeben.
  useEffect(() => {
    if (e.ton === "aus") return;
    const frei = () => void tonFreigeben();
    window.addEventListener("pointerdown", frei, { once: true });
    window.addEventListener("keydown", frei, { once: true });
    return () => {
      window.removeEventListener("pointerdown", frei);
      window.removeEventListener("keydown", frei);
    };
  }, [e.ton]);

  useEffect(() => {
    const d = q.daten?.alarme;
    if (!d) return;
    const neu = new Map(d.map((a) => [a.id, a]));
    const alt = vorher.current;
    vorher.current = neu;
    if (!alt) return; // erster Stand: nur merken
    const t = Date.now();
    const dazu: Hinweis[] = [];
    let ton: "krit" | "warn" | "entwarnung" | null = null;
    const wichtiger = (x: typeof ton) => {
      if (x === "krit" || ton === "krit") ton = "krit";
      else if (x === "warn" || ton === "warn") ton = "warn";
      else ton = ton ?? x;
    };
    for (const a of d) {
      const v = alt.get(a.id);
      if (a.ende) {
        if (v && !v.ende) {
          dazu.push({ schluessel: a.id + ":e", art: "entwarnung", alarm: a, seit: t });
          if (einst.current.entwarnung && einst.current.ton !== "aus") wichtiger("entwarnung");
        }
        continue;
      }
      if (a.bestaetigt_am) continue;
      if (!v || (v.ende && !a.ende)) {
        dazu.push({ schluessel: a.id + ":" + a.status + ":" + t, art: "neu", alarm: a, seit: t });
        wichtiger(tonFuer(einst.current.ton, a.status));
      } else if ((RANG[a.status] ?? 0) > (RANG[v.status] ?? 0)) {
        dazu.push({ schluessel: a.id + ":" + a.status + ":" + t, art: "schlimmer", alarm: a, seit: t });
        wichtiger(tonFuer(einst.current.ton, a.status));
      }
    }
    if (ton) spielen(einst.current.klang, einst.current.lautstaerke, ton);
    // Im Hintergrund zusätzlich als Benachrichtigung des Systems.
    if (systemRef.current && dazu.length && (document.hidden || !document.hasFocus())) {
      const zeigen = (titel: string, text: string, tag: string) => {
        try {
          const n = new Notification(titel, { body: text, tag, icon: "/icon-192.png", silent: einst.current.ton !== "aus" });
          n.onclick = () => {
            window.focus();
            zuAlarmen.current();
            n.close();
          };
        } catch {
          /* z. B. wenn die Erlaubnis gerade entzogen wurde */
        }
      };
      if (dazu.length > 3) {
        zeigen(`OpenWacht: ${dazu.length} Ereignisse`, dazu.slice(0, 3).map(kurz).join("\n") + "\n…", "openwacht-sammel");
      } else {
        for (const h of dazu) zeigen(kopf(h), h.alarm.name + (h.alarm.gegenstand ? ` · ${h.alarm.gegenstand}` : ""), h.alarm.id);
      }
    }
    if (einst.current.hinweise && dazu.length) setListe((l) => [...dazu, ...l].slice(0, 20));
  }, [q.daten]);

  // Ausblenden nach einer Weile (kritisch länger); nicht, solange die Maus darauf liegt.
  useEffect(() => {
    if (halt || liste.length === 0) return;
    const id = window.setInterval(() => {
      const t = Date.now();
      setListe((l) => l.filter((h) => t - h.seit < (h.alarm.status === "crit" && h.art !== "entwarnung" ? 20_000 : 9_000)));
    }, 1000);
    return () => window.clearInterval(id);
  }, [halt, liste.length]);

  if (!e.hinweise) return null;
  const zeigen = liste.slice(0, MAX_HINWEISE);
  return (
    <div className="rand-hinweise" role="status" aria-live="polite" onMouseEnter={() => setHalt(true)} onMouseLeave={() => setHalt(false)}>
      {zeigen.map((h) => {
        const st = h.art === "entwarnung" ? "ok" : h.alarm.status;
        return (
          <div key={h.schluessel} className={`rand-hinweis rand-hinweis-${st}`}>
            <span className={`signal signal-${st}`} aria-hidden="true" />
            <button type="button" className="rand-hinweis-text" onClick={onAlarme} title="Zu den Alarmen">
              <span className="rand-hinweis-kopf">
                {kopf(h)}
              </span>
              <span className="rand-hinweis-name">{h.alarm.name}</span>
              {h.alarm.gegenstand && <span className="rand-hinweis-gegenstand">{h.alarm.gegenstand}</span>}
            </button>
            <button
              type="button"
              className="rand-hinweis-zu"
              aria-label="Hinweis schließen"
              onClick={() => setListe((l) => l.filter((x) => x.schluessel !== h.schluessel))}
            >
              ×
            </button>
          </div>
        );
      })}
      {liste.length > MAX_HINWEISE && (
        <button type="button" className="rand-hinweis-mehr" onClick={() => setListe([])}>
          + {liste.length - MAX_HINWEISE} weitere · alle schließen
        </button>
      )}
    </div>
  );
}

// --- Einstellungen ---------------------------------------------------------------

export function TonFelder<T extends TonEinstellung>({ wert, setWert, name }: { wert: T; setWert: (w: T) => void; name: string }) {
  return (
    <>
      <fieldset className="feld-gruppe">
        <legend>Ton bei neuen Alarmen</legend>
        {(
          [
            ["aus", "Aus"],
            ["krit", "Nur bei Kritisch"],
            ["warn", "Bei Warnung und Kritisch"],
          ] as const
        ).map(([v, t]) => (
          <label key={v} className="haken">
            <input type="radio" name={name + "-ton"} checked={wert.ton === v} onChange={() => setWert({ ...wert, ton: v })} />
            <span>{t}</span>
          </label>
        ))}
      </fieldset>
      <label className="feld">
        <span>Klang</span>
        <select value={wert.klang} onChange={(e) => setWert({ ...wert, klang: e.target.value as Klang })} disabled={wert.ton === "aus"}>
          <option value="bling">Bling (zwei helle Töne)</option>
          <option value="gong">Gong (tief, lang)</option>
          <option value="doppel">Doppelton (kurz)</option>
        </select>
      </label>
      <label className="feld">
        <span>Lautstärke: {wert.lautstaerke} %</span>
        <input
          type="range"
          min={0}
          max={100}
          step={5}
          value={wert.lautstaerke}
          disabled={wert.ton === "aus"}
          onChange={(e) => setWert({ ...wert, lautstaerke: Number(e.target.value) })}
        />
      </label>
      <label className="haken">
        <input type="checkbox" checked={wert.entwarnung} disabled={wert.ton === "aus"} onChange={(e) => setWert({ ...wert, entwarnung: e.target.checked })} />
        <span>Leiser Ton bei Entwarnung</span>
      </label>
      <div className="aktionen">
        <button
          type="button"
          className="knopf"
          disabled={wert.ton === "aus" || wert.lautstaerke === 0}
          onClick={async () => {
            await tonFreigeben();
            spielen(wert.klang, wert.lautstaerke, "krit", true);
          }}
        >
          Probehören
        </button>
      </div>
    </>
  );
}

// Windows-Benachrichtigung und „Als App installieren“: gelten für diesen Browser.
function SystemFelder() {
  const an = useSystemAn();
  const [stand, setStand] = useState("");
  const [kannInstallieren, setKannInstallieren] = useState(installieren !== null);
  const moeglich = systemMoeglich();
  const gesperrt = moeglich && Notification.permission === "denied";
  return (
    <fieldset className="feld-gruppe">
      <legend>Benachrichtigung des Systems (nur dieser Browser)</legend>
      <label className="haken">
        <input
          type="checkbox"
          checked={an}
          disabled={!moeglich || gesperrt}
          onChange={async (ev) => {
            const ok = await systemSetzen(ev.target.checked);
            setStand(ev.target.checked && !ok ? "Der Browser hat keine Erlaubnis gegeben." : "");
          }}
        />
        <span>Auch als Windows-Benachrichtigung, wenn OpenWacht im Hintergrund ist</span>
      </label>
      <p className="klein">
        {!moeglich
          ? "Dieser Browser kann hier keine Benachrichtigungen zeigen (sie brauchen HTTPS)."
          : gesperrt
            ? "Benachrichtigungen sind für diese Seite gesperrt. Erlauben lässt sich das über das Schloss links in der Adressleiste → Berechtigungen."
            : "OpenWacht muss dafür offen sein, als Tab oder als App (minimiert reicht). Ein Klick auf die Benachrichtigung öffnet die Alarme."}
        {stand && ` ${stand}`}
      </p>
      {kannInstallieren && (
        <div className="aktionen">
          <button
            type="button"
            className="knopf"
            onClick={async () => {
              const e = installieren;
              if (!e) return;
              installieren = null;
              setKannInstallieren(false);
              await e.prompt().catch(() => undefined);
            }}
          >
            Als App installieren
          </button>
        </div>
      )}
    </fieldset>
  );
}

export function TonDialog({ wert, onGespeichert, onZu }: { wert: HinweiseTon; onGespeichert: (w: HinweiseTon) => void; onZu: () => void }) {
  const [w, setW] = useState<HinweiseTon>(wert);
  const [fehler, setFehler] = useState("");
  return (
    <Dialog titel="Hinweise und Ton" onZu={onZu}>
      <form
        className="formular formular-flach ton-formular"
        onSubmit={async (ev) => {
          ev.preventDefault();
          setFehler("");
          try {
            const r = await api<HinweiseTon>("PUT", "/api/v1/ich/hinweise-ton", w);
            onGespeichert(r);
            onZu();
          } catch (err) {
            setFehler(err instanceof Error ? err.message : String(err));
          }
        }}
      >
        <p className="klein">Gilt nur für dich, in jedem Browser, in dem du angemeldet bist. Die Seite muss dafür offen sein.</p>
        <label className="haken">
          <input type="checkbox" checked={w.hinweise} onChange={(e) => setW({ ...w, hinweise: e.target.checked })} />
          <span>Hinweise am Rand bei neuen Alarmen, Verschlechterungen und Entwarnungen</span>
        </label>
        <TonFelder wert={w} setWert={setW} name="ich" />
        <SystemFelder />
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" type="submit">
            Speichern
          </button>
          <button className="knopf" type="button" onClick={onZu}>
            Abbrechen
          </button>
        </div>
      </form>
    </Dialog>
  );
}
