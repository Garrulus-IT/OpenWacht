// SPDX-License-Identifier: AGPL-3.0-only

// Startseite: Übersicht und Dashboard in einem (Etappe 17, frei anpassbar seit
// 1.0.7).
//
// Raster: 12 Spalten, jedes Widget mit freier Breite (2–12 Spalten) und Höhe
// (1–6 Reihen). Das Raster richtet sich nach seiner eigenen Breite, nicht nach
// dem Fenster (die Seitenleiste zählt also nicht mit): ab 780 px 12 Spalten,
// ab 520 px 6 (Widgets halb oder ganz breit), darunter eine Spalte. Mit „An
// Fenster anpassen“ teilen sich die Reihen die Höhe des Fensters, sodass das
// Dashboard ohne Rollen auf den Bildschirm passt (je Browser gemerkt, weil ein
// Leitstand-Bildschirm etwas anderes braucht als ein Notebook).
//
// „Anpassen“ erlaubt: Ziehen am ⠿ und ▲▼ (Reihenfolge), Ziehen an der Ecke
// (Größe), ⚙ (Titel, Größe, Seite, Mandant, Inhalt), ⧉ (verdoppeln), ✕, dazu
// Seiten anlegen, umbenennen und löschen. Das Layout liegt je Benutzer in der
// Datenbank und folgt ihm auf jedes Gerät.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { api, type Geraet, type Mandant, type Sensor } from "./api";
import { baumReihe, bereichFuer, mandantName, type Bereich } from "./bereich";
import type { Ort } from "./navigation";
import { useQuelle } from "./quelle";
import { graphTitel, Q, WidgetInhalt } from "./Widgets";
import {
  ausRoh,
  fuerSpeichern,
  klemmen,
  maxHoehe,
  maxSeiten,
  maxWidgets,
  minBreite,
  neueId,
  seiteLoeschen,
  spaltenFuer,
  spanne,
  SPALTEN,
  standardLayout,
  widgetArten,
  type Widget,
  type WidgetRoh,
  type WidgetTyp,
} from "./widgets";
import type { Zeitraum } from "./Verlauf";

interface Props {
  bereich: Bereich;
  mandanten: Mandant[];
  kopfZiel: HTMLElement | null;
  melden: (e: unknown) => void;
  gehe: (o: Partial<Ort>) => void;
}

type Speicherstand = "" | "speichert" | "gespeichert" | "fehler";

interface Stand {
  widgets: Widget[];
  seiten: string[];
}

const FENSTER = "openwacht.dashboard.fenster";
const SEITE = "openwacht.dashboard.seite";

function merken(schluessel: string, wert: string) {
  try {
    window.localStorage.setItem(schluessel, wert);
  } catch {
    // Privater Modus oder gesperrter Speicher: Die Wahl gilt dann nur bis zum Neuladen.
  }
}

function gemerkt(schluessel: string) {
  try {
    return window.localStorage.getItem(schluessel);
  } catch {
    return null;
  }
}

function verschieben<T>(liste: T[], von: number, nach: number): T[] {
  if (von === nach || von < 0 || nach < 0 || von >= liste.length || nach >= liste.length) return liste;
  const neu = liste.slice();
  const [x] = neu.splice(von, 1);
  neu.splice(nach, 0, x!);
  return neu;
}

export function Startseite({ bereich, mandanten, kopfZiel, melden, gehe }: Props) {
  const [stand0, setStand0] = useState<Stand | null>(null);
  const [bearb, setBearb] = useState(false);
  const [stand, setStand] = useState<Speicherstand>("");
  const [zieht, setZieht] = useState<string | null>(null);
  const [ziel, setZiel] = useState<string | null>(null);
  const [katalog, setKatalog] = useState(false);
  const [einstellen, setEinstellen] = useState<Widget | null>(null);
  const [ansage, setAnsage] = useState("");
  const [seite, setSeite] = useState(() => Number(gemerkt(SEITE)) || 0);
  const [fenster, setFenster] = useState(() => gemerkt(FENSTER) === "1");
  const [spalten, setSpalten] = useState<12 | 6 | 1>(12);
  const [reihe, setReihe] = useState<number | null>(null);
  // Größe ziehen: Vorschau, gespeichert wird beim Loslassen
  const [mass, setMass] = useState<{ id: string; breite: number; hoehe: number } | null>(null);
  const raster = useRef<HTMLDivElement>(null);
  // Speichern nacheinander: Läuft eine Anfrage, wird nur der neueste Stand nachgeschickt.
  const warteschlange = useRef<{ laeuft: boolean; naechster: Stand | null }>({ laeuft: false, naechster: null });
  const geraete = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);

  useEffect(() => {
    let weg = false;
    api<{ widgets: WidgetRoh[] | null; seiten?: string[] }>("GET", "/api/v1/dashboard/layout")
      .then((r) => {
        if (weg) return;
        const seiten = r.seiten ?? [];
        setStand0({ widgets: r.widgets ? r.widgets.map((w) => ausRoh(w, seiten.length)) : standardLayout(), seiten });
      })
      .catch((e: unknown) => {
        if (weg) return;
        // Ohne gespeichertes Layout trotzdem etwas zeigen.
        setStand0({ widgets: standardLayout(), seiten: [] });
        melden(e);
      });
    return () => {
      weg = true;
    };
  }, [melden]);

  const senden = useCallback(
    async (s: Stand) => {
      const q = warteschlange.current;
      if (q.laeuft) {
        q.naechster = s;
        return;
      }
      q.laeuft = true;
      setStand("speichert");
      let aktuell: Stand | null = s;
      while (aktuell) {
        try {
          await api("PUT", "/api/v1/dashboard/layout", { widgets: fuerSpeichern(aktuell.widgets), seiten: aktuell.seiten });
          setStand("gespeichert");
        } catch (e) {
          setStand("fehler");
          melden(e);
        }
        aktuell = q.naechster;
        q.naechster = null;
      }
      q.laeuft = false;
    },
    [melden],
  );

  const seitenZahl = Math.max(1, stand0?.seiten.length ?? 1);
  const aktiv = seite < seitenZahl ? seite : 0;
  const layout = useMemo(() => stand0?.widgets ?? [], [stand0]);
  const sichtbar = useMemo(() => layout.filter((w) => (w.seite ?? 0) === aktiv), [layout, aktiv]);

  // Das Raster richtet sich nach seiner eigenen Breite.
  useLayoutEffect(() => {
    const el = raster.current;
    if (!el) return;
    const messen = () => setSpalten(spaltenFuer(el.clientWidth));
    messen();
    const ro = new ResizeObserver(messen);
    ro.observe(el);
    return () => ro.disconnect();
  }, [stand0 === null]);

  // „An Fenster anpassen“: Die Reihen teilen sich die Höhe bis zum unteren Rand.
  useLayoutEffect(() => {
    const el = raster.current;
    if (!el || !fenster || bearb || spalten === 1) {
      setReihe(null);
      return;
    }
    const rechnen = () => {
      const stil = window.getComputedStyle(el);
      const reihen = stil.gridTemplateRows.split(" ").filter(Boolean).length || 1;
      const luecke = parseFloat(stil.rowGap) || 0;
      const frei = window.innerHeight - el.getBoundingClientRect().top - 16;
      const h = Math.floor((frei - (reihen - 1) * luecke) / reihen);
      // Unter 7rem wird ein Widget unlesbar: dann lieber rollen.
      const min = 7 * parseFloat(window.getComputedStyle(document.documentElement).fontSize);
      setReihe(Math.max(min, h));
    };
    rechnen();
    window.addEventListener("resize", rechnen);
    return () => window.removeEventListener("resize", rechnen);
  }, [fenster, bearb, spalten, sichtbar]);

  const aendern = (widgets: Widget[], text = "", seiten = stand0?.seiten ?? []) => {
    const neu = { widgets, seiten };
    setStand0(neu);
    setAnsage(text);
    void senden(neu);
  };

  const zuruecksetzen = async () => {
    if (!window.confirm("Standard wiederherstellen? Alle Seiten und Widgets deines Dashboards gehen verloren.")) return;
    try {
      await api("DELETE", "/api/v1/dashboard/layout");
      setStand0({ widgets: standardLayout(), seiten: [] });
      setSeite(0);
      setStand("gespeichert");
      setAnsage("Standard wiederhergestellt.");
    } catch (e) {
      melden(e);
    }
  };

  const zuSeite = (n: number) => {
    setSeite(n);
    merken(SEITE, String(n));
  };

  const nachId = useMemo(() => new Map(mandanten.map((m) => [m.id, m])), [mandanten]);
  const bereichVon = (w: Widget) =>
    w.mandant_id && nachId.has(w.mandant_id) ? (bereichFuer(mandanten, w.mandant_id, true) ?? bereich) : bereich;
  const titel = (w: Widget) =>
    w.titel?.trim() || (w.typ === "graph" ? graphTitel(w, geraete.daten?.geraete ?? null) : widgetArten[w.typ].titel);

  const knopf =
    kopfZiel &&
    stand0 &&
    createPortal(
      bearb ? null : (
        <>
          <button
            className="knopf"
            aria-pressed={fenster}
            title="Die Reihen teilen sich die Höhe des Fensters, das Dashboard passt ohne Rollen auf den Bildschirm (für diesen Browser gemerkt)"
            onClick={() => {
              setFenster(!fenster);
              merken(FENSTER, fenster ? "0" : "1");
            }}
          >
            ⤢ An Fenster anpassen
          </button>
          <button className="knopf" onClick={() => setBearb(true)}>
            ✎ Anpassen
          </button>
        </>
      ),
      kopfZiel,
    );

  if (!stand0) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }

  const seiten = stand0.seiten;
  const seitenNamen = seiten.length > 0 ? seiten : ["Übersicht"];

  const seiteNeu = () => {
    const name = window.prompt("Name der neuen Seite (höchstens 40 Zeichen)", `Seite ${seitenNamen.length + 1}`)?.trim();
    if (!name) return;
    const neu = [...seitenNamen, name.slice(0, 40)];
    aendern(layout, `Seite ${name} angelegt`, neu);
    zuSeite(neu.length - 1);
  };
  const seiteUmbenennen = () => {
    const name = window.prompt("Name der Seite (höchstens 40 Zeichen)", seitenNamen[aktiv])?.trim();
    if (!name) return;
    aendern(
      layout,
      `Seite heißt jetzt ${name}`,
      seitenNamen.map((s, i) => (i === aktiv ? name.slice(0, 40) : s)),
    );
  };
  const seiteWeg = () => {
    const n = sichtbar.length;
    if (!window.confirm(`Seite „${seitenNamen[aktiv]}“ löschen?${n ? ` ${n === 1 ? "Ihr Widget geht" : `Ihre ${n} Widgets gehen`} verloren.` : ""}`)) return;
    const neu = seitenNamen.filter((_, i) => i !== aktiv);
    aendern(seiteLoeschen(layout, aktiv), "Seite gelöscht", neu.length === 1 && neu[0] === "Übersicht" ? [] : neu);
    zuSeite(0);
  };

  // Größe ziehen: aus der Zeigerposition Spalten und Reihen errechnen.
  const groesseZiehen = (w: Widget, e: React.PointerEvent<HTMLButtonElement>) => {
    const el = raster.current;
    const karte = e.currentTarget.closest("section");
    if (!el || !karte) return;
    e.preventDefault();
    const stil = window.getComputedStyle(el);
    const luecke = parseFloat(stil.columnGap) || 0;
    const spalte = (el.clientWidth - (SPALTEN - 1) * luecke) / SPALTEN;
    const zeile = parseFloat(stil.gridAutoRows) || 216;
    const links = karte.getBoundingClientRect().left;
    const oben = karte.getBoundingClientRect().top;
    const griff = e.currentTarget;
    griff.setPointerCapture(e.pointerId);
    let letzte = { breite: w.breite, hoehe: w.hoehe };
    const bewegen = (ev: PointerEvent) => {
      letzte = {
        breite: klemmen((ev.clientX - links + luecke) / (spalte + luecke), minBreite, SPALTEN),
        hoehe: klemmen((ev.clientY - oben + luecke) / (zeile + luecke), 1, maxHoehe),
      };
      setMass({ id: w.id, ...letzte });
    };
    const ende = () => {
      griff.removeEventListener("pointermove", bewegen);
      griff.removeEventListener("pointerup", ende);
      griff.removeEventListener("pointercancel", ende);
      setMass(null);
      if (letzte.breite !== w.breite || letzte.hoehe !== w.hoehe) {
        aendern(
          layout.map((x) => (x.id === w.id ? { ...x, ...letzte } : x)),
          `${titel(w)}: ${letzte.breite} Spalten, ${letzte.hoehe} ${letzte.hoehe === 1 ? "Reihe" : "Reihen"}`,
        );
      }
    };
    griff.addEventListener("pointermove", bewegen);
    griff.addEventListener("pointerup", ende);
    griff.addEventListener("pointercancel", ende);
  };

  const index = (id: string) => layout.findIndex((x) => x.id === id);
  // Nachbar auf derselben Seite (davor −1, dahinter +1), als Index im ganzen Layout
  const nachbar = (id: string, richtung: -1 | 1) => {
    const i = sichtbar.findIndex((x) => x.id === id) + richtung;
    return i >= 0 && i < sichtbar.length ? index(sichtbar[i]!.id) : -1;
  };

  return (
    <section className="ansicht startseite" aria-labelledby="startseite-titel">
      {knopf}
      <h1 id="startseite-titel" className="sr-only">
        Dashboard {bereich.mandant.name}
      </h1>
      <p className="sr-only" aria-live="polite">
        {ansage}
      </p>
      {bearb && (
        <div className="anpassen-leiste">
          <b>Dashboard anpassen</b>
          <span className="klein">
            ⠿ ziehen oder ▲▼: Reihenfolge · Ecke ◢ ziehen: Größe · ⚙: Titel, Größe, Seite, Inhalt · gespeichert für dein Konto
            {stand === "speichert"
              ? " · speichert …"
              : stand === "gespeichert"
                ? " · gespeichert"
                : stand === "fehler"
                  ? " · nicht gespeichert"
                  : ""}
          </span>
          <span className="anpassen-knoepfe">
            <button className="knopf" onClick={() => void zuruecksetzen()}>
              Standard wiederherstellen
            </button>
            <button className="knopf knopf-haupt" onClick={() => setBearb(false)}>
              Fertig
            </button>
          </span>
        </div>
      )}
      {(seitenNamen.length > 1 || bearb) && (
        <div className="dash-seiten" role="tablist" aria-label="Seiten des Dashboards">
          {seitenNamen.map((name, i) => (
            <button key={i} role="tab" className="dash-seite" aria-selected={i === aktiv} onClick={() => zuSeite(i)}>
              {name}
            </button>
          ))}
          {bearb && (
            <span className="dash-seiten-werkzeug">
              <button className="knopf-text" onClick={seiteUmbenennen}>
                Umbenennen
              </button>
              {seitenNamen.length > 1 && (
                <button className="knopf-text" onClick={seiteWeg}>
                  Seite löschen
                </button>
              )}
              {seitenNamen.length < maxSeiten && (
                <button className="knopf-text" onClick={seiteNeu}>
                  + Seite
                </button>
              )}
            </span>
          )}
        </div>
      )}
      {sichtbar.length === 0 && !bearb && (
        <p className="leer">Diese Seite ist leer. Über „✎ Anpassen“ fügst du Widgets hinzu oder stellst den Standard wieder her.</p>
      )}
      <div
        ref={raster}
        className={`raster raster-${spalten}${bearb ? " raster-bearbeiten" : ""}${reihe ? " raster-fenster" : ""}`}
        style={reihe ? { gridAutoRows: `${reihe}px` } : undefined}
      >
        {sichtbar.map((w) => {
          const wb = bereichVon(w);
          const t = titel(w);
          const i = index(w.id);
          const m = mass?.id === w.id ? { ...w, ...mass } : w;
          const vor = nachbar(w.id, -1);
          const hinter = nachbar(w.id, 1);
          return (
            <section
              key={w.id}
              className={`panel widget widget-${w.typ}${spanne(m, spalten) >= (spalten === 12 ? 7 : 6) ? " widget-breit" : ""}${ziel === w.id && zieht && zieht !== w.id ? " widget-ziel" : ""}${zieht === w.id ? " widget-zieht" : ""}${mass?.id === w.id ? " widget-misst" : ""}`}
              style={spalten === 1 ? undefined : { gridColumn: `span ${spanne(m, spalten)}`, gridRow: `span ${m.hoehe}` }}
              data-hoehe={m.hoehe}
              aria-label={t}
              onDragOver={(e) => {
                if (!bearb || !zieht) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = "move";
                if (ziel !== w.id) setZiel(w.id);
              }}
              onDragLeave={() => setZiel((z) => (z === w.id ? null : z))}
              onDrop={(e) => {
                e.preventDefault();
                // Erst die Quelle bestimmen, dann den Zug zurücksetzen.
                const von = layout.findIndex((x) => x.id === zieht);
                setZieht(null);
                setZiel(null);
                if (von >= 0 && von !== i) aendern(verschieben(layout, von, i), `${t}: neue Position`);
              }}
            >
              <div className="panel-kopf">
                <h2 className="panel-titel">{t}</h2>
                {w.mandant_id && nachId.has(w.mandant_id) && <span className="mandant-marke">{mandantName(wb, w.mandant_id)}</span>}
                {bearb && (
                  <span className="werkzeug">
                    <button
                      className="werkzeug-knopf griff"
                      draggable
                      aria-hidden="true"
                      tabIndex={-1}
                      title="Ziehen"
                      onDragStart={(e) => {
                        e.dataTransfer.effectAllowed = "move";
                        e.dataTransfer.setData("text/plain", w.id);
                        const el = e.currentTarget.closest("section");
                        if (el) e.dataTransfer.setDragImage(el, 20, 20);
                        setZieht(w.id);
                      }}
                      onDragEnd={() => {
                        setZieht(null);
                        setZiel(null);
                      }}
                    >
                      ⠿
                    </button>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`${t} nach vorn`}
                      title="nach vorn"
                      disabled={vor < 0}
                      onClick={() => aendern(verschieben(layout, i, vor), `${t} nach vorn`)}
                    >
                      ▲
                    </button>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`${t} nach hinten`}
                      title="nach hinten"
                      disabled={hinter < 0}
                      onClick={() => aendern(verschieben(layout, i, hinter), `${t} nach hinten`)}
                    >
                      ▼
                    </button>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`Einstellungen von ${t}`}
                      title="Einstellungen: Titel, Größe, Seite, Inhalt"
                      onClick={() => setEinstellen(w)}
                    >
                      ⚙
                    </button>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`${t} verdoppeln`}
                      title="Verdoppeln"
                      disabled={layout.length >= maxWidgets}
                      onClick={() =>
                        aendern([...layout.slice(0, i + 1), { ...w, id: neueId(layout) }, ...layout.slice(i + 1)], `${t} verdoppelt`)
                      }
                    >
                      ⧉
                    </button>
                    <button
                      className="werkzeug-knopf werkzeug-weg"
                      aria-label={`${t} entfernen`}
                      title="Entfernen"
                      onClick={() =>
                        aendern(
                          layout.filter((x) => x.id !== w.id),
                          `${t} entfernt`,
                        )
                      }
                    >
                      ✕
                    </button>
                  </span>
                )}
              </div>
              <div className="panel-inhalt">
                <WidgetInhalt w={w} bereich={wb} mandanten={mandanten} gehe={gehe} />
              </div>
              {bearb && spalten === 12 && (
                <button
                  className="widget-ecke"
                  aria-hidden="true"
                  tabIndex={-1}
                  title={`Größe ziehen (jetzt ${m.breite} × ${m.hoehe}); mit der Tastatur über ⚙`}
                  onPointerDown={(e) => groesseZiehen(w, e)}
                >
                  {mass?.id === w.id ? `${m.breite} × ${m.hoehe}` : "◢"}
                </button>
              )}
            </section>
          );
        })}
        {bearb && layout.length < maxWidgets && (
          <button className="widget-neu" onClick={() => setKatalog(true)}>
            + Widget hinzufügen
          </button>
        )}
      </div>

      {katalog && (
        <Dialog titel="Widget hinzufügen" onZu={() => setKatalog(false)}>
          <div className="katalog">
            {(Object.keys(widgetArten) as WidgetTyp[]).map((typ) => {
              const a = widgetArten[typ];
              const schon = layout.filter((w) => w.typ === typ).length;
              return (
                <button
                  key={typ}
                  className="katalog-karte"
                  onClick={() => {
                    setKatalog(false);
                    const neu: Widget = { id: neueId(layout), typ, breite: a.breite, hoehe: a.hoehe, seite: aktiv };
                    aendern([...layout, neu], `${a.titel} hinzugefügt`);
                    // Notiz und einzelner Sensor brauchen sofort ihren Inhalt.
                    if (typ === "notiz" || typ === "sensor") setEinstellen(neu);
                  }}
                >
                  <b>{a.titel}</b>
                  <span className="klein">
                    {a.text}
                    {schon ? ` · schon ${schon}×` : ""}
                  </span>
                </button>
              );
            })}
          </div>
        </Dialog>
      )}

      {einstellen && (
        <Einstellungen
          w={einstellen}
          mandanten={mandanten}
          geraete={geraete.daten?.geraete ?? []}
          seiten={seitenNamen}
          onZu={() => setEinstellen(null)}
          onSpeichern={(neu) => {
            setEinstellen(null);
            aendern(
              layout.map((x) => (x.id === neu.id ? neu : x)),
              "Einstellungen übernommen",
            );
          }}
        />
      )}
    </section>
  );
}

// Modaler Dialog mit dem eingebauten <dialog> (Fokus bleibt im Dialog, Escape schließt).
export function Dialog(props: { titel: string; onZu: () => void; children: React.ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
  }, []);
  return (
    <dialog ref={ref} className="dialog" aria-label={props.titel} onClose={props.onZu} onCancel={props.onZu}>
      <div className="dialog-kopf">
        <h2 className="panel-titel">{props.titel}</h2>
        <button className="knopf" onClick={() => ref.current?.close()}>
          Schließen
        </button>
      </div>
      <div className="dialog-inhalt">{props.children}</div>
    </dialog>
  );
}

const zeitraeume: { wert: Zeitraum; text: string }[] = [
  { wert: "1h", text: "1 Std." },
  { wert: "24h", text: "24 Std." },
  { wert: "7t", text: "7 Tage" },
  { wert: "30t", text: "30 Tage" },
];

function Einstellungen(props: {
  w: Widget;
  mandanten: Mandant[];
  geraete: Geraet[];
  seiten: string[];
  onZu: () => void;
  onSpeichern: (w: Widget) => void;
}) {
  const { w } = props;
  const [titel, setTitel] = useState(w.titel ?? "");
  const [breite, setBreite] = useState(w.breite);
  const [hoehe, setHoehe] = useState(w.hoehe);
  const [seite, setSeite] = useState(w.seite ?? 0);
  const [mandant, setMandant] = useState(w.mandant_id ?? "");
  const [geraet, setGeraet] = useState(w.geraet_id ?? "");
  const [zeitraum, setZeitraum] = useState<Zeitraum>(w.zeitraum ?? "24h");
  const [wert, setWert] = useState(w.wert ?? "cpu");
  const [text, setText] = useState(w.text ?? "");
  const [sensor, setSensor] = useState(w.sensor ?? "");
  const [suche, setSuche] = useState("");
  const sensoren = useQuelle<{ sensoren: Sensor[] }>(w.typ === "sensor" ? Q.sensoren : null, 60_000);
  const reihe = baumReihe(props.mandanten);
  const namen = new Map(props.mandanten.map((m) => [m.id, m.name]));
  const istGraph = w.typ === "graph";
  const ohneMandant = w.typ === "uhr" || w.typ === "notiz" || w.typ === "sensor";
  const geraete = props.geraete
    .filter((g) => namen.has(g.mandant_id) && (g.agent_id || g.snmp_id))
    .sort((a, b) => a.name.localeCompare(b.name, "de"));
  const s = suche.trim().toLowerCase();
  const wahl = (sensoren.daten?.sensoren ?? [])
    .filter((x) => x.schluessel === sensor || !s || `${x.host ?? ""} ${x.name}`.toLowerCase().includes(s))
    .sort((a, b) => `${a.host ?? ""} ${a.name}`.localeCompare(`${b.host ?? ""} ${b.name}`, "de"))
    .slice(0, 300);
  const speichern = (e: FormEvent) => {
    e.preventDefault();
    const neu: Widget = { id: w.id, typ: w.typ, breite, hoehe, seite };
    if (titel.trim()) neu.titel = titel.trim();
    if (istGraph && geraet) neu.geraet_id = geraet;
    else if (mandant && !ohneMandant) neu.mandant_id = mandant;
    if (istGraph) {
      neu.zeitraum = zeitraum;
      neu.wert = wert;
    }
    if (w.typ === "notiz") neu.text = text;
    if (w.typ === "sensor" && sensor) neu.sensor = sensor;
    props.onSpeichern(neu);
  };
  return (
    <Dialog titel={`Einstellungen: ${widgetArten[w.typ].titel}`} onZu={props.onZu}>
      <form className="formular einstellungen" onSubmit={speichern}>
        <label className="feld">
          <span>Titel</span>
          <input value={titel} maxLength={60} placeholder={widgetArten[w.typ].titel} onChange={(e) => setTitel(e.target.value)} />
        </label>
        <div className="feld-reihe">
          <label className="feld">
            <span>Breite (Spalten von 12)</span>
            <select value={breite} onChange={(e) => setBreite(Number(e.target.value))}>
              {Array.from({ length: SPALTEN - minBreite + 1 }, (_, i) => i + minBreite).map((n) => (
                <option key={n} value={n}>
                  {n}
                  {n === 12 ? " (ganze Breite)" : n === 6 ? " (halbe Breite)" : n === 4 ? " (ein Drittel)" : n === 3 ? " (ein Viertel)" : ""}
                </option>
              ))}
            </select>
          </label>
          <label className="feld">
            <span>Höhe (Reihen)</span>
            <select value={hoehe} onChange={(e) => setHoehe(Number(e.target.value))}>
              {Array.from({ length: maxHoehe }, (_, i) => i + 1).map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        </div>
        {props.seiten.length > 1 && (
          <label className="feld">
            <span>Seite</span>
            <select value={seite} onChange={(e) => setSeite(Number(e.target.value))}>
              {props.seiten.map((name, i) => (
                <option key={i} value={i}>
                  {name}
                </option>
              ))}
            </select>
          </label>
        )}
        {w.typ === "notiz" && (
          <label className="feld">
            <span>Text (höchstens 500 Zeichen)</span>
            <textarea value={text} maxLength={500} rows={5} onChange={(e) => setText(e.target.value)} />
          </label>
        )}
        {w.typ === "sensor" && (
          <>
            <label className="feld">
              <span>Sensor suchen</span>
              <input type="search" value={suche} placeholder="Gerät oder Sensor" onChange={(e) => setSuche(e.target.value)} />
            </label>
            <label className="feld">
              <span>Sensor</span>
              <select value={sensor} size={8} onChange={(e) => setSensor(e.target.value)}>
                {wahl.map((x) => (
                  <option key={x.schluessel} value={x.schluessel}>
                    {x.host ? `${x.host} · ` : ""}
                    {x.name}
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
        {istGraph && (
          <>
            <label className="feld">
              <span>Wert</span>
              <select value={wert} onChange={(e) => setWert(e.target.value as "cpu" | "speicher")}>
                <option value="cpu">CPU-Auslastung</option>
                <option value="speicher">Arbeitsspeicher belegt</option>
              </select>
            </label>
            <label className="feld">
              <span>Zeitraum</span>
              <select value={zeitraum} onChange={(e) => setZeitraum(e.target.value as Zeitraum)}>
                {zeitraeume.map((z) => (
                  <option key={z.wert} value={z.wert}>
                    {z.text}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Gerät</span>
              <select value={geraet} onChange={(e) => setGeraet(e.target.value)}>
                <option value="">die höchsten im Bereich</option>
                {geraete.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({namen.get(g.mandant_id)})
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
        {!ohneMandant && (
          <>
            <label className="feld">
              <span>Mandant</span>
              <select value={mandant} disabled={istGraph && !!geraet} onChange={(e) => setMandant(e.target.value)}>
                <option value="">wie in der Seitenleiste</option>
                {reihe.map(({ m, tiefe }) => (
                  <option key={m.id} value={m.id}>
                    {" ".repeat(tiefe) + m.name}
                  </option>
                ))}
              </select>
            </label>
            <p className="klein">
              {istGraph && geraet
                ? "Ein Graph mit Gerät zeigt immer dieses Gerät, egal welcher Mandant gewählt ist."
                : "Ein fester Mandant zeigt ihn mit allen Untermandanten, egal was in der Seitenleiste gewählt ist."}
            </p>
          </>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Übernehmen</button>
        </div>
      </form>
    </Dialog>
  );
}
