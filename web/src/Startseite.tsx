// SPDX-License-Identifier: AGPL-3.0-only

// Startseite: Übersicht und Dashboard in einem (Etappe 17). Widgets im
// 12-Spalten-Raster in drei Größen (klein 4 Spalten, breit 8, hoch 4 Spalten
// und zwei Reihen). „Anpassen“ erlaubt Ziehen (HTML5) und ▲▼, Größe, ⚙
// Einstellungen, ✕ Entfernen, „+ Widget“ und „Standard wiederherstellen“; am
// Handy gibt es nur ▲▼ (eine Spalte). Das Layout liegt je Benutzer in der
// Datenbank und folgt ihm auf jedes Gerät.

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { api, type Geraet, type Mandant } from "./api";
import { baumReihe, bereichFuer, mandantName, type Bereich } from "./bereich";
import type { Ort } from "./navigation";
import { useQuelle } from "./quelle";
import { graphTitel, Q, WidgetInhalt } from "./Widgets";
import {
  fuerSpeichern,
  groessen,
  maxWidgets,
  neueId,
  standardLayout,
  verfuegbar,
  widgetArten,
  type Widget,
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

function verschieben<T>(liste: T[], von: number, nach: number): T[] {
  if (von === nach || von < 0 || nach < 0 || von >= liste.length || nach >= liste.length) return liste;
  const neu = liste.slice();
  const [x] = neu.splice(von, 1);
  neu.splice(nach, 0, x!);
  return neu;
}

export function Startseite({ bereich, mandanten, kopfZiel, melden, gehe }: Props) {
  const [layout, setLayout] = useState<Widget[] | null>(null);
  const [bearb, setBearb] = useState(false);
  const [stand, setStand] = useState<Speicherstand>("");
  const [zieht, setZieht] = useState<string | null>(null);
  const [ziel, setZiel] = useState<string | null>(null);
  const [katalog, setKatalog] = useState(false);
  const [einstellen, setEinstellen] = useState<Widget | null>(null);
  const [ansage, setAnsage] = useState("");
  // Speichern nacheinander: Läuft eine Anfrage, wird nur der neueste Stand nachgeschickt.
  const warteschlange = useRef<{ laeuft: boolean; naechster: Widget[] | null }>({ laeuft: false, naechster: null });
  const geraete = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);

  useEffect(() => {
    let weg = false;
    api<{ widgets: Widget[] | null }>("GET", "/api/v1/dashboard/layout")
      .then((r) => {
        if (!weg) setLayout(r.widgets ?? standardLayout());
      })
      .catch((e: unknown) => {
        if (weg) return;
        // Ohne gespeichertes Layout trotzdem etwas zeigen.
        setLayout(standardLayout());
        melden(e);
      });
    return () => {
      weg = true;
    };
  }, [melden]);

  const senden = useCallback(
    async (l: Widget[]) => {
      const q = warteschlange.current;
      if (q.laeuft) {
        q.naechster = l;
        return;
      }
      q.laeuft = true;
      setStand("speichert");
      let aktuell: Widget[] | null = l;
      while (aktuell) {
        try {
          await api("PUT", "/api/v1/dashboard/layout", { widgets: fuerSpeichern(aktuell) });
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

  const aendern = (neu: Widget[], text = "") => {
    setLayout(neu);
    setAnsage(text);
    void senden(neu);
  };

  const zuruecksetzen = async () => {
    try {
      await api("DELETE", "/api/v1/dashboard/layout");
      setLayout(standardLayout());
      setStand("gespeichert");
      setAnsage("Standard wiederhergestellt.");
    } catch (e) {
      melden(e);
    }
  };

  const nachId = useMemo(() => new Map(mandanten.map((m) => [m.id, m])), [mandanten]);
  const bereichVon = (w: Widget) =>
    w.mandant_id && nachId.has(w.mandant_id) ? (bereichFuer(mandanten, w.mandant_id, true) ?? bereich) : bereich;
  const titel = (w: Widget) => (w.typ === "graph" ? graphTitel(w, geraete.daten?.geraete ?? null) : widgetArten[w.typ].titel);

  const knopf =
    kopfZiel &&
    layout &&
    createPortal(
      bearb ? null : (
        <button className="knopf" onClick={() => setBearb(true)}>
          ✎ Anpassen
        </button>
      ),
      kopfZiel,
    );

  if (!layout) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }

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
            Ziehen am ⠿ oder ▲▼ zum Verschieben · K/B/H = klein, breit, hoch · gespeichert für dein Konto
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
      {layout.length === 0 && !bearb && (
        <p className="leer">Dein Dashboard ist leer. Über „✎ Anpassen“ fügst du Widgets hinzu oder stellst den Standard wieder her.</p>
      )}
      <div className={`raster${bearb ? " raster-bearbeiten" : ""}`}>
        {layout.map((w, i) => {
          const wb = bereichVon(w);
          const t = titel(w);
          return (
            <section
              key={w.id}
              className={`panel widget widget-${w.groesse}${ziel === w.id && zieht && zieht !== w.id ? " widget-ziel" : ""}${zieht === w.id ? " widget-zieht" : ""}`}
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
                if (von >= 0 && von !== i) aendern(verschieben(layout, von, i), `${t}: neue Position ${i + 1}`);
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
                      disabled={i === 0}
                      onClick={() => aendern(verschieben(layout, i, i - 1), `${t}: Position ${i}`)}
                    >
                      ▲
                    </button>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`${t} nach hinten`}
                      title="nach hinten"
                      disabled={i === layout.length - 1}
                      onClick={() => aendern(verschieben(layout, i, i + 1), `${t}: Position ${i + 2}`)}
                    >
                      ▼
                    </button>
                    <span className="werkzeug-gruppe" role="group" aria-label={`Größe von ${t}`}>
                      {groessen.map((g) => (
                        <button
                          key={g.id}
                          className="werkzeug-knopf werkzeug-groesse"
                          aria-pressed={w.groesse === g.id}
                          aria-label={g.text}
                          title={g.text}
                          onClick={() =>
                            aendern(
                              layout.map((x) => (x.id === w.id ? { ...x, groesse: g.id } : x)),
                              `${t}: ${g.text}`,
                            )
                          }
                        >
                          {g.kurz}
                        </button>
                      ))}
                    </span>
                    <button
                      className="werkzeug-knopf"
                      aria-label={`Einstellungen von ${t}`}
                      title="Einstellungen"
                      onClick={() => setEinstellen(w)}
                    >
                      ⚙
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
              const frei = verfuegbar(layout, typ);
              const a = widgetArten[typ];
              return (
                <button
                  key={typ}
                  className="katalog-karte"
                  disabled={!frei}
                  onClick={() => {
                    setKatalog(false);
                    aendern([...layout, { id: neueId(layout), typ, groesse: a.groesse }], `${a.titel} hinzugefügt`);
                  }}
                >
                  <b>{a.titel}</b>
                  <span className="klein">{frei ? `${a.text} · Startgröße ${a.groesse}` : "schon auf dem Dashboard"}</span>
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

function Einstellungen(props: { w: Widget; mandanten: Mandant[]; geraete: Geraet[]; onZu: () => void; onSpeichern: (w: Widget) => void }) {
  const { w } = props;
  const [mandant, setMandant] = useState(w.mandant_id ?? "");
  const [geraet, setGeraet] = useState(w.geraet_id ?? "");
  const [zeitraum, setZeitraum] = useState<Zeitraum>(w.zeitraum ?? "24h");
  const [wert, setWert] = useState(w.wert ?? "cpu");
  const reihe = baumReihe(props.mandanten);
  const namen = new Map(props.mandanten.map((m) => [m.id, m.name]));
  const istGraph = w.typ === "graph";
  const geraete = props.geraete
    .filter((g) => namen.has(g.mandant_id) && (g.agent_id || g.snmp_id))
    .sort((a, b) => a.name.localeCompare(b.name, "de"));
  const speichern = (e: FormEvent) => {
    e.preventDefault();
    const neu: Widget = { id: w.id, typ: w.typ, groesse: w.groesse };
    if (istGraph && geraet) neu.geraet_id = geraet;
    else if (mandant) neu.mandant_id = mandant;
    if (istGraph) {
      neu.zeitraum = zeitraum;
      neu.wert = wert;
    }
    props.onSpeichern(neu);
  };
  return (
    <Dialog titel={`Einstellungen: ${widgetArten[w.typ].titel}`} onZu={props.onZu}>
      <form className="formular einstellungen" onSubmit={speichern}>
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
        <div className="aktionen">
          <button className="knopf knopf-haupt">Übernehmen</button>
        </div>
      </form>
    </Dialog>
  );
}
