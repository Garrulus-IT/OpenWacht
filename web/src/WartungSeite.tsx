// SPDX-License-Identifier: AGPL-3.0-only

// Seite „Wartung“ (Etappe 20b): laufende Wartungen und Wartungsfenster.
// Fenster gibt es einmalig, wöchentlich oder monatlich (Patchday) für ein
// Gerät, einen Sensor oder eine Gruppe mit Untergruppen. Läuft ein Fenster,
// legt die Zentrale die Wartung selbst an; sie erscheint dann oben unter
// „Laufend“ und überall sonst wie eine Wartung von Hand.

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { api } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";

type ZielArt = "geraet" | "sensor" | "gruppe";
type Wiederholung = "einmalig" | "woechentlich" | "monatlich";

interface Laufend {
  id: string;
  mandant_id: string;
  geraet_id: string | null;
  check_id: string | null;
  geraet: string;
  sensor: string | null;
  seit: string;
  bis: string;
  grund: string;
  von: string | null;
  fenster_id: string | null;
}

interface Fenster {
  id: string;
  mandant_id: string;
  name: string;
  grund: string;
  ziel_art: ZielArt;
  ziel_id: string;
  ziel_name: string;
  untergruppen: boolean;
  wiederholung: Wiederholung;
  beginn: string | null;
  ende: string | null;
  wochentage: number[];
  nter: number | null;
  wochentag: number | null;
  versatz: number | null;
  uhrzeit: string | null;
  dauer_min: number | null;
  zeitzone: string;
  aktiv: boolean;
  von: string | null;
  text: string;
  laeuft_bis: string | null;
  naechstes: [string, string] | null;
}

interface Ziel {
  art: ZielArt;
  id: string;
  mandant_id: string;
  name: string;
  geraet?: string;
}

interface Antwort {
  laufend: Laufend[];
  fenster: Fenster[];
  ziele: Ziel[];
}

const artText: Record<ZielArt, string> = { geraet: "Gerät", sensor: "Sensor", gruppe: "Gruppe" };
const tage = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];
const tageLang = ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"];

// Zeiten eines Fensters in seiner Zeitzone (sonst passt „um 20:00“ nicht zur Anzeige).
function zeit(iso: string, zone?: string) {
  const o: Intl.DateTimeFormatOptions = { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" };
  try {
    return new Date(iso).toLocaleString("de-DE", zone ? { ...o, timeZone: zone } : o);
  } catch {
    return new Date(iso).toLocaleString("de-DE", o);
  }
}

// datetime-local erwartet Ortszeit ohne Zone.
function ortszeit(d: Date) {
  const z = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}`;
}

export function WartungSeite({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const [d, setD] = useState<Antwort | null>(null);
  const [formular, setFormular] = useState<Fenster | "neu" | null>(null);
  const darf = darfPflegen(bereich, bereich.mandant.id);

  const laden = useCallback(async () => {
    try {
      const r = await api<Antwort>("GET", bereich.mehrere ? "/api/v1/wartung" : `/api/v1/wartung?mandant=${bereich.mandant.id}`);
      setD({
        laufend: r.laufend.filter((x) => bereich.ids.has(x.mandant_id)),
        fenster: r.fenster.filter((x) => bereich.ids.has(x.mandant_id)),
        ziele: r.ziele.filter((x) => bereich.ids.has(x.mandant_id) && darfPflegen(bereich, x.mandant_id)),
      });
    } catch (e) {
      melden(e);
    }
  }, [bereich, melden]);

  useEffect(() => {
    setFormular(null);
    void laden();
    const t = setInterval(() => {
      if (!document.hidden) void laden();
    }, 30000);
    return () => clearInterval(t);
  }, [laden]);

  const aktion = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      await laden();
    } catch (e) {
      melden(e);
    }
  };

  return (
    <section className="ansicht wartung-seite" aria-labelledby="wartung-titel">
      <h1 id="wartung-titel" className="sr-only">
        Wartung
      </h1>
      <section className="panel" aria-labelledby="laufend-titel">
        <div className="panel-kopf">
          <h2 className="panel-titel" id="laufend-titel">
            Laufende Wartungen
          </h2>
        </div>
        <div className="panel-inhalt">
          {d === null ? (
            <p className="klein">Lädt …</p>
          ) : d.laufend.length === 0 ? (
            <p className="leer">Gerade ist nichts in Wartung.</p>
          ) : (
            <table className="tabelle wartung-tabelle">
              <thead>
                <tr>
                  <th>Ziel</th>
                  <th>Bis</th>
                  <th>Grund</th>
                  <th>Von</th>
                  <th>
                    <span className="sr-only">Aktion</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.laufend.map((l) => (
                  <tr key={l.id}>
                    <td data-titel="Ziel">
                      {l.sensor ? `${l.geraet} · ${l.sensor}` : l.geraet}
                      {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, l.mandant_id)}</span>}
                    </td>
                    <td data-titel="Bis">{zeit(l.bis)}</td>
                    <td data-titel="Grund">{l.grund || "–"}</td>
                    <td data-titel="Von">{l.von ?? "–"}</td>
                    <td>
                      {darfPflegen(bereich, l.mandant_id) && (
                        <button
                          className="knopf knopf-klein"
                          onClick={() =>
                            aktion(() =>
                              api("DELETE", l.check_id ? `/api/v1/checks/${l.check_id}/wartung` : `/api/v1/geraete/${l.geraet_id}/wartung`),
                            )
                          }
                        >
                          Beenden
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="hinweis klein">
            In der Wartung laufen Messungen weiter; es gehen keine neuen Alarme und keine Erinnerungen hinaus, Entwarnungen schon. Eine
            vorzeitig beendete Wartung aus einem Fenster beginnt erst beim nächsten Termin wieder.
          </p>
        </div>
      </section>

      <section className="panel" aria-labelledby="fenster-titel">
        <div className="panel-kopf">
          <h2 className="panel-titel" id="fenster-titel">
            Wartungsfenster
          </h2>
          {darf && !formular && (
            <button className="knopf" onClick={() => setFormular("neu")}>
              Fenster anlegen
            </button>
          )}
        </div>
        <div className="panel-inhalt">
          {formular && d && (
            <FensterFormular
              fenster={formular === "neu" ? null : formular}
              ziele={d.ziele}
              onFertig={() => {
                setFormular(null);
                void laden();
              }}
            />
          )}
          {d === null ? null : d.fenster.length === 0 ? (
            !formular && (
              <p className="leer">
                Noch keine Wartungsfenster. Ein Fenster setzt Geräte, Sensoren oder ganze Gruppen zu festen Zeiten in Wartung, z. B. jeden
                Monat nach dem Patchday.
              </p>
            )
          ) : (
            <ul className="fenster-liste">
              {d.fenster.map((f) => (
                <li key={f.id} className={f.aktiv ? (f.laeuft_bis ? "fenster-laeuft" : "") : "fenster-pause"}>
                  <div className="fenster-kopf">
                    <span className="name">{f.name}</span>
                    {f.laeuft_bis ? (
                      <span className="marke marke-wartung">läuft bis {zeit(f.laeuft_bis, f.zeitzone)}</span>
                    ) : !f.aktiv ? (
                      <span className="marke">pausiert</span>
                    ) : null}
                    {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, f.mandant_id)}</span>}
                  </div>
                  <div className="klein">
                    {artText[f.ziel_art]} {f.ziel_name}
                    {f.ziel_art === "gruppe" && (f.untergruppen ? " mit Untergruppen" : " ohne Untergruppen")} · {f.text}
                    {f.zeitzone !== "Europe/Berlin" && ` (${f.zeitzone})`}
                  </div>
                  {f.aktiv && f.naechstes && !f.laeuft_bis && <div className="klein">nächstes Mal: {zeit(f.naechstes[0], f.zeitzone)}</div>}
                  {f.grund && <div className="klein">Grund: {f.grund}</div>}
                  {darfPflegen(bereich, f.mandant_id) && (
                    <div className="aktionen">
                      <button className="knopf knopf-klein" onClick={() => setFormular(f)}>
                        Bearbeiten
                      </button>
                      <button
                        className="knopf knopf-klein"
                        onClick={() => aktion(() => api("PUT", `/api/v1/wartungsfenster/${f.id}`, { ...eingabe(f), aktiv: !f.aktiv }))}
                      >
                        {f.aktiv ? "Pausieren" : "Fortsetzen"}
                      </button>
                      <button
                        className="knopf knopf-klein knopf-gefahr"
                        onClick={() => {
                          if (window.confirm(`Wartungsfenster „${f.name}“ löschen? Eine laufende Wartung daraus endet sofort.`))
                            void aktion(() => api("DELETE", `/api/v1/wartungsfenster/${f.id}`));
                        }}
                      >
                        Löschen
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>
    </section>
  );
}

// API-Rumpf aus einem gespeicherten Fenster (Pausieren).
function eingabe(f: Fenster): Record<string, unknown> {
  return {
    name: f.name,
    grund: f.grund,
    ziel_art: f.ziel_art,
    ziel_id: f.ziel_id,
    untergruppen: f.untergruppen,
    wiederholung: f.wiederholung,
    beginn: f.beginn,
    ende: f.ende,
    wochentage: f.wochentage,
    nter: f.nter ?? 0,
    wochentag: f.wochentag ?? 0,
    versatz: f.versatz ?? 0,
    uhrzeit: f.uhrzeit ?? "",
    dauer_min: f.dauer_min ?? 0,
    zeitzone: f.zeitzone,
    aktiv: f.aktiv,
  };
}

function FensterFormular(props: { fenster: Fenster | null; ziele: Ziel[]; onFertig: () => void }) {
  const f = props.fenster;
  const jetzt = new Date();
  const [name, setName] = useState(f?.name ?? "");
  const [grund, setGrund] = useState(f?.grund ?? "");
  const [art, setArt] = useState<ZielArt>(f?.ziel_art ?? "geraet");
  const [zielId, setZielId] = useState(f?.ziel_id ?? "");
  const [unter, setUnter] = useState(f?.untergruppen ?? true);
  const [wdh, setWdh] = useState<Wiederholung>(f?.wiederholung ?? "woechentlich");
  const [beginn, setBeginn] = useState(ortszeit(f?.beginn ? new Date(f.beginn) : jetzt));
  const [ende, setEnde] = useState(ortszeit(f?.ende ? new Date(f.ende) : new Date(jetzt.getTime() + 2 * 3600e3)));
  const [wtage, setWtage] = useState<Set<number>>(new Set(f?.wochentage ?? [2]));
  const [nter, setNter] = useState(f?.nter ?? 2);
  const [wtag, setWtag] = useState(f?.wochentag ?? 2);
  const [versatz, setVersatz] = useState(String(f?.versatz ?? 1));
  const [uhrzeit, setUhrzeit] = useState(f?.uhrzeit ?? "22:00");
  const [stunden, setStunden] = useState(String(Math.floor((f?.dauer_min ?? 240) / 60)));
  const [minuten, setMinuten] = useState(String((f?.dauer_min ?? 240) % 60));
  const [zone, setZone] = useState(f?.zeitzone ?? "Europe/Berlin");
  const [fehler, setFehler] = useState("");
  const [sendet, setSendet] = useState(false);

  const auswahl = useMemo(() => props.ziele.filter((z) => z.art === art), [props.ziele, art]);
  useEffect(() => {
    if (!auswahl.some((z) => z.id === zielId)) setZielId(auswahl[0]?.id ?? "");
  }, [auswahl, zielId]);

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setSendet(true);
    const body: Record<string, unknown> = {
      name,
      grund,
      ziel_art: art,
      ziel_id: zielId,
      untergruppen: unter,
      wiederholung: wdh,
      zeitzone: zone.trim(),
      aktiv: f?.aktiv ?? true,
    };
    if (wdh === "einmalig") {
      body.beginn = new Date(beginn).toISOString();
      body.ende = new Date(ende).toISOString();
    } else {
      body.uhrzeit = uhrzeit;
      body.dauer_min = (Number(stunden) || 0) * 60 + (Number(minuten) || 0);
      if (wdh === "woechentlich") body.wochentage = [...wtage].sort();
      else Object.assign(body, { nter, wochentag: wtag, versatz: Number(versatz) || 0 });
    }
    try {
      if (f) await api("PUT", `/api/v1/wartungsfenster/${f.id}`, body);
      else await api("POST", "/api/v1/wartungsfenster", body);
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setSendet(false);
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{f ? `„${f.name}“ bearbeiten` : "Wartungsfenster anlegen"}</h3>
        <label className="feld">
          <span>Name</span>
          <input required maxLength={100} value={name} placeholder="z. B. Patchday Windows" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="feld">
          <span>Grund (optional)</span>
          <input maxLength={200} value={grund} placeholder="z. B. Windows-Updates" onChange={(e) => setGrund(e.target.value)} />
        </label>
        <label className="feld">
          <span>Ziel</span>
          <select value={art} onChange={(e) => setArt(e.target.value as ZielArt)}>
            <option value="geraet">Gerät</option>
            <option value="sensor">Sensor</option>
            <option value="gruppe">Gruppe</option>
          </select>
        </label>
        <label className="feld">
          <span>{artText[art]}</span>
          <select required value={zielId} onChange={(e) => setZielId(e.target.value)}>
            {auswahl.length === 0 && <option value="">– keine –</option>}
            {auswahl.map((z) => (
              <option key={z.id} value={z.id}>
                {z.geraet ? `${z.geraet} · ${z.name}` : z.name}
              </option>
            ))}
          </select>
        </label>
        {art === "gruppe" && (
          <label className="haken formular-voll">
            <input type="checkbox" checked={unter} onChange={(e) => setUnter(e.target.checked)} />
            <span>Mit Untergruppen (Geräte, die später in die Gruppe kommen, sind automatisch dabei)</span>
          </label>
        )}

        <fieldset className="formular-voll kanal-art">
          <legend>Wiederholung</legend>
          {(
            [
              ["einmalig", "einmalig"],
              ["woechentlich", "wöchentlich"],
              ["monatlich", "monatlich"],
            ] as [Wiederholung, string][]
          ).map(([w, t]) => (
            <label key={w} className="haken">
              <input type="radio" name="wdh" checked={wdh === w} onChange={() => setWdh(w)} />
              <span>{t}</span>
            </label>
          ))}
        </fieldset>

        {wdh === "einmalig" ? (
          <>
            <label className="feld">
              <span>Beginn</span>
              <input type="datetime-local" required value={beginn} onChange={(e) => setBeginn(e.target.value)} />
            </label>
            <label className="feld">
              <span>Ende</span>
              <input type="datetime-local" required value={ende} onChange={(e) => setEnde(e.target.value)} />
            </label>
            <p className="hinweis formular-voll">Beginn in der Vergangenheit heißt: sofort. Höchstens 7 Tage.</p>
          </>
        ) : (
          <>
            {wdh === "woechentlich" ? (
              <fieldset className="formular-voll kanal-art">
                <legend>Wochentage</legend>
                {tage.map((t, i) => (
                  <label key={t} className="haken">
                    <input
                      type="checkbox"
                      checked={wtage.has(i + 1)}
                      onChange={(e) => {
                        const n = new Set(wtage);
                        if (e.target.checked) n.add(i + 1);
                        else n.delete(i + 1);
                        setWtage(n);
                      }}
                    />
                    <span>{t}</span>
                  </label>
                ))}
              </fieldset>
            ) : (
              <>
                <label className="feld">
                  <span>Am</span>
                  <select value={nter} onChange={(e) => setNter(Number(e.target.value))}>
                    <option value={1}>1.</option>
                    <option value={2}>2.</option>
                    <option value={3}>3.</option>
                    <option value={4}>4.</option>
                    <option value={-1}>letzten</option>
                  </select>
                </label>
                <label className="feld">
                  <span>Wochentag</span>
                  <select value={wtag} onChange={(e) => setWtag(Number(e.target.value))}>
                    {tageLang.map((t, i) => (
                      <option key={t} value={i + 1}>
                        {t}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="feld">
                  <span>plus Tage</span>
                  <input inputMode="numeric" pattern="[0-9]{1,2}" value={versatz} onChange={(e) => setVersatz(e.target.value)} />
                </label>
                <p className="hinweis formular-voll">Patchday von Microsoft ist der 2. Dienstag; „plus 1 Tag“ heißt: am Mittwoch danach.</p>
              </>
            )}
            <label className="feld">
              <span>Uhrzeit</span>
              <input type="time" required value={uhrzeit} onChange={(e) => setUhrzeit(e.target.value)} />
            </label>
            <label className="feld">
              <span>Dauer Std.</span>
              <input inputMode="numeric" pattern="[0-9]{1,3}" value={stunden} onChange={(e) => setStunden(e.target.value)} />
            </label>
            <label className="feld">
              <span>Min.</span>
              <input inputMode="numeric" pattern="[0-9]{1,2}" value={minuten} onChange={(e) => setMinuten(e.target.value)} />
            </label>
          </>
        )}
        <label className="feld">
          <span>Zeitzone</span>
          <input list="zonen" required maxLength={64} value={zone} onChange={(e) => setZone(e.target.value)} />
          <datalist id="zonen">
            <option value="Europe/Berlin" />
            <option value="Europe/Vienna" />
            <option value="Europe/Zurich" />
            <option value="UTC" />
          </datalist>
        </label>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={sendet || !zielId}>
            {f ? "Speichern" : "Anlegen"}
          </button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
