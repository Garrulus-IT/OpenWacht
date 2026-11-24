// SPDX-License-Identifier: AGPL-3.0-only

// Seite „Alarme“ (Etappe 17, vorher Übersicht und Reiter Alarmierung):
// Aktiv = aktive Alarme mit Bestätigen und die Sensoren nach Zustand,
// Protokoll = Alarme der letzten 30 Tage, Kanäle = Alarmkanäle (ntfy).
// Alles im gewählten Bereich.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type Alarm, type Alarmkanal, type Sensor, type Wartung } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";
import { vor } from "./zeit";
import { alarmListe, type AlarmReiter, type Ort } from "./navigation";
import { wartungBis } from "./Wartung";
import { Alarme } from "./Alarme";
import { Hinweise, type HinweisDaten } from "./Hinweise";
import { KennMarke, kennStil } from "./kennfarbe";

interface Props {
  bereich: Bereich;
  unter: AlarmReiter;
  melden: (e: unknown) => void;
  gehe: (o: Partial<Ort>) => void;
}

interface Daten {
  sensoren: Sensor[];
  alarme: Alarm[];
  kanaele: Alarmkanal[];
  hinweise: HinweisDaten;
  jetzt: number;
}

// Kacheln in der Reihenfolge der Dringlichkeit.
// Sensoren in Wartung zählen unter „Wartung“, egal wie sie gerade messen.
export type Gruppe = "crit" | "warn" | "unknown" | "ok" | "wartung" | "pause";
export const gruppen: { id: Gruppe; text: string }[] = [
  { id: "crit", text: "Kritisch" },
  { id: "warn", text: "Warnung" },
  { id: "unknown", text: "Unbekannt" },
  { id: "ok", text: "OK" },
  { id: "wartung", text: "Wartung" },
  { id: "pause", text: "Pausiert" },
];
export function gruppe(s: Sensor): Gruppe {
  if (s.status === "pause") return "pause";
  if (s.wartung) return "wartung";
  return s.status === "neu" ? "unknown" : s.status;
}
export const rang: Record<Gruppe, number> = { crit: 0, unknown: 1, warn: 2, ok: 3, wartung: 4, pause: 5 };

export function alarmSchluessel(a: Alarm) {
  if (a.check_id) return `c:${a.check_id}`;
  return a.snmp_id ? `s:${a.snmp_id}/${a.gegenstand}` : `h:${a.agent_id}/${a.gegenstand}`;
}
export const statusText: Record<string, string> = {
  crit: "Kritisch",
  warn: "Warnung",
  unknown: "Unbekannt",
  ok: "OK",
  pause: "Pausiert",
  neu: "Neu",
};

export function sensorTitel(s: { host?: string; name: string }) {
  return s.host ? `${s.host} · ${s.name}` : s.name;
}

function zeit(iso: string) {
  return new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

export function dauer(von: string, bis: number) {
  const m = Math.max(1, Math.round((bis - Date.parse(von)) / 60000));
  if (m < 60) return `${m} Min.`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h} Std. ${m % 60} Min.` : `${h} Std.`;
  return `${Math.round(h / 24)} Tage`;
}

export function AlarmeSeite({ bereich, unter, melden, gehe }: Props) {
  return (
    <section className="ansicht" aria-labelledby="alarme-seite-titel">
      <h1 id="alarme-seite-titel" className="sr-only">
        Alarme
      </h1>
      <div className="umschalter unterreiter" role="group" aria-label="Alarme">
        {alarmListe.map((a) => (
          <button key={a.id} type="button" className="umschalter-knopf" aria-pressed={unter === a.id} onClick={() => gehe({ alarm: a.id })}>
            {a.text}
          </button>
        ))}
      </div>
      {unter === "kanaele" ? (
        <Alarme bereich={bereich} melden={melden} />
      ) : (
        <AlarmeDaten bereich={bereich} unter={unter} melden={melden} gehe={gehe} />
      )}
    </section>
  );
}

function AlarmeDaten({ bereich, unter, melden, gehe }: Props) {
  const [d, setD] = useState<Daten | null>(null);
  const [filter, setFilter] = useState<Gruppe | "probleme">("probleme");
  const [protokollAlle, setProtokollAlle] = useState(false);

  const laden = useCallback(async () => {
    try {
      const [s, a, k, h] = await Promise.all([
        api<{ sensoren: Sensor[] }>("GET", "/api/v1/sensoren"),
        api<{ alarme: Alarm[] }>("GET", "/api/v1/alarme?limit=500"),
        api<{ kanaele: Alarmkanal[] }>("GET", "/api/v1/alarm-kanaele"),
        api<HinweisDaten>("GET", "/api/v1/hinweise"),
      ]);
      const drin = (m: string) => bereich.ids.has(m);
      setD({
        sensoren: s.sensoren.filter((x) => drin(x.mandant_id)),
        alarme: a.alarme.filter((x) => drin(x.mandant_id)),
        kanaele: k.kanaele.filter((x) => drin(x.mandant_id)),
        hinweise: h,
        jetzt: Date.now(),
      });
    } catch (e) {
      melden(e);
    }
  }, [bereich, melden]);

  useEffect(() => {
    void laden();
    const t = setInterval(() => {
      if (!document.hidden) void laden();
    }, 15000);
    return () => clearInterval(t);
  }, [laden]);

  if (!d) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }

  const zahl: Record<Gruppe, number> = { crit: 0, warn: 0, unknown: 0, ok: 0, wartung: 0, pause: 0 };
  for (const s of d.sensoren) zahl[gruppe(s)]++;
  const wartungJe = new Map(d.sensoren.filter((s) => s.wartung).map((s) => [s.schluessel, s.wartung!]));
  const offen = d.alarme
    .filter((a) => !a.ende)
    .sort(
      (a, b) =>
        Number(!!a.bestaetigt_am) - Number(!!b.bestaetigt_am) ||
        rang[a.status] - rang[b.status] ||
        Date.parse(b.beginn) - Date.parse(a.beginn),
    );
  const gestoert = d.kanaele.filter((k) => k.aktiv && k.letzter_fehler);
  const sichtbar = d.sensoren
    .filter((s) => (filter === "probleme" ? !["ok", "pause", "wartung"].includes(gruppe(s)) : gruppe(s) === filter))
    .sort((a, b) => rang[gruppe(a)] - rang[gruppe(b)] || sensorTitel(a).localeCompare(sensorTitel(b), "de"));
  const protokoll = d.alarme.slice(0, protokollAlle ? 500 : 15);

  const hinweise = <Hinweise d={d.hinweise} jetzt={d.jetzt} drin={(m) => bereich.ids.has(m)} />;

  if (unter === "protokoll") {
    return (
      <>
        {hinweise}
        <div className="abschnitt-kopf">
          <h2 className="abschnitt">Alarmprotokoll</h2>
          <p className="klein">letzte 30 Tage, neueste zuerst</p>
        </div>
        {d.alarme.length === 0 ? (
          <p className="leer">In den letzten 30 Tagen gab es keine Alarme.</p>
        ) : (
          <>
            <div className="tabelle-rahmen">
              <table className="tabelle tabelle-kompakt protokoll">
                <thead>
                  <tr>
                    <th scope="col">Beginn</th>
                    <th scope="col">Sensor</th>
                    <th scope="col">Zustand</th>
                    <th scope="col">Dauer</th>
                    <th scope="col">Bestätigt</th>
                  </tr>
                </thead>
                <tbody>
                  {protokoll.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <time dateTime={a.beginn}>{zeit(a.beginn)}</time>
                      </td>
                      <td>
                        <div className="name">{a.name}</div>
                        <div className="klein">
                          {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, a.mandant_id)}</span>}
                          {a.meldung}
                        </div>
                      </td>
                      <td>
                        <span className={`marke marke-${a.ende ? "ende" : a.status}`}>
                          {a.ende ? `war ${statusText[a.schlimmster]}` : statusText[a.status]}
                        </span>
                      </td>
                      <td>{a.ende ? dauer(a.beginn, Date.parse(a.ende)) : `läuft seit ${dauer(a.beginn, d.jetzt)}`}</td>
                      <td>
                        {a.bestaetigt_von ? (
                          <span>
                            {a.bestaetigt_von}
                            {a.kommentar ? ` – ${a.kommentar}` : ""}
                          </span>
                        ) : (
                          <span className="klein">–</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {d.alarme.length > protokoll.length && (
              <button className="knopf protokoll-mehr" onClick={() => setProtokollAlle(true)}>
                Alle {d.alarme.length} Einträge zeigen
              </button>
            )}
          </>
        )}
      </>
    );
  }

  return (
    <>
      <div className="kachel-reihe" role="group" aria-label="Sensoren nach Zustand">
        {gruppen.map((g) => (
          <button
            key={g.id}
            type="button"
            className={`kachel kachel-${g.id}${zahl[g.id] === 0 ? " kachel-null" : ""}`}
            aria-pressed={filter === g.id}
            onClick={() => setFilter(filter === g.id ? "probleme" : g.id)}
          >
            <span className="kachel-zahl">{zahl[g.id]}</span>
            <span className="kachel-text">{g.text}</span>
          </button>
        ))}
      </div>

      {hinweise}

      {gestoert.length > 0 && (
        <p className="meldung meldung-fehler">
          {gestoert.length === 1 ? "Ein Alarmkanal ist gestört" : `${gestoert.length} Alarmkanäle sind gestört`}:{" "}
          {gestoert.map((k) => k.name).join(", ")}. Meldungen kommen dort nicht an.{" "}
          <button className="knopf-text" onClick={() => gehe({ alarm: "kanaele" })}>
            Zu den Kanälen
          </button>
        </p>
      )}

      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Aktive Alarme</h2>
        {offen.length > 0 && (
          <p className="klein">
            {offen.length} offen, davon {offen.filter((a) => a.bestaetigt_am).length} bestätigt
          </p>
        )}
      </div>
      {offen.length === 0 ? (
        <p className="leer">Keine aktiven Alarme.</p>
      ) : (
        <ul className="alarm-liste">
          {offen.map((a) => (
            <AlarmZeile
              key={a.id}
              a={a}
              wartung={wartungJe.get(alarmSchluessel(a))}
              bereich={bereich}
              jetzt={d.jetzt}
              onGeaendert={laden}
              melden={melden}
            />
          ))}
        </ul>
      )}

      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Sensoren</h2>
        <p className="klein" aria-live="polite">
          {filter === "probleme" ? "alle, die nicht OK sind" : `nur ${gruppen.find((g) => g.id === filter)!.text} · `}
          {filter !== "probleme" && (
            <button className="knopf-text" onClick={() => setFilter("probleme")}>
              nur Probleme zeigen
            </button>
          )}
        </p>
      </div>
      {sichtbar.length === 0 ? (
        <p className="leer">{filter === "probleme" ? "Alle Sensoren sind OK." : "Keine Sensoren in diesem Zustand."}</p>
      ) : (
        <ul className="sensor-liste">
          {sichtbar.map((s) => (
            <li key={s.schluessel} className={`sensor sensor-${gruppe(s)}`}>
              <span
                className={`signal signal-${s.status}${kennStil(s.kennfarbe, s.status).className}`}
                style={kennStil(s.kennfarbe, s.status).style}
                aria-hidden="true"
              />
              <span className="sensor-text">
                <span className="name">{sensorTitel(s)}</span>
                <span className="klein">
                  <span className="sr-only">{statusText[s.status]}: </span>
                  {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, s.mandant_id)}</span>}
                  {s.meldung}
                  {s.seit && s.status !== "ok" ? ` · ${vor(s.seit, d.jetzt)}` : ""}
                  {s.alarm?.bestaetigt_am ? " · bestätigt" : ""}
                  {s.wartung && s.status !== "pause" ? ` · Wartung ${wartungBis(s.wartung)}` : ""}
                  <KennMarke k={s.kennfarbe} status={s.status} />
                </span>
              </span>
              <button
                className="knopf-text"
                onClick={() => gehe({ reiter: "hosts", mandant: s.mandant_id, mitUnter: false, geraet: s.geraet_id })}
              >
                Anzeigen
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

export function AlarmZeile(props: {
  a: Alarm;
  wartung?: Wartung;
  bereich: Bereich;
  jetzt: number;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const { a, bereich, jetzt } = props;
  const darf = darfPflegen(bereich, a.mandant_id);
  const [offen, setOffen] = useState(false);
  const [kommentar, setKommentar] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const bestaetigen = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      await api("POST", `/api/v1/alarme/${a.id}/bestaetigen`, { kommentar });
      setOffen(false);
      props.onGeaendert();
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <li
      className={`alarm alarm-${a.status}${a.bestaetigt_am ? " alarm-bestaetigt" : ""}${kennStil(a.kennfarbe, a.status).className}`}
      style={kennStil(a.kennfarbe, a.status).style}
    >
      <span className={`signal signal-${a.status}`} aria-hidden="true" />
      <div className="alarm-text">
        <span className="name">{a.name}</span>
        <span className="klein">
          <span className="sr-only">{statusText[a.status]}: </span>
          {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, a.mandant_id)}</span>}
          {a.meldung} · Alarm seit {dauer(a.beginn, jetzt)}
          {props.wartung ? ` · Wartung ${wartungBis(props.wartung)}` : ""}
          <KennMarke k={a.kennfarbe} status={a.status} />
        </span>
        {a.bestaetigt_am && (
          <span className="klein alarm-quittung">
            Bestätigt von {a.bestaetigt_von ?? "unbekannt"} {vor(a.bestaetigt_am, jetzt)}
            {a.kommentar ? `: ${a.kommentar}` : ""}
          </span>
        )}
        {offen && (
          <form className="formular-zeile alarm-formular" onSubmit={bestaetigen}>
            <label className="feld feld-breit">
              <span>Kommentar (optional)</span>
              <input
                autoFocus
                maxLength={300}
                value={kommentar}
                placeholder="z. B. Platte wird morgen getauscht"
                onChange={(e) => setKommentar(e.target.value)}
              />
            </label>
            <button className="knopf knopf-haupt" disabled={arbeitet}>
              Bestätigen
            </button>
            <button type="button" className="knopf" onClick={() => setOffen(false)}>
              Abbrechen
            </button>
          </form>
        )}
      </div>
      {!a.bestaetigt_am && darf && !offen && (
        <button
          className="knopf"
          onClick={() => setOffen(true)}
          title="Keine Erinnerungen mehr; Entwarnung und Verschlimmerung werden weiter gemeldet"
        >
          Bestätigen
        </button>
      )}
    </li>
  );
}
