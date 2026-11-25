// SPDX-License-Identifier: AGPL-3.0-only

// Seite „Sensor-Vorlagen“ (Etappe 18): eingebaute und eigene Vorlagen, eine
// Sensorart mit Vorbelegung. Anwenden legt je Gerät eine Kopie an (einmalig,
// auch für eine ganze Gruppe); Änderungen an der Vorlage ändern keine Sensoren.

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, type CheckTyp, type CheckZiel, type Geraet, type Gruppe, type Vorlage, type VorlagenSatz } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";
import { CheckFormular, typText, zielText } from "./Checks";
import { useKennfarben, useVorlagen, type VorlagenListe } from "./SensorenReiter";
import { Kennfarben } from "./Kennfarben";

const intervallKurz = (s: number) => (s % 3600 === 0 ? `${s / 3600}\u00a0Std.` : s % 60 === 0 ? `${s / 60}\u00a0Min.` : `${s}\u00a0s`);

// Platzhalter-Gerät für das Formular: {adresse} bleibt stehen.
const vorlagenGeraet: Geraet = { id: "", mandant_id: "", name: "", adresse: "{adresse}" } as Geraet;

export function SensorVorlagen({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const { liste, neuLaden } = useVorlagen(true, melden);
  const [geraete, setGeraete] = useState<Geraet[]>([]);
  const [gruppen, setGruppen] = useState<Gruppe[]>([]);
  const [netze, setNetze] = useState<string[]>([]);
  // „neu“, ID einer eigenen Vorlage (bearbeiten) oder „kopie:<id>“
  const [form, setForm] = useState("");
  const [anwenden, setAnwenden] = useState<Vorlage | VorlagenSatz | null>(null);
  const [loeschen, setLoeschen] = useState<Vorlage | null>(null);
  // Satz-Formular (0.46.0): „neu“, ID eines eigenen Satzes oder „kopie:<id>“ (eingebauter Satz)
  const [satzForm, setSatzForm] = useState("");
  const [satzLoeschen, setSatzLoeschen] = useState<VorlagenSatz | null>(null);
  const darf = darfPflegen(bereich, bereich.mandant.id);

  useEffect(() => {
    let ok = true;
    Promise.all([
      api<{ geraete: Geraet[] }>("GET", "/api/v1/geraete"),
      api<{ gruppen: Gruppe[] }>("GET", "/api/v1/gruppen"),
      api<{ netze: string[] }>("GET", "/api/v1/checks"),
    ])
      .then(([g, gr, c]) => {
        if (!ok) return;
        setGeraete(g.geraete.filter((x) => bereich.ids.has(x.mandant_id)));
        setGruppen(gr.gruppen.filter((x) => bereich.ids.has(x.mandant_id)));
        setNetze(c.netze);
      })
      .catch((e) => ok && melden(e));
    return () => {
      ok = false;
    };
  }, [bereich, melden]);

  const eigene = (liste?.eigene ?? []).filter((v) => v.mandant_id && bereich.ids.has(v.mandant_id));
  const eigeneSaetze = (liste?.eigene_saetze ?? []).filter((s) => s.mandant_id && bereich.ids.has(s.mandant_id));
  const satzVorbelegt: VorlagenSatz | null = satzForm.startsWith("kopie:")
    ? ((liste?.saetze ?? []).find((s) => s.id === satzForm.slice(6)) ?? null)
    : (eigeneSaetze.find((s) => s.id === satzForm) ?? null);
  const alle = liste ? [...liste.eingebaut, ...eigene] : [];
  const vorbelegt: Vorlage | null = form.startsWith("kopie:")
    ? (alle.find((v) => v.id === form.slice(6)) ?? null)
    : (eigene.find((v) => v.id === form) ?? null);

  const speichern = async (body: { name: string; typ: CheckTyp; ziel: CheckZiel; intervall_sekunden: number }) => {
    if (form && !form.startsWith("kopie:") && form !== "neu") {
      await api("PUT", `/api/v1/sensor-vorlagen/${form}`, { ...body, notiz: vorbelegt?.notiz ?? "" });
    } else {
      await api("POST", `/api/v1/mandanten/${bereich.mandant.id}/sensor-vorlagen`, { ...body, notiz: vorbelegt?.notiz ?? "" });
    }
    neuLaden();
  };

  const zeile = (v: Vorlage, eigen: boolean) => (
    <tr key={v.id}>
      <td className="name">
        {v.name}
        {v.notiz && <span className="klein umbruch">{v.notiz}</span>}
        {eigen && bereich.mehrere && v.mandant_id && <span className="mandant-marke">{mandantName(bereich, v.mandant_id)}</span>}
      </td>
      <td>{typText[v.typ]}</td>
      <td>{v.am_agent ? "Agent" : v.typ === "snmp_oid" ? "SNMP" : "Zentrale"}</td>
      <td className="umbruch klein">{zielText(v)}</td>
      <td>{intervallKurz(v.intervall_sekunden)}</td>
      <td className="aktionen-zelle">
        {darf && (
          <button className="knopf knopf-klein knopf-haupt" onClick={() => setAnwenden(v)}>
            Anwenden
          </button>
        )}
        {darf && !eigen && (
          <button className="knopf knopf-klein" onClick={() => setForm(`kopie:${v.id}`)}>
            Als eigene
          </button>
        )}
        {eigen && v.mandant_id && darfPflegen(bereich, v.mandant_id) && (
          <>
            <button className="knopf knopf-klein" onClick={() => setForm(v.id)}>
              Bearbeiten
            </button>
            <button className="knopf knopf-klein knopf-gefahr" onClick={() => setLoeschen(v)}>
              Löschen
            </button>
          </>
        )}
      </td>
    </tr>
  );

  const kopf = (
    <thead>
      <tr>
        <th scope="col">Vorlage</th>
        <th scope="col">Art</th>
        <th scope="col">misst</th>
        <th scope="col">Vorbelegung</th>
        <th scope="col">Takt</th>
        <th scope="col">
          <span className="sr-only">Aktionen</span>
        </th>
      </tr>
    </thead>
  );

  return (
    <section className="ansicht" aria-labelledby="vorlagen-titel">
      <div className="panel">
        <div className="panel-kopf">
          <h1 id="vorlagen-titel" className="panel-titel">
            Sensor-Vorlagen
          </h1>
          {darf && !form && (
            <button className="knopf knopf-haupt" onClick={() => setForm("neu")}>
              + Vorlage
            </button>
          )}
        </div>
        <div className="panel-inhalt">
          <p className="klein">
            Eine Vorlage ist eine Sensorart mit Vorbelegung. Anwenden legt je Gerät eine Kopie an, auch für alle Geräte einer Gruppe;
            spätere Änderungen an der Vorlage ändern keine Sensoren. {"{adresse}"} steht für die Adresse des Geräts. Sensoren auf dem Agent
            sind feste Messarten mit Parametern, keine Skripte, und messen nur, was am Rechner freigegeben ist.
          </p>

          {form && (
            <CheckFormular
              key={form}
              geraet={vorlagenGeraet}
              geraete={[]}
              check={null}
              vorlage={vorbelegt}
              hatAgent
              netze={netze}
              titel={
                form === "neu"
                  ? `Neue Vorlage für „${bereich.mandant.name}“`
                  : form.startsWith("kopie:")
                    ? `Eigene Vorlage aus „${vorbelegt?.name ?? ""}“`
                    : `Vorlage „${vorbelegt?.name ?? ""}“ bearbeiten`
              }
              speichern={speichern}
              onFertig={() => setForm("")}
              melden={melden}
            />
          )}

          {loeschen && (
            <div className="bestaetigung" role="alertdialog" aria-label="Vorlage löschen">
              <p>Vorlage „{loeschen.name}“ löschen? Sensoren, die daraus angelegt wurden, bleiben.</p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/sensor-vorlagen/${loeschen.id}`);
                      neuLaden();
                    } catch (e) {
                      melden(e);
                    }
                    setLoeschen(null);
                  }}
                >
                  Löschen
                </button>
                <button className="knopf" onClick={() => setLoeschen(null)}>
                  Abbrechen
                </button>
              </div>
            </div>
          )}

          {anwenden && (
            <Anwenden
              v={anwenden}
              geraete={geraete}
              gruppen={gruppen}
              bereich={bereich}
              onFertig={() => setAnwenden(null)}
              melden={melden}
            />
          )}

          <h2 className="klein-titel">Eigene Vorlagen</h2>
          {eigene.length === 0 ? (
            <p className="klein">Noch keine. Mit „+ Vorlage“ oder „Als eigene“ bei einer eingebauten Vorlage anlegen.</p>
          ) : (
            <div className="tabelle-rahmen">
              <table className="tabelle tabelle-kompakt">
                {kopf}
                <tbody>{eigene.map((v) => zeile(v, true))}</tbody>
              </table>
            </div>
          )}
          <div className="satz-kopf">
            <h2 className="klein-titel">Vorlagensätze</h2>
            {darf && !satzForm && (
              <button className="knopf knopf-klein" onClick={() => setSatzForm("neu")}>
                + Vorlagensatz
              </button>
            )}
          </div>
          <p className="klein">
            Ein Satz legt mehrere Sensoren für eine Anwendung auf einmal an, z. B. Dienste und Kennzahlen eines Windows-Servers. Eigene
            Sätze stellst du aus Vorlagen zusammen; „Als eigenen“ kopiert einen eingebauten Satz zum Anpassen.
          </p>
          {satzForm && liste && (
            <SatzFormular
              key={satzForm}
              satz={satzVorbelegt}
              kopie={satzForm.startsWith("kopie:")}
              liste={liste}
              eigene={eigene}
              bereich={bereich}
              onFertig={() => {
                setSatzForm("");
                neuLaden();
              }}
            />
          )}
          {satzLoeschen && (
            <div className="bestaetigung" role="alertdialog" aria-label="Vorlagensatz löschen">
              <p>Vorlagensatz „{satzLoeschen.name}“ löschen? Sensoren, die daraus angelegt wurden, bleiben.</p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/sensor-vorlagensaetze/${satzLoeschen.id}`);
                      neuLaden();
                    } catch (e) {
                      melden(e);
                    }
                    setSatzLoeschen(null);
                  }}
                >
                  Löschen
                </button>
                <button className="knopf" onClick={() => setSatzLoeschen(null)}>
                  Abbrechen
                </button>
              </div>
            </div>
          )}
          <div className="tabelle-rahmen">
            <table className="tabelle tabelle-kompakt">
              <thead>
                <tr>
                  <th scope="col">Satz</th>
                  <th scope="col">Sensoren</th>
                  <th scope="col">
                    <span className="sr-only">Aktionen</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {[...eigeneSaetze, ...(liste?.saetze ?? [])].map((s) => (
                  <tr key={s.id}>
                    <td className="name">
                      {s.name}
                      {s.mandant_id && <span className="marke">eigen</span>}
                      {s.notiz && <span className="klein umbruch">{s.notiz}</span>}
                      {s.mandant_id && bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, s.mandant_id)}</span>}
                    </td>
                    <td className="klein umbruch">
                      <span className="satz-anzahl">{s.sensoren.length} Sensoren:</span>{" "}
                      {s.sensoren.map((v) => v.name.replace(/^[^:]+:\s*/, "")).join(" · ")}
                    </td>
                    <td className="aktionen-zelle">
                      {darf && (
                        <button className="knopf knopf-klein knopf-haupt" onClick={() => setAnwenden(s)}>
                          Anwenden
                        </button>
                      )}
                      {darf && !s.mandant_id && (
                        <button className="knopf knopf-klein" onClick={() => setSatzForm(`kopie:${s.id}`)}>
                          Als eigenen
                        </button>
                      )}
                      {s.mandant_id && darfPflegen(bereich, s.mandant_id) && (
                        <>
                          <button className="knopf knopf-klein" onClick={() => setSatzForm(s.id)}>
                            Bearbeiten
                          </button>
                          <button className="knopf knopf-klein knopf-gefahr" onClick={() => setSatzLoeschen(s)}>
                            Löschen
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h2 className="klein-titel">Eingebaut</h2>
          <div className="tabelle-rahmen">
            <table className="tabelle tabelle-kompakt">
              {kopf}
              <tbody>{(liste?.eingebaut ?? []).map((v) => zeile(v, false))}</tbody>
            </table>
          </div>
        </div>
      </div>
      <Kennfarben bereich={bereich} melden={melden} />
    </section>
  );
}

const istSatz = (v: Vorlage | VorlagenSatz): v is VorlagenSatz => "sensoren" in v;

// Formular für eigene Vorlagensätze (0.46.0): Einträge sind Kopien von
// Vorlagen (eingebaute, eigene oder Sensoren eingebauter Sätze).
function SatzFormular(props: {
  satz: VorlagenSatz | null;
  kopie: boolean;
  liste: VorlagenListe;
  eigene: Vorlage[];
  bereich: Bereich;
  onFertig: () => void;
}) {
  const { satz, kopie, bereich } = props;
  const neu = !satz || kopie;
  const [name, setName] = useState(satz ? (kopie ? `${satz.name} (eigen)` : satz.name) : "");
  const [notiz, setNotiz] = useState(satz?.notiz ?? "");
  const [eintraege, setEintraege] = useState<Vorlage[]>(satz?.sensoren ?? []);
  // Kennfarbe je Eintrag (1.0.1); beim Anwenden bekommt der Sensor sie mit
  const kennfarben = useKennfarben(() => {});
  const [wahl, setWahl] = useState("");
  const [fehler, setFehler] = useState("");
  const [sendet, setSendet] = useState(false);
  const quellen: { titel: string; liste: Vorlage[] }[] = [
    { titel: "Eigene Vorlagen", liste: props.eigene },
    { titel: "Eingebaute Vorlagen", liste: props.liste.eingebaut },
    ...(props.liste.saetze ?? []).map((s) => ({ titel: `Satz ${s.name}`, liste: s.sensoren })),
  ];
  const alle = quellen.flatMap((q) => q.liste);

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setSendet(true);
    setFehler("");
    const body = {
      name,
      notiz,
      sensoren: eintraege.map((v) => ({
        name: v.name,
        typ: v.typ,
        ziel: v.ziel,
        intervall_sekunden: v.intervall_sekunden,
        notiz: v.notiz,
        ...(v.kennfarbe_id ? { kennfarbe_id: v.kennfarbe_id } : {}),
      })),
    };
    try {
      if (neu) await api("POST", `/api/v1/mandanten/${bereich.mandant.id}/sensor-vorlagensaetze`, body);
      else await api("PUT", `/api/v1/sensor-vorlagensaetze/${satz!.id}`, body);
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setSendet(false);
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden} aria-label="Vorlagensatz">
        <h3 className="einschub-titel">
          {neu ? `Neuer Vorlagensatz für „${bereich.mandant.name}“` : `Vorlagensatz „${satz!.name}“ bearbeiten`}
        </h3>
        <label className="feld">
          <span>Name</span>
          <input required maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="feld feld-breit">
          <span>Notiz (optional)</span>
          <input maxLength={500} value={notiz} onChange={(e) => setNotiz(e.target.value)} />
        </label>
        <div className="formular-voll">
          <p className="klein">
            {eintraege.length} von höchstens 50 Sensoren. Jeder Eintrag ist eine Kopie; spätere Änderungen an der Vorlage ändern den Satz
            nicht.
          </p>
          <ul className="satz-eintraege">
            {eintraege.map((v, i) => (
              <li key={`${v.name}-${i}`}>
                <span>
                  {v.name} <span className="klein">({typText[v.typ]})</span>
                </span>
                {kennfarben.liste.length > 0 && (
                  <select
                    aria-label={`Kennfarbe für ${v.name}`}
                    value={v.kennfarbe_id ?? ""}
                    onChange={(e) =>
                      setEintraege(eintraege.map((x, j) => (j === i ? { ...x, kennfarbe_id: e.target.value || undefined } : x)))
                    }
                  >
                    <option value="">keine Kennfarbe</option>
                    {kennfarben.liste.map((k) => (
                      <option key={k.id} value={k.id}>
                        {k.name}
                      </option>
                    ))}
                  </select>
                )}
                <button
                  type="button"
                  className="knopf knopf-klein"
                  aria-label={`${v.name} entfernen`}
                  onClick={() => setEintraege(eintraege.filter((_, j) => j !== i))}
                >
                  Entfernen
                </button>
              </li>
            ))}
          </ul>
        </div>
        <label className="feld feld-breit">
          <span>Vorlage hinzufügen</span>
          <select
            value={wahl}
            onChange={(e) => {
              const v = alle.find((x) => x.id === e.target.value);
              if (v && !eintraege.some((x) => x.name.toLowerCase() === v.name.toLowerCase())) setEintraege([...eintraege, v]);
              setWahl("");
            }}
          >
            <option value="">Bitte wählen</option>
            {quellen
              .filter((q) => q.liste.length > 0)
              .map((q) => (
                <optgroup key={q.titel} label={q.titel}>
                  {q.liste.map((v) => (
                    <option key={v.id} value={v.id} disabled={eintraege.some((x) => x.name.toLowerCase() === v.name.toLowerCase())}>
                      {v.name}
                    </option>
                  ))}
                </optgroup>
              ))}
          </select>
        </label>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={sendet || eintraege.length === 0 || !name.trim()}>
            Speichern
          </button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

function Anwenden(props: {
  v: Vorlage | VorlagenSatz;
  geraete: Geraet[];
  gruppen: Gruppe[];
  bereich: Bereich;
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const { v } = props;
  const [ziel, setZiel] = useState<"geraete" | "gruppe">("geraete");
  const [wahl, setWahl] = useState<Set<string>>(new Set());
  const [gruppe, setGruppe] = useState("");
  const [unter, setUnter] = useState(true);
  const [sendet, setSendet] = useState(false);
  const [fehler, setFehler] = useState("");
  const [ergebnis, setErgebnis] = useState<{
    angelegt: number;
    uebersprungen: { geraet: string; sensor?: string; grund: string }[];
  } | null>(null);
  const satz = istSatz(v);
  const sensoren = satz ? v.sensoren : [v];
  const auswahl = satz ? { satz_id: v.id } : { vorlage_id: v.id };
  const sortiert = useMemo(() => props.geraete.slice().sort((a, b) => a.name.localeCompare(b.name, "de")), [props.geraete]);
  const pfad = (g: Gruppe): string => {
    const e = props.gruppen.find((x) => x.id === g.eltern_id);
    return e ? `${pfad(e)} / ${g.name}` : g.name;
  };

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setSendet(true);
    setFehler("");
    try {
      const body = ziel === "gruppe" ? { ...auswahl, gruppe_id: gruppe, mit_untergruppen: unter } : { ...auswahl, geraete: [...wahl] };
      setErgebnis(await api("POST", "/api/v1/sensor-vorlagen/anwenden", body));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setSendet(false);
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">„{v.name}“ anwenden</h3>
        <p className="hinweis formular-voll">
          {satz ? `Legt je Gerät ${sensoren.length} Sensoren an. ` : `Legt je Gerät einen Sensor „${v.name}“ an. `}
          {sensoren.some((x) => x.braucht_adresse) ? "Geräte ohne Adresse werden dabei übersprungen. " : ""}
          {sensoren.some((x) => x.am_agent)
            ? "Sensoren auf dem Agent nur bei Geräten mit Agent; gemessen wird erst nach Freigabe am Rechner. "
            : ""}
          {sensoren.some((x) => x.typ === "snmp_oid") ? "SNMP-Sensoren nur bei Geräten mit SNMP-Abfrage. " : ""}
        </p>
        <fieldset className="formular-voll wahl-gruppe">
          <legend className="sr-only">Ziel</legend>
          <label className="haken">
            <input type="radio" name="ziel" checked={ziel === "geraete"} onChange={() => setZiel("geraete")} />
            <span>Einzelne Geräte</span>
          </label>
          <label className="haken">
            <input type="radio" name="ziel" checked={ziel === "gruppe"} onChange={() => setZiel("gruppe")} />
            <span>Alle Geräte einer Gruppe</span>
          </label>
        </fieldset>
        {ziel === "geraete" ? (
          <div className="formular-voll geraete-wahl" role="group" aria-label="Geräte">
            {sortiert.length === 0 && <p className="klein">Keine Geräte im gewählten Bereich.</p>}
            {sortiert.map((g) => (
              <label key={g.id} className="haken">
                <input
                  type="checkbox"
                  checked={wahl.has(g.id)}
                  onChange={(e) => {
                    const n = new Set(wahl);
                    if (e.target.checked) n.add(g.id);
                    else n.delete(g.id);
                    setWahl(n);
                  }}
                />
                <span>
                  {g.name}
                  {g.adresse ? <span className="klein"> · {g.adresse}</span> : null}
                </span>
              </label>
            ))}
          </div>
        ) : (
          <>
            <label className="feld">
              <span>Gruppe</span>
              <select required value={gruppe} onChange={(e) => setGruppe(e.target.value)}>
                <option value="">Bitte wählen</option>
                {props.gruppen
                  .map((g) => ({ g, p: pfad(g) }))
                  .sort((a, b) => a.p.localeCompare(b.p, "de"))
                  .map(({ g, p }) => (
                    <option key={g.id} value={g.id}>
                      {p}
                      {props.bereich.mehrere ? ` (${mandantName(props.bereich, g.mandant_id)})` : ""}
                    </option>
                  ))}
              </select>
            </label>
            <label className="haken">
              <input type="checkbox" checked={unter} onChange={(e) => setUnter(e.target.checked)} />
              <span>mit Untergruppen</span>
            </label>
            <p className="klein formular-voll">Gilt einmalig für die Geräte, die jetzt in der Gruppe sind.</p>
          </>
        )}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        {ergebnis && (
          <div className="meldung formular-voll" role="status">
            <p>
              {ergebnis.angelegt === 1 ? "1 Sensor angelegt" : `${ergebnis.angelegt} Sensoren angelegt`}
              {ergebnis.uebersprungen.length ? `, ${ergebnis.uebersprungen.length} übersprungen:` : "."}
            </p>
            {ergebnis.uebersprungen.length > 0 && (
              <ul className="klein">
                {ergebnis.uebersprungen.map((u, i) => (
                  <li key={i}>
                    {u.geraet}
                    {u.sensor ? ` · ${u.sensor}` : ""}: {u.grund}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="aktionen">
          {!ergebnis && (
            <button className="knopf knopf-haupt" disabled={sendet || (ziel === "geraete" ? wahl.size === 0 : !gruppe)}>
              Anlegen
            </button>
          )}
          <button type="button" className="knopf" onClick={props.onFertig}>
            {ergebnis ? "Schließen" : "Abbrechen"}
          </button>
        </div>
      </form>
    </div>
  );
}
