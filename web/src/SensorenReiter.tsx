// SPDX-License-Identifier: AGPL-3.0-only

// Reiter „Sensoren“ am Gerät (Etappe 18): alle Sensoren auf einen Blick mit
// Herkunft (Standard, Vorlage, eigen) und „+ Sensor“, frei oder aus einer
// Vorlage. Bearbeiten und Löschen auch hier (0.99.2), dazu alle Sensoren einer Vorlage bzw. eines Satzes
// auf einmal entfernen; Pausieren unter „Übersicht“.

import { useEffect, useState, type CSSProperties } from "react";
import { api, type Agent, type Check, type Geraet, type KennfarbeEintrag, type Sensor, type Vorlage, type VorlagenSatz } from "./api";
import { KennMarke, kennStil, type Kennfarbe } from "./kennfarbe";
import { anzeige, anzeigeText, CheckFormular, istAgentArt, typText, zielText } from "./Checks";

export interface VorlagenListe {
  eingebaut: Vorlage[];
  eigene: Vorlage[];
  saetze?: VorlagenSatz[];
  eigene_saetze?: VorlagenSatz[];
}

export function useVorlagen(aktiv: boolean, melden: (e: unknown) => void) {
  const [liste, setListe] = useState<VorlagenListe | null>(null);
  const [stand, setStand] = useState(0);
  useEffect(() => {
    if (!aktiv) return;
    let ok = true;
    api<VorlagenListe>("GET", "/api/v1/sensor-vorlagen")
      .then((l) => ok && setListe(l))
      .catch((e) => ok && melden(e));
    return () => {
      ok = false;
    };
    // melden ist stabil genug; neu laden nur bei aktiv/stand
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aktiv, stand]);
  return { liste, neuLaden: () => setStand((x) => x + 1) };
}

const standardArt: Record<Sensor["art"], string> = { host: "Agent", snmp: "SNMP", check: "Zentrale" };

// Alle sichtbaren Kennfarben (eigener Mandant, darunter und darüber).
export function useKennfarben(melden: (e: unknown) => void) {
  const [liste, setListe] = useState<KennfarbeEintrag[]>([]);
  const [stand, setStand] = useState(0);
  useEffect(() => {
    let ok = true;
    api<{ kennfarben: KennfarbeEintrag[] }>("GET", "/api/v1/kennfarben")
      .then((l) => ok && setListe(l.kennfarben))
      .catch((e) => ok && melden(e));
    return () => {
      ok = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stand]);
  return { liste, neuLaden: () => setStand((x) => x + 1) };
}

// Auswahl der Kennfarbe eines Sensors; ohne Recht nur die Marke.
function KennfarbeWahl(props: {
  schluessel: string;
  name: string;
  aktuell: Kennfarbe | undefined;
  liste: KennfarbeEintrag[];
  darf: boolean;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const [arbeitet, setArbeitet] = useState(false);
  const k = props.aktuell;
  if (!props.darf || props.liste.length === 0) {
    return k ? <KennMarke k={k} immer /> : <span className="klein">–</span>;
  }
  return (
    <span className="kenn-wahl">
      {k && <span className="kenn-feld" style={{ "--kenn": k.farbe } as CSSProperties} aria-hidden="true" />}
      <select
        aria-label={`Kennfarbe für ${props.name}`}
        value={k?.id ?? ""}
        disabled={arbeitet}
        onChange={async (e) => {
          setArbeitet(true);
          try {
            await api("PUT", "/api/v1/sensoren/kennfarbe", { schluessel: props.schluessel, kennfarbe_id: e.target.value || null });
            props.onGeaendert();
          } catch (err) {
            props.melden(err);
          } finally {
            setArbeitet(false);
          }
        }}
      >
        <option value="">keine</option>
        {props.liste.map((x) => (
          <option key={x.id} value={x.id}>
            {x.name}
          </option>
        ))}
      </select>
    </span>
  );
}

export function SensorenReiter(props: {
  g: Geraet;
  agent: Agent | null;
  checks: Check[];
  sensoren: Sensor[];
  geschwister: Geraet[];
  netze: string[];
  hatSnmp: boolean;
  darf: boolean;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const { g, agent } = props;
  const { liste } = useVorlagen(true, props.melden);
  const kennfarben = useKennfarben(props.melden);
  const [schritt, setSchritt] = useState<"" | "wahl" | "formular">("");
  const [wahl, setWahl] = useState("");
  const [bearbeite, setBearbeite] = useState<Check | null>(null);
  // Löschen mit Bestätigung: ein Sensor oder alle einer Herkunft (0.99.2)
  const [loeschen, setLoeschen] = useState<{ check: Check } | { herkunft: string; anzahl: number } | null>(null);
  const [arbeitet, setArbeitet] = useState(false);
  // Ausnehmen einzelner Werte einer Quelle (SNMP, NetApp …) mit Begründung (0.99.2)
  const [ausnehmen, setAusnehmen] = useState<Sensor | null>(null);
  const [grund, setGrund] = useState("");
  const freigabe = agent?.messwerte?.sensoren ?? null;
  const alle = liste ? [...liste.eingebaut, ...liste.eigene] : [];
  const vorlage = alle.find((v) => v.id === wahl) ?? null;
  const standard = props.sensoren.filter((s) => s.art !== "check");
  const checks = props.checks.slice().sort((a, b) => a.name.localeCompare(b.name, "de"));
  // Herkünfte mit ihrer Zahl an Sensoren (Vorlage oder Satz)
  const herkuenfte = [...checks.reduce((m, c) => (c.herkunft ? m.set(c.herkunft, (m.get(c.herkunft) ?? 0) + 1) : m), new Map<string, number>())].sort(
    (a, b) => a[0].localeCompare(b[0], "de"),
  );
  const loeschenBestaetigt = async () => {
    if (!loeschen) return;
    setArbeitet(true);
    try {
      if ("check" in loeschen) await api("DELETE", `/api/v1/checks/${loeschen.check.id}`);
      else await api("POST", `/api/v1/geraete/${g.id}/checks/herkunft-loeschen`, { herkunft: loeschen.herkunft });
      setLoeschen(null);
      props.onGeaendert();
    } catch (e) {
      props.melden(e);
    } finally {
      setArbeitet(false);
    }
  };
  const ausnahme = async (s: Sensor, an: boolean) => {
    setArbeitet(true);
    try {
      if (an) await api("POST", "/api/v1/sensoren/ausnehmen", { schluessel: s.schluessel, begruendung: grund.trim() });
      else await api("POST", "/api/v1/sensoren/einbeziehen", { schluessel: s.schluessel });
      setAusnehmen(null);
      setGrund("");
      props.onGeaendert();
    } catch (e) {
      props.melden(e);
    } finally {
      setArbeitet(false);
    }
  };
  const fertig = () => {
    setSchritt("");
    setWahl("");
    setBearbeite(null);
    props.onGeaendert();
  };

  return (
    <div className="sensoren-reiter">
      <div className="sensoren-kopf">
        <p className="klein">
          {agent
            ? freigabe
              ? `Am Agent freigegeben: ${freigabe.arten.map((a) => typText[a]).join(", ")}${freigabe.ordner?.length ? ` (Ordner ${freigabe.ordner.join(", ")})` : ""}${freigabe.indikatoren?.length ? ` (Objekte ${freigabe.indikatoren.join(", ")})` : ""}.`
              : "Am Agent sind noch keine Sensoren freigegeben (openwacht-agent sensoren -arten …)."
            : "Ohne Agent: nur Sensoren, die die Zentrale misst."}
        </p>
        {props.darf && schritt === "" && !bearbeite && (
          <button className="knopf knopf-haupt" onClick={() => setSchritt("wahl")}>
            + Sensor
          </button>
        )}
      </div>

      {schritt === "wahl" && (
        <div className="einschub">
          <form
            className="formular formular-flach"
            onSubmit={(e) => {
              e.preventDefault();
              setSchritt("formular");
            }}
          >
            <h3 className="einschub-titel">Sensor hinzufügen</h3>
            <label className="feld formular-voll">
              <span>Vorlage</span>
              <select value={wahl} onChange={(e) => setWahl(e.target.value)}>
                <option value="">Ohne Vorlage (frei einrichten)</option>
                {liste && (
                  <>
                    <optgroup label="Eingebaut">
                      {liste.eingebaut.map((v) => (
                        <option key={v.id} value={v.id} disabled={(v.am_agent && !agent) || (v.typ === "snmp_oid" && !props.hatSnmp)}>
                          {v.name} · {v.am_agent ? "Agent" : v.typ === "snmp_oid" ? "SNMP" : "Zentrale"}
                          {v.am_agent && !agent ? " (nur mit Agent)" : v.typ === "snmp_oid" && !props.hatSnmp ? " (nur mit SNMP)" : ""}
                        </option>
                      ))}
                    </optgroup>
                    {liste.eigene.length > 0 && (
                      <optgroup label="Eigene">
                        {liste.eigene.map((v) => (
                          <option key={v.id} value={v.id} disabled={v.am_agent && !agent}>
                            {v.name} · {v.am_agent ? "Agent" : "Zentrale"}
                          </option>
                        ))}
                      </optgroup>
                    )}
                  </>
                )}
              </select>
            </label>
            {vorlage && (
              <p className="hinweis formular-voll">
                {typText[vorlage.typ]}
                {vorlage.notiz ? `: ${vorlage.notiz}` : ""}
                {vorlage.braucht_adresse && !g.adresse ? " Das Gerät hat keine Adresse; bitte im nächsten Schritt eintragen." : ""}
              </p>
            )}
            <div className="aktionen">
              <button className="knopf knopf-haupt">Weiter</button>
              <button type="button" className="knopf" onClick={() => setSchritt("")}>
                Abbrechen
              </button>
            </div>
          </form>
        </div>
      )}

      {(schritt === "formular" || bearbeite) && (
        <CheckFormular
          key={bearbeite?.id ?? `neu-${wahl}`}
          geraet={g}
          geraete={props.geschwister}
          vergeben={props.checks.map((c) => c.name)}
          check={bearbeite}
          vorlage={bearbeite ? null : vorlage}
          hatAgent={!!agent}
          hatSnmp={props.hatSnmp}
          freigabe={freigabe}
          netze={props.netze}
          onFertig={fertig}
          melden={props.melden}
        />
      )}

      {loeschen && (
        <div className="bestaetigung" role="alertdialog" aria-label="Sensoren löschen">
          <p>
            {"check" in loeschen
              ? `Sensor „${loeschen.check.name}“ von ${g.name} löschen? Verlauf und Alarme des Sensors gehen verloren.`
              : `Alle ${loeschen.anzahl} Sensoren aus „${loeschen.herkunft}“ von ${g.name} löschen? Verlauf und Alarme dieser Sensoren gehen verloren; andere Sensoren bleiben.`}
          </p>
          <div className="aktionen">
            <button className="knopf knopf-gefahr" disabled={arbeitet} onClick={loeschenBestaetigt}>
              Löschen
            </button>
            <button className="knopf" onClick={() => setLoeschen(null)}>
              Abbrechen
            </button>
          </div>
        </div>
      )}

      {ausnehmen && (
        <div className="einschub">
          <form
            className="formular formular-flach"
            onSubmit={(e) => {
              e.preventDefault();
              void ausnahme(ausnehmen, true);
            }}
          >
            <h3 className="einschub-titel">„{ausnehmen.name}“ ausnehmen</h3>
            <p className="hinweis formular-voll">
              Der Wert wird weiter abgefragt, meldet aber keine Alarme mehr; ein offener Alarm endet. Er erscheint grau als
              „ausgenommen“. Die Begründung steht im Audit-Log und am Sensor.
            </p>
            <label className="feld formular-voll">
              <span>Begründung</span>
              <input
                value={grund}
                minLength={3}
                maxLength={300}
                required
                placeholder="z. B. alte Vault-Beziehung, wird nicht mehr gepflegt"
                onChange={(e) => setGrund(e.target.value)}
              />
            </label>
            <div className="aktionen">
              <button className="knopf knopf-haupt" disabled={arbeitet || grund.trim().length < 3}>
                Ausnehmen
              </button>
              <button type="button" className="knopf" onClick={() => setAusnehmen(null)}>
                Abbrechen
              </button>
            </div>
          </form>
        </div>
      )}

      {props.darf && herkuenfte.length > 0 && (
        <ul className="herkunft-liste" aria-label="Sensoren nach Herkunft">
          {herkuenfte.map(([h, n]) => (
            <li key={h}>
              <span className="marke marke-vorlage">{h}</span>
              <span className="klein">
                {n} {n === 1 ? "Sensor" : "Sensoren"}
              </span>
              <button
                className="knopf knopf-klein knopf-gefahr"
                onClick={() => {
                  setSchritt("");
                  setBearbeite(null);
                  setLoeschen({ herkunft: h, anzahl: n });
                }}
              >
                Von diesem Gerät entfernen
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="tabelle-rahmen">
        <table className="tabelle tabelle-kompakt sensoren-tabelle">
          <caption className="sr-only">Sensoren von {g.name}</caption>
          <thead>
            <tr>
              <th scope="col">Sensor</th>
              <th scope="col">Art</th>
              <th scope="col">Herkunft</th>
              <th scope="col">Zustand</th>
              <th scope="col">Kennfarbe</th>
            </tr>
          </thead>
          <tbody>
            {standard.map((s) => (
              <tr key={s.schluessel}>
                <td className="name">
                  {s.name}
                  {props.darf && s.art === "snmp" && s.gegenstand !== "stumm" && s.ausgenommen === undefined && (
                    <button
                      className="knopf-text klein"
                      aria-label={`${s.name} ausnehmen`}
                      onClick={() => {
                        setSchritt("");
                        setBearbeite(null);
                        setGrund("");
                        setAusnehmen(s);
                      }}
                    >
                      Ausnehmen
                    </button>
                  )}
                  {props.darf && s.ausgenommen !== undefined && (
                    <button className="knopf-text klein" aria-label={`${s.name} wieder überwachen`} disabled={arbeitet} onClick={() => void ausnahme(s, false)}>
                      Wieder überwachen
                    </button>
                  )}
                </td>
                <td>
                  Messwert
                  <span className="klein">{standardArt[s.art]}</span>
                </td>
                <td>
                  <span className="marke marke-ende">Standard</span>
                </td>
                <td>
                  <span
                    className={`signal signal-${s.status}${kennStil(s.kennfarbe, s.status).className}`}
                    style={kennStil(s.kennfarbe, s.status).style}
                    aria-hidden="true"
                  />{" "}
                  {s.meldung}
                </td>
                <td>
                  <KennfarbeWahl
                    schluessel={s.schluessel}
                    name={s.name}
                    aktuell={s.kennfarbe}
                    liste={kennfarben.liste}
                    darf={props.darf}
                    onGeaendert={props.onGeaendert}
                    melden={props.melden}
                  />
                </td>
              </tr>
            ))}
            {checks.map((c) => {
              const a = anzeige(c);
              const sn = props.sensoren.find((x) => x.schluessel === `c:${c.id}`);
              return (
                <tr key={c.id}>
                  <td className="name">
                    {c.name}
                    <span className="klein umbruch">{zielText(c)}</span>
                    {props.darf && (
                      <button
                        className="knopf-text klein"
                        aria-label={`${c.name} bearbeiten`}
                        onClick={() => {
                          setSchritt("");
                          setBearbeite(c);
                        }}
                      >
                        Bearbeiten
                      </button>
                    )}
                    {props.darf && (
                      <button
                        className="knopf-text klein knopf-text-gefahr"
                        aria-label={`${c.name} löschen`}
                        onClick={() => {
                          setSchritt("");
                          setBearbeite(null);
                          setLoeschen({ check: c });
                        }}
                      >
                        Löschen
                      </button>
                    )}
                  </td>
                  <td>
                    {typText[c.typ]}
                    <span className="klein">{istAgentArt(c.typ) ? "am Agent" : c.typ === "snmp_oid" ? "mit SNMP" : "an der Zentrale"}</span>
                  </td>
                  <td>
                    {c.herkunft ? (
                      <span className="marke marke-vorlage" title="Kopie aus dieser Vorlage">
                        {c.herkunft}
                      </span>
                    ) : (
                      <span className="marke marke-ende">eigen</span>
                    )}
                  </td>
                  <td>
                    <span className={`signal signal-${a}${kennStil(sn?.kennfarbe, a).className}`} style={kennStil(sn?.kennfarbe, a).style} aria-hidden="true" />{" "}
                    {c.veraltet ? "kein Ergebnis vom Agent" : a === "neu" || a === "pause" ? anzeigeText[a] : c.meldung}
                  </td>
                  <td>
                    <KennfarbeWahl
                      schluessel={`c:${c.id}`}
                      name={c.name}
                      aktuell={sn?.kennfarbe}
                      liste={kennfarben.liste}
                      darf={props.darf}
                      onGeaendert={props.onGeaendert}
                      melden={props.melden}
                    />
                  </td>
                </tr>
              );
            })}
            {standard.length === 0 && checks.length === 0 && (
              <tr>
                <td colSpan={5} className="platzhalter">
                  Noch keine Sensoren. Mit „+ Sensor“ legst du einen an, frei oder aus einer Vorlage.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="klein">
        Sensoren aus einer Vorlage sind Kopien: Ändert sich die Vorlage, bleiben sie, wie sie sind. Sensoren auf dem Agent sind feste
        Messarten mit Parametern, keine Skripte (Leitprinzip 1).
      </p>
    </div>
  );
}
