// SPDX-License-Identifier: AGPL-3.0-only

// Kennfarben verwalten (0.99.2): Name und frei gewählte Farbe je Mandant.
// Die Farbe muss auf hellem und dunklem Grund mindestens 3:1 Kontrast haben;
// die Oberfläche zeigt das beim Wählen, die Zentrale prüft es noch einmal.

import { useId, useState, type CSSProperties, type FormEvent } from "react";
import { api, type KennfarbeEintrag } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";
import { GRUND_DUNKEL, GRUND_HELL, kennfarbePruefen, schriftAuf, zahl } from "./kennfarbe";
import { useKennfarben } from "./SensorenReiter";

// Vorschläge mit genug Kontrast; frei wählbar bleibt jede andere Farbe.
const VORSCHLAEGE = ["#c0307a", "#e05a00", "#00838a", "#7b5cd6", "#8a5a2b", "#2a78d6"];

function Vorschau({ farbe }: { farbe: string }) {
  const stil = { "--kenn": farbe, "--auf-kenn": schriftAuf(farbe) } as CSSProperties;
  return (
    <span className="kenn-vorschau" aria-hidden="true">
      {[GRUND_HELL, GRUND_DUNKEL].map((grund) => (
        <span key={grund} className="kenn-vorschau-grund" style={{ background: grund }}>
          <span className="signal signal-crit kenn" style={stil} />
          <span className="signal signal-warn kenn" style={stil} />
          <span className="zst zst-crit kenn" style={stil}>
            Kritisch
          </span>
        </span>
      ))}
    </span>
  );
}

function Formular(props: {
  bereich: Bereich;
  eintrag: KennfarbeEintrag | null;
  onFertig: (geaendert: boolean) => void;
  melden: (e: unknown) => void;
}) {
  const id = useId();
  const [name, setName] = useState(props.eintrag?.name ?? "");
  const [farbe, setFarbe] = useState(props.eintrag?.farbe ?? VORSCHLAEGE[0]!);
  const [arbeitet, setArbeitet] = useState(false);
  const p = kennfarbePruefen(farbe);

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    if (p.fehler) return;
    setArbeitet(true);
    try {
      const body = { name: name.trim(), farbe: farbe.toLowerCase() };
      if (props.eintrag) await api("PUT", `/api/v1/kennfarben/${props.eintrag.id}`, body);
      else await api("POST", `/api/v1/mandanten/${props.bereich.mandant.id}/kennfarben`, body);
      props.onFertig(true);
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={speichern}>
        <h3 className="einschub-titel">{props.eintrag ? "Kennfarbe ändern" : `Neue Kennfarbe für ${props.bereich.mandant.name}`}</h3>
        <label className="feld">
          <span>Name (erscheint in Legende und Tooltip)</span>
          <input value={name} maxLength={40} required placeholder="z. B. Neustart verpasst" onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="feld">
          <span id={`${id}-farbe`}>Farbe</span>
          <span className="kenn-farbwahl">
            <input type="color" aria-labelledby={`${id}-farbe`} value={/^#[0-9a-f]{6}$/i.test(farbe) ? farbe : "#000000"} onChange={(e) => setFarbe(e.target.value)} />
            <input
              className="mono kenn-hex"
              aria-label="Farbe als #rrggbb"
              value={farbe}
              maxLength={7}
              pattern="#[0-9a-fA-F]{6}"
              onChange={(e) => setFarbe(e.target.value.trim())}
            />
            {VORSCHLAEGE.map((v) => (
              <button
                key={v}
                type="button"
                className="kenn-vorschlag"
                style={{ "--kenn": v } as CSSProperties}
                aria-label={`Vorschlag ${v}`}
                aria-pressed={farbe.toLowerCase() === v}
                onClick={() => setFarbe(v)}
              />
            ))}
          </span>
        </div>
        <div className="formular-voll">
          {!/^#[0-9a-f]{6}$/i.test(farbe) ? (
            <p className="hinweis">Bitte als #rrggbb angeben, z. B. #c0307a.</p>
          ) : (
            <>
              <Vorschau farbe={farbe} />
              <p className={p.fehler ? "hinweis hinweis-fehler" : "klein"} role={p.fehler ? "alert" : undefined}>
                Kontrast hell {zahl(p.hell)}:1, dunkel {zahl(p.dunkel)}:1 (nötig je 3:1). {p.fehler ?? "Passt."}
              </p>
            </>
          )}
        </div>
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={arbeitet || !!p.fehler || !name.trim()}>
            Speichern
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig(false)}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

export function Kennfarben({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const { liste, neuLaden } = useKennfarben(melden);
  const [form, setForm] = useState<"" | "neu" | string>("");
  const [loeschen, setLoeschen] = useState<KennfarbeEintrag | null>(null);
  const darf = darfPflegen(bereich, bereich.mandant.id);
  const bearbeite = liste.find((k) => k.id === form) ?? null;

  return (
    <div className="panel" id="kennfarben">
      <div className="panel-kopf">
        <h2 className="panel-titel">Kennfarben</h2>
        {darf && !form && (
          <button className="knopf knopf-haupt" onClick={() => setForm("neu")}>
            + Kennfarbe
          </button>
        )}
      </div>
      <div className="panel-inhalt">
        <p className="klein">
          Eine Kennfarbe ersetzt Gelb und Rot eines Sensors, wenn er nicht OK ist, z. B. Pink für „Neustart verpasst“. Form und Text der
          Schwere bleiben, Benachrichtigungen ebenso. Bei gleicher Schwere gewinnt am Gerät immer der Sensor ohne Kennfarbe. Zuordnen lässt
          sie sich im Reiter „Sensoren“ eines Geräts und an Trap-Regeln; die Wandanzeige zeigt alle Kennfarben in der Legende.
        </p>
        {(form === "neu" || bearbeite) && (
          <Formular
            key={form}
            bereich={bereich}
            eintrag={bearbeite}
            melden={melden}
            onFertig={(geaendert) => {
              setForm("");
              if (geaendert) neuLaden();
            }}
          />
        )}
        {loeschen && (
          <div className="bestaetigung" role="alertdialog" aria-label="Kennfarbe löschen">
            <p>
              Kennfarbe „{loeschen.name}“ löschen?{" "}
              {loeschen.verwendet > 0
                ? `${loeschen.verwendet} Sensoren bzw. Regeln zeigen danach wieder Gelb und Rot; sie selbst bleiben.`
                : "Sie wird nirgends verwendet."}
            </p>
            <div className="aktionen">
              <button
                className="knopf knopf-gefahr"
                onClick={async () => {
                  try {
                    await api("DELETE", `/api/v1/kennfarben/${loeschen.id}`);
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
        {liste.length === 0 ? (
          <p className="leer">Noch keine Kennfarben.</p>
        ) : (
          <div className="tabelle-rahmen">
            <table className="tabelle tabelle-kompakt">
              <thead>
                <tr>
                  <th scope="col">Kennfarbe</th>
                  <th scope="col">Farbe</th>
                  <th scope="col">Mandant</th>
                  <th scope="col">verwendet</th>
                  <th scope="col">
                    <span className="sr-only">Aktionen</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {liste.map((k) => {
                  const pflegen = darfPflegen(bereich, k.mandant_id);
                  return (
                    <tr key={k.id}>
                      <td>
                        <span className="kenn-marke" style={{ "--kenn": k.farbe } as CSSProperties}>
                          {k.name}
                        </span>
                      </td>
                      <td className="mono">{k.farbe}</td>
                      <td>{mandantName(bereich, k.mandant_id) || "übergeordnet"}</td>
                      <td className="mono">{k.verwendet}</td>
                      <td className="nowrap">
                        {pflegen && (
                          <>
                            <button className="knopf knopf-klein" onClick={() => setForm(k.id)}>
                              Ändern
                            </button>{" "}
                            <button className="knopf knopf-klein knopf-gefahr" onClick={() => setLoeschen(k)}>
                              Löschen
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
