// SPDX-License-Identifier: AGPL-3.0-only

// Geräte aus einer CSV-Datei anlegen (Etappe 27): erst prüfen, dann anlegen.
// Die Zentrale legt alles in einer Transaktion an; hat eine Zeile einen
// Fehler, wird nichts angelegt.

import { useState, type ChangeEvent } from "react";
import { api, ApiError, type Mandant } from "./api";

interface Zeile {
  zeile: number;
  name: string;
  ok: boolean;
  fehler?: string;
  gruppe?: string;
  profil?: string;
  vorlage?: string;
}

interface Antwort {
  zeilen: Zeile[];
  fehlerhaft: number;
  angelegt: number;
  fehler?: string;
}

const beispiel =
  "name;adresse;gruppe;profil;vorlage\nsw-hauptsitz-01;10.10.0.2;Hauptsitz/Keller;Switches;Ping mit Verlust\ndrucker-2og;drucker2.lan;;;";

export function GeraeteImport(props: { mandant: Mandant; onSchliessen: (angelegt: boolean) => void; melden: (e: unknown) => void }) {
  const [text, setText] = useState("");
  const [ergebnis, setErgebnis] = useState<Antwort | null>(null);
  const [geprueft, setGeprueft] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const senden = async (nurPruefen: boolean) => {
    setFehler("");
    setArbeitet(true);
    try {
      const r = await api<Antwort>("POST", `/api/v1/mandanten/${props.mandant.id}/geraete/import`, { csv: text, nur_pruefen: nurPruefen });
      if (nurPruefen) {
        setErgebnis(r);
        setGeprueft(text);
      } else {
        props.onSchliessen(true);
      }
    } catch (err) {
      if (err instanceof ApiError && Array.isArray(err.body.zeilen)) {
        setErgebnis(err.body as unknown as Antwort);
        setGeprueft(text);
      } else {
        setErgebnis(null);
        setFehler(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setArbeitet(false);
    }
  };

  const datei = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 256 * 1024) {
      setFehler("Die Datei ist zu groß (höchstens 256 KiB).");
      return;
    }
    setText(await f.text());
    setErgebnis(null);
  };

  const bereit = ergebnis !== null && ergebnis.fehlerhaft === 0 && geprueft === text && text.trim() !== "";
  return (
    <div className="einschub">
      <div className="formular formular-flach">
        <h3 className="einschub-titel">Geräte importieren (CSV)</h3>
        <p className="hinweis formular-voll">
          Neue Geräte in „{props.mandant.name}“, höchstens 500 je Datei. Kopfzeile mit den Spalten{" "}
          <code>name;adresse;gruppe;profil;vorlage</code> (Trennzeichen <code>;</code> oder <code>,</code>, nur <code>name</code> ist
          Pflicht). Gruppen als Pfad <code>Oben/Unten</code>, sie müssen schon bestehen. Profil ist ein SNMP-Profil (nur Admins), Vorlage
          eine Sensor-Vorlage ohne Agent.
        </p>
        <label className="feld formular-voll">
          <span>Datei</span>
          <input type="file" accept=".csv,text/csv,text/plain" onChange={(e) => void datei(e)} />
        </label>
        <label className="feld formular-voll">
          <span>Inhalt</span>
          <textarea
            className="csv-feld"
            rows={8}
            spellCheck={false}
            value={text}
            placeholder={beispiel}
            onChange={(e) => {
              setText(e.target.value);
              setErgebnis(null);
            }}
          />
        </label>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        {ergebnis && (
          <div className="formular-voll">
            <p className={ergebnis.fehlerhaft ? "meldung meldung-fehler" : "meldung meldung-ok"} role="status">
              {ergebnis.fehlerhaft
                ? `${ergebnis.fehlerhaft} von ${ergebnis.zeilen.length} Zeilen haben Fehler. Bitte korrigieren und erneut prüfen; angelegt wird nur alles oder nichts.`
                : `${ergebnis.zeilen.length} ${ergebnis.zeilen.length === 1 ? "Gerät ist" : "Geräte sind"} bereit zum Anlegen.`}
            </p>
            <div className="tabelle-rahmen">
              <table className="tabelle">
                <thead>
                  <tr>
                    <th scope="col">Zeile</th>
                    <th scope="col">Name</th>
                    <th scope="col">Gruppe</th>
                    <th scope="col">Profil</th>
                    <th scope="col">Vorlage</th>
                    <th scope="col">Ergebnis</th>
                  </tr>
                </thead>
                <tbody>
                  {ergebnis.zeilen.map((z) => (
                    <tr key={z.zeile} className={z.ok ? undefined : "zeile-fehler"}>
                      <td>{z.zeile}</td>
                      <td className="name umbruch">{z.name}</td>
                      <td className="umbruch">{z.gruppe}</td>
                      <td className="umbruch">{z.profil}</td>
                      <td className="umbruch">{z.vorlage}</td>
                      <td className="umbruch">{z.ok ? "OK" : z.fehler}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        <div className="aktionen">
          <button type="button" className="knopf" disabled={arbeitet || !text.trim()} onClick={() => void senden(true)}>
            {arbeitet ? "Prüft …" : "Prüfen"}
          </button>
          <button type="button" className="knopf knopf-haupt" disabled={arbeitet || !bereit} onClick={() => void senden(false)}>
            {bereit ? `${ergebnis.zeilen.length} anlegen` : "Anlegen"}
          </button>
          <button type="button" className="knopf" onClick={() => props.onSchliessen(false)}>
            Abbrechen
          </button>
        </div>
      </div>
    </div>
  );
}
