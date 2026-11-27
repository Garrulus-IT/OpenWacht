// SPDX-License-Identifier: AGPL-3.0-only

// Citrix-Site eines Geräts (1.0.6): Monitor Service (OData v4) am Delivery
// Controller. Zeigt registrierte und nicht registrierte VDAs (Namen nur der
// nicht registrierten) und fehlgeschlagene Verbindungen der letzten Stunde
// als Zahl je Fehlerart, nie Benutzer. Einrichten mit „Verbindung prüfen“ und
// Fingerabdruck; Anmeldung per Windows-Anmeldung (NTLM), nur HTTPS.
//
// Benutzer und Passwort verlassen die Zentrale nie wieder: Die Liste sagt nur,
// ob Zugangsdaten gespeichert sind. Einrichten, ändern und entfernen dürfen
// nur Admins.

import { useState, type FormEvent } from "react";
import { api, type CitrixInfo, type Geraet, type Snmp } from "./api";
import { abdruck } from "./FritzBox";
import { vor } from "./zeit";

// ConnectionFailureEnumValue (Citrix Monitor Service), wie in der Zentrale.
const fehlerText: Record<number, string> = {
  0: "unbekannt",
  2: "Sitzung vorbereiten",
  3: "Registrierung abgelaufen",
  4: "Verbindung abgelaufen",
  5: "Lizenz",
  6: "Ticket",
  7: "sonstiges",
  8: "allgemeiner Fehler",
  9: "Wartungsmodus",
  10: "Anwendung deaktiviert",
  11: "Funktion nicht lizenziert",
  12: "keine Maschine frei",
  13: "Sitzungsgrenze erreicht",
};

export function citrixKurz(q: Snmp) {
  const x = q.messwerte?.citrix;
  if (!q.aktiv) return "Citrix-Abfrage ausgeschaltet";
  if (!x) return q.fehler ? `Citrix: ${q.fehler}` : "Citrix: noch nicht abgefragt";
  const teile = [`Citrix ${x.registriert} von ${x.vdas} VDAs registriert`];
  if (x.nicht_registriert > 0) teile.push(`${x.nicht_registriert} nicht registriert`);
  if (x.fehler_gesamt > 0) teile.push(`${x.fehler_gesamt} Verbindungsfehler in ${x.fehler_minuten} Min.`);
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

export function CitrixTeil(props: {
  q: Snmp;
  g: Geraet;
  darfAdmin: boolean;
  darfPflegen: boolean;
  jetzt: number;
  onBearbeiten: () => void;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
  ohneAktionen?: boolean;
  entfernen?: boolean;
  onEntfernenEnde?: () => void;
}) {
  const { q, jetzt } = props;
  const x = q.messwerte?.citrix;
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (v: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(v);
    else if (!v) props.onEntfernenEnde?.();
  };
  const fehlt = q.messwerte?.teilweise ?? [];
  return (
    <div className="geraet-snmp geraet-citrix">
      <h3 className="klein-titel">
        Citrix-Site
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port} (Delivery Controller, Monitor Service), alle {q.intervall_sekunden} s
        {q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, jetzt)}` : ""}
        {!q.hat_community && " · keine Zugangsdaten gespeichert"}
        {x?.fingerabdruck && ` · HTTPS, Zertifikat ${abdruck(x.fingerabdruck).slice(0, 23)}…`}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {fehlt.includes("fehler") && <p className="meldung meldung-warnung">Fehlgeschlagene Verbindungen nicht abfragbar. Letzter Zustand bleibt.</p>}
      {x && (
        <dl className="eckdaten">
          <div>
            <dt>VDAs</dt>
            <dd>{x.vdas}</dd>
          </div>
          <div>
            <dt>registriert</dt>
            <dd>{x.registriert}</dd>
          </div>
          <div>
            <dt>im Wartungsmodus</dt>
            <dd>{x.wartung}</dd>
          </div>
          <div>
            <dt>nicht registriert</dt>
            <dd>{x.nicht_registriert}</dd>
          </div>
          <div>
            <dt>Verbindungsfehler ({x.fehler_minuten} Min.)</dt>
            <dd>{x.fehler_gesamt}</dd>
          </div>
        </dl>
      )}
      {x && (x.nicht_registriert_namen ?? []).length > 0 && (
        <p className="klein">
          Nicht registriert (ohne Wartungsmodus): <span className="mono">{(x.nicht_registriert_namen ?? []).join(", ")}</span>
          {x.nicht_registriert > (x.nicht_registriert_namen ?? []).length && " …"}
        </p>
      )}
      {x && (x.fehler ?? []).length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Fehlerart</th>
                <th scope="col">Anzahl</th>
              </tr>
            </thead>
            <tbody>
              {(x.fehler ?? []).map((f) => (
                <tr key={f.code}>
                  <td>{fehlerText[f.code] ?? `Code ${f.code}`}</td>
                  <td>{f.anzahl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="Citrix-Abfrage entfernen">
              <p>
                Citrix-Abfrage für „{props.g.name}“ entfernen? Zugangsdaten und Meldezustand gehen verloren; das Alarmprotokoll bleibt. Die Rolle
                des AD-Kontos in Citrix bitte zusätzlich entfernen.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/citrix`);
                      props.onGeaendert();
                    } catch (e) {
                      props.melden(e);
                    }
                    setEntfernen(false);
                  }}
                >
                  Entfernen
                </button>
                <button className="knopf" onClick={() => setEntfernen(false)}>
                  Abbrechen
                </button>
              </div>
            </div>
          ) : (
            <>
              {props.darfPflegen && q.aktiv && (
                <button
                  className="knopf"
                  onClick={async () => {
                    try {
                      await api("POST", `/api/v1/snmp/${q.id}/jetzt`);
                      setTimeout(props.onGeaendert, 2500);
                    } catch (e) {
                      props.melden(e);
                    }
                  }}
                >
                  Jetzt abfragen
                </button>
              )}
              {props.darfAdmin && (
                <>
                  <button className="knopf" onClick={props.onBearbeiten}>
                    Citrix bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    Citrix entfernen
                  </button>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// --- Einrichten und bearbeiten ---------------------------------------------------------

type Pruefung = { ok: true; citrix: CitrixInfo } | { ok: false; fehler: string; fingerabdruck_neu?: string };

export function CitrixFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const gespeichert = q?.messwerte?.citrix?.fingerabdruck;
  const [adresse, setAdresse] = useState(q?.adresse ?? props.g.adresse ?? "");
  const [port, setPort] = useState(String(q?.port ?? 443));
  const [benutzer, setBenutzer] = useState("");
  const [passwort, setPasswort] = useState("");
  // leer = beim Ändern der gespeicherte Fingerabdruck
  const [abdruckFeld, setAbdruckFeld] = useState("");
  const [intervall, setIntervall] = useState(String(q?.intervall_sekunden ?? 300));
  const [aktiv, setAktiv] = useState(q?.aktiv ?? true);
  const [fehler, setFehler] = useState("");
  const [pruefung, setPruefung] = useState<Pruefung | null>(null);
  const [prueft, setPrueft] = useState(false);
  const zielNeu = !q || adresse.trim() !== q.adresse || (Number(port) || 443) !== q.port;

  const daten = () => {
    const d: Record<string, unknown> = {
      adresse: adresse.trim(),
      port: Number(port) || 443,
      benutzer: benutzer.trim(),
      intervall_sekunden: Number(intervall) || 300,
      aktiv,
    };
    if (passwort) d.passwort = passwort;
    if (abdruckFeld.trim()) d.fingerabdruck = abdruckFeld.trim();
    return d;
  };
  const pruefen = async () => {
    setFehler("");
    setPruefung(null);
    setPrueft(true);
    try {
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/citrix/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/citrix`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  const neuerAbdruck = pruefung && !pruefung.ok ? pruefung.fingerabdruck_neu : undefined;
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "Citrix bearbeiten" : `Citrix für „${props.g.name}“ einrichten`}</h3>
        <details className="formular-voll hinweis">
          <summary>Nur lesendes Konto in Citrix einrichten</summary>
          <p className="klein">
            In Web Studio bzw. Citrix Studio unter „Administratoren“ ein AD-Konto (z. B. svc-openwacht) mit der Rolle „Read Only Administrator“
            und dem Bereich „Alle“ hinzufügen. OpenWacht liest nur: Maschinen (Name, Registrierung, Wartungsmodus) und fehlgeschlagene
            Verbindungen der letzten Stunde als Zahl je Fehlerart, nie Benutzer. Adresse: ein Delivery Controller, HTTPS (der Monitor Service
            antwortet unter /Citrix/Monitor/OData/v4/Data/), die Anmeldung läuft per Windows-Anmeldung (NTLM).
          </p>
        </details>
        <label className="feld">
          <span>Adresse des Delivery Controllers</span>
          <input required maxLength={253} value={adresse} placeholder="ddc-01.beispiel.example" onChange={(e) => setAdresse(e.target.value)} />
        </label>
        <label className="feld feld-schmal">
          <span>Port</span>
          <input inputMode="numeric" pattern="[0-9]*" value={port} placeholder="443" onChange={(e) => setPort(e.target.value)} />
        </label>
        <label className="feld">
          <span>Benutzer (AD-Konto)</span>
          <input
            autoComplete="off"
            spellCheck={false}
            required
            maxLength={300}
            value={benutzer}
            placeholder="BEISPIEL\svc-openwacht"
            onChange={(e) => setBenutzer(e.target.value)}
          />
        </label>
        <label className="feld">
          <span>Passwort{zielNeu && q ? " (bei neuer Adresse oder neuem Port neu eingeben)" : q ? " (leer = unverändert)" : ""}</span>
          <input
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            required={!q || zielNeu}
            maxLength={256}
            value={passwort}
            placeholder={q ? "••••••••" : ""}
            onChange={(e) => setPasswort(e.target.value)}
          />
        </label>
        <label className="feld formular-voll">
          <span>
            Fingerabdruck des Zertifikats (SHA-256)
            {gespeichert && !zielNeu ? " (leer = unverändert)" : " (über „Verbindung prüfen“ holen)"}
          </span>
          <input
            spellCheck={false}
            className="mono"
            maxLength={100}
            value={abdruckFeld}
            placeholder={gespeichert ? abdruck(gespeichert) : "AB:CD:…"}
            onChange={(e) => setAbdruckFeld(e.target.value)}
          />
        </label>
        <label className="feld feld-schmal">
          <span>Abfrage alle</span>
          <select value={intervall} onChange={(e) => setIntervall(e.target.value)}>
            {[60, 120, 300, 600, 900, 1800, 3600].map((s) => (
              <option key={s} value={s}>
                {s < 3600 ? `${s / 60} Min.` : "1 Std."}
              </option>
            ))}
          </select>
        </label>
        {q && (
          <label className="haken formular-voll">
            <input type="checkbox" checked={aktiv} onChange={(e) => setAktiv(e.target.checked)} />
            <span>Abfrage eingeschaltet</span>
          </label>
        )}
        {pruefung &&
          (pruefung.ok ? (
            <p className="meldung meldung-ok formular-voll" role="status">
              Verbunden: {pruefung.citrix.vdas} VDAs, davon {pruefung.citrix.nicht_registriert} nicht registriert;{" "}
              {pruefung.citrix.fehler_nicht_lesbar
                ? "fehlgeschlagene Verbindungen nicht lesbar."
                : `${pruefung.citrix.fehler_gesamt} fehlgeschlagene Verbindungen in der letzten Stunde.`}
            </p>
          ) : neuerAbdruck ? (
            <div className="meldung meldung-warnung formular-voll" role="status">
              <p>
                {pruefung.fehler} Der Controller zeigt dieses Zertifikat:
                <br />
                <span className="mono umbruch">{neuerAbdruck}</span>
              </p>
              <p className="klein">
                Zum Vergleich auf dem Controller in der Zertifikatsverwaltung (certlm.msc → Eigene Zertifikate → Zertifikat → Details →
                Fingerabdruck; Windows zeigt dort SHA-1). SHA-256 in PowerShell:{" "}
                <span className="mono">
                  [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash((Get-Item
                  Cert:\LocalMachine\My\&lt;SHA-1-Fingerabdruck&gt;).RawData))
                </span>
                . Nur übernehmen, wenn er übereinstimmt.
              </p>
              <button type="button" className="knopf" onClick={() => setAbdruckFeld(neuerAbdruck)}>
                Fingerabdruck übernehmen
              </button>
            </div>
          ) : (
            <p className="meldung meldung-fehler formular-voll" role="status">
              Keine Verbindung: {pruefung.fehler}
            </p>
          ))}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Speichern</button>
          <button type="button" className="knopf" disabled={prueft} onClick={() => void pruefen()}>
            {prueft ? "Prüft …" : "Verbindung prüfen"}
          </button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
