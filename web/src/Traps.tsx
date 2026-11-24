// SPDX-License-Identifier: AGPL-3.0-only

// Traps (Etappe 14): Protokoll und Zustände am Gerät, Regeln unter Hosts →
// „Trap-Regeln“.
//
// Traps empfängt ein eigener Dienst der Zentrale. Was ein Trap bewirkt,
// legen Regeln je Mandant fest (erste passende gilt, eigener Mandant vor den
// Eltern). Pflegen dürfen nur Admins; Zustände zurücksetzen Admins und
// Operatoren. Alle Texte kommen als Text in die Oberfläche (kein HTML).

import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  api,
  type Geraet,
  type Gruppe,
  type Snmp,
  type TrapEintrag,
  type TrapRegel,
  type TrapVergleich,
  type TrapWirkung,
  type TrapZustand,
} from "./api";
import { optionen } from "./Gruppen";
import { mandantName, rolleIn, type Bereich } from "./bereich";
import { vor } from "./zeit";
import { KennMarke, kennStil } from "./kennfarbe";
import { useKennfarben } from "./SensorenReiter";

export const wirkungText: Record<TrapWirkung | "none", string> = {
  warn: "Warnung",
  crit: "Kritisch",
  ok: "Entwarnung",
  ignore: "ignorieren",
  none: "keine Regel",
};

const vergleichText: Record<TrapVergleich, string> = {
  gleich: "ist gleich",
  nicht: "ist nicht",
  enthaelt: "enthält",
  beginnt: "beginnt mit",
};

// Häufige Traps (SNMPv2-MIB, IF-MIB, UPS-MIB) als Vorschläge.
const bekannteTraps: { oid: string; name: string }[] = [
  { oid: "1.3.6.1.6.3.1.1.5.1", name: "coldStart (Kaltstart)" },
  { oid: "1.3.6.1.6.3.1.1.5.2", name: "warmStart (Warmstart)" },
  { oid: "1.3.6.1.6.3.1.1.5.3", name: "linkDown (Schnittstelle getrennt)" },
  { oid: "1.3.6.1.6.3.1.1.5.4", name: "linkUp (Schnittstelle verbunden)" },
  { oid: "1.3.6.1.6.3.1.1.5.5", name: "authenticationFailure (Anmeldefehler)" },
  { oid: "1.3.6.1.2.1.33.2.1", name: "upsTrapOnBattery (USV im Batteriebetrieb)" },
  { oid: "1.3.6.1.2.1.33.2.3", name: "upsTrapAlarmEntryAdded (USV-Alarm)" },
  { oid: "*", name: "alle Traps" },
];
const bekannteWerte: { oid: string; name: string }[] = [
  { oid: "1.3.6.1.2.1.2.2.1.1", name: "ifIndex (Nummer der Schnittstelle)" },
  { oid: "1.3.6.1.2.1.2.2.1.2", name: "ifDescr (Beschreibung der Schnittstelle)" },
  { oid: "1.3.6.1.2.1.31.1.1.1.1", name: "ifName (Name der Schnittstelle)" },
];

function trapText(e: { trap_name: string; trap_oid: string }) {
  return e.trap_name ? `${e.trap_name} (${e.trap_oid})` : e.trap_oid;
}

// --- Am Gerät -----------------------------------------------------------------------

export function TrapTeil(props: { q: Snmp; darfPflegen: boolean; jetzt: number; melden: (e: unknown) => void }) {
  const { q } = props;
  const [daten, setDaten] = useState<{ traps: TrapEintrag[]; zustaende: TrapZustand[] } | null>(null);
  const [alle, setAlle] = useState(false);
  const laden = useCallback(async () => {
    try {
      setDaten(
        await api<{ traps: TrapEintrag[]; zustaende: TrapZustand[] }>("GET", `/api/v1/snmp/${q.id}/traps?anzahl=${alle ? 200 : 15}`),
      );
    } catch (e) {
      props.melden(e);
    }
  }, [q.id, alle, props.melden]);
  // Neu laden, wenn sich die Quelle ändert (die Hosts-Ansicht lädt alle 15 s neu).
  useEffect(() => {
    void laden();
  }, [laden, q.zuletzt_versucht]);

  const zuruecksetzen = async (z: TrapZustand) => {
    try {
      await api("POST", `/api/v1/snmp/${q.id}/traps/zuruecksetzen`, { regel: z.regel, instanz: z.instanz });
      await laden();
    } catch (e) {
      props.melden(e);
    }
  };

  return (
    <div className="trap-teil">
      <h3 className="klein-titel">Traps</h3>
      {daten === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : (
        <>
          {daten.zustaende.length > 0 && (
            <ul className="liste-schlicht">
              {daten.zustaende.map((z) => (
                <li key={z.regel + "\u0000" + z.instanz}>
                  <span className={`marke marke-${z.status}${kennStil(z.kennfarbe, z.status).className}`} style={kennStil(z.kennfarbe, z.status).style}>
                    {wirkungText[z.status]}
                  </span>{" "}
                  {z.name}
                  {z.instanz && ` (${z.instanz})`}
                  {!z.bestaetigt && (
                    <span className="marke marke-unknown" title="v1/v2c-Traps lassen sich fälschen.">
                      unbestätigt
                    </span>
                  )}
                  <span className="klein">
                    {" "}
                    seit {vor(z.seit, props.jetzt)}
                    {z.anzahl > 1 && `, ${z.anzahl}×`}
                    {z.bis ? `, endet ${new Date(z.bis).toLocaleString("de-DE")}` : ", bis zur Entwarnung"}
                  </span>
                  <br />
                  <span className="klein">{z.meldung}</span>
                  {props.darfPflegen && (
                    <>
                      {" "}
                      <button className="knopf-text" onClick={() => void zuruecksetzen(z)}>
                        Zurücksetzen
                      </button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          {daten.traps.length === 0 ? (
            <p className="klein">Noch keine Traps empfangen.</p>
          ) : (
            <div className="tabelle-rahmen">
              <table className="tabelle tabelle-kompakt">
                <thead>
                  <tr>
                    <th scope="col">Empfangen</th>
                    <th scope="col">Trap</th>
                    <th scope="col">Werte</th>
                    <th scope="col">Regel</th>
                  </tr>
                </thead>
                <tbody>
                  {daten.traps.map((e) => (
                    <tr key={e.id}>
                      <td>
                        {vor(e.empfangen, props.jetzt)}
                        <br />
                        <span className="klein">
                          v{e.version}
                          {e.inform ? ", Inform" : ""}
                          {!e.bestaetigt && ", unbestätigt"}
                        </span>
                      </td>
                      <td className="mono">{trapText(e)}</td>
                      <td>
                        <ul className="trap-werte">
                          {e.werte.slice(0, 6).map((w, i) => (
                            <li key={i}>
                              <span className="mono">{w.oid}</span> = {w.wert || `(${w.typ})`}
                            </li>
                          ))}
                          {e.werte.length > 6 && <li>… {e.werte.length - 6} weitere</li>}
                        </ul>
                      </td>
                      <td>
                        {e.ergebnis === "none" ? "–" : wirkungText[e.ergebnis]}
                        {e.regel_name && <span className="klein"> ({e.regel_name})</span>}
                        <KennMarke k={e.kennfarbe} status={e.ergebnis} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {daten.traps.length >= 15 && (
            <button className="knopf-text" onClick={() => setAlle(!alle)}>
              {alle ? "Weniger anzeigen" : "Mehr anzeigen (bis 200)"}
            </button>
          )}
        </>
      )}
    </div>
  );
}

// --- Regeln -------------------------------------------------------------------------

interface RegelWerte {
  name: string;
  aktiv: boolean;
  eingrenzung: string; // "" | "g:<id>" | "d:<id>"
  trap_oid: string;
  bedingung: boolean;
  wert_oid: string;
  wert_vergleich: TrapVergleich;
  wert: string;
  wirkung: TrapWirkung;
  schluessel_oid: string;
  dauer: string;
  beendet: string;
  kennfarbe: string;
}

function regelStart(r: TrapRegel | null): RegelWerte {
  return {
    name: r?.name ?? "",
    aktiv: r?.aktiv ?? true,
    eingrenzung: r?.gruppe_id ? `g:${r.gruppe_id}` : r?.geraet_id ? `d:${r.geraet_id}` : "",
    trap_oid: r?.trap_oid ?? "",
    bedingung: !!r?.wert_oid,
    wert_oid: r?.wert_oid ?? "",
    wert_vergleich: r?.wert_vergleich ?? "gleich",
    wert: r?.wert ?? "",
    wirkung: r?.wirkung ?? "warn",
    schluessel_oid: r?.schluessel_oid ?? "",
    dauer: String(r?.dauer_minuten ?? 60),
    beendet: r?.beendet ?? "",
    kennfarbe: r?.kennfarbe_id ?? "",
  };
}

function regelDaten(w: RegelWerte, mandant: string) {
  return {
    mandant_id: mandant,
    name: w.name.trim(),
    aktiv: w.aktiv,
    gruppe_id: w.eingrenzung.startsWith("g:") ? w.eingrenzung.slice(2) : "",
    geraet_id: w.eingrenzung.startsWith("d:") ? w.eingrenzung.slice(2) : "",
    trap_oid: w.trap_oid.trim(),
    wert_oid: w.bedingung ? w.wert_oid.trim() : "",
    wert_vergleich: w.bedingung ? w.wert_vergleich : "",
    wert: w.bedingung ? w.wert : "",
    wirkung: w.wirkung,
    schluessel_oid: w.wirkung === "ignore" ? "" : w.schluessel_oid.trim(),
    dauer_minuten: w.wirkung === "warn" || w.wirkung === "crit" ? Number(w.dauer) || 0 : 60,
    beendet: w.wirkung === "ok" ? w.beendet : "",
    kennfarbe_id: w.wirkung === "warn" || w.wirkung === "crit" ? w.kennfarbe : "",
  };
}

function eingrenzungText(r: TrapRegel, gruppen: Gruppe[], geraete: Geraet[]) {
  if (r.gruppe_id) {
    const o = optionen(gruppen, r.mandant_id).find((x) => x.id === r.gruppe_id);
    return `Gruppe ${o?.text ?? "?"}`;
  }
  if (r.geraet_id) return `Gerät ${geraete.find((g) => g.id === r.geraet_id)?.name ?? "?"}`;
  return "alle Geräte";
}

function RegelFormular(props: {
  mandant: string;
  regel: TrapRegel | null;
  regeln: TrapRegel[];
  gruppen: Gruppe[];
  geraete: Geraet[];
  onFertig: (geaendert: boolean) => void;
}) {
  const [w, setW] = useState(() => regelStart(props.regel));
  const [fehler, setFehler] = useState("");
  const kennfarben = useKennfarben((e) => setFehler(e instanceof Error ? e.message : String(e)));
  const ziele = props.regeln.filter(
    (r) => r.mandant_id === props.mandant && (r.wirkung === "warn" || r.wirkung === "crit") && r.id !== props.regel?.id,
  );
  const gruppen = optionen(props.gruppen, props.mandant);
  const geraete = props.geraete.filter((g) => g.mandant_id === props.mandant).sort((a, b) => a.name.localeCompare(b.name, "de"));
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      if (props.regel) await api("PUT", `/api/v1/trapregeln/${props.regel.id}`, regelDaten(w, props.mandant));
      else await api("POST", "/api/v1/trapregeln", regelDaten(w, props.mandant));
      props.onFertig(true);
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  const zustand = w.wirkung === "warn" || w.wirkung === "crit";
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{props.regel ? "Regel bearbeiten" : "Regel hinzufügen"}</h3>
        <label className="feld">
          <span>Name</span>
          <input
            required
            maxLength={100}
            value={w.name}
            placeholder="z. B. Port getrennt"
            onChange={(e) => setW({ ...w, name: e.target.value })}
          />
        </label>
        <label className="feld">
          <span>Trap-OID</span>
          <input
            required
            maxLength={200}
            list="trap-oids"
            className="mono"
            value={w.trap_oid}
            placeholder="1.3.6.1.6.3.1.1.5.3, ….* oder *"
            onChange={(e) => setW({ ...w, trap_oid: e.target.value })}
          />
          <datalist id="trap-oids">
            {bekannteTraps.map((t) => (
              <option key={t.oid} value={t.oid}>
                {t.name}
              </option>
            ))}
          </datalist>
        </label>
        <label className="feld feld-schmal">
          <span>Wirkung</span>
          <select value={w.wirkung} onChange={(e) => setW({ ...w, wirkung: e.target.value as TrapWirkung })}>
            <option value="warn">Warnung</option>
            <option value="crit">Fehler</option>
            <option value="ok">Entwarnung</option>
            <option value="ignore">ignorieren</option>
          </select>
        </label>
        <label className="feld">
          <span>Gilt für</span>
          <select value={w.eingrenzung} onChange={(e) => setW({ ...w, eingrenzung: e.target.value })}>
            <option value="">alle Geräte (auch Untermandanten)</option>
            {gruppen.length > 0 && (
              <optgroup label="Gruppe (mit Untergruppen)">
                {gruppen.map((g) => (
                  <option key={g.id} value={`g:${g.id}`}>
                    {g.text}
                  </option>
                ))}
              </optgroup>
            )}
            {geraete.length > 0 && (
              <optgroup label="Gerät">
                {geraete.map((g) => (
                  <option key={g.id} value={`d:${g.id}`}>
                    {g.name}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>
        {w.wirkung === "ok" && (
          <label className="feld">
            <span>Beendet den Zustand von</span>
            <select required value={w.beendet} onChange={(e) => setW({ ...w, beendet: e.target.value })}>
              <option value="">– Regel wählen –</option>
              {ziele.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {zustand && kennfarben.liste.length > 0 && (
          <label className="feld">
            <span>Kennfarbe (optional, statt Gelb bzw. Rot)</span>
            <select value={w.kennfarbe} onChange={(e) => setW({ ...w, kennfarbe: e.target.value })}>
              <option value="">keine</option>
              {kennfarben.liste.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {w.wirkung !== "ignore" && (
          <label className="feld">
            <span>Unterscheiden nach (OID, optional)</span>
            <input
              maxLength={200}
              list="trap-werte"
              className="mono"
              value={w.schluessel_oid}
              placeholder="z. B. 1.3.6.1.2.1.2.2.1.1 (ifIndex)"
              onChange={(e) => setW({ ...w, schluessel_oid: e.target.value })}
            />
            <datalist id="trap-werte">
              {bekannteWerte.map((t) => (
                <option key={t.oid} value={t.oid}>
                  {t.name}
                </option>
              ))}
            </datalist>
          </label>
        )}
        {zustand && (
          <label className="feld feld-schmal">
            <span>Endet nach (Minuten)</span>
            <input inputMode="numeric" pattern="[0-9]*" value={w.dauer} onChange={(e) => setW({ ...w, dauer: e.target.value })} />
          </label>
        )}
        <label className="haken formular-voll">
          <input type="checkbox" checked={w.bedingung} onChange={(e) => setW({ ...w, bedingung: e.target.checked })} />
          <span>Nur wenn ein Wert passt</span>
        </label>
        {w.bedingung && (
          <>
            <label className="feld">
              <span>OID des Werts</span>
              <input
                required
                maxLength={200}
                list="trap-werte"
                className="mono"
                value={w.wert_oid}
                onChange={(e) => setW({ ...w, wert_oid: e.target.value })}
              />
            </label>
            <label className="feld feld-schmal">
              <span>Vergleich</span>
              <select value={w.wert_vergleich} onChange={(e) => setW({ ...w, wert_vergleich: e.target.value as TrapVergleich })}>
                {Object.entries(vergleichText).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Wert</span>
              <input maxLength={200} value={w.wert} onChange={(e) => setW({ ...w, wert: e.target.value })} />
            </label>
          </>
        )}
        <label className="haken formular-voll">
          <input type="checkbox" checked={w.aktiv} onChange={(e) => setW({ ...w, aktiv: e.target.checked })} />
          <span>Regel aktiv</span>
        </label>
        <p className="hinweis klein formular-voll">
          {zustand
            ? "Der Zustand endet durch eine Entwarnung, nach der eingestellten Zeit (0 = nie) oder von Hand. „Unterscheiden nach“ trennt Zustände, z. B. je Schnittstelle."
            : w.wirkung === "ok"
              ? "Mit „Unterscheiden nach“ beendet die Entwarnung nur den Zustand mit demselben Wert (z. B. dieselbe Schnittstelle), sonst alle Zustände der Regel."
              : "Ignorierte Traps stehen im Protokoll, bewirken aber nichts."}{" "}
          Groß- und Kleinschreibung zählt beim Vergleich nicht.
        </p>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Speichern</button>
          <button type="button" className="knopf" onClick={() => props.onFertig(false)}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

function regelBeschreibung(r: TrapRegel, regeln: TrapRegel[]) {
  const teile = [r.trap_oid === "*" ? "alle Traps" : r.trap_oid];
  if (r.wert_oid) teile.push(`wenn ${r.wert_oid} ${vergleichText[r.wert_vergleich ?? "gleich"]} „${r.wert ?? ""}“`);
  if (r.schluessel_oid) teile.push(`je ${r.schluessel_oid}`);
  if (r.wirkung === "ok") teile.push(`beendet „${regeln.find((x) => x.id === r.beendet)?.name ?? "?"}“`);
  if (r.wirkung === "warn" || r.wirkung === "crit")
    teile.push(r.dauer_minuten ? `endet nach ${r.dauer_minuten} Min.` : "bis zur Entwarnung");
  return teile.join(" · ");
}

export function TrapRegeln(props: {
  bereich: Bereich;
  gruppen: Gruppe[];
  geraete: Geraet[];
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const { bereich } = props;
  const [daten, setDaten] = useState<{ regeln: TrapRegel[]; engine_id: string; dienst_gestartet: string | null } | null>(null);
  const [bearbeite, setBearbeite] = useState<{ mandant: string; regel: TrapRegel | null } | null>(null);
  const [loeschen, setLoeschen] = useState<TrapRegel | null>(null);
  const kennfarben = useKennfarben(props.melden);
  const laden = useCallback(async () => {
    try {
      const d = await api<{ regeln: TrapRegel[]; engine_id: string; dienst_gestartet: string | null }>("GET", "/api/v1/trapregeln");
      setDaten({ ...d, regeln: d.regeln.filter((r) => bereich.ids.has(r.mandant_id)) });
    } catch (e) {
      props.melden(e);
    }
  }, [bereich, props.melden]);
  useEffect(() => {
    void laden();
  }, [laden]);

  const mandanten = [...bereich.ids].filter((m) => m === bereich.mandant.id || daten?.regeln.some((r) => r.mandant_id === m));
  mandanten.sort((a, b) =>
    a === bereich.mandant.id ? -1 : b === bereich.mandant.id ? 1 : mandantName(bereich, a).localeCompare(mandantName(bereich, b), "de"),
  );

  const ausfuehren = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      props.melden(e);
    }
    await laden();
  };
  const schieben = (liste: TrapRegel[], i: number, richtung: -1 | 1) => {
    const j = i + richtung;
    if (j < 0 || j >= liste.length) return;
    const ids = liste.map((r) => r.id);
    [ids[i], ids[j]] = [ids[j]!, ids[i]!];
    void ausfuehren(() => api("POST", `/api/v1/mandanten/${liste[0]!.mandant_id}/trapregeln/reihenfolge`, { ids }));
  };

  return (
    <section className="trap-regeln" aria-labelledby="trapregeln-titel">
      <div className="abschnitt-kopf">
        <h3 id="trapregeln-titel" className="klein-titel">
          Trap-Regeln
        </h3>
        <span className="kopf-knoepfe">
          <button className="knopf" onClick={props.onFertig}>
            Fertig
          </button>
        </span>
      </div>
      <p className="klein">
        Je Trap gilt die erste passende Regel: zuerst die Regeln des Mandanten des Geräts, dann die der übergeordneten Mandanten (die ein
        Untermandant nicht sieht). Traps ohne passende Regel stehen nur im Protokoll. Änderungen wirken nach spätestens 10 Sekunden. Pflegen
        dürfen Admins.
      </p>
      {daten && (
        <dl className="eckdaten">
          <div>
            <dt>Engine-ID von OpenWacht</dt>
            <dd className="engine-id">{daten.engine_id}</dd>
          </div>
          <div>
            <dt>Trap-Dienst</dt>
            <dd>
              {daten.dienst_gestartet
                ? `zuletzt gestartet ${new Date(daten.dienst_gestartet).toLocaleString("de-DE")}`
                : "noch nie gestartet (Einrichtung siehe Runbook)"}
            </dd>
          </div>
        </dl>
      )}
      {daten === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : (
        mandanten.map((m) => {
          const liste = daten.regeln.filter((r) => r.mandant_id === m);
          const admin = rolleIn(bereich, m) === "admin";
          return (
            <div key={m} className="regel-mandant">
              {(bereich.mehrere || mandanten.length > 1) && <h4 className="klein-titel">{mandantName(bereich, m)}</h4>}
              {liste.length === 0 ? (
                <p className="leer">Noch keine Regeln.</p>
              ) : (
                <div className="tabelle-rahmen">
                  <table className="tabelle tabelle-kompakt">
                    <thead>
                      <tr>
                        <th scope="col">#</th>
                        <th scope="col">Regel</th>
                        <th scope="col">Wirkung</th>
                        <th scope="col">Gilt für</th>
                        {admin && <th scope="col">Aktionen</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {liste.map((r, i) => (
                        <tr key={r.id} className={`regel-zeile${r.aktiv ? "" : " regel-aus"}`}>
                          <td>{i + 1}</td>
                          <td>
                            {r.name}
                            {!r.aktiv && " (aus)"}
                            <br />
                            <span className="klein mono">{regelBeschreibung(r, daten.regeln)}</span>
                          </td>
                          <td>
                            <span
                              className={r.wirkung === "warn" || r.wirkung === "crit" ? `marke marke-${r.wirkung}` : "marke marke-ende"}
                            >
                              {wirkungText[r.wirkung]}
                            </span>
                            <KennMarke k={kennfarben.liste.find((k) => k.id === r.kennfarbe_id)} status={r.wirkung} />
                          </td>
                          <td>{eingrenzungText(r, props.gruppen, props.geraete)}</td>
                          {admin && (
                            <td>
                              <span className="regel-aktionen">
                                <button
                                  className="knopf-text"
                                  aria-label={`${r.name} nach oben`}
                                  disabled={i === 0}
                                  onClick={() => schieben(liste, i, -1)}
                                >
                                  ↑
                                </button>
                                <button
                                  className="knopf-text"
                                  aria-label={`${r.name} nach unten`}
                                  disabled={i === liste.length - 1}
                                  onClick={() => schieben(liste, i, 1)}
                                >
                                  ↓
                                </button>
                                <button className="knopf-text" onClick={() => setBearbeite({ mandant: m, regel: r })}>
                                  Bearbeiten
                                </button>
                                <button className="knopf-text" onClick={() => setLoeschen(r)}>
                                  Löschen
                                </button>
                              </span>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {loeschen && loeschen.mandant_id === m && (
                <div className="bestaetigung" role="alertdialog" aria-label="Regel löschen">
                  <p>Regel „{loeschen.name}“ löschen? Ihre Zustände enden sofort (mit Entwarnung); das Protokoll bleibt.</p>
                  <div className="aktionen">
                    <button
                      className="knopf knopf-gefahr"
                      onClick={() => {
                        const r = loeschen;
                        setLoeschen(null);
                        void ausfuehren(() => api("DELETE", `/api/v1/trapregeln/${r.id}`));
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
              {bearbeite && bearbeite.mandant === m ? (
                <RegelFormular
                  mandant={m}
                  regel={bearbeite.regel}
                  regeln={daten.regeln}
                  gruppen={props.gruppen}
                  geraete={props.geraete}
                  onFertig={(geaendert) => {
                    setBearbeite(null);
                    if (geaendert) void laden();
                  }}
                />
              ) : (
                admin && (
                  <div className="aktionen">
                    <button className="knopf" onClick={() => setBearbeite({ mandant: m, regel: null })}>
                      Regel hinzufügen
                    </button>
                    {liste.length === 0 && (
                      <button
                        className="knopf"
                        onClick={() => void ausfuehren(() => api("POST", `/api/v1/mandanten/${m}/trapregeln/standard`))}
                      >
                        Standardregeln anlegen
                      </button>
                    )}
                  </div>
                )
              )}
            </div>
          );
        })
      )}
    </section>
  );
}
