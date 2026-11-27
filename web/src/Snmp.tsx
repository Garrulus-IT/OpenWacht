// SPDX-License-Identifier: AGPL-3.0-only

// SNMP eines Geräts: Messwerte, Schnittstellen (mit „überwachen“), Synology,
// USV und Verbrauchsmaterial; Einrichten mit „Verbindung prüfen“.
//
// Community und v3-Passwörter verlassen die Zentrale nie wieder: Die Liste
// sagt nur, ob Zugangsdaten gespeichert sind. Einrichten, ändern und
// entfernen dürfen nur Admins. SNMPv3 nur mit authPriv (SHA, AES).

import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  type Geraet,
  type Mandant,
  type Sammler,
  type Snmp,
  type SnmpMesswerte,
  type SnmpProfil,
  type SnmpSchnittstelle,
  type SnmpSystem,
} from "./api";
import { SnmpVerlauf } from "./Verlauf";
import { prognoseSchluessel, PrognoseZeile, type PlattenPrognose } from "./Prognose";
import { SparkReihen, type SparkDaten } from "./Sparkline";
import { ReihenVerlauf } from "./Verlauf";
import { PortBild, langsam, nachbarText, poeNachIndex, poeText, portNummer } from "./PortBild";
import { Aufnehmen } from "./Aufnehmen";
import { finder } from "./Netzbild";
import { useQuelle } from "./quelle";
import { bitrate, laufzeit, Pegel, prozent } from "./Pegel";
import { bytes, vor } from "./zeit";
import { TrapTeil } from "./Traps";

// Anzeige der v3-Verfahren
export const authText: Record<string, string> = {
  sha: "SHA-1",
  sha224: "SHA-224",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};
export const privText: Record<string, string> = {
  aes: "AES-128",
  aes192: "AES-192",
  aes256: "AES-256",
  aes192c: "AES-192 (Cisco/Reeder)",
  aes256c: "AES-256 (Cisco/Reeder)",
};

export function versionText(q: Snmp) {
  if (q.version === "3") return `SNMPv3 (${authText[q.v3_auth ?? ""] ?? q.v3_auth}, ${privText[q.v3_priv ?? ""] ?? q.v3_priv})`;
  return `SNMP v${q.version}`;
}

// --- Darstellung ---------------------------------------------------------------------

const ifStatusText: Record<SnmpSchnittstelle["status"], string> = {
  up: "verbunden",
  down: "getrennt",
  testing: "Test",
  unknown: "unbekannt",
  dormant: "bereit",
  notPresent: "fehlt",
  lowerLayerDown: "getrennt (unten)",
};

const raidText: Record<number, string> = {
  1: "normal",
  2: "wird repariert",
  3: "wird migriert",
  4: "wird erweitert",
  5: "wird gelöscht",
  6: "wird erstellt",
  7: "wird synchronisiert",
  8: "Paritätsprüfung",
  9: "wird zusammengesetzt",
  10: "wird abgebrochen",
  11: "beeinträchtigt",
  12: "abgestürzt",
  13: "Datenbereinigung",
};

const laufwerkText: Record<number, string> = {
  1: "normal",
  2: "initialisiert",
  3: "nicht initialisiert",
  4: "Systempartition fehlerhaft",
  5: "defekt",
  6: "getrennt",
};
const gesundheitText: Record<number, string> = { 2: "Warnung", 3: "kritisch", 4: "fällt aus" };

function geschwindigkeit(bps: number) {
  return bps > 0 ? bitrate(bps) : "–";
}

// Loopback und Tunnel zuletzt; mit Verbindung zuerst.
function ifRang(i: SnmpSchnittstelle) {
  if (i.typ === 24) return 3;
  return i.status === "up" ? 0 : i.admin_an ? 1 : 2;
}

// Für den Verlauf: überwachte zuerst, dann die mit dem meisten Verkehr.
function verlaufSchnittstellen(m: SnmpMesswerte, ueberwacht: string[]) {
  const mitRate = m.schnittstellen
    .filter((i) => i.typ !== 24 && (i.ein_bps !== null || i.aus_bps !== null) && !ueberwacht.includes(i.name))
    .sort((a, b) => (b.ein_bps ?? 0) + (b.aus_bps ?? 0) - ((a.ein_bps ?? 0) + (a.aus_bps ?? 0)))
    .map((i) => i.name);
  return [...ueberwacht, ...mitRate].slice(0, 6);
}

export function snmpKurz(q: Snmp) {
  const m = q.messwerte;
  if (!q.aktiv) return "SNMP ausgeschaltet";
  if (!m) return q.fehler ? `SNMP: ${q.fehler}` : "SNMP: noch nicht abgefragt";
  const phys = m.schnittstellen.filter((i) => i.typ !== 24);
  const teile = [q.version === "3" ? "SNMPv3" : `SNMP v${q.version}`];
  if (phys.length) teile.push(`${phys.filter((i) => i.status === "up").length} von ${phys.length} Schnittstellen verbunden`);
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

// --- Teil im aufgeklappten Gerät ------------------------------------------------------

export function SnmpTeil(props: {
  q: Snmp;
  g: Geraet;
  darfAdmin: boolean;
  darfPflegen: boolean;
  jetzt: number;
  prognose: Map<string, PlattenPrognose>;
  spark: SparkDaten | null;
  onBearbeiten: () => void;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
  // Etappe 19: Knöpfe stehen im Aktionsmenü des Geräts; hier nur noch die
  // Rückfrage zum Entfernen, geöffnet von außen.
  ohneAktionen?: boolean;
  // 1.0.12: anderes Gerät öffnen (LLDP-Nachbar, gerade aufgenommenes Gerät)
  onOeffnen?: (id: string) => void;
  entfernen?: boolean;
  onEntfernenEnde?: () => void;
}) {
  const { q } = props;
  const m = q.messwerte;
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (x: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(x);
    else if (!x) props.onEntfernenEnde?.();
  };
  const [ueberwacht, setUeberwacht] = useState<string[] | null>(null);
  const [alle, setAlle] = useState(false);
  // Schnittstelle, deren Verlauf aufgeklappt ist
  const [ifOffen, setIfOffen] = useState("");
  // im Bild der Ports gewählter Port (ifIndex)
  const [portWahl, setPortWahl] = useState<number | null>(null);
  const [poeArbeitet, setPoeArbeitet] = useState(false);
  const [poeHinweis, setPoeHinweis] = useState("");
  // Nachbar des gewählten Ports, der gerade aufgenommen wird (Stelle in der Liste)
  const [aufnahme, setAufnahme] = useState<number | null>(null);
  // Geräte und Abfragen, um LLDP-Nachbarn bekannten Geräten zuzuordnen (gemeinsamer Speicher)
  const lldpDa = (props.q.messwerte?.lldp?.length ?? 0) > 0;
  const qGeraete = useQuelle<{ geraete: Geraet[] }>(lldpDa ? "/api/v1/geraete" : null, 60_000);
  const qQuellen = useQuelle<{ snmp: Snmp[] }>(lldpDa ? "/api/v1/snmp" : null, 60_000);
  const finde = finder(qGeraete.daten?.geraete ?? [], qQuellen.daten?.snmp ?? []);
  const aktuell = ueberwacht ?? q.ueberwacht;
  const geaendert = ueberwacht !== null && ueberwacht.join("\n") !== q.ueberwacht.join("\n");

  const speichern = async () => {
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/snmp`, {
        version: q.version,
        adresse: q.adresse,
        port: q.port,
        intervall_sekunden: q.intervall_sekunden,
        aktiv: q.aktiv,
        ueberwacht: aktuell,
      });
      setUeberwacht(null);
      props.onGeaendert();
    } catch (e) {
      props.melden(e);
    }
  };

  const ifs = (m?.schnittstellen ?? []).slice().sort((a, b) => ifRang(a) - ifRang(b) || a.index - b.index);
  const viele = ifs.length > 12;
  const gezeigt = viele && !alle ? ifs.filter((i) => i.status === "up" || aktuell.includes(i.name)) : ifs;
  // überwachte, die das Gerät nicht mehr meldet
  const fehlend = aktuell.filter((n) => !ifs.some((i) => i.name === n));

  return (
    <div className="geraet-snmp">
      <h3 className="klein-titel">
        {versionText(q)}{" "}
        {q.version === "3" ? (
          <span className="marke marke-ok" title="authPriv: Anfragen und Antworten sind authentifiziert und verschlüsselt.">
            verschlüsselt
          </span>
        ) : (
          <span className="marke marke-warn" title="SNMP v1 und v2c senden die Community unverschlüsselt durchs Netz.">
            Community im Klartext
          </span>
        )}
        {q.traps && <span className="marke marke-ende">Traps an</span>}
        {q.profil_id && (
          <span className="marke marke-ende" title="Version und Zugangsdaten kommen aus einem SNMP-Profil.">
            Profil {q.profil_name ?? "eines übergeordneten Mandanten"}
          </span>
        )}
        {q.sammler_name && (
          <span className="marke marke-ende" title="Ein Agent in diesem Netz fragt das Gerät ab und meldet die Werte an die Zentrale.">
            über Sammler {q.sammler_name}
          </span>
        )}
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port}, alle {q.intervall_sekunden} s{q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, props.jetzt)}` : ""}
        {!q.hat_community && (q.version === "3" ? " · keine v3-Zugangsdaten gespeichert" : " · keine Community gespeichert")}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {m && (m.gekuerzt?.length || m.teilweise?.length) ? (
        <p className="meldung meldung-warnung">
          {m.gekuerzt?.length ? `Gekürzt (zu viele Einträge): ${m.gekuerzt.join(", ")}. ` : ""}
          {m.teilweise?.length ? `Nicht vollständig gelesen: ${m.teilweise.join(", ")}.` : ""}
        </p>
      ) : null}

      {m && (
        <dl className="eckdaten">
          {m.system.beschreibung && (
            <div>
              <dt>System</dt>
              <dd>{m.system.beschreibung}</dd>
            </div>
          )}
          {m.synology && (
            <div>
              <dt>Synology</dt>
              <dd>
                {m.synology.modell}
                {m.synology.version && `, ${m.synology.version}`}
                {m.synology.update === 1 && ", Update verfügbar"}
              </dd>
            </div>
          )}
          <div>
            <dt>Name</dt>
            <dd>
              {m.system.name || "–"}
              {m.system.standort && `, Standort ${m.system.standort}`}
            </dd>
          </div>
          <div>
            <dt>Läuft seit</dt>
            <dd>
              {laufzeit(m.system.laufzeit_s)}
              {q.neustart_am && ` (Neustart erkannt ${vor(q.neustart_am, props.jetzt)})`}
            </dd>
          </div>
          {m.cpu && (
            <div>
              <dt>CPU</dt>
              <dd>
                <Pegel wert={m.cpu.auslastung_prozent} titel={m.cpu.kerne ? `${m.cpu.kerne} Kerne` : "CPU-Auslastung"} />
              </dd>
            </div>
          )}
          {m.speicher && m.speicher.gesamt > 0 && (
            <div>
              <dt>Arbeitsspeicher</dt>
              <dd>
                {bytes(m.speicher.gesamt - m.speicher.verfuegbar)} von {bytes(m.speicher.gesamt)} belegt
              </dd>
            </div>
          )}
          {m.synology && (
            <div>
              <dt>Zustand</dt>
              <dd>
                {[
                  m.synology.system === 2 ? "System ausgefallen" : "System normal",
                  m.synology.netzteil === 2 ? "Netzteil ausgefallen" : "",
                  m.synology.luefter_system === 2 ? "Systemlüfter ausgefallen" : "",
                  m.synology.luefter_cpu === 2 ? "CPU-Lüfter ausgefallen" : "",
                  m.synology.temperatur !== null ? `${m.synology.temperatur} °C` : "",
                ]
                  .filter(Boolean)
                  .join(", ")}
              </dd>
            </div>
          )}
          {m.usv && (
            <div>
              <dt>USV</dt>
              <dd>
                {m.usv.modell && `${m.usv.modell}: `}
                {m.usv.batterie_schwach ? "Batterie schwach" : m.usv.batteriebetrieb ? "Batteriebetrieb" : "Netzbetrieb"}
                {m.usv.batterie_tauschen && ", Batterie tauschen"}
                {m.usv.ladung_prozent !== null && `, Ladung ${Math.round(m.usv.ladung_prozent)} %`}
                {m.usv.restlaufzeit_s !== null && `, Restlaufzeit ${Math.round(m.usv.restlaufzeit_s / 60)} Min.`}
                {m.usv.last_prozent !== null && `, Last ${Math.round(m.usv.last_prozent)} %`}
                {m.usv.quelle === "synology" && <span className="klein"> (per USB am NAS)</span>}
              </dd>
            </div>
          )}
        </dl>
      )}

      {m && m.platten.length > 0 && (
        <table className="tabelle tabelle-kompakt">
          <thead>
            <tr>
              <th scope="col">Speicher</th>
              <th scope="col">Belegt</th>
              <th scope="col">Frei</th>
            </tr>
          </thead>
          <tbody>
            {m.platten.map((p) => (
              <tr key={p.einhaengepunkt}>
                <td className="mono">{p.einhaengepunkt}</td>
                <td>
                  <Pegel wert={prozent(p.gesamt - p.frei, p.gesamt)} titel={`${bytes(p.gesamt - p.frei)} von ${bytes(p.gesamt)}`} />
                </td>
                <td>
                  {bytes(p.frei)} von {bytes(p.gesamt)}
                  <br />
                  <PrognoseZeile p={props.prognose.get(prognoseSchluessel("snmp", q.id, p.einhaengepunkt))} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {m?.synology && (m.synology.laufwerke.length > 0 || m.synology.raids.length > 0) && (
        <table className="tabelle tabelle-kompakt">
          <thead>
            <tr>
              <th scope="col">Laufwerk / Speicherpool</th>
              <th scope="col">Zustand</th>
              <th scope="col">Temperatur</th>
            </tr>
          </thead>
          <tbody>
            {m.synology.raids.map((r) => (
              <tr key={"r" + r.name}>
                <td>{r.name}</td>
                <td className={r.status === 11 || r.status === 12 ? "text-crit" : undefined}>
                  {raidText[r.status] ?? `Status ${r.status}`}
                </td>
                <td>–</td>
              </tr>
            ))}
            {m.synology.laufwerke.map((d) => (
              <tr key={"d" + d.name}>
                <td>
                  {d.name}
                  {d.modell && <span className="klein"> {d.modell}</span>}
                </td>
                <td className={d.status >= 4 || d.gesundheit >= 3 ? "text-crit" : undefined}>
                  {laufwerkText[d.status] ?? `Status ${d.status}`}
                  {gesundheitText[d.gesundheit] && `, Gesundheit ${gesundheitText[d.gesundheit]}`}
                </td>
                <td>{d.temperatur !== null ? `${d.temperatur} °C` : "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {m && m.verbrauchsmaterial.length > 0 && (
        <table className="tabelle tabelle-kompakt">
          <thead>
            <tr>
              <th scope="col">Verbrauchsmaterial</th>
              <th scope="col">Übrig</th>
            </tr>
          </thead>
          <tbody>
            {m.verbrauchsmaterial.map((v) => (
              <tr key={v.name}>
                <td>{v.name}</td>
                <td>{v.prozent !== null ? `${Math.round(v.prozent)} %` : v.stand === -3 ? "vorhanden" : "unbekannt"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {m && (
        <PortBild
          ifs={m.schnittstellen}
          poe={m.poe}
          lldp={m.lldp}
          ueberwacht={aktuell}
          gewaehlt={portWahl}
          name={m.system.name || props.g.name}
          onWahl={(i) => {
            setPortWahl(i);
            setPoeHinweis("");
            setAufnahme(null);
          }}
        />
      )}
      {m &&
        portWahl !== null &&
        (() => {
          const i = m.schnittstellen.find((x) => x.index === portWahl);
          if (!i) return null;
          const nr = portNummer(m.schnittstellen, i.index);
          const p = poeNachIndex(m.poe).get(i.index);
          const nachbarn = (m.lldp ?? []).filter((n) => n.index === i.index);
          const poeSensor = async () => {
            if (!p) return;
            setPoeArbeitet(true);
            try {
              await api("POST", `/api/v1/geraete/${props.g.id}/checks`, {
                name: `${props.g.name}: PoE Port ${nr} liefert Strom`.slice(0, 100),
                typ: "snmp_oid",
                ziel: { oid: `1.3.6.1.2.1.105.1.1.1.6.${p.gruppe}.${p.port}`, gleich: "3" },
                intervall_sekunden: 300,
              });
              setPoeHinweis(`Sensor „PoE Port ${nr} liefert Strom“ angelegt. Er steht im Reiter „Sensoren“.`);
              props.onGeaendert();
            } catch (e) {
              props.melden(e);
            } finally {
              setPoeArbeitet(false);
            }
          };
          return (
            <div className="einschub port-einzel" role="region" aria-label={`Port ${nr}`}>
              <h4 className="einschub-titel">
                Port {nr}: {i.name}
                {i.alias ? ` (${i.alias})` : ""}
              </h4>
              <dl className="eckdaten">
                <dt>Status</dt>
                <dd className={i.status !== "up" && aktuell.includes(i.name) ? "text-crit" : undefined}>
                  {i.admin_an ? ifStatusText[i.status] : "abgeschaltet"}
                </dd>
                {i.seit_s !== undefined && (
                  <>
                    <dt>Seit</dt>
                    <dd>
                      {i.status === "up" ? "verbunden" : "in diesem Zustand"} seit {laufzeit(i.seit_s)}
                    </dd>
                  </>
                )}
                <dt>Geschwindigkeit</dt>
                <dd>
                  {geschwindigkeit(i.geschwindigkeit_bps)}
                  {langsam(i) ? " (unter 1 Gbit/s: Kabel oder Gegenstelle prüfen, falls das Gerät mehr kann)" : ""}
                </dd>
                <dt>Verkehr</dt>
                <dd>
                  ein {i.ein_bps !== null ? bitrate(i.ein_bps) : "–"}, aus {i.aus_bps !== null ? bitrate(i.aus_bps) : "–"}
                </dd>
                <dt>Neue Fehler</dt>
                <dd>{i.fehler_neu ?? "–"}</dd>
                <dt>Nachbar (LLDP)</dt>
                <dd className="port-nachbarn">
                  {nachbarn.length === 0
                    ? "keiner gemeldet"
                    : nachbarn.map((n, k) => {
                        const id = finde(n.name);
                        return (
                          <span key={k} className="port-nachbar">
                            {id && props.onOeffnen && id !== props.g.id ? (
                              <button type="button" className="knopf-text" title="Gerät öffnen" onClick={() => props.onOeffnen?.(id)}>
                                {nachbarText(n)}
                              </button>
                            ) : (
                              <span>{nachbarText(n)}</span>
                            )}
                            {n.adresse && <span className="klein"> · {n.adresse}</span>}
                            {id === undefined && props.darfPflegen && (
                              <button
                                type="button"
                                className="knopf-text klein"
                                aria-expanded={aufnahme === k}
                                onClick={() => setAufnahme(aufnahme === k ? null : k)}
                              >
                                + Ins Monitoring aufnehmen
                              </button>
                            )}
                          </span>
                        );
                      })}
                </dd>
                {p && (
                  <>
                    <dt>PoE</dt>
                    <dd className={p.status === 4 || p.status === 6 ? "text-crit" : undefined}>{poeText[p.status] ?? "unbekannt"}</dd>
                  </>
                )}
              </dl>
              <div className="aktionen">
                <label>
                  <input
                    type="checkbox"
                    checked={aktuell.includes(i.name)}
                    disabled={!props.darfAdmin}
                    onChange={(e) => setUeberwacht(e.target.checked ? [...aktuell, i.name] : aktuell.filter((n) => n !== i.name))}
                  />{" "}
                  Überwachen (meldet, wenn der Port nicht verbunden ist)
                </label>
                {p && props.darfPflegen && (
                  <button type="button" className="knopf" disabled={poeArbeitet} onClick={() => void poeSensor()}>
                    PoE-Sensor für diesen Port anlegen
                  </button>
                )}
                <button type="button" className="knopf" onClick={() => setPortWahl(null)}>
                  Schließen
                </button>
              </div>
              {poeHinweis && (
                <p className="klein" role="status">
                  {poeHinweis}
                </p>
              )}
              {p && props.darfPflegen && (
                <p className="klein">Der PoE-Sensor wird kritisch, sobald der Port keinen Strom mehr liefert.</p>
              )}
              {aufnahme !== null && nachbarn[aufnahme] && (
                <Aufnehmen
                  key={`${i.index}-${aufnahme}`}
                  k={{ name: nachbarn[aufnahme]!.name ?? nachbarn[aufnahme]!.port ?? "", adresse: nachbarn[aufnahme]!.adresse, port: `Port ${nr}` }}
                  sw={props.g}
                  melden={props.melden}
                  onAbbrechen={() => setAufnahme(null)}
                  onFertig={(id) => {
                    setAufnahme(null);
                    props.onGeaendert();
                    props.onOeffnen?.(id);
                  }}
                />
              )}
              <ReihenVerlauf
                pfad={`/api/v1/snmp/${q.id}/verlauf`}
                titel={`Verkehr ${i.name}`}
                reihen={[
                  { name: "if_ein:" + i.name, text: "ein" },
                  { name: "if_aus:" + i.name, text: "aus" },
                ]}
                einheit=""
                format={bitrate}
              />
            </div>
          );
        })()}

      {ifs.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <caption className="klein">
              Schnittstellen{props.darfAdmin ? ": „Überwachen“ meldet, wenn eine Schnittstelle nicht verbunden ist." : ""}
            </caption>
            <thead>
              <tr>
                <th scope="col">Überwachen</th>
                <th scope="col">Name</th>
                <th scope="col">Status</th>
                <th scope="col">Geschw.</th>
                <th scope="col">Ein</th>
                <th scope="col">Aus</th>
                <th scope="col">Fehler</th>
                <th scope="col">24 Std.</th>
              </tr>
            </thead>
            <tbody>
              {gezeigt
                .map((i) => (
                  <tr key={i.index}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`${i.name} überwachen`}
                        checked={aktuell.includes(i.name)}
                        disabled={!props.darfAdmin}
                        onChange={(e) => setUeberwacht(e.target.checked ? [...aktuell, i.name] : aktuell.filter((n) => n !== i.name))}
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="knopf-text"
                        aria-expanded={ifOffen === i.name}
                        title="Verlauf des Verkehrs"
                        onClick={() => setIfOffen(ifOffen === i.name ? "" : i.name)}
                      >
                        {i.name}
                      </button>
                      {i.alias && <span className="klein"> {i.alias}</span>}
                    </td>
                    <td className={i.status !== "up" && aktuell.includes(i.name) ? "text-crit" : undefined}>
                      {i.admin_an ? ifStatusText[i.status] : "abgeschaltet"}
                    </td>
                    <td>{geschwindigkeit(i.geschwindigkeit_bps)}</td>
                    <td>{i.ein_bps !== null ? bitrate(i.ein_bps) : "–"}</td>
                    <td>{i.aus_bps !== null ? bitrate(i.aus_bps) : "–"}</td>
                    <td>{i.fehler_neu ?? "–"}</td>
                    <td>
                      <button
                        type="button"
                        className="sparkline-knopf"
                        aria-expanded={ifOffen === i.name}
                        aria-label={`Verlauf des Verkehrs von ${i.name}`}
                        onClick={() => setIfOffen(ifOffen === i.name ? "" : i.name)}
                      >
                        <SparkReihen
                          d={props.spark}
                          quelle="snmp"
                          namen={["if_ein:" + i.name, "if_aus:" + i.name]}
                          titel={`Verkehr ${i.name}, 24 Stunden`}
                        />
                      </button>
                    </td>
                  </tr>
                ))
                .flatMap((zeile, k) => {
                  const i = gezeigt[k]!;
                  return ifOffen === i.name
                    ? [
                        zeile,
                        <tr key={"v" + i.index} className="zeile-verlauf">
                          <td colSpan={8}>
                            <ReihenVerlauf
                              pfad={`/api/v1/snmp/${q.id}/verlauf`}
                              titel={`Verkehr ${i.name}`}
                              reihen={[
                                { name: "if_ein:" + i.name, text: "ein" },
                                { name: "if_aus:" + i.name, text: "aus" },
                              ]}
                              einheit=""
                              format={bitrate}
                            />
                          </td>
                        </tr>,
                      ]
                    : [zeile];
                })}
              {fehlend.map((n) => (
                <tr key={"f" + n}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`${n} überwachen`}
                      checked
                      disabled={!props.darfAdmin}
                      onChange={() => setUeberwacht(aktuell.filter((x) => x !== n))}
                    />
                  </td>
                  <td>{n}</td>
                  <td className="text-crit" colSpan={6}>
                    meldet das Gerät nicht mehr
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {viele && (
            <button className="knopf-text" onClick={() => setAlle(!alle)}>
              {alle ? "Nur verbundene und überwachte zeigen" : `Alle ${ifs.length} Schnittstellen zeigen`}
            </button>
          )}
          {geaendert && props.darfAdmin && (
            <div className="aktionen">
              <button className="knopf knopf-haupt" onClick={() => void speichern()}>
                Überwachung speichern
              </button>
              <button className="knopf" onClick={() => setUeberwacht(null)}>
                Verwerfen
              </button>
            </div>
          )}
        </div>
      )}

      {m && <SnmpVerlauf snmpId={q.id} schnittstellen={verlaufSchnittstellen(m, q.ueberwacht)} />}

      {q.traps && <TrapTeil q={q} darfPflegen={props.darfPflegen || props.darfAdmin} jetzt={props.jetzt} melden={props.melden} />}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="SNMP entfernen">
              <p>SNMP für „{props.g.name}“ entfernen? Community, Verlauf und Meldezustand gehen verloren; das Alarmprotokoll bleibt.</p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/snmp`);
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
                    SNMP bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    SNMP entfernen
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

export interface SnmpWerte {
  version: "1" | "2c" | "3";
  adresse: string;
  port: string;
  community: string;
  benutzer: string;
  auth: string;
  authPasswort: string;
  priv: string;
  privPasswort: string;
  intervall: string;
  aktiv: boolean;
  traps: boolean;
  // Agent-ID des Sammlers, "" = die Zentrale fragt ab
  sammler: string;
  // Zugangsprofil (Etappe 27), "" = eigene Zugangsdaten
  profil: string;
}

export function snmpStart(g: Geraet, q: Snmp | null): SnmpWerte {
  return {
    version:
      q && q.version !== "pve" && q.version !== "tr064" && q.version !== "vcenter" && q.version !== "ontap" && q.version !== "xapi" && q.version !== "citrix"
        ? q.version
        : "3",
    adresse: q?.adresse ?? g.adresse ?? "",
    port: String(q?.port ?? 161),
    community: "",
    benutzer: "",
    auth: q?.v3_auth ?? "sha256",
    authPasswort: "",
    priv: q?.v3_priv ?? "aes",
    privPasswort: "",
    intervall: String(q?.intervall_sekunden ?? 60),
    aktiv: q?.aktiv ?? true,
    traps: q?.traps ?? false,
    sammler: q?.sammler ?? "",
    profil: q?.profil_id ?? "",
  };
}

// Art der Zugangsdaten: v1 und v2c teilen die Community.
export function snmpArt(v: string) {
  return v === "3" ? "v3" : "v1";
}

export function snmpDaten(w: SnmpWerte, ueberwacht: string[]) {
  const v3 = w.version === "3";
  const profil = !!w.profil;
  return {
    version: w.version,
    adresse: w.adresse.trim(),
    port: Number(w.port) || 161,
    // Mit Profil kommen Version und Zugangsdaten aus dem Profil.
    profil: w.profil,
    community: v3 || profil ? "" : w.community,
    // Leere Passwörter = gespeicherte Zugangsdaten behalten
    v3:
      v3 && !profil && (w.authPasswort || w.privPasswort)
        ? { benutzer: w.benutzer.trim(), auth: w.auth, auth_passwort: w.authPasswort, priv: w.priv, priv_passwort: w.privPasswort }
        : null,
    intervall_sekunden: Number(w.intervall) || 60,
    aktiv: w.aktiv,
    // Traps nimmt nur die Zentrale an
    traps: w.traps && !w.sammler,
    sammler: w.sammler,
    ueberwacht,
  };
}

// Profile, die für ein Gerät des Mandanten in Frage kommen: aus dem Mandanten
// selbst oder einem darüber. Die Liste der Zentrale enthält nur Profile, die
// der Benutzer als Admin sieht (Leser und Operatoren bekommen keine).
export function useSnmpProfile(mandant: string | undefined) {
  const [liste, setListe] = useState<SnmpProfil[]>([]);
  useEffect(() => {
    if (!mandant) return;
    let ok = true;
    Promise.all([api<{ profile: SnmpProfil[] }>("GET", "/api/v1/snmp-profile"), api<{ mandanten: Mandant[] }>("GET", "/api/v1/mandanten")])
      .then(([p, m]) => {
        if (!ok) return;
        const nachId = new Map(m.mandanten.map((x) => [x.id, x]));
        const kette = new Map<string, number>();
        let cur: string | null | undefined = mandant;
        for (let tiefe = 0; cur && !kette.has(cur) && tiefe < 64; tiefe++) {
          kette.set(cur, tiefe);
          cur = nachId.get(cur)?.uebergeordnet_id;
        }
        setListe(
          p.profile
            .filter((x) => kette.has(x.mandant_id))
            .sort((a, b) => kette.get(a.mandant_id)! - kette.get(b.mandant_id)! || a.name.localeCompare(b.name, "de")),
        );
      })
      .catch(() => ok && setListe([]));
    return () => {
      ok = false;
    };
  }, [mandant]);
  return liste;
}

export function profilVersion(p: { version: string; v3_auth: string | null; v3_priv: string | null }) {
  return p.version === "3"
    ? `SNMPv3 (${authText[p.v3_auth ?? ""] ?? p.v3_auth}, ${privText[p.v3_priv ?? ""] ?? p.v3_priv})`
    : `SNMP v${p.version}`;
}

// Felder für Version, Adresse, Port, Community und Intervall.
export function SnmpFelder(props: {
  w: SnmpWerte;
  setW: (w: SnmpWerte) => void;
  neu: boolean;
  adresseOptional?: boolean;
  // Agents mit Freigabe als Sammler; angeboten werden nur die des Mandanten
  sammler?: Sammler[];
  mandant?: string;
}) {
  const { w, setW } = props;
  const auswahl = (props.sammler ?? []).filter((s) => s.mandant_id === props.mandant || s.id === w.sammler);
  const gewaehlt = auswahl.find((s) => s.id === w.sammler);
  const profile = useSnmpProfile(props.mandant);
  const profil = profile.find((p) => p.id === w.profil);
  return (
    <>
      {(profile.length > 0 || w.profil) && (
        <label className="feld formular-voll">
          <span>Profil</span>
          <select
            value={w.profil}
            onChange={(e) => {
              const p = profile.find((x) => x.id === e.target.value);
              setW({ ...w, profil: e.target.value, version: p ? p.version : w.version });
            }}
          >
            <option value="">Eigene Zugangsdaten</option>
            {profile.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({profilVersion(p)})
              </option>
            ))}
            {w.profil && !profil && <option value={w.profil}>Profil eines übergeordneten Mandanten</option>}
          </select>
        </label>
      )}
      {(auswahl.length > 0 || w.sammler) && (
        <label className="feld formular-voll">
          <span>Abgefragt von</span>
          <select value={w.sammler} onChange={(e) => setW({ ...w, sammler: e.target.value, traps: e.target.value ? false : w.traps })}>
            <option value="">Zentrale</option>
            {auswahl.map((s) => (
              <option key={s.id} value={s.id}>
                Sammler {s.name} ({s.netze.join(", ")})
              </option>
            ))}
            {w.sammler && !gewaehlt && <option value={w.sammler}>Sammler (nicht mehr freigegeben)</option>}
          </select>
        </label>
      )}
      {w.sammler && (
        <p className="hinweis klein formular-voll">
          {gewaehlt
            ? `Der Agent ${gewaehlt.name} fragt das Gerät in seinem Netz ab und meldet die Werte an die Zentrale. Er darf nur Adressen in ${gewaehlt.netze.join(", ")} abfragen; die Netze legt man auf dem Rechner fest (openwacht-agent sammler -netze …).`
            : "Dieser Agent ist nicht mehr als Sammler freigegeben oder gesperrt. Bitte einen anderen Sammler oder die Zentrale wählen."}{" "}
          Fällt der Sammler aus, werden seine Geräte grau, und es kommt ein Alarm am Sammler.
        </p>
      )}
      {w.profil ? (
        <p className="hinweis klein formular-voll">
          Version und Zugangsdaten kommen aus dem Profil{profil ? ` „${profil.name}“ (${profilVersion(profil)})` : ""}. Ändert jemand das
          Profil, übernimmt das Gerät die neuen Zugangsdaten.
        </p>
      ) : (
        <fieldset className="feld formular-voll auswahl auswahl-reihe">
          <legend>SNMP-Version</legend>
          <label>
            <input type="radio" name="snmp-version" checked={w.version === "3"} onChange={() => setW({ ...w, version: "3" })} />
            <span>v3 (verschlüsselt, empfohlen)</span>
          </label>
          <label>
            <input type="radio" name="snmp-version" checked={w.version === "2c"} onChange={() => setW({ ...w, version: "2c" })} />
            <span>v2c</span>
          </label>
          <label>
            <input type="radio" name="snmp-version" checked={w.version === "1"} onChange={() => setW({ ...w, version: "1" })} />
            <span>v1 (nur für alte Geräte)</span>
          </label>
        </fieldset>
      )}
      {!props.adresseOptional && (
        <label className="feld">
          <span>Adresse des Geräts</span>
          <input
            required
            maxLength={253}
            value={w.adresse}
            placeholder="10.10.0.2 oder sw-core01.example.com"
            onChange={(e) => setW({ ...w, adresse: e.target.value })}
          />
        </label>
      )}
      <label className="feld feld-schmal">
        <span>Port</span>
        <input inputMode="numeric" pattern="[0-9]*" value={w.port} onChange={(e) => setW({ ...w, port: e.target.value })} />
      </label>
      {w.profil ? null : w.version === "3" ? (
        <V3Felder w={w} setW={setW} neu={props.neu} />
      ) : (
        <label className="feld">
          <span>Community{props.neu ? "" : " (leer = unverändert)"}</span>
          <input
            type="password"
            autoComplete="off"
            required={props.neu}
            maxLength={64}
            value={w.community}
            placeholder={props.neu ? "wie am Gerät eingestellt" : "••••••••"}
            onChange={(e) => setW({ ...w, community: e.target.value })}
          />
        </label>
      )}
      <label className="feld feld-schmal">
        <span>Abfrage alle</span>
        <select value={w.intervall} onChange={(e) => setW({ ...w, intervall: e.target.value })}>
          {[30, 60, 120, 300, 600, 900, 1800, 3600].map((s) => (
            <option key={s} value={s}>
              {s < 60 ? `${s} Sekunden` : s < 3600 ? `${s / 60} Min.` : "1 Std."}
            </option>
          ))}
        </select>
      </label>
      {!w.sammler && (
        <label className="haken formular-voll">
          <input type="checkbox" checked={w.traps} onChange={(e) => setW({ ...w, traps: e.target.checked })} />
          <span>Traps von diesem Gerät annehmen</span>
        </label>
      )}
      {w.traps && !w.sammler && (
        <p className="hinweis klein formular-voll">
          Am Gerät als Trap-Ziel die Adresse von OpenWacht mit Port 162 eintragen,{" "}
          {w.version === "3"
            ? "mit demselben v3-Benutzer (authPriv). Für Informs ermittelt das Gerät die Engine-ID von OpenWacht selbst; manche Geräte wollen sie eingetragen haben (steht unter Hosts → Trap-Regeln)."
            : "mit derselben Community. v1- und v2c-Traps lassen sich fälschen und gelten deshalb als unbestätigt."}{" "}
          Was ein Trap bewirkt, legen die Trap-Regeln fest.
        </p>
      )}
      {w.version !== "3" && (
        <p className="hinweis klein formular-voll">
          SNMP v1 und v2c senden die Community unverschlüsselt. Am Gerät nur Lesezugriff erlauben und die Abfrage möglichst auf die Adresse{" "}
          {w.sammler ? "des Sammlers" : "der Zentrale"} beschränken. Besser SNMPv3, wenn das Gerät es kann.
        </p>
      )}
    </>
  );
}

// v3: Benutzer, Verfahren und zwei Passwörter. Nur authPriv; MD5 und DES gibt es nicht.
export function V3Felder(props: { w: SnmpWerte; setW: (w: SnmpWerte) => void; neu: boolean }) {
  const { w, setW, neu } = props;
  // Neue Zugangsdaten nur vollständig: Wer ein Passwort eingibt, gibt alles ein.
  const pflicht = neu || !!w.authPasswort || !!w.privPasswort || !!w.benutzer;
  return (
    <>
      <label className="feld">
        <span>Benutzer{neu ? "" : " (leer = unverändert)"}</span>
        <input
          autoComplete="off"
          required={pflicht}
          maxLength={32}
          value={w.benutzer}
          placeholder={neu ? "wie am Gerät eingestellt" : "••••••••"}
          onChange={(e) => setW({ ...w, benutzer: e.target.value })}
        />
      </label>
      <label className="feld feld-schmal">
        <span>Authentifizierung</span>
        <select value={w.auth} onChange={(e) => setW({ ...w, auth: e.target.value })}>
          {Object.entries(authText).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </label>
      <label className="feld">
        <span>Passwort Authentifizierung</span>
        <input
          type="password"
          autoComplete="new-password"
          required={pflicht}
          minLength={8}
          maxLength={128}
          value={w.authPasswort}
          placeholder={neu ? "mindestens 8 Zeichen" : "••••••••"}
          onChange={(e) => setW({ ...w, authPasswort: e.target.value })}
        />
      </label>
      <label className="feld feld-schmal">
        <span>Verschlüsselung</span>
        <select value={w.priv} onChange={(e) => setW({ ...w, priv: e.target.value })}>
          {Object.entries(privText).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </label>
      <label className="feld">
        <span>Passwort Verschlüsselung</span>
        <input
          type="password"
          autoComplete="new-password"
          required={pflicht}
          minLength={8}
          maxLength={128}
          value={w.privPasswort}
          placeholder={neu ? "mindestens 8 Zeichen" : "••••••••"}
          onChange={(e) => setW({ ...w, privPasswort: e.target.value })}
        />
      </label>
      <p className="hinweis klein formular-voll">
        Nur authPriv. MD5 und DES sind nicht erlaubt; Geräte, die nur das können, bleiben bei v2c. Benutzer, Verfahren oder Passwörter
        ändern heißt: alles neu eingeben.
      </p>
    </>
  );
}

// Ergebnis von „Verbindung prüfen“.
export function PruefErgebnis({ e }: { e: { ok: true; system: SnmpSystem } | { ok: false; fehler: string } | null }) {
  if (!e) return null;
  if (!e.ok)
    return (
      <p className="meldung meldung-fehler formular-voll" role="status">
        Keine Verbindung: {e.fehler}
      </p>
    );
  return (
    <p className="meldung meldung-ok formular-voll" role="status">
      Verbunden mit „{e.system.name || "ohne Namen"}“: {e.system.beschreibung || "keine Beschreibung"}
    </p>
  );
}

export type Pruefung = { ok: true; system: SnmpSystem } | { ok: false; fehler: string };

export function SnmpFormular(props: {
  g: Geraet;
  q: Snmp | null;
  sammler?: Sammler[];
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const [w, setW] = useState(() => snmpStart(props.g, props.q));
  const [fehler, setFehler] = useState("");
  const [pruefung, setPruefung] = useState<Pruefung | null>(null);
  const [prueft, setPrueft] = useState(false);
  const neu =
    !props.q ||
    w.adresse.trim() !== props.q.adresse ||
    (Number(w.port) || 161) !== props.q.port ||
    snmpArt(w.version) !== snmpArt(props.q.version) ||
    // vom Profil auf eigene Zugangsdaten: neu eingeben
    (!!props.q.profil_id && !w.profil);

  const pruefen = async () => {
    setFehler("");
    setPruefung(null);
    setPrueft(true);
    try {
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/snmp/pruefen`, snmpDaten(w, [])));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/snmp`, snmpDaten(w, props.q?.ueberwacht ?? []));
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{props.q ? "SNMP bearbeiten" : `SNMP für „${props.g.name}“ einrichten`}</h3>
        <SnmpFelder w={w} setW={setW} neu={neu} sammler={props.sammler} mandant={props.g.mandant_id} />
        {props.q && (
          <label className="haken formular-voll">
            <input type="checkbox" checked={w.aktiv} onChange={(e) => setW({ ...w, aktiv: e.target.checked })} />
            <span>Abfrage eingeschaltet</span>
          </label>
        )}
        <PruefErgebnis e={pruefung} />
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Speichern</button>
          {!w.sammler && (
            <button type="button" className="knopf" disabled={prueft} onClick={() => void pruefen()}>
              {prueft ? "Prüft …" : "Verbindung prüfen"}
            </button>
          )}
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
