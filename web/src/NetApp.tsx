// SPDX-License-Identifier: AGPL-3.0-only

// NetApp ONTAP eines Geräts (0.41.0): Knoten und HA, Aggregate und Volumes
// mit Belegung und Prognose, Platten, Shelves, SnapMirror und EMS über die
// ONTAP-REST-API; Einrichten mit „Verbindung prüfen“ und Fingerabdruck.
//
// Benutzer und Passwort verlassen die Zentrale nie wieder: Die Liste sagt nur,
// ob Zugangsdaten gespeichert sind. Einrichten, ändern und entfernen dürfen
// nur Admins. Die Zentrale liest nur und lehnt Konten mit Schreibrecht ab.

import { useState, type FormEvent } from "react";
import { api, type Geraet, type NetAppInfo, type NetAppMesswerte, type Snmp } from "./api";
import { SnmpVerlauf } from "./Verlauf";
import { prognoseSchluessel, PrognoseZeile, type PlattenPrognose } from "./Prognose";
import { SparkReihen, type SparkDaten } from "./Sparkline";
import { laufzeit, Pegel, prozent } from "./Pegel";
import { bytes, vor } from "./zeit";
import { abdruck } from "./FritzBox";

const knotenText: Record<string, string> = {
  up: "läuft",
  booting: "startet",
  down: "ausgefallen",
  taken_over: "vom Partner übernommen",
  waiting_for_giveback: "übernommen, wartet auf Rückgabe",
  degraded: "eingeschränkt",
  unknown: "unbekannt",
};

const teilText: Record<string, string> = { psu: "Netzteil", module: "Modul", fan: "Lüfter" };

function dauer(s: number) {
  const h = Math.floor(s / 3600);
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} Min.`;
  if (h < 72) return `${h} Std.`;
  return `${Math.floor(h / 24)} Tage`;
}

export function netappKurz(q: Snmp) {
  const o = q.messwerte?.ontap;
  if (!q.aktiv) return "NetApp-Abfrage ausgeschaltet";
  if (!o) return q.fehler ? `NetApp: ${q.fehler}` : "NetApp: noch nicht abgefragt";
  const teile = [`NetApp ${o.cluster || ""}`.trim(), `${o.knoten.length} Knoten`];
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

function knotenZeile(n: NetAppMesswerte["knoten"][number]) {
  const probleme: string[] = [];
  if (n.uebernahme === "in_takeover") probleme.push(`hat ${n.partner || "den Partner"} übernommen`);
  if (n.uebernahme === "failed") probleme.push("Übernahme fehlgeschlagen");
  if (n.uebernahme === "not_possible" && n.partner) probleme.push("Übernahme nicht möglich");
  if (n.partner && !n.ha) probleme.push("Failover aus");
  if (n.uebertemperatur) probleme.push("Übertemperatur");
  if (n.luefter_ausgefallen > 0) probleme.push(`${n.luefter_ausgefallen} Lüfter ausgefallen`);
  if (n.netzteile_ausgefallen > 0) probleme.push(`${n.netzteile_ausgefallen} Netzteil(e) ausgefallen`);
  return probleme;
}

export function NetAppTeil(props: {
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
  ohneAktionen?: boolean;
  entfernen?: boolean;
  onEntfernenEnde?: () => void;
}) {
  const { q, jetzt } = props;
  const m = q.messwerte;
  const o = m?.ontap;
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const [alleVolumes, setAlleVolumes] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (x: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(x);
    else if (!x) props.onEntfernenEnde?.();
  };
  const platte = new Map((m?.platten ?? []).map((d) => [d.einhaengepunkt, d]));
  const fehlt = [...(m?.teilweise ?? [])];
  // Volumes: zuerst gestörte und volle, dann nach Name; ohne „alle“ höchstens 15
  const volumes = (o?.volumes ?? [])
    .slice()
    .sort(
      (a, b) =>
        Number(b.zustand !== "online") - Number(a.zustand !== "online") ||
        prozent(b.belegt, b.gesamt || 1) - prozent(a.belegt, a.gesamt || 1) ||
        a.name.localeCompare(b.name, "de"),
    );
  const gezeigt = alleVolumes ? volumes : volumes.slice(0, 15);

  const belegung = (name: string) => {
    const d = platte.get(name);
    if (!d) return null;
    return (
      <>
        <td>
          <Pegel wert={prozent(d.gesamt - d.frei, d.gesamt)} titel={`${bytes(d.gesamt - d.frei)} von ${bytes(d.gesamt)}`} />
        </td>
        <td>
          {bytes(d.frei)} von {bytes(d.gesamt)}
          <br />
          <PrognoseZeile p={props.prognose.get(prognoseSchluessel("snmp", q.id, name))} />
        </td>
        <td>
          <SparkReihen d={props.spark} quelle="snmp" namen={["platte:" + name]} prozent titel={`Belegung ${name}, 24 Stunden`} />
        </td>
      </>
    );
  };

  return (
    <div className="geraet-snmp geraet-netapp">
      <h3 className="klein-titel">
        NetApp {o?.cluster || ""}
        {o?.version ? ` · ${o.version.replace(/^NetApp Release /, "ONTAP ").replace(/:.*$/, "")}` : ""}
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port}, alle {q.intervall_sekunden} s{q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, jetzt)}` : ""}
        {!q.hat_community && " · keine Zugangsdaten gespeichert"}
        {o?.fingerabdruck && ` · HTTPS, Zertifikat ${abdruck(o.fingerabdruck).slice(0, 23)}…`}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {fehlt.length > 0 && (
        <p className="meldung meldung-warnung">Nicht abfragbar: {fehlt.join(", ")}. Die Rolle des Kontos braucht Leserecht auf /api.</p>
      )}
      {(m?.gekuerzt ?? []).length > 0 && <p className="klein">Gekürzt (über der Grenze): {m!.gekuerzt!.join(", ")}.</p>}

      {o && o.knoten.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Knoten</th>
                <th scope="col">Zustand</th>
                <th scope="col">HA-Partner</th>
                <th scope="col">Läuft seit</th>
              </tr>
            </thead>
            <tbody>
              {o.knoten.map((n) => {
                const probleme = knotenZeile(n);
                const schlecht = n.zustand !== "up" || probleme.length > 0;
                return (
                  <tr key={n.name}>
                    <td>
                      <span className="mono">{n.name}</span> {n.modell && <span className="klein">{n.modell}</span>}
                    </td>
                    <td className={schlecht ? "text-crit" : undefined}>
                      {knotenText[n.zustand] ?? n.zustand}
                      {probleme.length > 0 && `: ${probleme.join(", ")}`}
                    </td>
                    <td>{n.partner ? <span className="mono">{n.partner}</span> : <span className="klein">keiner</span>}</td>
                    <td>{n.laufzeit_s > 0 ? laufzeit(n.laufzeit_s) : "–"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {o && o.aggregate.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Aggregat</th>
                <th scope="col">Belegt</th>
                <th scope="col">Frei</th>
                <th scope="col">24 Std.</th>
              </tr>
            </thead>
            <tbody>
              {o.aggregate.map((a) => (
                <tr key={a.name}>
                  <td>
                    <span className="mono">{a.name}</span> {a.knoten && <span className="klein">{a.knoten}</span>}
                    {a.iops !== undefined && (
                      <span className="klein">
                        {" "}
                        · {Math.round(a.iops)} IOPS{a.latenz_ms !== undefined ? `, ${a.latenz_ms.toFixed(2)} ms` : ""}
                      </span>
                    )}
                  </td>
                  {a.zustand !== "online" ? (
                    <td colSpan={3} className="text-crit">
                      nicht verfügbar ({a.zustand})
                    </td>
                  ) : (
                    (belegung("Aggregat " + a.name) ?? (
                      <td colSpan={3} className="klein">
                        keine Angabe
                      </td>
                    ))
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {o && volumes.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <caption className="klein">
              {volumes.length} Volumes; Spiegelziele (dp) ohne Alarm für „voll“, weil die Quelle sie füllt.
            </caption>
            <thead>
              <tr>
                <th scope="col">Volume</th>
                <th scope="col">Belegt</th>
                <th scope="col">Frei</th>
                <th scope="col">24 Std.</th>
              </tr>
            </thead>
            <tbody>
              {gezeigt.map((v) => (
                <tr key={v.name}>
                  <td>
                    <span className="mono">{v.name}</span>
                    {v.typ !== "rw" && <span className="klein"> · {v.typ}</span>}
                  </td>
                  {v.zustand !== "online" ? (
                    <td colSpan={3} className={v.zustand === "offline" || v.zustand === "restricted" ? "text-warn" : "text-crit"}>
                      {v.zustand}
                    </td>
                  ) : (
                    (belegung("Volume " + v.name) ??
                    (v.gesamt > 0 ? (
                      <>
                        <td>
                          <Pegel wert={prozent(v.belegt, v.gesamt)} titel={`${bytes(v.belegt)} von ${bytes(v.gesamt)}`} />
                        </td>
                        <td colSpan={2}>
                          {bytes(v.gesamt - v.belegt)} von {bytes(v.gesamt)}
                        </td>
                      </>
                    ) : (
                      <td colSpan={3} className="klein">
                        keine Angabe
                      </td>
                    )))
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {volumes.length > 15 && (
            <button className="knopf-text" onClick={() => setAlleVolumes(!alleVolumes)}>
              {alleVolumes ? "Weniger zeigen" : `Alle ${volumes.length} Volumes zeigen`}
            </button>
          )}
        </div>
      )}

      {o && (
        <dl className="eckdaten">
          <div>
            <dt>Platten</dt>
            <dd className={o.platten.auffaellig.length > 0 ? "text-crit" : undefined}>
              {o.platten.gesamt} Platten, {o.platten.ersatz} Ersatz
              {o.platten.auffaellig.length > 0 &&
                ` · auffällig: ${o.platten.auffaellig.map((d) => `${d.name} (${d.zustand === "broken" || d.behaelter === "broken" ? "ausgefallen" : d.zustand})`).join(", ")}`}
            </dd>
          </div>
          {o.shelves.map((s) => {
            const schlecht = s.teile.filter((t) => t.zustand === "error");
            const temps = s.temperaturen.filter((t) => t.grad !== undefined).map((t) => t.grad!);
            return (
              <div key={s.id}>
                <dt>Shelf {s.id}</dt>
                <dd className={s.zustand === "error" || schlecht.length > 0 ? "text-crit" : undefined}>
                  {s.modell ? `${s.modell}, ` : ""}
                  {schlecht.length > 0
                    ? schlecht.map((t) => `${teilText[t.art] ?? t.art} ${t.id} gestört`).join(", ")
                    : s.zustand === "error"
                      ? "meldet einen Fehler"
                      : "Netzteile, Module und Lüfter normal"}
                  {temps.length > 0 && `, bis ${Math.max(...temps)} °C`}
                </dd>
              </div>
            );
          })}
          {m && m.system.laufzeit_s > 0 && q.neustart_am && (
            <div>
              <dt>Neustart</dt>
              <dd>erkannt {vor(q.neustart_am, jetzt)}</dd>
            </div>
          )}
        </dl>
      )}

      {o && o.snapmirror.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">SnapMirror-Ziel</th>
                <th scope="col">Quelle</th>
                <th scope="col">Zustand</th>
                <th scope="col">Verzögerung</th>
              </tr>
            </thead>
            <tbody>
              {o.snapmirror.map((r) => (
                <tr key={r.ziel}>
                  <td className="mono">{r.ziel}</td>
                  <td className="mono">{r.quelle}</td>
                  <td className={r.gesund ? undefined : "text-crit"}>
                    {r.gesund ? r.zustand : `nicht gesund${r.grund ? `: ${r.grund}` : ""}`}
                  </td>
                  <td>{r.verzoegerung_s !== undefined ? dauer(r.verzoegerung_s) : "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {o && o.ems.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <caption className="klein">EMS-Ereignisse „emergency“ und „alert“ der letzten Stunde</caption>
            <thead>
              <tr>
                <th scope="col">Zeit</th>
                <th scope="col">Meldung</th>
                <th scope="col">Text</th>
              </tr>
            </thead>
            <tbody>
              {o.ems.map((e, i) => (
                <tr key={i}>
                  <td>{vor(e.zeit, jetzt)}</td>
                  <td>
                    <span className="mono">{e.name}</span> <span className="klein text-crit">{e.schwere}</span>
                  </td>
                  <td>
                    {e.knoten && <span className="mono">{e.knoten}: </span>}
                    {e.meldung}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {m && <SnmpVerlauf snmpId={q.id} schnittstellen={[]} />}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="NetApp-Abfrage entfernen">
              <p>
                NetApp-Abfrage für „{props.g.name}“ entfernen? Zugangsdaten, Verlauf und Meldezustand gehen verloren; das Alarmprotokoll
                bleibt. Das Konto in ONTAP bitte zusätzlich löschen.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/netapp`);
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
                    NetApp bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    NetApp entfernen
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

type Pruefung = { ok: true; netapp: NetAppInfo } | { ok: false; fehler: string; fingerabdruck_neu?: string; schreibrecht?: boolean };

export function NetAppFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const gespeichert = q?.messwerte?.ontap?.fingerabdruck;
  const [adresse, setAdresse] = useState(q?.adresse ?? props.g.adresse ?? "");
  const [port, setPort] = useState(String(q?.port ?? 443));
  const [benutzer, setBenutzer] = useState("");
  const [passwort, setPasswort] = useState("");
  // leer = beim Ändern der gespeicherte Fingerabdruck
  const [abdruckFeld, setAbdruckFeld] = useState("");
  const [intervall, setIntervall] = useState(String(q?.intervall_sekunden ?? 120));
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
      intervall_sekunden: Number(intervall) || 120,
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
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/netapp/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/netapp`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  const neuerAbdruck = pruefung && !pruefung.ok ? pruefung.fingerabdruck_neu : undefined;
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "NetApp bearbeiten" : `NetApp für „${props.g.name}“ einrichten`}</h3>
        <details className="formular-voll hinweis">
          <summary>Nur lesendes Konto in ONTAP anlegen</summary>
          <p className="klein">Auf der Cluster-Shell (Beispiel, Namen frei wählbar):</p>
          <pre className="befehl">
            {`security login rest-role create -role openwacht_lesen -api /api -access readonly
security login create -user-or-group-name svc-openwacht -application http -authentication-method password -role openwacht_lesen`}
          </pre>
          <p className="klein">
            OpenWacht ruft nur lesende Endpunkte aus einer festen Liste auf und prüft vor jeder Abfrage die Rechte des Kontos: Ein Konto mit
            Schreibrecht (zum Beispiel die Rolle „admin“) wird abgelehnt. Adresse: die Cluster-Management-Schnittstelle, HTTPS auf Port 443.
          </p>
        </details>
        <label className="feld">
          <span>Adresse des Clusters</span>
          <input
            required
            maxLength={253}
            value={adresse}
            placeholder="aff.beispiel.example oder 10.20.0.10"
            onChange={(e) => setAdresse(e.target.value)}
          />
        </label>
        <label className="feld feld-schmal">
          <span>Port</span>
          <input inputMode="numeric" pattern="[0-9]*" value={port} placeholder="443" onChange={(e) => setPort(e.target.value)} />
        </label>
        <label className="feld">
          <span>Benutzer</span>
          <input
            autoComplete="off"
            spellCheck={false}
            required
            maxLength={128}
            value={benutzer}
            placeholder="svc-openwacht"
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
              Verbunden mit {pruefung.netapp.cluster || "dem Cluster"}
              {pruefung.netapp.version ? ` (${pruefung.netapp.version.replace(/:.*$/, "")})` : ""}: {pruefung.netapp.knoten} Knoten,{" "}
              {pruefung.netapp.aggregate} Aggregate, {pruefung.netapp.volumes} Volumes, {pruefung.netapp.platten} Platten,{" "}
              {pruefung.netapp.shelves} Shelves, {pruefung.netapp.snapmirror} SnapMirror-Beziehungen. Das Konto hat nur Leserecht.
            </p>
          ) : neuerAbdruck ? (
            <div className="meldung meldung-warnung formular-voll" role="status">
              <p>
                {pruefung.fehler} Der Cluster zeigt dieses Zertifikat:
                <br />
                <span className="mono umbruch">{neuerAbdruck}</span>
              </p>
              <p className="klein">
                Zum Vergleich auf der Cluster-Shell <span className="mono">security certificate show -type server -fields public-cert</span>{" "}
                oder im Browser https://{adresse.trim() || "…"} den SHA-256-Fingerabdruck ansehen. Nur übernehmen, wenn er übereinstimmt.
              </p>
              <button type="button" className="knopf" onClick={() => setAbdruckFeld(neuerAbdruck)}>
                Fingerabdruck übernehmen
              </button>
            </div>
          ) : (
            <p className="meldung meldung-fehler formular-voll" role="status">
              {pruefung.schreibrecht ? "Abgelehnt: " : "Keine Verbindung: "}
              {pruefung.fehler}
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
