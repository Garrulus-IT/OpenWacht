// SPDX-License-Identifier: AGPL-3.0-only

// Proxmox eines Geräts: Gäste mit Backup-Stand, Speicher, Thin-Pools und
// Verlauf; Einrichten mit „Verbindung prüfen“.
//
// Das API-Token verlässt die Zentrale nie wieder: Die Liste sagt nur, ob eines
// gespeichert ist. Einrichten, ändern und entfernen dürfen nur Admins. Die
// Zentrale liest nur (Rolle PVEAuditor) und schickt dem Host keine Befehle.

import { useState, type FormEvent } from "react";
import { api, type Geraet, type ProxmoxGast, type ProxmoxInfo, type Snmp } from "./api";
import { SnmpVerlauf } from "./Verlauf";
import { prognoseSchluessel, PrognoseZeile, type PlattenPrognose } from "./Prognose";
import { SparkReihen, type SparkDaten } from "./Sparkline";
import { laufzeit, Pegel, prozent } from "./Pegel";
import { bytes, vor } from "./zeit";

// Schwellen wie in der Zentrale (internal/alarm/proxmox.go)
const BACKUP_WARN_S = 26 * 3600;
const BACKUP_KRIT_S = 50 * 3600;

const statusText: Record<string, string> = {
  running: "läuft",
  stopped: "gestoppt",
  paused: "angehalten",
  suspended: "angehalten",
  // ESXi-Hosts (vCenter)
  not_responding: "antwortet nicht",
  disconnected: "getrennt",
  standby: "Standby",
  powered_off: "ausgeschaltet",
};

// vCenter (Etappe 26) nutzt dieselbe Darstellung: ESXi-Hosts und VMs als Gäste.
const quelle = (q: Snmp) => (q.version === "vcenter" ? "vCenter" : "Proxmox");

export function proxmoxKurz(q: Snmp) {
  const p = q.messwerte?.proxmox;
  if (!q.aktiv) return `${quelle(q)} ausgeschaltet`;
  if (!p) return q.fehler ? `${quelle(q)}: ${q.fehler}` : `${quelle(q)}: noch nicht abgefragt`;
  const gaeste = p.gaeste.filter((g) => !g.vorlage);
  if (q.version === "vcenter") {
    const hosts = gaeste.filter((g) => g.typ === "esxi");
    const vms = gaeste.filter((g) => g.typ === "vm");
    const t = [
      `vCenter: ${hosts.filter((g) => g.status === "running").length} von ${hosts.length} Hosts verbunden`,
      `${vms.filter((g) => g.status === "running").length} von ${vms.length} VMs an`,
    ];
    if (q.fehler) t.push("letzte Abfrage gescheitert");
    return t.join(", ");
  }
  const teile = [`Proxmox VE ${p.version}`, `${gaeste.filter((g) => g.status === "running").length} von ${gaeste.length} Gästen laufen`];
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

function gastArt(g: ProxmoxGast) {
  return g.typ === "lxc" ? "CT" : g.typ === "esxi" ? "ESXi" : "VM";
}

// Backup-Zelle: Alter des letzten erfolgreichen Backups mit Schwellen.
function BackupStand({ g, jetzt, bekannt }: { g: ProxmoxGast; jetzt: number; bekannt: boolean }) {
  const ueberwacht = g.im_backup_job === true || (g.im_backup_job === undefined && !!g.backup_ok);
  if (!ueberwacht) {
    return <span className="klein">{bekannt ? "kein Backup-Job" : "–"}</span>;
  }
  const fehlgeschlagen =
    !!g.backup_fehler && !!g.backup_versucht && (!g.backup_ok || Date.parse(g.backup_versucht) > Date.parse(g.backup_ok));
  if (!g.backup_ok) {
    return (
      <span className="text-crit">
        keins in 8 Tagen
        {fehlgeschlagen && <span className="klein"> · {g.backup_fehler}</span>}
      </span>
    );
  }
  const alter = (jetzt - Date.parse(g.backup_ok)) / 1000;
  const klasse = alter >= BACKUP_KRIT_S ? "text-crit" : alter >= BACKUP_WARN_S ? "text-warn" : undefined;
  return (
    <span className={klasse}>
      {vor(g.backup_ok, jetzt)}
      {fehlgeschlagen && <span className="text-crit klein"> · letzter Versuch: {g.backup_fehler}</span>}
    </span>
  );
}

export function ProxmoxTeil(props: {
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
  entfernen?: boolean;
  onEntfernenEnde?: () => void;
}) {
  const { q, jetzt } = props;
  const m = q.messwerte;
  const p = m?.proxmox;
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (x: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(x);
    else if (!x) props.onEntfernenEnde?.();
  };
  const [vorlagen, setVorlagen] = useState(false);
  const gaeste = (p?.gaeste ?? []).filter((g) => vorlagen || !g.vorlage);
  const nVorlagen = (p?.gaeste ?? []).filter((g) => g.vorlage).length;
  const platte = new Map((m?.platten ?? []).map((x) => [x.einhaengepunkt, x]));
  const vc = q.version === "vcenter";

  return (
    <div className="geraet-snmp geraet-proxmox">
      <h3 className="klein-titel">
        {q.version === "vcenter" ? "VMware vCenter" : `Proxmox VE${p?.version ? ` ${p.version}` : ""}`}
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port}, alle {q.intervall_sekunden} s{q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, jetzt)}` : ""}
        {!q.hat_community && (vc ? " · kein Passwort gespeichert" : " · kein API-Token gespeichert")}
        {q.ca ? ` · CA ${q.ca.fingerabdruck.slice(0, 23)}…` : " · System-CAs"}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {p?.zu_viele_rechte && p.zu_viele_rechte.length > 0 && (
        <p className="meldung meldung-warnung">
          Das API-Token hat mehr Rechte als nötig ({p.zu_viele_rechte.join(", ")}). OpenWacht liest nur; bitte auf die Rolle PVEAuditor
          beschränken.
        </p>
      )}
      {m?.teilweise?.length ? <p className="meldung meldung-warnung">Nicht vollständig gelesen: {m.teilweise.join(", ")}.</p> : null}

      {m && p && !vc && (
        <dl className="eckdaten">
          <div>
            <dt>Knoten</dt>
            <dd>{p.knoten}</dd>
          </div>
          <div>
            <dt>Läuft seit</dt>
            <dd>
              {laufzeit(m.system.laufzeit_s)}
              {q.neustart_am && ` (Neustart erkannt ${vor(q.neustart_am, jetzt)})`}
            </dd>
          </div>
        </dl>
      )}

      {p && gaeste.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <caption className="klein">
              {vc
                ? "Hosts und VMs: Alarm, wenn ein ESXi-Host nicht verbunden ist. VMs nur zur Übersicht (vCenter sagt nicht, welche laufen sollen)."
                : "Gäste: Alarm, wenn ein Gast mit „beim Booten starten“ nicht läuft oder das letzte Backup älter als 26 Std. ist (kritisch ab 50 Std.)."}
            </caption>
            <thead>
              <tr>
                <th scope="col">{vc ? "Art" : "ID"}</th>
                <th scope="col">Name</th>
                <th scope="col">Status</th>
                {!vc && <th scope="col">Letztes Backup</th>}
              </tr>
            </thead>
            <tbody>
              {gaeste.map((g) => {
                const sollLaufen = !g.vorlage && g.beim_booten === true;
                return (
                  <tr key={g.typ + g.vmid}>
                    <td className={vc ? undefined : "mono"}>{vc ? gastArt(g) : `${gastArt(g)} ${g.vmid}`}</td>
                    <td>
                      {g.name || "–"}
                      {g.vorlage && <span className="klein"> (Vorlage)</span>}
                    </td>
                    <td className={sollLaufen && g.status !== "running" ? "text-crit" : undefined}>
                      {statusText[g.status] ?? g.status}
                      {g.status === "running" && g.laufzeit_s > 0 && <span className="klein"> seit {laufzeit(g.laufzeit_s)}</span>}
                      {sollLaufen && !vc && <span className="klein"> · startet beim Booten</span>}
                    </td>
                    {!vc && (
                      <td>
                        <BackupStand g={g} jetzt={jetzt} bekannt={p.backup_jobs_bekannt} />
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {nVorlagen > 0 && (
            <button className="knopf-text" onClick={() => setVorlagen(!vorlagen)}>
              {vorlagen ? "Vorlagen ausblenden" : `${nVorlagen} Vorlage${nVorlagen === 1 ? "" : "n"} zeigen`}
            </button>
          )}
        </div>
      )}
      {p && p.gaeste.length === 0 && <p className="klein">{vc ? "Keine Hosts und VMs gefunden." : "Keine Gäste auf diesem Knoten."}</p>}

      {p && p.speicherorte.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Speicher</th>
                <th scope="col">Belegt</th>
                <th scope="col">Frei</th>
                <th scope="col">24 Std.</th>
              </tr>
            </thead>
            <tbody>
              {p.speicherorte.map((sp) => {
                const d = platte.get(sp.name);
                return (
                  <tr key={sp.name}>
                    <td>
                      <span className="mono">{sp.name}</span> <span className="klein">{sp.typ}</span>
                      {sp.geteilt && <span className="klein"> · geteilt</span>}
                    </td>
                    {!sp.eingeschaltet ? (
                      <td colSpan={3} className="klein">
                        abgeschaltet
                      </td>
                    ) : !sp.aktiv ? (
                      <td colSpan={3} className="text-crit">
                        nicht verfügbar
                      </td>
                    ) : d ? (
                      <>
                        <td>
                          <Pegel wert={prozent(d.gesamt - d.frei, d.gesamt)} titel={`${bytes(d.gesamt - d.frei)} von ${bytes(d.gesamt)}`} />
                        </td>
                        <td>
                          {bytes(d.frei)} von {bytes(d.gesamt)}
                          <br />
                          <PrognoseZeile p={props.prognose.get(prognoseSchluessel("snmp", q.id, sp.name))} />
                        </td>
                        <td>
                          <SparkReihen
                            d={props.spark}
                            quelle="snmp"
                            namen={["platte:" + sp.name]}
                            prozent
                            titel={`Belegung ${sp.name}, 24 Stunden`}
                          />
                        </td>
                      </>
                    ) : (
                      <td colSpan={3} className="klein">
                        keine Angabe
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {p && p.thin_pools.length > 0 && (
        <table className="tabelle tabelle-kompakt">
          <caption className="klein">Thin-Pools: Volle Metadaten können den Pool beschädigen; Warnung ab 80 %, kritisch ab 90 %.</caption>
          <thead>
            <tr>
              <th scope="col">Thin-Pool</th>
              <th scope="col">Daten</th>
              <th scope="col">Metadaten</th>
            </tr>
          </thead>
          <tbody>
            {p.thin_pools.map((t) => (
              <tr key={t.name}>
                <td className="mono">{t.name}</td>
                <td>
                  <span className="nur-schmal klein">Daten </span>
                  {t.gesamt > 0 ? <Pegel wert={prozent(t.belegt, t.gesamt)} titel={`${bytes(t.belegt)} von ${bytes(t.gesamt)}`} /> : "–"}
                </td>
                <td>
                  <span className="nur-schmal klein">Metadaten </span>
                  {t.metadaten_gesamt > 0 ? (
                    <Pegel
                      wert={prozent(t.metadaten_belegt, t.metadaten_gesamt)}
                      titel={`${bytes(t.metadaten_belegt)} von ${bytes(t.metadaten_gesamt)}`}
                    />
                  ) : (
                    "–"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {m && <SnmpVerlauf snmpId={q.id} schnittstellen={[]} />}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="Proxmox-Abfrage entfernen">
              <p>
                Proxmox-Abfrage für „{props.g.name}“ entfernen? API-Token, Verlauf und Meldezustand gehen verloren; das Alarmprotokoll
                bleibt. Das Token auf dem Proxmox-Host bitte zusätzlich löschen.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/proxmox`);
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
                    {quelle(q)} bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    {quelle(q)} entfernen
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

type Pruefung = { ok: true; proxmox: ProxmoxInfo } | { ok: false; fehler: string };

// Befehle für den Proxmox-Host (als root in der Shell des Hosts).
const befehle = `pveum user add openwacht@pve --comment "OpenWacht, nur lesend"
pveum acl modify / --users openwacht@pve --roles PVEAuditor
pveum user token add openwacht@pve monitor --privsep 1
pveum acl modify / --tokens 'openwacht@pve!monitor' --roles PVEAuditor
cat /etc/pve/pve-root-ca.pem`;

export function ProxmoxFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const [adresse, setAdresse] = useState(q?.adresse ?? props.g.adresse ?? "");
  const [port, setPort] = useState(String(q?.port ?? 8006));
  const [token, setToken] = useState("");
  // null = CA unverändert lassen
  const [ca, setCa] = useState<string | null>(q ? null : "");
  const [intervall, setIntervall] = useState(String(q?.intervall_sekunden ?? 60));
  const [aktiv, setAktiv] = useState(q?.aktiv ?? true);
  const [fehler, setFehler] = useState("");
  const [pruefung, setPruefung] = useState<Pruefung | null>(null);
  const [prueft, setPrueft] = useState(false);
  const zielNeu = !q || adresse.trim() !== q.adresse || (Number(port) || 8006) !== q.port || ca !== null;

  const daten = () => {
    const d: Record<string, unknown> = {
      adresse: adresse.trim(),
      port: Number(port) || 8006,
      intervall_sekunden: Number(intervall) || 60,
      aktiv,
    };
    if (token.trim()) d.token = token.trim();
    if (ca !== null) d.ca = ca;
    return d;
  };
  const pruefen = async () => {
    setFehler("");
    setPruefung(null);
    setPrueft(true);
    try {
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/proxmox/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/proxmox`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "Proxmox bearbeiten" : `Proxmox für „${props.g.name}“ einrichten`}</h3>
        <details className="formular-voll hinweis">
          <summary>Token auf dem Proxmox-Host anlegen (nur lesend)</summary>
          <p className="klein">
            Als root in der Shell des Hosts. Die Ausgabe von <span className="mono">token add</span> zeigt das Geheimnis nur einmal; das
            Token hier als <span className="mono">openwacht@pve!monitor=…</span> eintragen. Die letzte Zeile zeigt die CA.
          </p>
          <pre className="befehl">{befehle}</pre>
        </details>
        <label className="feld">
          <span>Adresse des Hosts</span>
          <input
            required
            maxLength={253}
            value={adresse}
            placeholder="10.10.0.5 oder pve-01.example.com"
            onChange={(e) => setAdresse(e.target.value)}
          />
        </label>
        <label className="feld feld-schmal">
          <span>Port</span>
          <input inputMode="numeric" pattern="[0-9]*" value={port} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label className="feld formular-voll">
          <span>API-Token{zielNeu && q ? " (bei neuer Adresse, Port oder CA neu eingeben)" : q ? " (leer = unverändert)" : ""}</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            required={!q || zielNeu}
            maxLength={220}
            value={token}
            placeholder={q ? "••••••••" : "openwacht@pve!monitor=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
            onChange={(e) => setToken(e.target.value)}
          />
        </label>
        {ca === null ? (
          <div className="feld formular-voll">
            <span>CA des Hosts</span>
            <p className="klein">
              {q?.ca ? (
                <>
                  {q.ca.name}, gültig bis {new Date(q.ca.gueltig_bis).toLocaleDateString("de-DE")}
                  <br />
                  <span className="mono umbruch">{q.ca.fingerabdruck}</span>
                </>
              ) : (
                "System-CAs (z. B. bei einem ACME-Zertifikat)"
              )}{" "}
              <button type="button" className="knopf-text" onClick={() => setCa("")}>
                Ändern
              </button>
            </p>
          </div>
        ) : (
          <label className="feld formular-voll">
            <span>CA des Hosts (Inhalt von /etc/pve/pve-root-ca.pem; leer = System-CAs)</span>
            <textarea
              rows={5}
              spellCheck={false}
              className="mono"
              value={ca}
              placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
              onChange={(e) => setCa(e.target.value)}
            />
          </label>
        )}
        <label className="feld feld-schmal">
          <span>Abfrage alle</span>
          <select value={intervall} onChange={(e) => setIntervall(e.target.value)}>
            {[30, 60, 120, 300, 600, 900, 1800, 3600].map((s) => (
              <option key={s} value={s}>
                {s < 60 ? `${s} Sekunden` : s < 3600 ? `${s / 60} Min.` : "1 Std."}
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
            <p
              className={`meldung ${pruefung.proxmox.zu_viele_rechte.length ? "meldung-warnung" : "meldung-ok"} formular-voll`}
              role="status"
            >
              Verbunden mit Knoten „{pruefung.proxmox.knoten}“, Proxmox VE {pruefung.proxmox.version}, läuft seit{" "}
              {laufzeit(pruefung.proxmox.laufzeit_s).replace(/\.$/, "")}.
              {pruefung.proxmox.zu_viele_rechte.length > 0 &&
                ` Das Token hat mehr Rechte als nötig: ${pruefung.proxmox.zu_viele_rechte.join(", ")}.`}
            </p>
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
