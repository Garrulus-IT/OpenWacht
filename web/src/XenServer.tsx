// SPDX-License-Identifier: AGPL-3.0-only

// XenServer bzw. XCP-ng eines Geräts (0.42.0): Pool und HA, Hosts mit CPU,
// RAM, Wartungsmodus und Updates, VMs (nur Name, Zustand und Zahlen) und
// Storage-Repositories mit Belegung, Prognose und Anbindung über XAPI;
// Einrichten mit „Verbindung prüfen“ und Fingerabdruck.
//
// Benutzer und Passwort verlassen die Zentrale nie wieder: Die Liste sagt nur,
// ob Zugangsdaten gespeichert sind. Einrichten, ändern und entfernen dürfen
// nur Admins. Die Zentrale liest nur, lehnt root ab und jede Sitzung mit mehr
// Rechten als „read-only“.

import { useState, type FormEvent } from "react";
import { api, type Geraet, type Snmp, type XenServerInfo, type XenServerMesswerte } from "./api";
import { SnmpVerlauf } from "./Verlauf";
import { prognoseSchluessel, PrognoseZeile, type PlattenPrognose } from "./Prognose";
import { SparkReihen, type SparkDaten } from "./Sparkline";
import { laufzeit, Pegel, prozent } from "./Pegel";
import { bytes, vor } from "./zeit";
import { abdruck } from "./FritzBox";

const vmText: Record<string, string> = {
  running: "läuft",
  halted: "aus",
  paused: "angehalten",
  suspended: "ausgesetzt",
  unknown: "unbekannt",
};

const schrittText: Record<string, string> = {
  reboot_host: "Host neu starten",
  reboot_host_on_livepatch_failure: "Host neu starten (Livepatch fehlgeschlagen)",
  reboot_host_on_kernel_livepatch_failure: "Host neu starten (Kernel-Livepatch fehlgeschlagen)",
  reboot_host_on_xen_livepatch_failure: "Host neu starten (Xen-Livepatch fehlgeschlagen)",
  restart_toolstack: "Toolstack neu starten",
  restart_device_model: "Gerätemodell der VMs neu starten",
  restart_vm: "VMs neu starten",
};

export function xenKurz(q: Snmp) {
  const x = q.messwerte?.xapi;
  if (!q.aktiv) return "XenServer-Abfrage ausgeschaltet";
  if (!x) return q.fehler ? `XenServer: ${q.fehler}` : "XenServer: noch nicht abgefragt";
  const n = x.vm_anzahl;
  const teile = [
    `XenServer ${x.pool || ""}`.trim(),
    `${x.hosts.length} Hosts`,
    `${n.laufend} von ${n.laufend + n.aus + n.angehalten + n.ausgesetzt} VMs laufen`,
  ];
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

function hostZustand(h: XenServerMesswerte["hosts"][number]): [string, string | undefined] {
  if (!h.erreichbar) return ["nicht erreichbar", "text-crit"];
  if (h.wartung) return ["Wartungsmodus", "text-warn"];
  if (!h.aktiviert) return ["deaktiviert", "text-warn"];
  return ["läuft", undefined];
}

function vmKlasse(v: XenServerMesswerte["vms"][number]) {
  if (!v.soll_laufen || v.zustand === "running") return undefined;
  return v.zustand === "halted" || v.zustand === "unknown" ? "text-crit" : "text-warn";
}

export function XenServerTeil(props: {
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
  const x = m?.xapi;
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const [alleVMs, setAlleVMs] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (v: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(v);
    else if (!v) props.onEntfernenEnde?.();
  };
  const platte = new Map((m?.platten ?? []).map((d) => [d.einhaengepunkt, d]));
  const fehlt = [...(m?.teilweise ?? [])];
  // VMs: zuerst die, die laufen sollen und nicht laufen, dann laufende nach CPU, dann nach Name; ohne „alle“ höchstens 15
  const vms = (x?.vms ?? [])
    .slice()
    .sort(
      (a, b) =>
        Number(!!vmKlasse(b)) - Number(!!vmKlasse(a)) ||
        Number(b.zustand === "running") - Number(a.zustand === "running") ||
        (b.cpu_prozent ?? 0) - (a.cpu_prozent ?? 0) ||
        a.name.localeCompare(b.name, "de"),
    );
  const gezeigt = alleVMs ? vms : vms.slice(0, 15);
  const anzahl = x ? x.vm_anzahl.laufend + x.vm_anzahl.aus + x.vm_anzahl.angehalten + x.vm_anzahl.ausgesetzt : 0;
  const updates = (x?.hosts ?? []).filter((h) => h.updates === "ausstehend" || (h.ausstehend ?? []).length > 0);

  return (
    <div className="geraet-snmp geraet-xenserver">
      <h3 className="klein-titel">
        XenServer {x?.pool || ""}
        {x?.produkt ? ` · ${x.produkt}` : ""}
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port} (Pool-Master{x?.master ? ` ${x.master}` : ""}), alle {q.intervall_sekunden} s
        {q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, jetzt)}` : ""}
        {!q.hat_community && " · keine Zugangsdaten gespeichert"}
        {x?.fingerabdruck && ` · HTTPS, Zertifikat ${abdruck(x.fingerabdruck).slice(0, 23)}…`}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {fehlt.length > 0 && <p className="meldung meldung-warnung">Nicht abfragbar: {fehlt.join(", ")}. Letzter Zustand bleibt.</p>}

      {x && x.hosts.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Zustand</th>
                <th scope="col">CPU</th>
                <th scope="col">RAM</th>
                <th scope="col">Läuft seit</th>
              </tr>
            </thead>
            <tbody>
              {x.hosts.map((h) => {
                const [text, klasse] = hostZustand(h);
                return (
                  <tr key={h.name}>
                    <td>
                      <span className="mono">{h.name}</span> {h.master && <span className="klein">Pool-Master</span>}
                    </td>
                    <td className={klasse}>
                      {text}
                      {h.messwerte_fehler && <span className="klein"> · Messwerte: {h.messwerte_fehler}</span>}
                    </td>
                    <td>
                      {h.cpu_prozent !== undefined ? <Pegel wert={h.cpu_prozent} titel={`CPU ${Math.round(h.cpu_prozent)} %`} /> : "–"}
                    </td>
                    <td>
                      {h.ram_gesamt > 0 && h.ram_frei <= h.ram_gesamt && (h.ram_frei > 0 || h.cpu_prozent !== undefined) ? (
                        <Pegel
                          wert={prozent(h.ram_gesamt - h.ram_frei, h.ram_gesamt)}
                          titel={`${bytes(h.ram_gesamt - h.ram_frei)} von ${bytes(h.ram_gesamt)}`}
                        />
                      ) : h.ram_gesamt > 0 ? (
                        bytes(h.ram_gesamt)
                      ) : (
                        "–"
                      )}
                    </td>
                    <td>{h.laufzeit_s > 0 ? laufzeit(h.laufzeit_s) : "–"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {x && (
        <dl className="eckdaten">
          <div>
            <dt>HA</dt>
            <dd
              className={!x.ha.an ? undefined : x.ha.ueberbucht ? "text-crit" : x.ha.plan_fuer < x.ha.tolerieren ? "text-warn" : undefined}
            >
              {!x.ha.an
                ? "ausgeschaltet"
                : x.ha.ueberbucht
                  ? `überbucht (Plan für ${x.ha.plan_fuer} von ${x.ha.tolerieren} Ausfällen)`
                  : `an, Plan für ${x.ha.plan_fuer} von ${x.ha.tolerieren} Host-Ausfällen`}
            </dd>
          </div>
          <div>
            <dt>Updates</dt>
            <dd className={updates.length > 0 ? "text-warn" : undefined}>
              {x.hosts.every((h) => !h.updates && !(h.ausstehend ?? []).length)
                ? "nicht lesbar (z. B. XCP-ng oder ohne Update-Kanal)"
                : updates.length === 0
                  ? "alle Hosts aktuell"
                  : updates
                      .map(
                        (h) =>
                          `${h.name}: ${[h.updates === "ausstehend" ? "Updates ausstehend" : "", ...(h.ausstehend ?? []).map((s) => schrittText[s] ?? s)].filter(Boolean).join(", ")}`,
                      )
                      .join("; ")}
            </dd>
          </div>
          <div>
            <dt>VMs</dt>
            <dd>
              {anzahl} VMs: {x.vm_anzahl.laufend} laufen, {x.vm_anzahl.aus} aus
              {x.vm_anzahl.angehalten > 0 && `, ${x.vm_anzahl.angehalten} angehalten`}
              {x.vm_anzahl.ausgesetzt > 0 && `, ${x.vm_anzahl.ausgesetzt} ausgesetzt`}
            </dd>
          </div>
          {m && m.system.laufzeit_s > 0 && q.neustart_am && (
            <div>
              <dt>Neustart</dt>
              <dd>erkannt {vor(q.neustart_am, jetzt)}</dd>
            </div>
          )}
        </dl>
      )}

      {x && x.speicher.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Storage-Repository</th>
                <th scope="col">Belegt</th>
                <th scope="col">Frei</th>
                <th scope="col">24 Std.</th>
              </tr>
            </thead>
            <tbody>
              {x.speicher.map((s) => {
                const d = platte.get("SR " + s.name);
                return (
                  <tr key={s.name}>
                    <td>
                      <span className="mono">{s.name}</span>{" "}
                      <span className="klein">
                        {s.typ}
                        {s.geteilt ? ", geteilt" : ""}
                      </span>
                      {(s.nicht_angebunden ?? []).length > 0 && (
                        <span className="klein text-crit"> · nicht angebunden auf {s.nicht_angebunden!.join(", ")}</span>
                      )}
                    </td>
                    {d ? (
                      <>
                        <td>
                          <Pegel wert={prozent(d.gesamt - d.frei, d.gesamt)} titel={`${bytes(d.gesamt - d.frei)} von ${bytes(d.gesamt)}`} />
                        </td>
                        <td>
                          {bytes(d.frei)} von {bytes(d.gesamt)}
                          <br />
                          <PrognoseZeile p={props.prognose.get(prognoseSchluessel("snmp", q.id, "SR " + s.name))} />
                        </td>
                        <td>
                          <SparkReihen
                            d={props.spark}
                            quelle="snmp"
                            namen={["platte:SR " + s.name]}
                            prozent
                            titel={`Belegung ${s.name}, 24 Stunden`}
                          />
                        </td>
                      </>
                    ) : (
                      <td colSpan={3} className="klein">
                        {s.typ === "iso" || s.typ === "udev" ? "Medien, keine Belegung" : "keine Angabe"}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {x && vms.length > 0 && (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <caption className="klein">
              {anzahl > vms.length ? `${vms.length} von ${anzahl} VMs` : `${anzahl} VMs`}; Alarm nur für VMs, die laufen sollen (HA-Neustart
              „restart“ oder „automatisch starten“).
            </caption>
            <thead>
              <tr>
                <th scope="col">VM</th>
                <th scope="col">Zustand</th>
                <th scope="col">CPU</th>
                <th scope="col">RAM</th>
              </tr>
            </thead>
            <tbody>
              {gezeigt.map((v) => (
                <tr key={v.uuid}>
                  <td>
                    {v.name}
                    {v.host && <span className="klein"> · {v.host}</span>}
                  </td>
                  <td className={vmKlasse(v)}>
                    {vmText[v.zustand] ?? v.zustand}
                    {v.soll_laufen && v.zustand !== "running" && " (soll laufen)"}
                  </td>
                  <td>
                    {v.cpu_prozent !== undefined
                      ? `${Math.round(v.cpu_prozent)} % von ${v.vcpus} vCPU`
                      : v.vcpus > 0
                        ? `${v.vcpus} vCPU`
                        : "–"}
                  </td>
                  <td>{v.ram > 0 ? bytes(v.ram) : "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {vms.length > 15 && (
            <button className="knopf-text" onClick={() => setAlleVMs(!alleVMs)}>
              {alleVMs ? "Weniger zeigen" : `Alle ${vms.length} VMs zeigen`}
            </button>
          )}
        </div>
      )}

      {m && <SnmpVerlauf snmpId={q.id} schnittstellen={[]} />}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="XenServer-Abfrage entfernen">
              <p>
                XenServer-Abfrage für „{props.g.name}“ entfernen? Zugangsdaten, Verlauf und Meldezustand gehen verloren; das Alarmprotokoll
                bleibt. Die Rolle des AD-Kontos im Pool bitte zusätzlich entfernen.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/xenserver`);
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
                    XenServer bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    XenServer entfernen
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

type Pruefung =
  | { ok: true; xenserver: XenServerInfo }
  | { ok: false; fehler: string; fingerabdruck_neu?: string; schreibrecht?: boolean; neuer_master?: string };

export function XenServerFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const gespeichert = q?.messwerte?.xapi?.fingerabdruck;
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
  const istRoot = benutzer.trim().toLowerCase() === "root";

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
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/xenserver/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/xenserver`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  const neuerAbdruck = pruefung && !pruefung.ok ? pruefung.fingerabdruck_neu : undefined;
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "XenServer bearbeiten" : `XenServer für „${props.g.name}“ einrichten`}</h3>
        <details className="formular-voll hinweis">
          <summary>Nur lesendes Konto im Pool einrichten</summary>
          <p className="klein">
            XenServer vergibt Rollen nur an Konten aus dem Active Directory; ohne AD gibt es nur root, und root lehnt OpenWacht ab. Der Pool
            muss also in der Domäne sein. Dann auf dem Pool-Master (Beispiel, Konto frei wählbar):
          </p>
          <pre className="befehl">
            {`xe subject-add subject-name=svc-openwacht
xe subject-list subject-name=svc-openwacht params=uuid
xe subject-role-add uuid=<UUID aus der Zeile davor> role-name=read-only`}
          </pre>
          <p className="klein">
            In XenCenter geht dasselbe unter „Pool → Eigenschaften → Benutzer“. OpenWacht ruft nur lesende Methoden aus einer festen Liste
            auf und prüft nach jeder Anmeldung die Rechte der Sitzung: Hat das Konto mehr als „read-only“ (auch über eine Gruppe), wird es
            abgelehnt. Adresse: der Pool-Master, HTTPS auf Port 443. Für CPU und RAM der übrigen Hosts müssen auch deren Adressen in der
            Netzfreigabe liegen. Gilt auch für XCP-ng.
          </p>
        </details>
        <label className="feld">
          <span>Adresse des Pool-Masters</span>
          <input
            required
            maxLength={253}
            value={adresse}
            placeholder="xs-01.beispiel.example oder 10.20.0.11"
            onChange={(e) => setAdresse(e.target.value)}
          />
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
            maxLength={128}
            value={benutzer}
            placeholder="svc-openwacht@beispiel.example"
            aria-invalid={istRoot || undefined}
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
        {istRoot && (
          <p className="meldung meldung-fehler formular-voll" role="status">
            root wird abgelehnt: root hat alle Rechte. Bitte ein AD-Konto mit der Rolle „read-only“ nehmen.
          </p>
        )}
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
              Verbunden mit Pool {pruefung.xenserver.pool || "ohne Namen"}
              {pruefung.xenserver.produkt ? ` (${pruefung.xenserver.produkt})` : ""}, Pool-Master {pruefung.xenserver.master}:{" "}
              {pruefung.xenserver.hosts} Hosts, {pruefung.xenserver.vms} VMs, {pruefung.xenserver.speicher} Storage-Repositories, HA{" "}
              {pruefung.xenserver.ha ? "an" : "aus"}. Messwerte von {pruefung.xenserver.hosts_mit_messwerten} von {pruefung.xenserver.hosts}{" "}
              Hosts. Das Konto hat nur Leserecht.
            </p>
          ) : neuerAbdruck ? (
            <div className="meldung meldung-warnung formular-voll" role="status">
              <p>
                {pruefung.fehler} Der Pool-Master zeigt dieses Zertifikat:
                <br />
                <span className="mono umbruch">{neuerAbdruck}</span>
              </p>
              <p className="klein">
                Zum Vergleich auf dem Pool-Master{" "}
                <span className="mono">openssl x509 -in /etc/xensource/xapi-ssl.pem -noout -fingerprint -sha256</span> oder{" "}
                <span className="mono">xe certificate-list type=host params=host,fingerprint_sha256</span>. Nur übernehmen, wenn er
                übereinstimmt.
              </p>
              <button type="button" className="knopf" onClick={() => setAbdruckFeld(neuerAbdruck)}>
                Fingerabdruck übernehmen
              </button>
            </div>
          ) : (
            <div className="meldung meldung-fehler formular-voll" role="status">
              <p>
                {pruefung.schreibrecht ? "Abgelehnt: " : "Keine Verbindung: "}
                {pruefung.fehler}
              </p>
              {pruefung.neuer_master && (
                <p className="klein">
                  Neuer Pool-Master: <span className="mono">{pruefung.neuer_master}</span>. Adresse prüfen, eintragen und den Fingerabdruck
                  neu holen.
                </p>
              )}
            </div>
          ))}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={istRoot}>
            Speichern
          </button>
          <button type="button" className="knopf" disabled={prueft || istRoot} onClick={() => void pruefen()}>
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
