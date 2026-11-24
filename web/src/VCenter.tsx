// SPDX-License-Identifier: AGPL-3.0-only

// vCenter einrichten (Etappe 26). Die Anzeige teilt sich ProxmoxTeil.

import { useState, type FormEvent } from "react";
import { api, type Geraet, type Snmp } from "./api";

type VCPruefung = { ok: true; vcenter: { hosts: number; vms: number; datastores: number } } | { ok: false; fehler: string };

export function VCenterFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const [adresse, setAdresse] = useState(q?.adresse ?? props.g.adresse ?? "");
  const [port, setPort] = useState(String(q?.port ?? 443));
  const [benutzer, setBenutzer] = useState("");
  const [passwort, setPasswort] = useState("");
  // null = CA unverändert lassen
  const [ca, setCa] = useState<string | null>(q ? null : "");
  const [intervall, setIntervall] = useState(String(q?.intervall_sekunden ?? 60));
  const [aktiv, setAktiv] = useState(q?.aktiv ?? true);
  const [fehler, setFehler] = useState("");
  const [pruefung, setPruefung] = useState<VCPruefung | null>(null);
  const [prueft, setPrueft] = useState(false);
  const zielNeu = !q || adresse.trim() !== q.adresse || (Number(port) || 443) !== q.port || ca !== null;

  const daten = () => {
    const d: Record<string, unknown> = {
      adresse: adresse.trim(),
      port: Number(port) || 443,
      benutzer: benutzer.trim(),
      intervall_sekunden: Number(intervall) || 60,
      aktiv,
    };
    if (passwort) d.passwort = passwort;
    if (ca !== null) d.ca = ca;
    return d;
  };
  const pruefen = async () => {
    setFehler("");
    setPruefung(null);
    setPrueft(true);
    try {
      setPruefung(await api<VCPruefung>("POST", `/api/v1/geraete/${props.g.id}/vcenter/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/vcenter`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "vCenter bearbeiten" : `vCenter für „${props.g.name}“ einrichten`}</h3>
        <p className="klein formular-voll">
          Im vCenter ein eigenes Konto (z. B. svc-openwacht@vsphere.local) mit der Rolle „Read-only“ auf der obersten Ebene anlegen.
          OpenWacht meldet sich an und liest nur Hosts, VMs und Datastores. Das vCenter muss in der Netzfreigabe liegen.
        </p>
        <label className="feld">
          <span>Adresse des Hosts</span>
          <input required maxLength={253} value={adresse} placeholder="vcenter.example.com" onChange={(e) => setAdresse(e.target.value)} />
        </label>
        <label className="feld feld-schmal">
          <span>Port</span>
          <input inputMode="numeric" pattern="[0-9]*" value={port} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label className="feld">
          <span>Benutzer{q ? " (beim Ändern erneut angeben)" : ""}</span>
          <input
            required
            maxLength={128}
            spellCheck={false}
            value={benutzer}
            placeholder="svc-openwacht@vsphere.local"
            onChange={(e) => setBenutzer(e.target.value)}
          />
        </label>
        <label className="feld">
          <span>
            Passwort
            {zielNeu && q
              ? " (bei neuer Adresse, Port oder CA neu eingeben)"
              : q
                ? " (leer = unverändert, nur mit demselben Benutzer)"
                : ""}
          </span>
          <input
            type="password"
            autoComplete="new-password"
            required={!q || zielNeu}
            maxLength={256}
            value={passwort}
            placeholder={q ? "••••••••" : ""}
            onChange={(e) => setPasswort(e.target.value)}
          />
        </label>
        {ca === null ? (
          <div className="feld formular-voll">
            <span>CA des vCenter</span>
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
            <span>CA des vCenter (VMCA-Wurzel, im vCenter unter „Zertifikate“ herunterladbar; leer = System-CAs)</span>
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
            <p className="meldung meldung-ok formular-voll" role="status">
              Verbunden: {pruefung.vcenter.hosts} Hosts, {pruefung.vcenter.vms} VMs, {pruefung.vcenter.datastores} Datastores.
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
