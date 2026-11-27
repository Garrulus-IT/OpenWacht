// SPDX-License-Identifier: AGPL-3.0-only

// Einen LLDP-Nachbarn ins Monitoring aufnehmen (1.0.12): legt ein Gerät im
// Mandanten des Switches an, vorbelegt mit Name und Verwaltungsadresse aus
// LLDP, auf Wunsch mit dem Switch als Elterngerät und einem Ping-Sensor.
// Danach öffnet sich das neue Gerät, dort lassen sich Agent, SNMP und weitere
// Sensoren einrichten. Aufgerufen aus dem Bild der Ports und dem Netzbild.

import { useState, type FormEvent } from "react";
import { api, type Geraet } from "./api";

export interface Kandidat {
  name: string;
  adresse?: string;
  // Port am Switch, an dem der Nachbar hängt (z. B. „Port 5“)
  port: string;
}

// vorname: Name für das neue Gerät aus dem LLDP-Namen (ohne Domäne, höchstens 100 Zeichen).
function vorname(n: string) {
  const t = n.trim();
  if (/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(t)) return "";
  return t.slice(0, 100);
}

export function Aufnehmen(props: {
  k: Kandidat;
  // Switch, an dem der Nachbar gemeldet wurde
  sw: Geraet;
  onFertig: (id: string) => void;
  onAbbrechen: () => void;
  melden: (e: unknown) => void;
}) {
  const { k, sw } = props;
  const [name, setName] = useState(vorname(k.name));
  const [adresse, setAdresse] = useState(k.adresse ?? "");
  const [eltern, setEltern] = useState(true);
  const [ping, setPing] = useState(!!k.adresse);
  const [arbeitet, setArbeitet] = useState(false);
  const [fehler, setFehler] = useState("");

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setArbeitet(true);
    try {
      const r = await api<{ id: string }>("POST", `/api/v1/mandanten/${sw.mandant_id}/geraete`, {
        name: name.trim(),
        adresse: adresse.trim(),
        gruppe_id: sw.gruppe_id ?? "",
        ...(eltern ? { abhaengig_von: sw.id } : {}),
      });
      if (ping && adresse.trim()) {
        try {
          await api("POST", `/api/v1/geraete/${r.id}/checks`, {
            name: "Ping",
            typ: "ping",
            ziel: { host: adresse.trim() },
            intervall_sekunden: 60,
          });
        } catch (err) {
          // Das Gerät steht schon; den Sensor kann man dort von Hand anlegen.
          props.melden(err);
        }
      }
      props.onFertig(r.id);
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <div className="einschub aufnehmen">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h4 className="einschub-titel">Ins Monitoring aufnehmen</h4>
        <p className="aufnehmen-herkunft formular-voll">
          <span className="aufnehmen-marke">LLDP</span>
          <span>
            gemeldet von <strong>{sw.name}</strong>, {k.port}
            {k.name ? (
              <>
                {" "}
                als <code>{k.name}</code>
              </>
            ) : null}
          </span>
        </p>
        <label className="feld">
          <span>Name</span>
          <input required maxLength={100} value={name} placeholder="z. B. ap-flur" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="feld">
          <span>Adresse{k.adresse ? " (aus LLDP)" : " (optional)"}</span>
          <input
            maxLength={253}
            value={adresse}
            placeholder="Hostname oder IP-Adresse"
            onChange={(e) => {
              setAdresse(e.target.value);
              if (!e.target.value.trim()) setPing(false);
            }}
          />
        </label>
        <label className="haken formular-voll">
          <input type="checkbox" checked={eltern} onChange={(e) => setEltern(e.target.checked)} />
          <span>
            Hängt ab von „{sw.name}“
            <span className="klein"> – fällt der Switch aus, ruhen die Alarme dieses Geräts</span>
          </span>
        </label>
        <label className="haken formular-voll">
          <input type="checkbox" checked={ping} disabled={!adresse.trim()} onChange={(e) => setPing(e.target.checked)} />
          <span>
            Ping-Sensor anlegen
            <span className="klein">{adresse.trim() ? " – die Zentrale prüft jede Minute, ob das Gerät antwortet" : " – braucht eine Adresse"}</span>
          </span>
        </label>
        <p className="klein formular-voll">
          Das Gerät kommt in den Mandanten{sw.gruppe_id ? " und die Gruppe" : ""} des Switches. Agent, SNMP und weitere Sensoren richtest du
          danach am Gerät ein.
        </p>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim()}>
            Aufnehmen und öffnen
          </button>
          <button type="button" className="knopf" onClick={props.onAbbrechen}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
