// SPDX-License-Identifier: AGPL-3.0-only

// Gerät löschen (Etappe 19), auch mit Inhalt. Die Zentrale zählt vorher auf,
// was mitgeht; mit Inhalt muss der Name des Geräts eingetippt werden. Der
// Agent wird gesperrt und gelöscht, Sensoren, Abfragequellen, Trap-Regeln
// dieses Geräts und der Verlauf gehen mit, das Alarmprotokoll bleibt.

import { useEffect, useState, type FormEvent } from "react";
import { api } from "./api";

interface Vorschau {
  name: string;
  darf: boolean;
  sensoren: number;
  agents: { id: string; hostname: string; gesperrt: boolean }[];
  quellen: string[];
  trap_regeln: string[];
  wartung: boolean;
  sammler_fuer: number;
  regeln_blockiert: number;
}

const quelleText: Record<string, string> = {
  pve: "Proxmox-Abfrage",
  tr064: "FRITZ!Box-Abfrage",
  vcenter: "vCenter-Abfrage",
  ontap: "NetApp-Abfrage",
  xapi: "XenServer-Abfrage",
};

function anzahl(n: number, eins: string, viele: string) {
  return `${n} ${n === 1 ? eins : viele}`;
}

export function GeraetLoeschen(props: {
  geraetId: string;
  onGeloescht: () => void;
  onAbbrechen: () => void;
  melden: (e: unknown) => void;
}) {
  const [v, setV] = useState<Vorschau | null>(null);
  const [name, setName] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  useEffect(() => {
    let aus = false;
    api<Vorschau>("GET", `/api/v1/geraete/${props.geraetId}/loeschen`)
      .then((d) => !aus && setV(d))
      .catch((e) => !aus && setFehler(e instanceof Error ? e.message : String(e)));
    return () => {
      aus = true;
    };
  }, [props.geraetId]);

  const inhalt: string[] = [];
  if (v) {
    if (v.sensoren) inhalt.push(anzahl(v.sensoren, "Sensor", "Sensoren"));
    for (const a of v.agents) inhalt.push(`Agent „${a.hostname}“${a.gesperrt ? " (schon gesperrt)" : " – wird gesperrt"}`);
    for (const q of v.quellen) inhalt.push(quelleText[q] ?? `SNMP-Abfrage (v${q})`);
    if (v.trap_regeln.length) inhalt.push(`${anzahl(v.trap_regeln.length, "Trap-Regel", "Trap-Regeln")} (${v.trap_regeln.join(", ")})`);
    if (v.wartung) inhalt.push("die laufende Wartung");
  }
  const leer = v !== null && inhalt.length === 0;
  const gesperrt = v !== null && (v.sammler_fuer > 0 || v.regeln_blockiert > 0);
  const passt = leer || (v !== null && name.trim().toLowerCase() === v.name.toLowerCase());

  const loeschen = async (e: FormEvent) => {
    e.preventDefault();
    if (!v || !passt || gesperrt) return;
    setArbeitet(true);
    setFehler("");
    try {
      await api("DELETE", `/api/v1/geraete/${props.geraetId}`, leer ? undefined : { bestaetigung: name.trim() });
      props.onGeloescht();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
      setArbeitet(false);
    }
  };

  return (
    <form className="bestaetigung geraet-loeschen" role="alertdialog" aria-labelledby={`gl-${props.geraetId}`} onSubmit={loeschen}>
      <p id={`gl-${props.geraetId}`}>
        <strong>{v ? `„${v.name}“ löschen?` : "Gerät löschen?"}</strong>
      </p>
      {!v && !fehler && <p className="klein">Lade, was mitgelöscht würde …</p>}
      {v && !v.darf && <p>Löschen dürfen nur Admins und Operatoren.</p>}
      {v && v.darf && !leer && (
        <>
          <p>Mitgelöscht werden:</p>
          <ul className="loeschen-liste">
            {inhalt.map((t) => (
              <li key={t}>{t}</li>
            ))}
            <li>der Verlauf (Messwerte und Graphen)</li>
          </ul>
          <p className="klein">
            Das Alarmprotokoll und das Audit-Log bleiben.
            {v.agents.some((a) => !a.gesperrt) && " Den Agent auf dem Rechner danach deinstallieren; anmelden kann er sich nicht mehr."}
          </p>
        </>
      )}
      {v && v.darf && leer && <p>Das Gerät hat keine Sensoren, keinen Agent und keine Abfrage.</p>}
      {v && v.sammler_fuer > 0 && (
        <p className="meldung meldung-fehler">
          Der Agent ist Sammler für {anzahl(v.sammler_fuer, "weiteres Gerät", "weitere Geräte")}. Bitte dort zuerst unter „Abgefragt von“
          einen anderen Sammler oder die Zentrale wählen.
        </p>
      )}
      {v && v.regeln_blockiert > 0 && (
        <p className="meldung meldung-fehler">
          Eine Trap-Regel außerhalb dieses Geräts beendet eine Regel des Geräts. Bitte diese Entwarn-Regel zuerst ändern oder löschen.
        </p>
      )}
      {v && v.darf && !leer && !gesperrt && (
        <label className="feld">
          <span>Zur Bestätigung den Namen eintippen: {v.name}</span>
          <input autoFocus autoComplete="off" spellCheck={false} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
      )}
      {fehler && (
        <p className="meldung meldung-fehler" role="alert">
          {fehler}
        </p>
      )}
      <div className="aktionen">
        {v?.darf && !gesperrt && (
          <button className="knopf knopf-gefahr" disabled={!passt || arbeitet} autoFocus={leer}>
            {leer ? "Löschen" : "Endgültig löschen"}
          </button>
        )}
        <button type="button" className="knopf" onClick={props.onAbbrechen}>
          Abbrechen
        </button>
      </div>
    </form>
  );
}
