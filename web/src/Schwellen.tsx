// SPDX-License-Identifier: AGPL-3.0-only

// Schwellen für Hosts (Etappe 19): global und je Mandant auf der Seite
// Einstellungen, je Gerät im Aktionsmenü. Leeres Feld = erbt (vom Mandanten
// bzw. global), 0 = aus. „Stumm nach“ wird in Minuten eingegeben, die API
// rechnet in Sekunden.

import { useEffect, useState, type FormEvent } from "react";
import { api } from "./api";

export type SchwellenWerte = Record<string, number | null>;

export const schwellenFelder: { id: string; text: string; einheit: string }[] = [
  { id: "stumm_nach_s", text: "Stumm nach", einheit: "Min." },
  { id: "platte_warn", text: "Platte Warnung", einheit: "%" },
  { id: "platte_krit", text: "Platte kritisch", einheit: "%" },
  { id: "speicher_warn", text: "RAM Warnung", einheit: "%" },
  { id: "speicher_krit", text: "RAM kritisch", einheit: "%" },
  { id: "cpu_warn", text: "CPU Warnung", einheit: "%" },
  { id: "cpu_krit", text: "CPU kritisch", einheit: "%" },
  { id: "platte_tage", text: "Platte voll in unter", einheit: "Tagen" },
];

// Anzeige eines Werts der API (Sekunden bzw. Prozent).
export function schwelleText(id: string, v: number | null | undefined): string {
  if (v === null || v === undefined) return "–";
  if (id === "stumm_nach_s") return `${Math.round(v / 60)} Min.`;
  if (id === "platte_tage") return v === 0 ? "aus" : `${v} Tage`;
  return v === 0 ? "aus" : `${v.toLocaleString("de-DE")} %`;
}

// Eingabe ↔ API
export function zuEingabe(w: SchwellenWerte): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of schwellenFelder) {
    const v = w[f.id];
    out[f.id] = v === null || v === undefined ? "" : f.id === "stumm_nach_s" ? String(Math.round(v / 60)) : String(v);
  }
  return out;
}

export function ausEingabe(e: Record<string, string>): { werte: SchwellenWerte; fehler: string } {
  const werte: SchwellenWerte = {};
  for (const f of schwellenFelder) {
    const t = (e[f.id] ?? "").trim().replace(",", ".");
    if (t === "") {
      werte[f.id] = null;
      continue;
    }
    const n = Number(t);
    if (!Number.isFinite(n) || n < 0) return { werte, fehler: `${f.text}: bitte eine Zahl angeben.` };
    if (f.id === "platte_tage") {
      if (n > 365 || !Number.isInteger(n)) return { werte, fehler: "„Platte voll in unter … Tagen“: 0 (aus) bis 365 Tage." };
      werte[f.id] = n;
    } else if (f.id === "stumm_nach_s") {
      if (n < 2 || n > 1440) return { werte, fehler: "„Stumm nach“: 2 bis 1440 Minuten." };
      werte[f.id] = Math.round(n) * 60;
    } else {
      if (n !== 0 && (n < 1 || n > 100)) return { werte, fehler: `${f.text}: 0 (aus) oder 1 bis 100 %.` };
      werte[f.id] = n;
    }
  }
  return { werte, fehler: "" };
}

// Eingabefelder; geerbt = was ohne Eintrag gilt (Platzhalter).
export function SchwellenFelder(props: {
  eingabe: Record<string, string>;
  setEingabe: (e: Record<string, string>) => void;
  geerbt: SchwellenWerte;
  gesperrt?: Record<string, boolean>;
  idPraefix: string;
}) {
  return (
    <div className="schwellen-felder">
      {schwellenFelder.map((f) => (
        <label key={f.id} className="feld" htmlFor={`${props.idPraefix}-${f.id}`}>
          <span>
            {f.text} ({f.einheit})
          </span>
          <input
            id={`${props.idPraefix}-${f.id}`}
            inputMode="decimal"
            maxLength={6}
            disabled={props.gesperrt?.[f.id]}
            value={props.eingabe[f.id] ?? ""}
            placeholder={`erbt: ${schwelleText(f.id, props.geerbt[f.id])}`}
            title={props.gesperrt?.[f.id] ? "per Startoption gesetzt" : undefined}
            onChange={(e) => props.setEingabe({ ...props.eingabe, [f.id]: e.target.value })}
          />
        </label>
      ))}
    </div>
  );
}

interface GeraetSchwellenAntwort {
  eigene: SchwellenWerte;
  mandant: SchwellenWerte;
  global: SchwellenWerte;
  wirksam: SchwellenWerte;
  darf_aendern: boolean;
}

// Schwellen eines Geräts (Agent und SNMP/Proxmox/FRITZ!Box des Geräts).
export function GeraetSchwellen(props: { geraetId: string; name: string; onFertig: () => void; melden: (e: unknown) => void }) {
  const [daten, setDaten] = useState<GeraetSchwellenAntwort | null>(null);
  const [eingabe, setEingabe] = useState<Record<string, string>>({});
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  useEffect(() => {
    let aus = false;
    api<GeraetSchwellenAntwort>("GET", `/api/v1/geraete/${props.geraetId}/schwellen`)
      .then((d) => {
        if (aus) return;
        setDaten(d);
        setEingabe(zuEingabe(d.eigene));
      })
      .catch((e) => !aus && setFehler(e instanceof Error ? e.message : String(e)));
    return () => {
      aus = true;
    };
  }, [props.geraetId]);

  const geerbt: SchwellenWerte = {};
  if (daten) for (const f of schwellenFelder) geerbt[f.id] = daten.mandant[f.id] ?? daten.global[f.id] ?? null;

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    const { werte, fehler } = ausEingabe(eingabe);
    if (fehler) {
      setFehler(fehler);
      return;
    }
    setArbeitet(true);
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.geraetId}/schwellen`, { schwellen: werte });
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <form className="formular schwellen-formular" onSubmit={speichern} aria-label={`Schwellen für ${props.name}`}>
      <h3 className="klein-titel">Schwellen für „{props.name}“</h3>
      <p className="hinweis klein">
        Leer = erbt vom Mandanten bzw. von den Einstellungen der Installation, 0 = aus. Gilt für den Agent und die SNMP-, Proxmox- bzw.
        FRITZ!Box-Abfrage des Geräts.
      </p>
      {!daten && !fehler && <p className="klein">Lade …</p>}
      {daten && <SchwellenFelder eingabe={eingabe} setEingabe={setEingabe} geerbt={geerbt} idPraefix={`gs-${props.geraetId}`} />}
      {fehler && (
        <p className="meldung meldung-fehler" role="alert">
          {fehler}
        </p>
      )}
      <div className="aktionen">
        {daten?.darf_aendern && (
          <button className="knopf knopf-haupt" disabled={arbeitet}>
            Speichern
          </button>
        )}
        {daten?.darf_aendern && (
          <button type="button" className="knopf" onClick={() => setEingabe(zuEingabe({}))}>
            Alle leeren (erben)
          </button>
        )}
        <button type="button" className="knopf" onClick={props.onFertig}>
          {daten?.darf_aendern ? "Abbrechen" : "Schließen"}
        </button>
      </div>
    </form>
  );
}
