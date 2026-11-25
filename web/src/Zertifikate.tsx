// SPDX-License-Identifier: AGPL-3.0-only

// Zertifikate (1.0.5): alle Sensoren „TLS-Zertifikat“ auf einen Blick,
// sortiert nach Ablauf.
//
// Die Daten kommen aus derselben Liste wie die Sensoren eines Geräts
// (/api/v1/checks); die Zentrale liefert nur, was der Benutzer sehen darf.
// Ablaufdatum und Aussteller stehen in der Meldung des letzten Laufs
// („gültig bis 31.01.2027 (noch 67 Tage), Aussteller …“); die Seite liest sie
// dort heraus und zeigt sie nur als Text an.

import { useMemo, useState } from "react";
import type { Check, Geraet } from "./api";
import { anzeige, anzeigeText, rang, type Anzeige } from "./Checks";
import { mandantName, type Bereich } from "./bereich";
import { useQuelle } from "./quelle";
import { Q } from "./Widgets";

const TAG = 86_400_000;

export interface ZertZeile {
  c: Check;
  stand: Anzeige;
  bis: Date | null;
  rest: number | null; // ganze Tage bis zum Ablauf, negativ = abgelaufen
  aussteller: string;
  problem: string;
}

// lesen: Ablaufdatum, Aussteller und ein Problem (z. B. falscher Name) aus der Meldung.
export function lesen(c: Check, heute: Date): ZertZeile {
  const m = c.meldung ?? "";
  const d = /(\d{2})\.(\d{2})\.(\d{4})/.exec(m);
  let bis: Date | null = null;
  if (d) {
    const x = new Date(Number(d[3]), Number(d[2]) - 1, Number(d[1]));
    if (x.getDate() === Number(d[1])) bis = x;
  }
  const tag0 = new Date(heute.getFullYear(), heute.getMonth(), heute.getDate());
  const rest = bis ? Math.round((bis.getTime() - tag0.getTime()) / TAG) : null;
  const a = /, Aussteller (.+)$/.exec(m);
  const i = m.indexOf("; gültig bis ");
  const problem = i > 0 ? m.slice(0, i) : bis ? "" : m;
  return { c, stand: anzeige(c), bis, rest, aussteller: a?.[1] ?? "", problem };
}

function restText(z: ZertZeile) {
  if (z.rest === null) return "–";
  if (z.rest < 0) return z.rest === -1 ? "seit 1 Tag abgelaufen" : `seit ${-z.rest} Tagen abgelaufen`;
  if (z.rest === 0) return "läuft heute ab";
  return z.rest === 1 ? "1 Tag" : `${z.rest} Tage`;
}

function adresse(c: Check) {
  const z = c.ziel;
  return `${z.host ?? ""}${z.port && z.port !== 443 ? `:${z.port}` : ""}${z.verbinde ? ` über ${z.verbinde}` : ""}`;
}

type Filter = "alle" | "bald" | "probleme";

export function Zertifikate({ bereich, onOeffnen }: { bereich: Bereich; onOeffnen: (id: string) => void }) {
  const qc = useQuelle<{ checks: Check[] }>("/api/v1/checks", 60_000);
  const qg = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 60_000);
  const [filter, setFilter] = useState<Filter>("alle");
  const [tage, setTage] = useState(30);

  const zeilen = useMemo(() => {
    if (!qc.daten) return null;
    const heute = new Date();
    return qc.daten.checks
      .filter((c) => c.typ === "tls" && bereich.ids.has(c.mandant_id))
      .map((c) => lesen(c, heute))
      .sort((a, b) => {
        // ohne Datum ans Ende, sonst nach Rest; bei Gleichstand der schlimmere Zustand zuerst
        if (a.rest === null || b.rest === null) return a.rest === null ? (b.rest === null ? rang[a.stand] - rang[b.stand] : 1) : -1;
        return a.rest - b.rest || rang[a.stand] - rang[b.stand];
      });
  }, [qc.daten, bereich]);

  const geraete = useMemo(() => new Map((qg.daten?.geraete ?? []).map((g) => [g.id, g])), [qg.daten]);

  const fehler = qc.fehler || qg.fehler;
  if (fehler) return <p className="meldung meldung-fehler">{fehler}</p>;
  if (!zeilen) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }
  const bald = (z: ZertZeile) => z.rest !== null && z.rest <= tage;
  const problem = (z: ZertZeile) => z.stand === "crit" || z.stand === "warn" || z.stand === "unknown";
  const gezeigt = zeilen.filter((z) => filter === "alle" || (filter === "bald" ? bald(z) : problem(z)));
  const nBald = zeilen.filter(bald).length;
  const nProbleme = zeilen.filter(problem).length;

  return (
    <section className="ansicht zertifikate" aria-labelledby="zert-titel">
      <h1 id="zert-titel" className="sr-only">
        Zertifikate
      </h1>
      <p className="klein">
        Alle Sensoren „TLS-Zertifikat“ im gewählten Bereich, das zuerst ablaufende oben. Datum und Aussteller stammen aus dem letzten Lauf
        des Sensors. Neue Zertifikate kommen über einen Sensor am Gerät dazu (Hosts → Gerät → Sensor hinzufügen → TLS-Zertifikat).
      </p>
      <div className="zert-leiste">
        <div className="umschalter" role="group" aria-label="Filter">
          <button type="button" className="umschalter-knopf" aria-pressed={filter === "alle"} onClick={() => setFilter("alle")}>
            Alle ({zeilen.length})
          </button>
          <button type="button" className="umschalter-knopf" aria-pressed={filter === "bald"} onClick={() => setFilter("bald")}>
            Bald fällig ({nBald})
          </button>
          <button type="button" className="umschalter-knopf" aria-pressed={filter === "probleme"} onClick={() => setFilter("probleme")}>
            Mit Problem ({nProbleme})
          </button>
        </div>
        <label className="zert-tage">
          <span>bald fällig: höchstens</span>
          <select value={tage} onChange={(e) => setTage(Number(e.target.value))}>
            {[14, 30, 60, 90].map((t) => (
              <option key={t} value={t}>
                {t} Tage
              </option>
            ))}
          </select>
        </label>
      </div>
      {zeilen.length === 0 ? (
        <p className="leer">Im gewählten Bereich gibt es noch keinen Sensor „TLS-Zertifikat“.</p>
      ) : gezeigt.length === 0 ? (
        <p className="leer">{filter === "bald" ? `Kein Zertifikat läuft in den nächsten ${tage} Tagen ab.` : "Kein Zertifikat mit Problem."}</p>
      ) : (
        <div className="tabelle-rahmen">
          <table className="tabelle tabelle-kompakt">
            <thead>
              <tr>
                <th scope="col">Zustand</th>
                <th scope="col">Zertifikat</th>
                <th scope="col">Gerät</th>
                <th scope="col">Gültig bis</th>
                <th scope="col">Rest</th>
                <th scope="col">Aussteller oder Hinweis</th>
              </tr>
            </thead>
            <tbody>
              {gezeigt.map((z) => {
                const g = geraete.get(z.c.geraet_id);
                return (
                  <tr key={z.c.id}>
                    <td>
                      <span className={`marke marke-${z.stand === "neu" || z.stand === "pause" ? "ende" : z.stand}`}>{anzeigeText[z.stand]}</span>
                    </td>
                    <td>
                      <div className="name">{adresse(z.c)}</div>
                      <div className="klein">
                        {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, z.c.mandant_id)}</span>}
                        {z.c.name}
                      </div>
                    </td>
                    <td>
                      <button type="button" className="knopf-text" onClick={() => onOeffnen(z.c.geraet_id)}>
                        {g?.name ?? "Gerät"}
                      </button>
                    </td>
                    <td>{z.bis ? z.bis.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" }) : "–"}</td>
                    <td className={z.rest !== null && z.rest <= tage ? "zert-bald" : undefined}>{restText(z)}</td>
                    <td className="klein">{z.problem || z.aussteller}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
