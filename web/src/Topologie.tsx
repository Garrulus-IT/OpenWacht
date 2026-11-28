// SPDX-License-Identifier: AGPL-3.0-only

// Topologie (1.0.3): die Abhängigkeiten der Geräte als Bäume.
//
// Grundlage ist dieselbe Angabe wie bei der Alarmunterdrückung: „hängt ab von“
// unter „Gerät bearbeiten“ (Elterngerät, gleicher Mandant, keine Kreise).
// Gezeigt werden nur Geräte, die von etwas abhängen oder von denen etwas
// abhängt. Jeder Knoten trägt Zustand (Form und Farbe) des Geräts; die Linie
// zu einem Gerät trägt dessen Zustand, gestrichelt, wenn es ruht oder
// unbekannt ist. Die Daten kommen aus den Listen, die auch Hosts nutzt; die
// Zentrale liefert nur, was der Benutzer sehen darf.

import { useMemo } from "react";
import type { Geraet, Mandant, Sensor, Snmp } from "./api";
import { anzeigeText, rang, type Anzeige } from "./Checks";
import { darfPflegen, type Bereich } from "./bereich";
import { Netzbild } from "./Netzbild";
import { useQuelle } from "./quelle";
import { Q } from "./Widgets";

type Stand = Anzeige | "wartung";

const standText: Record<Stand, string> = { ...anzeigeText, wartung: "Wartung" };

// Farbe der Linie zum Gerät (Form trägt der Knoten selbst).
const linie: Record<Stand, string> = {
  crit: "var(--krit)",
  warn: "var(--warn)",
  unknown: "var(--unbek)",
  ok: "var(--ok)",
  neu: "var(--leise)",
  pause: "var(--leise)",
  wartung: "var(--wartung)",
};

interface Knoten {
  g: Geraet;
  stand: Stand;
  kinder: Knoten[];
}

// Schlimmster Zustand der Sensoren eines Geräts; Wartung, wenn es in Wartung ist.
function standVon(g: Geraet, sensoren: Sensor[]): Stand {
  if (g.wartung) return "wartung";
  if (sensoren.length === 0) return "neu";
  return sensoren.map((s) => s.status as Anzeige).reduce((a, b) => (rang[b] < rang[a] ? b : a));
}

// Bäume je Mandant: Wurzeln sind Geräte ohne (sichtbares) Elterngerät, die
// selbst Kinder haben. Kreise sind in der Datenbank ausgeschlossen; besucht
// schützt trotzdem vor einer Endlosschleife.
export function baeume(geraete: Geraet[], sensoren: Sensor[]) {
  const jeGeraet = new Map<string, Sensor[]>();
  for (const s of sensoren) jeGeraet.set(s.geraet_id, [...(jeGeraet.get(s.geraet_id) ?? []), s]);
  const nachId = new Map(geraete.map((g) => [g.id, g]));
  const kinder = new Map<string, Geraet[]>();
  for (const g of geraete) {
    if (g.abhaengig_von && nachId.has(g.abhaengig_von)) {
      kinder.set(g.abhaengig_von, [...(kinder.get(g.abhaengig_von) ?? []), g]);
    }
  }
  const besucht = new Set<string>();
  const bauen = (g: Geraet): Knoten => {
    besucht.add(g.id);
    const k = (kinder.get(g.id) ?? [])
      .filter((c) => !besucht.has(c.id))
      .sort((a, b) => a.name.localeCompare(b.name, "de"))
      .map(bauen);
    return { g, stand: standVon(g, jeGeraet.get(g.id) ?? []), kinder: k };
  };
  const wurzeln = geraete
    .filter((g) => (!g.abhaengig_von || !nachId.has(g.abhaengig_von)) && kinder.has(g.id))
    .sort((a, b) => a.name.localeCompare(b.name, "de"))
    .map(bauen);
  const ohne = geraete.filter((g) => !besucht.has(g.id)).length;
  return { wurzeln, ohne };
}

function KnotenKarte({ k, onOeffnen }: { k: Knoten; onOeffnen: (id: string) => void }) {
  const { g, stand } = k;
  return (
    <button type="button" className={`topo-knoten topo-${stand}`} onClick={() => onOeffnen(g.id)} title={`${g.name}: ${standText[stand]}`}>
      <span className={`signal signal-${stand}`} aria-hidden="true" />
      <span className="topo-text">
        <span className="topo-name">{g.name}</span>
        <span className="topo-unter">
          <span className="sr-only">{standText[stand]}, </span>
          {g.nicht_erreichbar_wegen ? "ruht, Elterngerät nicht erreichbar" : g.adresse ?? standText[stand]}
        </span>
      </span>
    </button>
  );
}

function Zweig({ k, onOeffnen }: { k: Knoten; onOeffnen: (id: string) => void }) {
  return (
    <li className="topo-zweig">
      <KnotenKarte k={k} onOeffnen={onOeffnen} />
      {k.kinder.length > 0 && (
        <ul className="topo-kinder">
          {k.kinder.map((c) => (
            <Kind key={c.g.id} k={c} onOeffnen={onOeffnen} />
          ))}
        </ul>
      )}
    </li>
  );
}

// Ein Kind mit farbiger Linie nach oben; gestrichelt, wenn es ruht oder unbekannt ist.
function Kind({ k, onOeffnen }: { k: Knoten; onOeffnen: (id: string) => void }) {
  const gestrichelt = !!k.g.nicht_erreichbar_wegen || k.stand === "unknown" || k.stand === "neu" || k.stand === "pause";
  return (
    <li className={`topo-kind${gestrichelt ? " topo-gestrichelt" : ""}`} style={{ "--topo-linie": linie[k.stand] } as React.CSSProperties}>
      <KnotenKarte k={k} onOeffnen={onOeffnen} />
      {k.kinder.length > 0 && (
        <ul className="topo-kinder">
          {k.kinder.map((c) => (
            <Kind key={c.g.id} k={c} onOeffnen={onOeffnen} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function Topologie({
  bereich,
  onOeffnen,
  melden,
}: {
  bereich: Bereich;
  onOeffnen: (id: string) => void;
  melden: (e: unknown) => void;
}) {
  const qg = useQuelle<{ geraete: Geraet[] }>(Q.geraete, 30_000);
  const qs = useQuelle<{ sensoren: Sensor[] }>(Q.sensoren, 30_000);
  // Netzbild (1.0.11): LLDP-Nachbarn aus den SNMP-Abfragen; fehlen sie, bleibt es bei den Bäumen.
  const qn = useQuelle<{ snmp: Snmp[] }>(Q.snmp, 60_000);
  const jeMandant = useMemo(() => {
    if (!qg.daten || !qs.daten) return null;
    const geraete = qg.daten.geraete.filter((g) => bereich.ids.has(g.mandant_id));
    const sensoren = qs.daten.sensoren;
    const out: { m: Mandant; wurzeln: Knoten[]; ohne: number }[] = [];
    for (const id of bereich.ids) {
      const m = bereich.nachId.get(id);
      if (!m) continue;
      const { wurzeln, ohne } = baeume(
        geraete.filter((g) => g.mandant_id === id),
        sensoren,
      );
      out.push({ m, wurzeln, ohne });
    }
    return out.sort((a, b) => (a.m.id === bereich.mandant.id ? -1 : b.m.id === bereich.mandant.id ? 1 : a.m.name.localeCompare(b.m.name, "de")));
  }, [qg.daten, qs.daten, bereich]);

  const fehler = qg.fehler || qs.fehler;
  if (fehler) return <p className="meldung meldung-fehler">{fehler}</p>;
  if (!jeMandant) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }
  const mitBaum = jeMandant.filter((x) => x.wurzeln.length > 0);
  const imBereich = (qg.daten?.geraete ?? []).filter((g) => bereich.ids.has(g.mandant_id));
  const quellen = (qn.daten?.snmp ?? []).filter((q) => bereich.ids.has(q.mandant_id));
  const hatNetz = quellen.some((q) => (q.messwerte?.lldp?.length ?? 0) > 0);
  return (
    <section className="topologie" aria-labelledby="topo-titel">
      <h2 id="topo-titel" className="sr-only">
        Topologie
      </h2>
      <h3 className="abschnitt">Netz</h3>
      {hatNetz ? (
        <>
          <p className="klein topo-hinweis">
            Das Netzbild zeigt, welche Geräte miteinander verbunden sind, so wie sie es per LLDP melden, mit den Ports an
            beiden Enden. Eine dicke Linie steht für mehrere Verbindungen. Ein Klick öffnet das Gerät.
          </p>
          <Netzbild
            geraete={imBereich}
            quellen={quellen}
            sensoren={qs.daten?.sensoren ?? []}
            onOeffnen={onOeffnen}
            darf={(m) => darfPflegen(bereich, m)}
            melden={melden}
          />
        </>
      ) : (
        <p className="leer">
          Noch keine Verbindungen. Das Netzbild entsteht von selbst, sobald Geräte mit SNMP-Abfrage ihre Nachbarn per LLDP
          melden (Switches mit eingeschaltetem LLDP).
        </p>
      )}
      <h3 className="abschnitt">Abhängigkeiten</h3>
      <p className="klein topo-hinweis">
        Die Bäume zeigen, welches Gerät von welchem abhängt (am Gerät unter „Bearbeiten“ → „hängt ab von“). Fällt ein Gerät
        aus, ruhen die Alarme der Geräte darunter. Die Linie zu einem Gerät trägt dessen Zustand; gestrichelt heißt: ruht,
        unbekannt oder noch nicht geprüft. Ein Klick öffnet das Gerät.
      </p>
      {mitBaum.length === 0 ? (
        <p className="leer">
          Noch keine Abhängigkeiten. Unter Hosts am Gerät „Bearbeiten“ → „hängt ab von“ ein Elterngerät wählen, z. B. den
          Switch, an dem ein Drucker hängt.
        </p>
      ) : (
        mitBaum.map(({ m, wurzeln, ohne }) => (
          <div key={m.id} className="topo-mandant">
            {bereich.mehrere && <h3 className="abschnitt">{m.name}</h3>}
            <ul className="topo-wald">
              {wurzeln.map((k) => (
                <Zweig key={k.g.id} k={k} onOeffnen={onOeffnen} />
              ))}
            </ul>
            {ohne > 0 && (
              <p className="klein">
                {ohne === 1 ? "1 weiteres Gerät hängt" : `${ohne} weitere Geräte hängen`} weder von einem anderen ab, noch hängt
                etwas von {ohne === 1 ? "ihm" : "ihnen"} ab.
              </p>
            )}
          </div>
        ))
      )}
    </section>
  );
}
