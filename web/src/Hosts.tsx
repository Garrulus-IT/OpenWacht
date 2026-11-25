// SPDX-License-Identifier: AGPL-3.0-only

// Seite Hosts: alle Geräte des Bereichs. Ein Gerät wird mit einem Agent,
// mit Checks oder mit beidem überwacht. Ohne Auswahl zeigt die Seite den
// Gerätebaum über die ganze Breite; ist ein Gerät gewählt, steht der Baum
// links und das Gerät rechts als Karte mit den Reitern „Übersicht“ (Messwerte
// des Agents, Checks, SNMP, Proxmox) und „Sensoren“ (Etappe 18: eigene Sensoren und Vorlagen). Am Handy
// zeigt die Seite entweder die Liste oder das Gerät. Wartung gilt für das
// ganze Gerät.
//
// Geräte werden nie automatisch verknüpft. Schlägt die Zentrale vor, dass ein
// Gerät ohne Agent zu einem Agent gehört, entscheidet ein Admin oder Operator.

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, type Agent, type AgentToken, type Check, type Geraet, type Gruppe, type Mandant, type Messwerte, type Sammler, type Sensor, type Snmp } from "./api";
import { GruppeAuswahl, GruppenOrdnen, kinder, nachId, pfad } from "./Gruppen";
import { HostVerlauf } from "./Verlauf";
import { GeraetSensoren, useSparklines } from "./Sparkline";
import { SensorenReiter } from "./SensorenReiter";
import { bereichFilter, prognoseNach, prognoseSchluessel, PrognoseZeile, type PlattenPrognose, type PrognoseAntwort } from "./Prognose";
import { baumReihe, darfPflegen, mandantName, rolleIn, type Bereich } from "./bereich";
import { GeraeteImport } from "./GeraeteImport";
import { SnmpFelder, SnmpFormular, SnmpTeil, snmpDaten, snmpKurz, snmpStart } from "./Snmp";
import { ProxmoxFormular, ProxmoxTeil, proxmoxKurz } from "./Proxmox";
import { VCenterFormular } from "./VCenter";
import { FritzBoxFormular, FritzBoxTeil, fritzKurz } from "./FritzBox";
import { NetAppFormular, NetAppTeil, netappKurz } from "./NetApp";
import { XenServerFormular, XenServerTeil, xenKurz } from "./XenServer";
import { CitrixFormular, CitrixTeil, citrixKurz } from "./Citrix";
import { TrapRegeln } from "./Traps";
import { WartungHinweis, WartungMarke, WartungSteuerung } from "./Wartung";
import { Aktionsmenue } from "./Aktionsmenue";
import { GeraetLoeschen } from "./GeraetLoeschen";
import { GeraetSchwellen } from "./Schwellen";
import { anzeige, CheckFormular, CheckZeile, rang as checkRang, type Anzeige } from "./Checks";
import { bytes, vor } from "./zeit";
import { laufzeit, Pegel, prozent, zahl } from "./Pegel";
import type { GeraetReiter } from "./navigation";
import { kennfarbeVon, kennStil, type Kennfarbe } from "./kennfarbe";

// --- Darstellungshilfen -------------------------------------------------------

type Zustand = "online" | "still" | "gesperrt" | "neu";

function zustand(a: Agent, intervall: number, jetzt: number): Zustand {
  if (a.gesperrt) return "gesperrt";
  if (!a.zuletzt_gesehen) return "neu";
  // Online, solange höchstens drei Meldungen fehlen.
  return jetzt - Date.parse(a.zuletzt_gesehen) <= intervall * 3000 ? "online" : "still";
}

// SNMP-Werte gelten als veraltet, wenn die Abfrage scheitert, ausgeschaltet
// ist oder seit drei Abfragen nichts Neues kam (z. B. Sammler weg). Dann
// zeigt die Kopfzeile keine alten Pegel, nur das Alter (Etappe 16).
function snmpVeraltet(q: Snmp, erfasst: string, jetzt: number) {
  return !!q.fehler || !q.aktiv || jetzt - Date.parse(erfasst) > Math.max(q.intervall_sekunden * 3, 180) * 1000;
}

const zustandText: Record<Zustand, string> = {
  online: "meldet sich",
  still: "meldet sich nicht",
  gesperrt: "gesperrt",
  neu: "noch keine Meldung",
};

// Netzwerkfreigaben (wie alarm.NetworkFS in der Zentrale): Sie gehören zu
// einem anderen Gerät und zählen weder für die Kachel noch für Alarme.
const netzwerkFS = new Set(["nfs", "nfs4", "cifs", "smb3", "ceph", "glusterfs"]);
export function istNetzwerk(dateisystem: string) {
  return netzwerkFS.has(dateisystem.toLowerCase());
}

function vollstePlatte(m: Messwerte) {
  let max: { wert: number; mount: string } | null = null;
  for (const p of m.platten ?? []) {
    if (istNetzwerk(p.dateisystem)) continue;
    const w = prozent(p.gesamt - p.frei, p.gesamt);
    if (!max || w > max.wert) max = { wert: w, mount: p.einhaengepunkt };
  }
  return max;
}

// --- Geräte mit ihren Agents und Checks ------------------------------------------

interface Sicht {
  g: Geraet;
  agent: Agent | null; // aktiver Agent
  gesperrt: Agent[];
  checks: Check[];
  snmp: Snmp | null;
  // Sensoren des Geräts (leer, solange /api/v1/sensoren nicht geladen ist)
  sensoren: Sensor[];
  z: Zustand | null; // Zustand des aktiven Agents
  stand: Anzeige | "leer"; // schlimmster Zustand des Geräts
  // Kennfarbe des schlimmsten Sensors; null, wenn ein gleich schlimmer ohne ist
  kenn: Kennfarbe | null;
}

// Zustand des Geräts: der schlimmste seiner Sensoren, bewertet von der
// Zentrale mit denselben Schwellen wie die Alarme (Agent, Checks, SNMP).
// Laufen die Sensoren noch nicht, zählen Agent und Checks wie bisher.
function geraeteStand(agent: Zustand | null, checks: Check[], sensoren: Sensor[] | null): Anzeige | "leer" {
  const teile: Anzeige[] = sensoren ? sensoren.map((x) => x.status) : checks.map(anzeige);
  if (!sensoren) {
    if (agent === "still") teile.push("crit");
    if (agent === "neu") teile.push("neu");
    if (agent === "online") teile.push("ok");
  }
  if (teile.length === 0) return "leer";
  return teile.reduce((a, b) => (checkRang[b] < checkRang[a] ? b : a));
}

const standRang = (s: Anzeige | "leer") => (s === "leer" ? 6 : checkRang[s]);

function checkZusammenfassung(checks: Check[]) {
  if (checks.length === 0) return "";
  const z: Partial<Record<Anzeige, number>> = {};
  for (const c of checks) z[anzeige(c)] = (z[anzeige(c)] ?? 0) + 1;
  const probleme = [
    z.crit && `${z.crit} Fehler`,
    z.unknown && `${z.unknown} unbekannt`,
    z.warn && `${z.warn} ${z.warn === 1 ? "Warnung" : "Warnungen"}`,
  ].filter(Boolean);
  const n = `${checks.length} ${checks.length === 1 ? "Check" : "Checks"}`;
  return probleme.length ? `${n} (${probleme.join(", ")})` : n;
}

interface Props {
  bereich: Bereich;
  // gewähltes Gerät aus der Adresse (z. B. „Anzeigen“ in einem Widget)
  geraet: string;
  ansicht: GeraetReiter;
  onOeffnen: (id: string) => void;
  onAnsicht: (r: GeraetReiter) => void;
  // Name des gewählten Geräts für die Brotkrumen
  onKrume: (name: string | null) => void;
  melden: (e: unknown) => void;
}

export function Hosts({ bereich, geraet, ansicht, onOeffnen, onAnsicht, onKrume, melden }: Props) {
  const mandant = bereich.mandant;
  const darf = darfPflegen(bereich, mandant.id);
  const [daten, setDaten] = useState<{
    geraete: Geraet[];
    gruppen: Gruppe[];
    agents: Agent[];
    checks: Check[];
    snmp: Snmp[];
    sensoren: Sensor[] | null;
    prognose: Map<string, PlattenPrognose>;
  } | null>(null);
  const [intervall, setIntervall] = useState(60);
  const [zentrale, setZentrale] = useState("");
  const [netze, setNetze] = useState<string[]>([]);
  const [sammler, setSammler] = useState<Sammler[]>([]);
  const [jetzt, setJetzt] = useState(Date.now());
  const [hinzufuegen, setHinzufuegen] = useState<"" | "host" | "mehrere" | "import">("");
  const [ordnen, setOrdnen] = useState(false);
  const [regeln, setRegeln] = useState(false);
  // zugeklappte Gruppen, im Browser gemerkt (nur Gruppen-IDs, kein Geheimnis)
  const [zu, setZuState] = useState<Set<string>>(gemerktZu);
  const setZu = useCallback((n: Set<string>) => {
    setZuState(n);
    merkeZu(n);
  }, []);

  const laden = useCallback(async () => {
    try {
      // Ohne Filter liefert die Zentrale alles Sichtbare; hier auf den Bereich eingrenzen.
      const q = bereich.mehrere ? "" : `?mandant=${mandant.id}`;
      const [g, gr, a, c, sn, se, pr] = await Promise.all([
        api<{ geraete: Geraet[] }>("GET", `/api/v1/geraete${q}`),
        api<{ gruppen: Gruppe[] }>("GET", `/api/v1/gruppen${q}`),
        api<{ agents: Agent[]; intervall_sekunden: number; zentrale: string }>("GET", `/api/v1/agents${q}`),
        api<{ checks: Check[]; netze: string[] }>("GET", `/api/v1/checks${q}`),
        api<{ snmp: Snmp[]; sammler: Sammler[] }>("GET", `/api/v1/snmp${q}`),
        // Sensoren für den Zustand der Geräte; scheitern sie, bleibt die alte Bewertung.
        api<{ sensoren: Sensor[] }>("GET", "/api/v1/sensoren").catch(() => null),
        // Prognose der Platten; fehlt sie, bleibt die Anzeige ohne.
        api<PrognoseAntwort>("GET", `/api/v1/prognose/platten${bereichFilter(bereich)}`).catch(() => null),
      ]);
      const drin = (x: { mandant_id: string }) => bereich.ids.has(x.mandant_id);
      setDaten({
        geraete: g.geraete.filter(drin),
        gruppen: gr.gruppen.filter(drin),
        agents: a.agents.filter(drin),
        checks: c.checks.filter(drin),
        snmp: sn.snmp.filter(drin),
        sensoren: se ? se.sensoren.filter(drin) : null,
        prognose: prognoseNach(pr?.platten.filter(drin)),
      });
      setIntervall(a.intervall_sekunden);
      setZentrale(a.zentrale);
      setNetze(c.netze);
      setSammler(sn.sammler ?? []);
      setJetzt(Date.now());
    } catch (e) {
      melden(e);
    }
  }, [bereich, mandant.id, melden]);

  // Alle 15 Sekunden neu laden, solange das Fenster sichtbar ist.
  useEffect(() => {
    void laden();
    const t = setInterval(() => {
      if (!document.hidden) void laden();
    }, 15000);
    return () => clearInterval(t);
  }, [laden]);

  const sichten: Sicht[] = (daten?.geraete ?? []).map((g) => {
    const agents = (daten?.agents ?? []).filter((a) => a.geraet_id === g.id);
    const agent = agents.find((a) => !a.gesperrt) ?? null;
    const checks = (daten?.checks ?? []).filter((c) => c.geraet_id === g.id);
    const z = agent ? zustand(agent, intervall, jetzt) : null;
    const snmp = (daten?.snmp ?? []).find((q) => q.geraet_id === g.id) ?? null;
    const sensoren = daten?.sensoren ? daten.sensoren.filter((x) => x.geraet_id === g.id) : null;
    return {
      g,
      agent,
      gesperrt: agents.filter((a) => a.gesperrt),
      checks,
      snmp,
      sensoren: sensoren ?? [],
      z,
      stand: geraeteStand(z, checks, sensoren),
      kenn: null,
    };
  });
  for (const s of sichten) {
    s.kenn = kennfarbeVon(s.sensoren, s.stand, (x) => x.status, (x) => x.kennfarbe);
  }
  // Probleme zuerst; ein Gerät in Wartung kommt nach den Problemen (wie die
  // Kachel „Wartung“ in der Übersicht), behält aber sein Signal.
  const problem = (s: Sicht) => s.stand === "crit" || s.stand === "unknown" || s.stand === "warn";
  const sortRang = (s: Sicht) => (s.g.wartung && problem(s) ? 2.5 : standRang(s.stand));
  sichten.sort((a, b) => sortRang(a) - sortRang(b) || a.g.name.localeCompare(b.g.name, "de"));
  const probleme = sichten.filter((s) => problem(s) && !s.g.wartung).length;
  const inWartung = sichten.filter((s) => s.g.wartung).length;
  const gewaehlt = geraet ? sichten.find((s) => s.g.id === geraet) : undefined;
  const krume = gewaehlt?.g.name ?? null;
  useEffect(() => {
    onKrume(krume);
  }, [krume, onKrume]);
  useEffect(() => () => onKrume(null), [onKrume]);

  return (
    <section aria-labelledby="hosts-titel" className="hosts">
      <div className="abschnitt-kopf">
        <h2 id="hosts-titel" className="abschnitt">
          Hosts
        </h2>
        {sichten.length > 0 && (
          <p className="klein" aria-live="polite">
            {sichten.length} {sichten.length === 1 ? "Gerät" : "Geräte"}
            {probleme ? `, ${probleme} mit Problemen` : ""}
            {inWartung ? `, ${inWartung} in Wartung` : ""}
            {!probleme && !inWartung ? ", alle OK" : ""}
          </p>
        )}
        {!hinzufuegen && !ordnen && !regeln && (darf || daten?.snmp.some((q) => q.traps)) && (
          <span className="kopf-knoepfe">
            {(daten?.snmp.some((q) => q.version !== "pve" && q.version !== "tr064" && q.version !== "vcenter" && q.version !== "ontap" && q.version !== "xapi" && q.version !== "citrix") ||
              rolleIn(bereich, mandant.id) === "admin") && (
              <button className="knopf" onClick={() => setRegeln(true)}>
                Trap-Regeln
              </button>
            )}
            {darf && sichten.length > 0 && (
              <button className="knopf" onClick={() => setOrdnen(true)}>
                Gruppen ordnen
              </button>
            )}
            {darf && (
              <button className="knopf" onClick={() => setHinzufuegen("import")}>
                Importieren
              </button>
            )}
            {darf && (
              <button className="knopf" onClick={() => setHinzufuegen("host")}>
                Host hinzufügen
              </button>
            )}
          </span>
        )}
      </div>

      {hinzufuegen === "host" && (
        <HostHinzufuegen
          mandant={mandant}
          gruppen={daten?.gruppen ?? []}
          darfAdmin={rolleIn(bereich, mandant.id) === "admin"}
          zentrale={zentrale}
          sammler={sammler}
          onMehrere={() => setHinzufuegen("mehrere")}
          onSchliessen={(neu) => {
            setHinzufuegen("");
            void laden();
            if (neu) onOeffnen(neu);
          }}
          melden={melden}
        />
      )}
      {hinzufuegen === "import" && (
        <GeraeteImport
          mandant={mandant}
          onSchliessen={(angelegt) => {
            setHinzufuegen("");
            if (angelegt) void laden();
          }}
          melden={melden}
        />
      )}
      {hinzufuegen === "mehrere" && (
        <AgentsMehrere
          mandant={mandant}
          onSchliessen={() => {
            setHinzufuegen("");
            void laden();
          }}
          melden={melden}
        />
      )}

      {regeln && daten && (
        <TrapRegeln
          bereich={bereich}
          gruppen={daten.gruppen}
          geraete={daten.geraete}
          onFertig={() => {
            setRegeln(false);
            void laden();
          }}
          melden={melden}
        />
      )}
      {regeln ? null : daten === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : sichten.length === 0 ? (
        !hinzufuegen && (
          <p className="leer">
            {darf
              ? "Noch keine Hosts. Über „Host hinzufügen“ legst du ein Gerät an und wählst, ob ein Agent darauf läuft oder die Zentrale es von außen prüft."
              : bereich.mehrere
                ? "In diesem Bereich gibt es noch keine Hosts."
                : "In diesem Mandanten gibt es noch keine Hosts."}
          </p>
        )
      ) : ordnen ? (
        <GruppenOrdnen
          bereich={bereich}
          gruppen={daten.gruppen}
          geraete={sichten.map((s) => ({
            id: s.g.id,
            name: s.g.name,
            mandant_id: s.g.mandant_id,
            gruppe_id: s.g.gruppe_id,
            signal: `signal-${s.stand === "leer" ? "pause" : s.stand}`,
          }))}
          onGeaendert={laden}
          onFertig={() => setOrdnen(false)}
          melden={melden}
        />
      ) : (
        <div className={gewaehlt ? "hosts-geteilt" : "hosts-voll"}>
          <div className="hosts-liste">
            <HostBaum
              sichten={sichten}
              gruppen={daten.gruppen}
              bereich={bereich}
              zu={zu}
              setZu={setZu}
              zeile={(s) => (
                <GeraetZeile
                  key={s.g.id}
                  s={s}
                  alle={sichten}
                  gruppen={daten.gruppen}
                  jetzt={jetzt}
                  netze={netze}
                  sammler={sammler}
                  zentrale={zentrale}
                  darf={darfPflegen(bereich, s.g.mandant_id)}
                  darfAdmin={rolleIn(bereich, s.g.mandant_id) === "admin"}
                  mandanten={[...bereich.nachId.values()]}
                  mandant={bereich.mehrere ? mandantName(bereich, s.g.mandant_id) : ""}
                  prognose={daten.prognose}
                  onGeaendert={laden}
                  onOeffnen={onOeffnen}
                  melden={melden}
                  offen={false}
                  aktiv={geraet === s.g.id}
                  onUmschalten={() => onOeffnen(geraet === s.g.id ? "" : s.g.id)}
                />
              )}
            />
          </div>
          {gewaehlt && (
            <GeraetZeile
              key={gewaehlt.g.id}
              karte
              s={gewaehlt}
              alle={sichten}
              gruppen={daten.gruppen}
              jetzt={jetzt}
              netze={netze}
              sammler={sammler}
              zentrale={zentrale}
              darf={darfPflegen(bereich, gewaehlt.g.mandant_id)}
              darfAdmin={rolleIn(bereich, gewaehlt.g.mandant_id) === "admin"}
              mandanten={[...bereich.nachId.values()]}
              mandant={bereich.mehrere ? mandantName(bereich, gewaehlt.g.mandant_id) : ""}
              prognose={daten.prognose}
              onGeaendert={laden}
              onOeffnen={onOeffnen}
              melden={melden}
              offen
              ansicht={ansicht}
              onAnsicht={onAnsicht}
              onUmschalten={() => onOeffnen("")}
            />
          )}
        </div>
      )}
    </section>
  );
}

// Zugeklappte Gruppen überstehen Neuladen und Seitenwechsel. Liegt nur im
// Browser (localStorage); ist der Speicher gesperrt, gilt der Zustand bis
// zum Neuladen. Unbekannte IDs (gelöschte Gruppen) stören nicht.
const ZU_SCHLUESSEL = "openwacht.hosts.zugeklappt";

function gemerktZu(): Set<string> {
  try {
    const roh = window.localStorage.getItem(ZU_SCHLUESSEL);
    const liste: unknown = roh ? JSON.parse(roh) : [];
    if (Array.isArray(liste)) {
      return new Set(liste.filter((x): x is string => typeof x === "string" && x.length <= 64).slice(0, 1000));
    }
  } catch {
    /* gesperrt oder beschädigt: alles offen */
  }
  return new Set();
}

function merkeZu(n: Set<string>) {
  try {
    if (n.size === 0) window.localStorage.removeItem(ZU_SCHLUESSEL);
    else window.localStorage.setItem(ZU_SCHLUESSEL, JSON.stringify([...n].slice(0, 1000)));
  } catch {
    /* nicht speicherbar */
  }
}

// Hosts als Baum: Gruppen in ihrer Reihenfolge (aufklappbar), danach die
// Geräte ohne Gruppe. Eine Gruppe zeigt den schlimmsten Zustand ihrer Geräte,
// auch zugeklappt. Ohne Gruppen bleibt die Liste flach wie bisher.
function HostBaum(props: {
  sichten: Sicht[];
  gruppen: Gruppe[];
  bereich: Bereich;
  zu: Set<string>;
  setZu: (s: Set<string>) => void;
  zeile: (s: Sicht) => ReactNode;
}) {
  const { sichten, gruppen, bereich, zu } = props;
  const idx = nachId(gruppen);
  const ohne = sichten.filter((s) => !s.g.gruppe_id || !idx.has(s.g.gruppe_id));
  if (gruppen.length === 0) return <ul className="host-liste">{sichten.map(props.zeile)}</ul>;

  const mandanten = [...new Set(gruppen.map((g) => g.mandant_id))].sort((a, b) =>
    a === bereich.mandant.id ? -1 : b === bereich.mandant.id ? 1 : mandantName(bereich, a).localeCompare(mandantName(bereich, b), "de"),
  );
  // Geräte im Teilbaum einer Gruppe
  const unter = (id: string, n = 0): Sicht[] =>
    n > 5 ? [] : [...sichten.filter((s) => s.g.gruppe_id === id), ...gruppen.filter((c) => c.eltern_id === id).flatMap((c) => unter(c.id, n + 1))];

  const knoten = (g: Gruppe, oben: boolean): ReactNode => {
    const alle = unter(g.id);
    const offen = !zu.has(g.id);
    const stand = alle.reduce<Anzeige | "leer">((a, s) => (standRang(s.stand) < standRang(a) ? s.stand : a), "leer");
    const kenn = kennStil(kennfarbeVon(alle, stand, (s) => s.stand, (s) => s.kenn), stand);
    const probleme = alle.filter((s) => (s.stand === "crit" || s.stand === "unknown" || s.stand === "warn") && !s.g.wartung).length;
    const id = `gruppe-${g.id}`;
    return (
      <li key={g.id} className={`gruppe gruppe-${stand}`}>
        <button
          className="gruppe-kopf"
          aria-expanded={offen}
          aria-controls={id}
          title={pfad(idx, g.id)}
          onClick={() => {
            const n = new Set(zu);
            if (offen) n.add(g.id);
            else n.delete(g.id);
            props.setZu(n);
          }}
        >
          <span className="gruppe-pfeil" aria-hidden="true">
            {offen ? "▾" : "▸"}
          </span>
          <span className={`signal signal-${stand === "leer" ? "pause" : stand}${kenn.className}`} style={kenn.style} aria-hidden="true" />
          <span className="name">{g.name}</span>
          <span className="klein">
            {oben && bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, g.mandant_id)}</span>}
            {alle.length === 0 ? "leer" : `${alle.length} ${alle.length === 1 ? "Gerät" : "Geräte"}`}
            {probleme ? `, ${probleme} mit Problemen` : ""}
          </span>
        </button>
        {offen && (
          <ul className="host-liste gruppe-inhalt" id={id}>
            {kinder(gruppen, g.mandant_id, g.id).map((c) => knoten(c, false))}
            {sichten.filter((s) => s.g.gruppe_id === g.id).map(props.zeile)}
          </ul>
        )}
      </li>
    );
  };

  return (
    <ul className="host-liste host-baum">
      {mandanten.flatMap((m) => kinder(gruppen, m, null).map((g) => knoten(g, true)))}
      {ohne.length > 0 && (
        <li className="gruppe-ohne" aria-hidden="true">
          <span className="klein">Ohne Gruppe</span>
        </li>
      )}
      {ohne.map(props.zeile)}
    </ul>
  );
}

function GeraetZeile(props: {
  s: Sicht;
  alle: Sicht[];
  gruppen: Gruppe[];
  jetzt: number;
  netze: string[];
  sammler: Sammler[];
  zentrale: string;
  offen: boolean;
  onUmschalten: () => void;
  // Zeile des gewählten Geräts in der Liste
  aktiv?: boolean;
  // als Karte rechts neben der Liste, mit Reitern
  karte?: boolean;
  ansicht?: GeraetReiter;
  onAnsicht?: (r: GeraetReiter) => void;
  darf: boolean;
  darfAdmin: boolean;
  // alle sichtbaren Mandanten (Ziele zum Verschieben: die mit Rolle Admin)
  mandanten: Mandant[];
  // Name des Mandanten, wenn der Bereich mehrere umfasst
  mandant: string;
  prognose: Map<string, PlattenPrognose>;
  onGeaendert: () => void;
  onOeffnen: (id: string) => void;
  melden: (e: unknown) => void;
}) {
  const { s, jetzt, offen } = props;
  const { g, agent: a, z } = s;
  const m = a?.messwerte ?? null;
  const platte = m ? vollstePlatte(m) : null;
  const detailId = `geraet-${g.id}`;
  const [modus, setModus] = useState<
    "" | "bearbeiten" | "check" | "agent" | "snmp" | "proxmox" | "vcenter" | "fritzbox" | "netapp" | "xenserver" | "citrix" | "loeschen" | "wartung" | "schwellen" | "entfernen" | "verschieben"
  >("");
  const q = s.snmp;
  const istVc = q?.version === "vcenter";
  const istPve = q?.version === "pve" || istVc;
  const istFritz = q?.version === "tr064";
  const istNetApp = q?.version === "ontap";
  const istXen = q?.version === "xapi";
  const istCitrix = q?.version === "citrix";
  const quelleName = istVc ? "vCenter" : istPve ? "Proxmox" : istFritz ? "FRITZ!Box" : istNetApp ? "NetApp" : istXen ? "XenServer" : istCitrix ? "Citrix" : "SNMP";
  const quelleModus = istVc ? "vcenter" : istPve ? "proxmox" : istFritz ? "fritzbox" : istNetApp ? "netapp" : istXen ? "xenserver" : istCitrix ? "citrix" : "snmp";
  // Werte für die Kopfzeile: Agent, sonst SNMP (wenn das Gerät CPU/RAM/Platten meldet)
  const sm = !m && q?.messwerte ? q.messwerte : null;
  // Meldet sich das Gerät nicht mehr, keine alten Werte im Kopf zeigen.
  const mAlt = m && z !== "online" ? (a?.zuletzt_gesehen ?? m.erfasst) : null;
  const smAlt = sm && q && snmpVeraltet(q, sm.erfasst, jetzt) ? sm.erfasst : null;
  const alt = mAlt ?? smAlt;
  const smPlatte = sm
    ? sm.platten.reduce<{ wert: number; mount: string } | null>((max, p) => {
        const w = prozent(p.gesamt - p.frei, p.gesamt);
        return !max || w > max.wert ? { wert: w, mount: p.einhaengepunkt } : max;
      }, null)
    : null;
  const [checkOffen, setCheckOffen] = useState("");
  const spark = useSparklines(g.id, offen);
  const [bearbeite, setBearbeite] = useState<Check | null>(null);
  const geschwister = props.alle.map((x) => x.g).filter((x) => x.mandant_id === g.mandant_id);

  const checks = s.checks.slice().sort((x, y) => checkRang[anzeige(x)] - checkRang[anzeige(y)] || x.name.localeCompare(y.name, "de"));
  const art = [
    // Das Alter steht bei veralteten Werten rechts in der Kopfzeile, nicht doppelt.
    a && z ? `Agent ${zustandText[z]}${a.zuletzt_gesehen && z !== "online" && !mAlt ? `, zuletzt ${vor(a.zuletzt_gesehen, jetzt)}` : ""}` : "",
    !a && s.gesperrt.length > 0 ? "Agent gesperrt" : "",
    !a && g.adresse ? g.adresse : "",
    q ? (istPve ? proxmoxKurz(q) : istFritz ? fritzKurz(q) : istNetApp ? netappKurz(q) : istXen ? xenKurz(q) : istCitrix ? citrixKurz(q) : snmpKurz(q)) : "",
    checkZusammenfassung(s.checks),
    !a && !q && s.checks.length === 0 && s.gesperrt.length === 0 ? "noch nicht überwacht" : "",
  ].filter(Boolean);

  const kopfName = (
    <span className="host-name">
      <span
        className={`signal signal-${s.stand === "leer" ? "pause" : s.stand}${kennStil(s.kenn, s.stand).className}`}
        style={kennStil(s.kenn, s.stand).style}
        title={s.kenn && s.stand !== "ok" ? s.kenn.name : undefined}
        aria-hidden="true"
      />
      <span>
        <span className="name">{g.name}</span>
        <span className="klein">
          {props.mandant && <span className="mandant-marke">{props.mandant}</span>}
          {art.join(" · ")}
          {g.wartung && (
            <>
              {" "}
              <WartungMarke w={g.wartung} />
            </>
          )}
          {g.nicht_erreichbar_wegen && <span className="marke"> wegen {g.nicht_erreichbar_wegen}</span>}
          {g.vorschlaege.length > 0 && (
            <>
              {" "}
              <span className="marke marke-vorschlag">Vorschlag</span>
            </>
          )}
        </span>
      </span>
    </span>
  );
  const kopfWerte = (
    alt ? (
      <span className="host-werte-alt klein" title={`Letzte Werte von ${new Date(alt).toLocaleString("de-DE")}, siehe Verlauf`}>
        zuletzt gemeldet {vor(alt, jetzt)}
      </span>
    ) : m ? (
      <span className="host-werte">
        <span className="wert">
          <span className="wert-titel">CPU</span>
          <Pegel wert={m.cpu.auslastung_prozent} titel={`CPU-Auslastung, ${m.cpu.kerne} Kerne`} />
        </span>
        <span className="wert">
          <span className="wert-titel">RAM</span>
          <Pegel
            wert={prozent(m.speicher.gesamt - m.speicher.verfuegbar, m.speicher.gesamt)}
            titel={`${bytes(m.speicher.gesamt - m.speicher.verfuegbar)} von ${bytes(m.speicher.gesamt)} belegt`}
          />
        </span>
        <span className="wert">
          <span className="wert-titel">Platte</span>
          {platte ? <Pegel wert={platte.wert} titel={`Vollste Platte: ${platte.mount}`} /> : <span className="klein">keine</span>}
        </span>
      </span>
    ) : sm && (sm.cpu || sm.speicher || smPlatte) ? (
      <span className="host-werte">
        <span className="wert">
          <span className="wert-titel">CPU</span>
          {sm.cpu ? <Pegel wert={sm.cpu.auslastung_prozent} titel="CPU-Auslastung (SNMP)" /> : <span className="klein">–</span>}
        </span>
        <span className="wert">
          <span className="wert-titel">RAM</span>
          {sm.speicher && sm.speicher.gesamt > 0 ? (
            <Pegel
              wert={prozent(sm.speicher.gesamt - sm.speicher.verfuegbar, sm.speicher.gesamt)}
              titel={`${bytes(sm.speicher.gesamt - sm.speicher.verfuegbar)} von ${bytes(sm.speicher.gesamt)} belegt`}
            />
          ) : (
            <span className="klein">–</span>
          )}
        </span>
        <span className="wert">
          <span className="wert-titel">Platte</span>
          {smPlatte ? <Pegel wert={smPlatte.wert} titel={`Vollster Speicher: ${smPlatte.mount}`} /> : <span className="klein">keine</span>}
        </span>
      </span>
    ) : (
      <span className="check-stand">
        {checks.length === 1 && checks[0] && (
          <span className="check-meldung">{anzeige(checks[0]) === "pause" ? "pausiert" : (checks[0].meldung ?? "noch nicht geprüft")}</span>
        )}
      </span>
    )
  );
  const detail = (
    <>

      {g.wartung && <WartungHinweis w={g.wartung} />}
      {g.nicht_erreichbar_wegen && (
        <p className="meldung meldung-warnung" role="status">
          Nicht erreichbar wegen „{g.nicht_erreichbar_wegen}“: Alarme für dieses Gerät ruhen, bis es wieder erreichbar ist.
        </p>
      )}
      {g.vorschlaege.map((v) => (
        <Vorschlag key={v.geraet_id} g={g} v={v} darf={props.darf} onFertig={props.onGeaendert} onOeffnen={props.onOeffnen} melden={props.melden} />
      ))}

      <GeraetSensoren sensoren={s.sensoren} d={spark} misstZeit={(id) => s.checks.find((c) => c.id === id)?.typ !== "tls"} />

      {a && <AgentTeil a={a} darf={props.darf} prognose={props.prognose} onGeaendert={props.onGeaendert} melden={props.melden} />}
      {s.gesperrt.map((x) => (
        <GesperrterAgent key={x.id} a={x} darf={props.darf} onGeaendert={props.onGeaendert} melden={props.melden} />
      ))}

      {modus === "snmp" ? (
        <SnmpFormular
          g={g}
          q={q}
          sammler={props.sammler}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : modus === "vcenter" ? (
        <VCenterFormular
          g={g}
          q={istVc ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : modus === "proxmox" ? (
        <ProxmoxFormular
          g={g}
          q={istPve && !istVc ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : modus === "fritzbox" ? (
        <FritzBoxFormular
          g={g}
          q={istFritz ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : modus === "netapp" ? (
        <NetAppFormular
          g={g}
          q={istNetApp ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : q && istNetApp ? (
        <NetAppTeil
          q={q}
          g={g}
          darfAdmin={props.darfAdmin}
          darfPflegen={props.darf}
          jetzt={jetzt}
          prognose={props.prognose}
          spark={spark}
          onBearbeiten={() => setModus("netapp")}
          onGeaendert={props.onGeaendert}
          melden={props.melden}
          ohneAktionen
          entfernen={modus === "entfernen"}
          onEntfernenEnde={() => setModus("")}
        />
      ) : modus === "citrix" ? (
        <CitrixFormular
          g={g}
          q={istCitrix ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : q && istCitrix ? (
        <CitrixTeil
          q={q}
          g={g}
          darfAdmin={props.darfAdmin}
          darfPflegen={props.darf}
          jetzt={jetzt}
          onBearbeiten={() => setModus("citrix")}
          onGeaendert={props.onGeaendert}
          melden={props.melden}
          ohneAktionen
          entfernen={modus === "entfernen"}
          onEntfernenEnde={() => setModus("")}
        />
      ) : modus === "xenserver" ? (
        <XenServerFormular
          g={g}
          q={istXen ? q : null}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      ) : q && istXen ? (
        <XenServerTeil
          q={q}
          g={g}
          darfAdmin={props.darfAdmin}
          darfPflegen={props.darf}
          jetzt={jetzt}
          prognose={props.prognose}
          spark={spark}
          onBearbeiten={() => setModus("xenserver")}
          onGeaendert={props.onGeaendert}
          melden={props.melden}
          ohneAktionen
          entfernen={modus === "entfernen"}
          onEntfernenEnde={() => setModus("")}
        />
      ) : q && istFritz ? (
        <FritzBoxTeil
          q={q}
          g={g}
          darfAdmin={props.darfAdmin}
          darfPflegen={props.darf}
          jetzt={jetzt}
          onBearbeiten={() => setModus("fritzbox")}
          onGeaendert={props.onGeaendert}
          melden={props.melden}
          ohneAktionen
          entfernen={modus === "entfernen"}
          onEntfernenEnde={() => setModus("")}
        />
      ) : q && istPve ? (
        <ProxmoxTeil
          q={q}
          g={g}
          darfAdmin={props.darfAdmin}
          darfPflegen={props.darf}
          jetzt={jetzt}
          prognose={props.prognose}
          spark={spark}
          onBearbeiten={() => setModus(istVc ? "vcenter" : "proxmox")}
          onGeaendert={props.onGeaendert}
          melden={props.melden}
          ohneAktionen
          entfernen={modus === "entfernen"}
          onEntfernenEnde={() => setModus("")}
        />
      ) : (
        q && (
          <SnmpTeil
            q={q}
            g={g}
            darfAdmin={props.darfAdmin}
            darfPflegen={props.darf}
            jetzt={jetzt}
            prognose={props.prognose}
            spark={spark}
            onBearbeiten={() => setModus("snmp")}
            onGeaendert={props.onGeaendert}
            melden={props.melden}
            ohneAktionen
            entfernen={modus === "entfernen"}
            onEntfernenEnde={() => setModus("")}
          />
        )
      )}

      {(checks.length > 0 || modus === "check" || bearbeite) && (
        <div className="geraet-checks">
          <h3 className="klein-titel">Checks und eigene Sensoren</h3>
          {(modus === "check" || bearbeite) && (
            <CheckFormular
              geraet={g}
              geraete={geschwister}
              vergeben={s.checks.map((c) => c.name)}
              check={bearbeite}
              netze={props.netze}
              hatAgent={!!a}
              hatSnmp={!!q && !istPve && !istFritz && !istNetApp && !istXen && !istCitrix}
              freigabe={a?.messwerte?.sensoren ?? null}
              onFertig={(neu) => {
                setModus("");
                setBearbeite(null);
                if (neu) setCheckOffen(neu);
                props.onGeaendert();
              }}
              melden={props.melden}
            />
          )}
          {checks.length > 0 && (
            <ul className="host-liste unterliste">
              {checks.map((c) => (
                <CheckZeile
                  key={c.id}
                  c={c}
                  jetzt={jetzt}
                  offen={checkOffen === c.id}
                  onUmschalten={() => setCheckOffen(checkOffen === c.id ? "" : c.id)}
                  darf={props.darf}
                  onBearbeiten={() => {
                    setModus("");
                    setBearbeite(c);
                  }}
                  onGeaendert={props.onGeaendert}
                  melden={props.melden}
                />
              ))}
            </ul>
          )}
        </div>
      )}

      {modus === "bearbeiten" && (
        <GeraetFormular
          geraet={g}
          geraete={props.alle.map((x) => x.g)}
          gruppen={props.gruppen}
          onFertig={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      )}
      {modus === "agent" && (
        <GeraetAgent
          g={g}
          zentrale={props.zentrale}
          onSchliessen={() => {
            setModus("");
            props.onGeaendert();
          }}
          melden={props.melden}
        />
      )}
      {modus === "loeschen" && (
        <GeraetLoeschen
          geraetId={g.id}
          onGeloescht={() => {
            setModus("");
            props.onGeaendert();
          }}
          onAbbrechen={() => setModus("")}
          melden={props.melden}
        />
      )}
      {modus === "verschieben" && (
        <GeraetVerschieben
          g={g}
          mandanten={props.mandanten}
          onFertig={(verschoben) => {
            setModus("");
            if (verschoben) props.onGeaendert();
          }}
          melden={props.melden}
        />
      )}
      {modus === "schwellen" && <GeraetSchwellen geraetId={g.id} name={g.name} onFertig={() => setModus("")} melden={props.melden} />}
      <WartungSteuerung
        pfad={`/api/v1/geraete/${g.id}`}
        name={g.name}
        wartung={g.wartung}
        onGeaendert={props.onGeaendert}
        melden={props.melden}
        offen={modus === "wartung"}
        onSchliessen={() => setModus("")}
      />

      {props.darf && !modus && !bearbeite && (
        <div className="aktionen geraet-aktionen">
          {q?.aktiv && (
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
          <Aktionsmenue
            name={g.name}
            gruppen={[
              [
                { text: "Sensor hinzufügen", onWahl: () => setModus("check") },
                ...(!a ? [{ text: "Agent hinzufügen", onWahl: () => setModus("agent") }] : []),
                ...(!q && props.darfAdmin
                  ? [
                      { text: "SNMP einrichten", onWahl: () => setModus("snmp") },
                      { text: "Proxmox einrichten", onWahl: () => setModus("proxmox") },
                      { text: "vCenter einrichten", onWahl: () => setModus("vcenter") },
                      { text: "FRITZ!Box einrichten", onWahl: () => setModus("fritzbox") },
                      { text: "NetApp einrichten", onWahl: () => setModus("netapp") },
                      { text: "XenServer einrichten", onWahl: () => setModus("xenserver") },
                      { text: "Citrix einrichten", onWahl: () => setModus("citrix") },
                    ]
                  : []),
              ],
              [
                { text: "Gerät bearbeiten", onWahl: () => setModus("bearbeiten") },
                { text: "Schwellen …", onWahl: () => setModus("schwellen"), titel: "Schwellen für Platte, RAM, CPU und „stumm nach“" },
                ...(q && props.darfAdmin ? [{ text: `${quelleName} bearbeiten`, onWahl: () => setModus(quelleModus) }] : []),
                ...(props.darfAdmin && props.mandanten.some((m) => m.rolle === "admin" && m.id !== g.mandant_id)
                  ? [{ text: "In anderen Mandanten verschieben …", onWahl: () => setModus("verschieben") }]
                  : []),
              ],
              g.wartung
                ? [
                    { text: "Wartung ändern …", onWahl: () => setModus("wartung") },
                    {
                      text: "Wartung beenden",
                      onWahl: async () => {
                        try {
                          await api("DELETE", `/api/v1/geraete/${g.id}/wartung`);
                          props.onGeaendert();
                        } catch (e) {
                          props.melden(e);
                        }
                      },
                    },
                  ]
                : [{ text: "Wartung …", onWahl: () => setModus("wartung"), titel: "Alarme vorübergehend unterdrücken" }],
              [
                ...(q && props.darfAdmin ? [{ text: `${quelleName} entfernen …`, onWahl: () => setModus("entfernen"), gefahr: true }] : []),
                { text: "Gerät löschen …", onWahl: () => setModus("loeschen"), gefahr: true },
              ],
            ]}
          />
        </div>
      )}
    </>
  );

  if (props.karte) {
    const ansicht = props.ansicht ?? "uebersicht";
    const reiter: { id: GeraetReiter; text: string }[] = [
      { id: "uebersicht", text: "Übersicht" },
      { id: "sensoren", text: "Sensoren" },
    ];
    return (
      <article className={`panel geraet-karte geraet geraet-${s.stand}${z ? ` host-${z}` : ""}`} aria-label={g.name}>
        <div className="geraet-karte-kopf">
          <button className="knopf-text zurueck-liste" onClick={props.onUmschalten}>
            ‹ Alle Hosts
          </button>
          <h2 className="geraet-karte-titel">{kopfName}</h2>
          {kopfWerte}
        </div>
        <div className="geraet-reiter" role="tablist" aria-label={`Ansichten von ${g.name}`}>
          {reiter.map((r) => (
            <button
              key={r.id}
              role="tab"
              id={`${detailId}-${r.id}`}
              aria-selected={ansicht === r.id}
              aria-controls={`${detailId}-inhalt`}
              className="geraet-reiter-knopf"
              onClick={() => props.onAnsicht?.(r.id)}
            >
              {r.text}
            </button>
          ))}
        </div>
        <div className="host-detail" id={`${detailId}-inhalt`} role="tabpanel" aria-labelledby={`${detailId}-${ansicht}`}>
          {ansicht === "sensoren" ? (
            <SensorenReiter
              g={g}
              agent={a}
              checks={s.checks}
              sensoren={s.sensoren}
              geschwister={geschwister}
              netze={props.netze}
              hatSnmp={!!q && !istPve && !istFritz && !istNetApp && !istXen && !istCitrix}
              darf={props.darf}
              onGeaendert={props.onGeaendert}
              melden={props.melden}
            />
          ) : (
            detail
          )}
        </div>
      </article>
    );
  }

  return (
    <li className={`host geraet geraet-${s.stand}${z ? ` host-${z}` : ""}${props.aktiv ? " host-aktiv" : ""}`}>
      <button className="host-kopf" aria-expanded={offen} aria-current={props.aktiv ? "true" : undefined} aria-controls={detailId} onClick={props.onUmschalten}>
        {kopfName}
        {kopfWerte}
      </button>
      {offen && (
        <div className="host-detail" id={detailId}>
          {detail}
        </div>
      )}
    </li>
  );
}

// Gerät in einen anderen Mandanten verschieben (1.0.6): nur in Mandanten, die
// der Benutzer verwaltet; die Zentrale prüft das ebenso (Admin beider Mandanten).
function GeraetVerschieben(props: { g: Geraet; mandanten: Mandant[]; onFertig: (verschoben: boolean) => void; melden: (e: unknown) => void }) {
  const { g } = props;
  const ziele = baumReihe(props.mandanten).filter((x) => x.m.rolle === "admin" && x.m.id !== g.mandant_id);
  const [ziel, setZiel] = useState(ziele[0]?.m.id ?? "");
  const [laeuft, setLaeuft] = useState(false);
  const [ergebnis, setErgebnis] = useState<Record<string, number | boolean> | null>(null);
  if (ergebnis) {
    const n = (k: string) => Number(ergebnis[k] ?? 0);
    const weg = [
      n("wartungen_entfernt") ? `${n("wartungen_entfernt")} Wartung(en)` : "",
      n("abhaengigkeiten_geloest") ? `${n("abhaengigkeiten_geloest")} Abhängigkeit(en)` : "",
      n("kennfarben_entfernt") ? `${n("kennfarben_entfernt")} Kennfarbe(n)` : "",
    ].filter(Boolean);
    return (
      <div className="einschub" role="status">
        <p>
          „{g.name}“ ist verschoben: {n("sensoren")} Sensor(en), {n("abfragen")} Abfrage(n){ergebnis.agent ? ", Agent" : ""} und {n("alarme")} Alarm(e) sind mitgezogen.
          {weg.length > 0 && ` Entfernt: ${weg.join(", ")}.`}
        </p>
        <div className="aktionen">
          <button className="knopf knopf-haupt" onClick={() => props.onFertig(true)}>
            Fertig
          </button>
        </div>
      </div>
    );
  }
  return (
    <div className="einschub">
      <form
        className="formular formular-flach"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!ziel) return;
          setLaeuft(true);
          try {
            setErgebnis(await api<Record<string, number | boolean>>("POST", `/api/v1/geraete/${g.id}/verschieben`, { mandant_id: ziel }));
          } catch (err) {
            props.melden(err);
          }
          setLaeuft(false);
        }}
      >
        <h3 className="einschub-titel">„{g.name}“ in einen anderen Mandanten verschieben</h3>
        <label className="feld">
          <span>Neuer Mandant</span>
          <select value={ziel} onChange={(e) => setZiel(e.target.value)} required>
            {ziele.map((x) => (
              <option key={x.m.id} value={x.m.id}>
                {"\u00a0\u00a0".repeat(x.tiefe)}
                {x.m.name}
              </option>
            ))}
          </select>
        </label>
        <p className="hinweis klein formular-voll">
          Mit dem Gerät ziehen Agent, Abfragen, Sensoren, Schwellen, Trap-Regeln, Alarme und Verlauf um; der Agent braucht keine neue Registrierung. Weg fallen Gruppe,
          Abhängigkeiten, Wartungsfenster und Kennfarben, die im neuen Mandanten nicht gelten. Wer nur den alten Mandanten sieht, sieht das Gerät danach nicht mehr.
        </p>
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={!ziel || laeuft}>
            Verschieben
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig(false)}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

// Vorschlag der Zentrale: Dieses Gerät ohne Agent gehört wohl zu einem Gerät mit Agent.
function Vorschlag(props: {
  g: Geraet;
  v: Geraet["vorschlaege"][number];
  darf: boolean;
  onFertig: () => void;
  onOeffnen: (id: string) => void;
  melden: (e: unknown) => void;
}) {
  const { g, v } = props;
  const [frage, setFrage] = useState(false);
  return (
    <div className="meldung meldung-vorschlag">
      <p>
        Gehört wohl zu „{v.name}“ ({v.grund === "adresse" ? "der Agent dort meldet sich von dieser Adresse" : "gleicher Name"}).
        {props.darf && !frage && (
          <>
            {" "}
            <button className="knopf-text" onClick={() => setFrage(true)}>
              Zusammenführen …
            </button>
          </>
        )}
      </p>
      {frage && (
        <div className="aktionen">
          <span className="klein">
            Die Sensoren von „{g.name}“ wandern zu „{v.name}“, „{g.name}“ wird danach gelöscht. Verlauf und Einstellungen der Sensoren bleiben.
          </span>
          <button
            className="knopf knopf-haupt"
            onClick={async () => {
              try {
                const r = await api<{ id: string }>("POST", `/api/v1/geraete/${g.id}/zusammenfuehren`, { mit: v.geraet_id });
                props.onOeffnen(r.id);
                props.onFertig();
              } catch (e) {
                props.melden(e);
              }
              setFrage(false);
            }}
          >
            Zusammenführen
          </button>
          <button className="knopf" onClick={() => setFrage(false)}>
            Abbrechen
          </button>
        </div>
      )}
    </div>
  );
}

function AgentTeil(props: {
  a: Agent;
  darf: boolean;
  prognose: Map<string, PlattenPrognose>;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const { a } = props;
  const m = a.messwerte;
  const [bestaetigen, setBestaetigen] = useState(false);
  return (
    <div className="geraet-agent">
      {m && (
        <dl className="eckdaten">
          <div>
            <dt>System</dt>
            <dd>{m.os}</dd>
          </div>
          <div>
            <dt>Kernel</dt>
            <dd>
              {m.kernel} ({m.arch})
            </dd>
          </div>
          <div>
            <dt>Läuft seit</dt>
            <dd>{laufzeit(m.laufzeit_s)}</dd>
          </div>
          {m.cpu.ohne_last ? (
            <div>
              <dt>Prozessor</dt>
              <dd>{m.cpu.kerne} Kerne</dd>
            </div>
          ) : (
            <div>
              <dt>Last (1/5/15 Min.)</dt>
              <dd>
                {zahl.format(m.cpu.last1)} / {zahl.format(m.cpu.last5)} / {zahl.format(m.cpu.last15)} bei {m.cpu.kerne} Kernen
              </dd>
            </div>
          )}
          <div>
            <dt>Arbeitsspeicher</dt>
            <dd>
              {bytes(m.speicher.gesamt - m.speicher.verfuegbar)} von {bytes(m.speicher.gesamt)} belegt
              {m.speicher.swap_gesamt > 0 &&
                `, ${m.cpu.ohne_last ? "Auslagerung" : "Swap"} ${bytes(m.speicher.swap_gesamt - m.speicher.swap_frei)} von ${bytes(m.speicher.swap_gesamt)}`}
            </dd>
          </div>
          <div>
            <dt>Agent</dt>
            <dd>
              {a.hostname}, Version {m.agent}, Zertifikat bis {new Date(a.zertifikat_bis).toLocaleDateString("de-DE")}
              {a.adresse ? `, meldet sich von ${a.adresse}` : ""}
            </dd>
          </div>
        </dl>
      )}
      {m?.platten && m.platten.length > 0 && (
        <table className="tabelle tabelle-kompakt">
          <thead>
            <tr>
              <th scope="col">{m.cpu.ohne_last ? "Laufwerk" : "Einhängepunkt"}</th>
              <th scope="col">Dateisystem</th>
              <th scope="col">Belegt</th>
              <th scope="col">Frei</th>
            </tr>
          </thead>
          <tbody>
            {m.platten.map((p) => (
              <tr key={p.einhaengepunkt}>
                <td className="mono">{p.einhaengepunkt}</td>
                <td>
                  {p.dateisystem}
                  {istNetzwerk(p.dateisystem) && <span className="klein"> (Netzwerk, ohne Alarm)</span>}
                </td>
                <td>
                  <Pegel wert={prozent(p.gesamt - p.frei, p.gesamt)} titel={`${bytes(p.gesamt - p.frei)} von ${bytes(p.gesamt)}`} />
                </td>
                <td>
                  {bytes(p.frei)} von {bytes(p.gesamt)}
                  {!istNetzwerk(p.dateisystem) && (
                    <>
                      <br />
                      <PrognoseZeile p={props.prognose.get(prognoseSchluessel("host", a.id, p.einhaengepunkt))} />
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!m && <p className="klein">Der Agent „{a.hostname}“ hat sich registriert, aber noch keine Messwerte geschickt.</p>}
      {m && <HostVerlauf agentId={a.id} ohneLast={!!m.cpu.ohne_last} kerne={m.cpu.kerne} />}
      {props.darf && (
        <div className="aktionen">
          {bestaetigen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="Agent sperren">
              <p>
                Agent „{a.hostname}“ sperren? Er kann danach keine Daten mehr senden. Das lässt sich nicht rückgängig machen; für denselben
                Rechner brauchst du dann ein neues Token. Gerät und Sensoren bleiben.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("POST", `/api/v1/agents/${a.id}/sperren`);
                      props.onGeaendert();
                    } catch (e) {
                      props.melden(e);
                    }
                    setBestaetigen(false);
                  }}
                >
                  Endgültig sperren
                </button>
                <button className="knopf" onClick={() => setBestaetigen(false)}>
                  Abbrechen
                </button>
              </div>
            </div>
          ) : (
            <button className="knopf knopf-gefahr" onClick={() => setBestaetigen(true)}>
              Agent sperren
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function GesperrterAgent(props: { a: Agent; darf: boolean; onGeaendert: () => void; melden: (e: unknown) => void }) {
  const { a } = props;
  const [bestaetigen, setBestaetigen] = useState(false);
  return (
    <div className="geraet-gesperrt">
      <p className="klein">
        Agent „{a.hostname}“ gesperrt am {new Date(a.gesperrt!).toLocaleDateString("de-DE")}.
        {props.darf && !bestaetigen && (
          <>
            {" "}
            <button className="knopf-text" onClick={() => setBestaetigen(true)}>
              Agent löschen …
            </button>
          </>
        )}
      </p>
      {bestaetigen && (
        <div className="bestaetigung" role="alertdialog" aria-label="Agent löschen">
          <p>
            Agent „{a.hostname}“ löschen? Sein Verlauf geht verloren; Einträge im Alarmprotokoll bleiben. Hat das Gerät danach keine Sensoren
            mehr, wird es mit gelöscht.
          </p>
          <div className="aktionen">
            <button
              className="knopf knopf-gefahr"
              onClick={async () => {
                try {
                  await api("DELETE", `/api/v1/agents/${a.id}`);
                  props.onGeaendert();
                } catch (e) {
                  props.melden(e);
                }
                setBestaetigen(false);
              }}
            >
              Endgültig löschen
            </button>
            <button className="knopf" onClick={() => setBestaetigen(false)}>
              Abbrechen
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Gerät anlegen und bearbeiten ---------------------------------------------------

function GeraetFelder(props: {
  name: string;
  adresse: string;
  gruppe: string;
  gruppen: Gruppe[];
  mandant: string;
  setName: (s: string) => void;
  setAdresse: (s: string) => void;
  setGruppe: (s: string) => void;
}) {
  return (
    <>
      <label className="feld">
        <span>Name</span>
        <input required maxLength={100} value={props.name} placeholder="z. B. Dateiserver Hauptsitz" onChange={(e) => props.setName(e.target.value)} />
      </label>
      <label className="feld">
        <span>IP-Adresse oder Hostname (optional)</span>
        <input
          maxLength={253}
          value={props.adresse}
          placeholder="10.10.0.20 oder srv-file01.example.com"
          onChange={(e) => props.setAdresse(e.target.value)}
        />
      </label>
      <GruppeAuswahl gruppen={props.gruppen} mandant={props.mandant} wert={props.gruppe} setWert={props.setGruppe} />
    </>
  );
}

function GeraetFormular(props: { geraet: Geraet; geraete: Geraet[]; gruppen: Gruppe[]; onFertig: () => void; melden: (e: unknown) => void }) {
  const [name, setName] = useState(props.geraet.name);
  const [eltern, setEltern] = useState(props.geraet.abhaengig_von ?? "");
  const kandidaten = props.geraete
    .filter((x) => x.mandant_id === props.geraet.mandant_id && x.id !== props.geraet.id)
    .sort((a, b) => a.name.localeCompare(b.name, "de"));
  const [adresse, setAdresse] = useState(props.geraet.adresse ?? "");
  const [gruppe, setGruppe] = useState(props.geraet.gruppe_id ?? "");
  const [fehler, setFehler] = useState("");
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.geraet.id}`, { name, adresse, gruppe_id: gruppe, abhaengig_von: eltern });
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">„{props.geraet.name}“ bearbeiten</h3>
        <GeraetFelder
          name={name}
          adresse={adresse}
          gruppe={gruppe}
          gruppen={props.gruppen}
          mandant={props.geraet.mandant_id}
          setName={setName}
          setAdresse={setAdresse}
          setGruppe={setGruppe}
        />
        <label className="feld">
          <span>Hängt ab von (z. B. Router oder Switch davor)</span>
          <select value={eltern} onChange={(e) => setEltern(e.target.value)}>
            <option value="">keinem Gerät</option>
            {kandidaten.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </select>
        </label>
        <p className="hinweis klein formular-voll">
          Fällt das Gerät, von dem dieses abhängt, aus (Ping, Agent oder Abfragequelle), gehen für dieses keine eigenen Alarme raus. Die Adresse ist nur ein Vorschlag für neue Checks; bestehende Checks behalten ihr Ziel. Die Gruppe ordnet das Gerät in der Liste und der
          Wandanzeige ein; Gruppen legst du unter „Gruppen ordnen“ an.
        </p>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Speichern</button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

// Host hinzufügen: Name und Adresse, dann die Art der Überwachung.
function HostHinzufuegen(props: {
  mandant: Mandant;
  gruppen: Gruppe[];
  darfAdmin: boolean;
  zentrale: string;
  sammler: Sammler[];
  onMehrere: () => void;
  onSchliessen: (neueId?: string) => void;
  melden: (e: unknown) => void;
}) {
  const [name, setName] = useState("");
  const [adresse, setAdresse] = useState("");
  const [gruppe, setGruppe] = useState("");
  const [art, setArt] = useState<"agent" | "checks" | "snmp">("agent");
  const leer: Geraet = {
    id: "",
    mandant_id: props.mandant.id,
    name: "",
    adresse: null,
    gruppe_id: null,
    erstellt: "",
    agent_id: null,
    checks: 0,
    snmp_id: null,
    wartung: null,
    vorschlaege: [],
    abhaengig_von: null,
    nicht_erreichbar_wegen: null,
  };
  const [sw, setSw] = useState(() => snmpStart(leer, null));
  const [fehler, setFehler] = useState("");
  const [token, setToken] = useState<TokenErgebnis | null>(null);
  const [neu, setNeu] = useState("");

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      if (art === "snmp" && !adresse.trim()) {
        setFehler("Für SNMP bitte die Adresse des Geräts angeben.");
        return;
      }
      const r = await api<{ id: string }>("POST", `/api/v1/mandanten/${props.mandant.id}/geraete`, { name, adresse, gruppe_id: gruppe });
      if (art === "checks") {
        props.onSchliessen(r.id);
        return;
      }
      if (art === "snmp") {
        try {
          await api("PUT", `/api/v1/geraete/${r.id}/snmp`, snmpDaten({ ...sw, adresse }, []));
        } catch (err) {
          // Das Gerät steht schon; SNMP lässt sich dort erneut einrichten.
          props.melden(err);
        }
        props.onSchliessen(r.id);
        return;
      }
      setNeu(r.id);
      setToken(await api("POST", `/api/v1/geraete/${r.id}/agent-token`, {}));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };

  if (token) {
    return (
      <div className="einschub">
        <h3 className="einschub-titel">„{name}“ angelegt</h3>
        <TokenBefehle ergebnis={token} anzahl={1} onFertig={() => props.onSchliessen(neu)} melden={props.melden} />
      </div>
    );
  }
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">Host hinzufügen</h3>
        <p className="hinweis formular-voll">Neuer Host in „{props.mandant.name}“.</p>
        <GeraetFelder
          name={name}
          adresse={adresse}
          gruppe={gruppe}
          gruppen={props.gruppen}
          mandant={props.mandant.id}
          setName={setName}
          setAdresse={setAdresse}
          setGruppe={setGruppe}
        />
        <fieldset className="feld formular-voll auswahl">
          <legend>Wie wird er überwacht?</legend>
          <label>
            <input type="radio" name="art" checked={art === "agent"} onChange={() => setArt("agent")} />
            <span>
              <strong>Mit Agent</strong>
              <span className="klein"> – Linux oder Windows; meldet CPU, Arbeitsspeicher und Platten. Du bekommst ein Token und die Befehle.</span>
            </span>
          </label>
          {props.darfAdmin && (
            <label>
              <input type="radio" name="art" checked={art === "snmp"} onChange={() => setArt("snmp")} />
              <span>
                <strong>Per SNMP</strong>
                <span className="klein"> – Switches, Access Points, NAS, Drucker, USV mit Netzwerkkarte; die Zentrale oder ein Sammler fragt ab.</span>
              </span>
            </label>
          )}
          <label>
            <input type="radio" name="art" checked={art === "checks"} onChange={() => setArt("checks")} />
            <span>
              <strong>Nur von außen (Sensoren der Zentrale)</strong>
              <span className="klein"> – die Zentrale prüft Ping, Ports, Webseiten oder Zertifikate, z. B. für Drucker, Switches oder Webdienste.</span>
            </span>
          </label>
        </fieldset>
        {art === "snmp" && <SnmpFelder w={sw} setW={setSw} neu adresseOptional sammler={props.sammler} mandant={props.mandant.id} />}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">{art === "agent" ? "Anlegen und Token erzeugen" : "Anlegen"}</button>
          <button type="button" className="knopf" onClick={() => props.onSchliessen()}>
            Abbrechen
          </button>
          <button type="button" className="knopf-text" onClick={props.onMehrere}>
            Agents für mehrere Rechner …
          </button>
        </div>
      </form>
    </div>
  );
}

// Agent für ein bestehendes Gerät: Token gilt für genau einen Rechner.
function GeraetAgent(props: { g: Geraet; zentrale: string; onSchliessen: () => void; melden: (e: unknown) => void }) {
  const [token, setToken] = useState<TokenErgebnis | null>(null);
  const [fehler, setFehler] = useState("");
  return (
    <div className="einschub">
      <h3 className="einschub-titel">Agent für „{props.g.name}“</h3>
      {token ? (
        <TokenBefehle ergebnis={token} anzahl={1} onFertig={props.onSchliessen} melden={props.melden} />
      ) : (
        <>
          <p className="hinweis">Du bekommst ein Token für genau einen Rechner. Der Agent, der sich damit anmeldet, gehört zu diesem Gerät.</p>
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="aktionen">
            <button
              className="knopf knopf-haupt"
              onClick={async () => {
                setFehler("");
                try {
                  setToken(await api("POST", `/api/v1/geraete/${props.g.id}/agent-token`, {}));
                } catch (err) {
                  setFehler(err instanceof Error ? err.message : String(err));
                }
              }}
            >
              Token erzeugen
            </button>
            <button className="knopf" onClick={props.onSchliessen}>
              Abbrechen
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// Antwort beim Erzeugen eines Registrierungs-Tokens. download: je Plattform
// der fertige Befehl, nur wenn die Zentrale ein signiertes Paket hat
// (Etappe 34; die Prüfwerte stehen im Befehl selbst).
type TokenErgebnis = {
  token: string;
  laeuft_ab: string;
  zentrale: string;
  version?: string;
  download?: Record<string, { version: string; befehl: string; schluessel?: { id: string }[]; fingerabdruecke?: string[] }>;
};

type Weg = "paket" | "datei" | "download";

// Fertige Befehle für Linux und Windows zu einem frisch erzeugten Token.
function TokenBefehle(props: { ergebnis: TokenErgebnis; anzahl: number; onFertig: () => void; melden: (e: unknown) => void }) {
  const { ergebnis } = props;
  const [system, setSystem] = useState<"linux" | "windows">("linux");
  const [arch, setArch] = useState<"amd64" | "arm64">("amd64");
  const [weg, setWeg] = useState<Weg>("paket");
  const [kopiert, setKopiert] = useState(false);
  const zentrale = ergebnis.zentrale || "https://<zentrale>:8444";
  const v = ergebnis.version && /^\d+\.\d+\.\d+$/.test(ergebnis.version) ? ergebnis.version : "<version>";
  const rpmArch = arch === "amd64" ? "x86_64" : "aarch64";
  const winArch = system === "windows" ? (arch === "arm64" ? "arm64" : "amd64") : arch;
  const dl = ergebnis.download?.[`${system}/${winArch}`];
  const winPfad = "C:\\Program Files\\OpenWacht\\openwacht-agent.exe";
  let befehl = "";
  if (weg === "download" && dl) {
    befehl = dl.befehl;
  } else if (weg === "paket") {
    befehl =
      system === "linux"
        ? `OPENWACHT_ZENTRALE=${zentrale} OPENWACHT_TOKEN=${ergebnis.token} apt install ./openwacht-agent_${v}_${arch}.deb\n` +
          `# oder (RHEL, Rocky, Alma, SUSE):\n` +
          `OPENWACHT_ZENTRALE=${zentrale} OPENWACHT_TOKEN=${ergebnis.token} dnf install ./openwacht-agent-${v}-1.${rpmArch}.rpm`
        : `msiexec /i openwacht-agent_${v}_${winArch}.msi /qn ZENTRALE=${zentrale} TOKEN=${ergebnis.token}`;
  } else {
    // Eine Zeile je System (Etappe 21b): die Agent-Datei vorher selbst aus dem geprüften Artefakt kopieren.
    befehl =
      system === "linux"
        ? `install -o root -g root -m 0755 openwacht-agent_linux_${arch} /usr/local/bin/openwacht-agent && ` +
          `openwacht-agent registrieren -zentrale ${zentrale} -token ${ergebnis.token} && systemctl enable --now openwacht-agent`
        : `$ErrorActionPreference = 'Stop'; New-Item -ItemType Directory -Force 'C:\\Program Files\\OpenWacht' | Out-Null; ` +
          `Copy-Item .\\openwacht-agent_windows_${winArch}.exe '${winPfad}' -Force; Unblock-File '${winPfad}'; ` +
          `& '${winPfad}' registrieren -zentrale ${zentrale} -token ${ergebnis.token}; if ($LASTEXITCODE -eq 0) { Start-Service openwacht-agent }`;
  }
  const wege: { id: Weg; text: string }[] = [
    { id: "paket", text: system === "linux" ? "Paket (.deb/.rpm)" : "MSI" },
    { id: "datei", text: "Programmdatei" },
    { id: "download", text: "Von der Zentrale laden" },
  ];
  const wechsel = (f: () => void) => {
    f();
    setKopiert(false);
  };
  return (
    <>
      <div className="umschalter" role="group" aria-label="Betriebssystem">
        {(["linux", "windows"] as const).map((os) => (
          <button
            key={os}
            type="button"
            className="umschalter-knopf"
            aria-pressed={system === os}
            onClick={() => wechsel(() => setSystem(os))}
          >
            {os === "linux" ? "Linux" : "Windows"}
          </button>
        ))}
        <select aria-label="Architektur" value={arch} onChange={(e) => wechsel(() => setArch(e.target.value as "amd64" | "arm64"))}>
          <option value="amd64">x86-64 (amd64)</option>
          <option value="arm64">ARM 64 (arm64)</option>
        </select>
      </div>
      <div className="umschalter" role="group" aria-label="Installationsweg">
        {wege.map((w) => (
          <button
            key={w.id}
            type="button"
            className="umschalter-knopf"
            aria-pressed={weg === w.id}
            onClick={() => wechsel(() => setWeg(w.id))}
          >
            {w.text}
          </button>
        ))}
      </div>
      <p className="hinweis">
        {weg === "paket" &&
          (system === "linux"
            ? `Kopiere das Paket aus dem geprüften Artefakt auf den Rechner (Prüfsumme mit der signierten SHA256SUMS vergleichen) und führe die Zeile als root im selben Ordner aus. Das Paket richtet Benutzer, Dienst und Updates ein und registriert den Rechner.`
            : `Für Gruppenrichtlinie oder Intune: MSI aus dem geprüften Artefakt, stille Installation mit den Eigenschaften ZENTRALE und TOKEN (TOKEN steht nicht im Installationsprotokoll). Als Administrator bzw. als Systemkontext ausführen.`)}
        {weg === "datei" &&
          (system === "linux"
            ? `Kopiere openwacht-agent_linux_${arch} aus dem geprüften Artefakt auf den Rechner (Prüfsumme mit SHA256SUMS vergleichen) und führe die Zeile dort als root im selben Ordner aus (ohne root-Anmeldung vorher „sudo -i“).`
            : `Kopiere openwacht-agent_windows_${winArch}.exe aus dem geprüften Artefakt auf den Rechner (Prüfsumme mit SHA256SUMS vergleichen) und führe die Zeile in einer PowerShell als Administrator im selben Ordner aus.`)}
        {weg === "download" &&
          (dl
            ? system === "linux"
              ? `Lädt Version ${dl.version} von der Zentrale und installiert nur, wenn die Offline-Signatur passt (Prüfung mit openssl 3 auf dem Rechner). Vergleiche vorher die Schlüssel-Kennung im Befehl (${(dl.schluessel ?? []).map((k) => k.id).join(", ")}) mit der im Handbuch. Als root einfügen.`
              : `Lädt Version ${dl.version} von der Zentrale und installiert nur mit gültiger Authenticode-Signatur von OpenWacht. Vergleiche den Fingerabdruck im Befehl mit dem im Handbuch. Braucht Windows 11 oder Server 2022 (TLS 1.3); PowerShell als Administrator.`
            : `Die Zentrale bietet für ${system === "linux" ? "Linux" : "Windows"} (${winArch}) keinen Download an: Dafür braucht sie ein hochgeladenes, signiertes Agent-Paket${system === "windows" ? " und ein eingetragenes Authenticode-Zertifikat" : ""}. Nimm solange das Paket oder die Programmdatei.`)}{" "}
        Das Token wird nur jetzt angezeigt und gilt bis{" "}
        {new Date(ergebnis.laeuft_ab).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}
        {props.anzahl > 1 ? ` für ${props.anzahl} Rechner` : ""}.
      </p>
      {system === "windows" && weg !== "download" && (
        <p className="hinweis">
          Ist der Windows-Agent nicht signiert, startet er auf Rechnern mit Smart App Control nicht (abschalten geht nur einmal und
          nicht rückgängig). Sonst kann SmartScreen beim ersten Start warnen; Unblock-File entfernt die Download-Markierung der geprüften Datei.
        </p>
      )}
      {!ergebnis.zentrale && (
        <p className="meldung meldung-warnung">
          Der Agent-Port der Zentrale ist nicht eingerichtet (Startoption -agent-adresse). Ohne ihn können sich keine Agents anmelden.
        </p>
      )}
      {(weg !== "download" || dl) && (
        <pre className="befehl" tabIndex={0}>
          {befehl}
        </pre>
      )}
      <div className="aktionen">
        {(weg !== "download" || dl) && (
          <button
            className="knopf knopf-haupt"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(befehl);
                setKopiert(true);
              } catch {
                props.melden(new Error("Kopieren nicht möglich. Bitte den Befehl markieren und von Hand kopieren."));
              }
            }}
          >
            {kopiert ? "Kopiert" : "Befehl kopieren"}
          </button>
        )}
        <button className="knopf" onClick={props.onFertig}>
          Fertig
        </button>
      </div>
    </>
  );
}

// --- Agents für mehrere Rechner ---------------------------------------------------
// Ein Token für viele Rechner; jeder Agent bekommt beim Anmelden ein eigenes Gerät.

function AgentsMehrere(props: { mandant: Mandant; onSchliessen: () => void; melden: (e: unknown) => void }) {
  const [notiz, setNotiz] = useState("");
  const [anzahl, setAnzahl] = useState(5);
  const [stunden, setStunden] = useState(24);
  const [ergebnis, setErgebnis] = useState<TokenErgebnis | null>(null);
  const [tokens, setTokens] = useState<AgentToken[]>([]);

  const mandantId = props.mandant.id;
  const melden = props.melden;
  const ladeTokens = useCallback(async () => {
    try {
      const r = await api<{ tokens: AgentToken[] }>("GET", `/api/v1/mandanten/${mandantId}/agent-tokens`);
      setTokens(r.tokens);
    } catch (e) {
      melden(e);
    }
  }, [mandantId, melden]);

  useEffect(() => {
    void ladeTokens();
  }, [ladeTokens]);

  const erzeugen = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await api<TokenErgebnis>(
        "POST",
        `/api/v1/mandanten/${props.mandant.id}/agent-tokens`,
        { notiz, anzahl, gueltig_stunden: stunden },
      );
      setErgebnis(r);
      void ladeTokens();
    } catch (err) {
      props.melden(err);
    }
  };

  return (
    <div className="einschub">
      {ergebnis ? (
        <>
          <h3 className="einschub-titel">Token erzeugt</h3>
          <TokenBefehle ergebnis={ergebnis} anzahl={anzahl} onFertig={props.onSchliessen} melden={props.melden} />
        </>
      ) : (
        <form className="formular formular-flach" onSubmit={erzeugen}>
          <h3 className="einschub-titel">Agents für mehrere Rechner</h3>
          <p className="hinweis formular-voll">
            Ein Token, mit dem sich mehrere Agents in „{props.mandant.name}“ anmelden. Jeder Agent bekommt ein eigenes Gerät mit seinem
            Hostnamen. Das Token wird nur einmal angezeigt.
          </p>
          <label className="feld">
            <span>Notiz (optional)</span>
            <input maxLength={100} value={notiz} placeholder="z. B. Serverraum EG, Rack 2" onChange={(e) => setNotiz(e.target.value)} />
          </label>
          <label className="feld">
            <span>Für wie viele Rechner</span>
            <input type="number" min={1} max={1000} value={anzahl} onChange={(e) => setAnzahl(Number(e.target.value))} />
          </label>
          <label className="feld">
            <span>Gültig für</span>
            <select value={stunden} onChange={(e) => setStunden(Number(e.target.value))}>
              <option value={1}>1 Stunde</option>
              <option value={24}>24 Stunden</option>
              <option value={72}>3 Tage</option>
              <option value={168}>7 Tage</option>
            </select>
          </label>
          <div className="aktionen">
            <button className="knopf knopf-haupt">Token erzeugen</button>
            <button type="button" className="knopf" onClick={props.onSchliessen}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
      {tokens.length > 0 && (
        <div className="offene-tokens">
          <h4 className="klein-titel">Offene Tokens</h4>
          <ul>
            {tokens.map((t) => (
              <li key={t.id}>
                <span>
                  {t.notiz || "ohne Notiz"}, noch {t.restanzahl}× bis{" "}
                  {new Date(t.laeuft_ab).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}
                </span>
                <button
                  className="knopf-text"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/agent-tokens/${t.id}`);
                      void ladeTokens();
                    } catch (e) {
                      props.melden(e);
                    }
                  }}
                >
                  Widerrufen
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
