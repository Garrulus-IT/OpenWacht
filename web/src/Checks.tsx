// SPDX-License-Identifier: AGPL-3.0-only

// Bausteine für Checks. Checks gehören zu einem Gerät und stehen im Reiter
// Hosts unter ihrem Gerät (seit Etappe 8 gibt es keinen eigenen Reiter mehr).

import { useState, type FormEvent } from "react";
import {
  api,
  type AgentArt,
  type Check,
  type CheckStatus,
  type CheckTyp,
  type CheckZiel,
  type Geraet,
  type Messwerte,
  type Vorlage,
} from "./api";
import { CheckVerlauf } from "./Verlauf";
import { vor } from "./zeit";
import { WartungHinweis, WartungMarke, WartungSteuerung } from "./Wartung";

// Fehlschläge in Folge bis zum Alarm, wenn der Sensor nichts Eigenes hat
// (Standard der Zentrale seit 1.0.6; Warnungen gehen sofort raus).
export const STANDARD_FEHLVERSUCHE = 3;

// Einheiten für eigene SNMP-Werte (1.0.8), wie checks.Units in der Zentrale.
export const EINHEITEN = ["°C", "%", "W", "V", "A", "RPM", "MB", "GB", "s", "ms", "bit/s", "dBm"];

// Kurztext zu „Zahl aus Text“ für die Spalte „misst“.
function zahlAusTextKurz(z: CheckZiel): string {
  switch (z.zahl_aus_text) {
    case "erste":
      return " (erste Zahl im Text)";
    case "nte":
      return ` (${z.zahl_nr ?? 1}. Zahl im Text)`;
    case "nach":
      return ` (Zahl nach „${z.zahl_nach ?? ""}“)`;
  }
  return "";
}

// Anzeigezustand: Status des letzten Laufs, dazu „neu“ und „pausiert“.
export type Anzeige = CheckStatus | "neu" | "pause";

export function anzeige(c: Check): Anzeige {
  if (!c.aktiv) return "pause";
  return c.status ?? "neu";
}

export const anzeigeText: Record<Anzeige, string> = {
  ok: "OK",
  warn: "Warnung",
  crit: "Kritisch",
  unknown: "Unbekannt",
  neu: "noch nicht geprüft",
  pause: "Pausiert",
};

export const rang: Record<Anzeige, number> = { crit: 0, unknown: 1, warn: 2, neu: 3, ok: 4, pause: 5 };

export const typText: Record<CheckTyp, string> = {
  ping: "Ping",
  tcp: "TCP-Port",
  http: "HTTP(S)",
  tls: "TLS-Zertifikat",
  dns: "DNS-Auflösung",
  http_json: "HTTP-JSON-Wert",
  dienst: "Dienst läuft",
  prozess: "Prozess läuft",
  datei: "Datei- oder Ordneralter",
  tcp_banner: "TCP-Banner",
  ntp: "Zeitserver (NTP)",
  snmp_oid: "SNMP eigene OID",
  docker: "Docker-Container läuft",
  hyperv: "Hyper-V-VM läuft",
  leistungsindikator: "Windows-Leistungsindikator",
  autodienste: "Automatische Windows-Dienste laufen",
};

// 0.47.0: Zusammenfassung einer SNMP-Tabellenspalte
const spaltenText: Record<string, string> = {
  minimum: "kleinster Wert",
  maximum: "größter Wert",
  summe: "Summe",
  anzahl: "Zahl der Zeilen",
  anzahl_gleich: "Zeilen mit Wert gleich …",
  anzahl_ungleich: "Zeilen mit Wert ungleich …",
};

export const agentArten: AgentArt[] = ["dienst", "prozess", "datei", "docker", "hyperv", "leistungsindikator", "autodienste"];
export const istAgentArt = (t: CheckTyp): t is AgentArt => (agentArten as CheckTyp[]).includes(t);
const zentraleArten: CheckTyp[] = ["ping", "tcp", "http", "tls", "dns", "http_json", "tcp_banner", "ntp"];

// Platzhalter {adresse} einer Vorlage durch die Adresse des Geräts ersetzen.
export function setzeAdresse(ziel: CheckZiel, adresse: string): CheckZiel {
  const ersetze = (x: string | undefined, url = false) => {
    if (!x || !adresse) return x;
    const a = url && adresse.includes(":") ? `[${adresse}]` : adresse;
    return x.split("{adresse}").join(a);
  };
  return {
    ...ziel,
    host: ersetze(ziel.host),
    url: ersetze(ziel.url, true),
    name: ziel.name && ziel.name.includes("{adresse}") ? ersetze(ziel.name) : ziel.name,
  };
}

const intervalle: [number, string][] = [
  [60, "jede Minute"],
  [300, "alle 5 Minuten"],
  [900, "alle 15 Minuten"],
  [3600, "jede Stunde"],
];

function intervallText(s: number) {
  return intervalle.find(([w]) => w === s)?.[1] ?? `alle ${s} Sekunden`;
}

export function zielText(c: { typ: CheckTyp; ziel: CheckZiel }) {
  const z = c.ziel;
  switch (c.typ) {
    case "ping":
      return z.host ?? "";
    case "tcp":
      return `${z.host}:${z.port}`;
    case "http":
      return z.url ?? "";
    case "tls":
      return `${z.host}${z.port && z.port !== 443 ? `:${z.port}` : ""}${z.verbinde ? ` über ${z.verbinde}` : ""}`;
    case "dns":
      return `${z.name ?? ""}${z.server ? ` über ${z.server}` : ""}${z.eintrag ? ` (${z.eintrag})` : ""}`;
    case "http_json":
      return `${z.url ?? ""} → ${z.json_pfad ?? ""}`;
    case "tcp_banner":
      return `${z.host}:${z.port}${z.tls ? " (TLS)" : ""}`;
    case "ntp":
      return `${z.host}${z.port && z.port !== 123 ? `:${z.port}` : ""}`;
    case "snmp_oid":
      return `${z.oid ?? ""}${z.rate ? " (Rate)" : ""}${z.zusammenfassung ? ` (Spalte: ${spaltenText[z.zusammenfassung] ?? z.zusammenfassung})` : ""}${zahlAusTextKurz(z)}`;
    case "dienst":
    case "prozess":
    case "docker":
    case "hyperv":
      return z.name ?? "";
    case "datei":
      return `${z.pfad ?? ""}${z.ordner ? " (Ordner)" : ""}`;
    case "leistungsindikator":
      return `\\${z.objekt ?? ""}${z.instanz ? `(${z.instanz})` : ""}\\${z.indikator ?? ""}${z.bezug ? ` / ${z.bezug} in %` : ""}`;
    case "autodienste":
      return z.ausnahmen?.length ? `außer ${z.ausnahmen.join(", ")}` : "alle";
  }
}

// Automatischer Name aus Art und Ziel (Etappe 18c), wie checks.DefaultName in
// der Zentrale. Bleibt das Namensfeld leer oder beim Vorschlag, schickt das
// Formular einen leeren Namen; die Zentrale hängt bei Bedarf eine Nummer an.
export function vorschlagName(typ: CheckTyp, z: CheckZiel): string {
  const basis = (p: string) => p.replace(/[/\\]+$/, "").split(/[/\\]/).pop() ?? "";
  const urlPort = (u: string | undefined) => {
    try {
      const x = new URL(u ?? "");
      return x.port || (x.protocol === "https:" ? "443" : "80");
    } catch {
      return "";
    }
  };
  const n = (() => {
    switch (typ) {
      case "ping":
        return "Ping";
      case "tcp":
        return `TCP ${z.port ?? ""}`;
      case "http":
        return `HTTP ${urlPort(z.url)}`;
      case "tls":
        return `Zertifikat ${z.host ?? ""}`;
      case "dns":
        return `DNS ${z.name ?? ""}`;
      case "http_json":
        return `JSON ${z.json_pfad ?? ""}`;
      case "tcp_banner":
        return `Banner ${z.port ?? ""}`;
      case "ntp":
        return "NTP";
      case "snmp_oid":
        return `OID ${z.oid ?? ""}`;
      case "dienst":
        return `Dienst ${z.name ?? ""}`;
      case "prozess":
        return `Prozess ${z.name ?? ""}`;
      case "datei":
        return `${z.ordner ? "Ordner" : "Datei"} ${basis(z.pfad ?? "")}`;
      case "docker":
        return `Container ${z.name ?? ""}`;
      case "hyperv":
        return `Hyper-V-VM ${z.name ?? ""}`;
      case "leistungsindikator":
        return `${z.objekt ?? ""} ${z.indikator ?? ""}`;
      case "autodienste":
        return "Automatische Dienste";
    }
  })();
  return [...n.trim()].slice(0, 100).join("").trim();
}

// freierName: „Ping“, sonst „Ping 2“, „Ping 3“ … (wie checks.NumberedName).
export function freierName(basis: string, vergeben: string[]): string {
  const belegt = new Set(vergeben.map((n) => n.toLowerCase()));
  for (let i = 1; i <= vergeben.length + 1; i++) {
    const zusatz = i < 2 ? "" : ` ${i}`;
    const n = [...basis].slice(0, 100 - zusatz.length).join("").trim() + zusatz;
    if (!belegt.has(n.toLowerCase())) return n;
  }
  return basis;
}

// Schwellen und Erwartungen der neuen Arten in Worten (für die Detailansicht).
export function schwellenText(c: { typ: CheckTyp; ziel: CheckZiel }): string {
  const z = c.ziel;
  const teile: string[] = [];
  const zahl = (n: number) => String(n).replace(".", ",");
  switch (c.typ) {
    case "ping":
      teile.push(`${z.anzahl ?? 3} Pakete`);
      if (z.verlust_warnung) teile.push(`Warnung ab ${zahl(z.verlust_warnung)} % Verlust`);
      if (z.verlust_kritisch) teile.push(`Fehler ab ${zahl(z.verlust_kritisch)} % Verlust`);
      if (z.antwort_warnung_ms) teile.push(`Warnung ab ${zahl(z.antwort_warnung_ms)} ms`);
      if (z.antwort_kritisch_ms) teile.push(`Fehler ab ${zahl(z.antwort_kritisch_ms)} ms`);
      break;
    case "dns":
      if (z.erwartet?.length) teile.push(`erwartet ${z.erwartet.join(", ")}`);
      break;
    case "tcp_banner":
      if (z.enthaelt) teile.push(`erwartet „${z.enthaelt}“`);
      break;
    case "ntp":
      teile.push(`Warnung ab ${zahl(z.abweichung_warnung_ms ?? 100)} ms, Fehler ab ${zahl(z.abweichung_kritisch_ms ?? 1000)} ms`);
      break;
    case "http_json":
    case "snmp_oid":
    case "leistungsindikator":
      if (z.instanz === "*") teile.push(`alle Instanzen: ${z.zusammenfassung ?? "summe"}`);
      if (z.vergleichswert !== undefined) teile.push(`Wert ${z.vergleichswert}`);
      if (z.faktor) teile.push(`mal ${zahl(z.faktor)}`);
      if (z.einheit) teile.push(`in ${z.einheit}`);
      if (z.warnung_ueber !== undefined) teile.push(`Warnung über ${zahl(z.warnung_ueber)}`);
      if (z.kritisch_ueber !== undefined) teile.push(`Fehler über ${zahl(z.kritisch_ueber)}`);
      if (z.warnung_unter !== undefined) teile.push(`Warnung unter ${zahl(z.warnung_unter)}`);
      if (z.kritisch_unter !== undefined) teile.push(`Fehler unter ${zahl(z.kritisch_unter)}`);
      if (z.gleich !== undefined) teile.push(`erwartet „${z.gleich}“`);
      break;
    case "prozess":
      teile.push(`mindestens ${z.mindestens ?? 1}`);
      if (z.hoechstens) teile.push(`höchstens ${z.hoechstens}`);
      break;
    case "datei":
      if (z.warnung_stunden) teile.push(`Warnung ab ${zahl(z.warnung_stunden)} Std.`);
      if (z.kritisch_stunden) teile.push(`Fehler ab ${zahl(z.kritisch_stunden)} Std.`);
      if (z.mindestgroesse) teile.push(`mindestens ${z.mindestgroesse} Bytes`);
      break;
  }
  return teile.join(", ");
}

export function CheckZeile(props: {
  c: Check;
  jetzt: number;
  offen: boolean;
  onUmschalten: () => void;
  darf: boolean;
  onBearbeiten: () => void;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const { c, jetzt, offen } = props;
  const a = anzeige(c);
  const [loeschen, setLoeschen] = useState(false);
  const [angestossen, setAngestossen] = useState(false);
  const detailId = `check-${c.id}`;

  const aktion = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      props.onGeaendert();
    } catch (e) {
      props.melden(e);
    }
  };
  const speichern = (aktiv: boolean) =>
    aktion(() =>
      api("PUT", `/api/v1/checks/${c.id}`, { name: c.name, typ: c.typ, ziel: c.ziel, intervall_sekunden: c.intervall_sekunden, aktiv }),
    );

  return (
    <li className={`host check-${a}`}>
      <button className="host-kopf check-kopf" aria-expanded={offen} aria-controls={detailId} onClick={props.onUmschalten}>
        <span className="host-name">
          <span className={`signal signal-${a}`} aria-hidden="true" />
          <span>
            <span className="name">{c.name}</span>
            <span className="klein">
              {typText[c.typ]} · {zielText(c)}
              {c.am_agent && <span className="marke">am Agent</span>}
              {c.herkunft && (
                <span className="marke" title="angelegt aus der Vorlage">
                  Vorlage: {c.herkunft}
                </span>
              )}
              {c.veraltet && <span className="marke marke-alt">kein Ergebnis vom Agent</span>}
              {c.wartung && c.aktiv && (
                <>
                  {" "}
                  <WartungMarke w={c.wartung} />
                </>
              )}
            </span>
          </span>
        </span>
        <span className="check-stand">
          <span className="check-meldung">
            <span className="sr-only">{anzeigeText[a]}: </span>
            {a === "neu" || a === "pause" ? anzeigeText[a] : c.meldung}
          </span>
          {c.seit && a !== "pause" && (
            <span className="klein">
              {anzeigeText[a]} seit {vor(c.seit, jetzt).replace(/^vor /, "")}
            </span>
          )}
        </span>
      </button>

      {offen && (
        <div className="host-detail" id={detailId}>
          {c.wartung && c.aktiv && <WartungHinweis w={c.wartung} />}
          <dl className="eckdaten">
            <div>
              <dt>Ziel</dt>
              <dd className="umbruch">{zielText(c)}</dd>
            </div>
            <div>
              <dt>Geprüft</dt>
              <dd>
                {intervallText(c.intervall_sekunden)}
                {c.zuletzt ? `, zuletzt ${vor(c.zuletzt, jetzt)}` : ""}
              </dd>
            </div>
            {c.messwert && (
              <div>
                <dt>{c.typ === "http_json" ? "Wert" : c.am_agent ? "Messwert" : "Antwortzeit"}</dt>
                <dd>{c.messwert}</dd>
              </div>
            )}
            {schwellenText(c) && (
              <div>
                <dt>Schwellen</dt>
                <dd className="umbruch">{schwellenText(c)}</dd>
              </div>
            )}
            {c.fehler_in_folge > 1 && (
              <div>
                <dt>Fehlschläge in Folge</dt>
                <dd>{c.fehler_in_folge}</dd>
              </div>
            )}
            {c.typ === "tls" && (
              <div>
                <dt>Schwellen</dt>
                <dd>
                  Warnung ab {c.ziel.warnung_tage} Tagen, Fehler ab {c.ziel.kritisch_tage} Tagen Restlaufzeit
                </dd>
              </div>
            )}
            {c.typ === "http" && (c.ziel.erwarte_status || c.ziel.enthaelt) && (
              <div>
                <dt>Erwartet</dt>
                <dd className="umbruch">
                  {c.ziel.erwarte_status ? `Status ${c.ziel.erwarte_status.join(", ")}` : "Status 200 bis 399"}
                  {c.ziel.enthaelt ? `, Text „${c.ziel.enthaelt}“` : ""}
                </dd>
              </div>
            )}
          </dl>
          <CheckVerlauf checkId={c.id} misstZeit={c.typ !== "tls" && !c.am_agent} />
          {props.darf && (
            <div className="aktionen">
              {loeschen ? (
                <div className="bestaetigung" role="alertdialog" aria-label="Check löschen">
                  <p>„{c.name}“ löschen? Zustand, Einstellungen und Verlauf gehen verloren.</p>
                  <div className="aktionen">
                    <button className="knopf knopf-gefahr" onClick={() => aktion(() => api("DELETE", `/api/v1/checks/${c.id}`))}>
                      Löschen
                    </button>
                    <button className="knopf" onClick={() => setLoeschen(false)}>
                      Abbrechen
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  {c.aktiv && (
                    <button
                      className="knopf knopf-haupt"
                      disabled={angestossen}
                      onClick={async () => {
                        setAngestossen(true);
                        await aktion(() => api("POST", `/api/v1/checks/${c.id}/jetzt`));
                        // Ergebnis nach dem nächsten Planerlauf holen
                        setTimeout(() => {
                          setAngestossen(false);
                          props.onGeaendert();
                        }, 4000);
                      }}
                    >
                      {angestossen ? "Wird geprüft …" : "Jetzt prüfen"}
                    </button>
                  )}
                  <button className="knopf" onClick={props.onBearbeiten}>
                    Bearbeiten
                  </button>
                  {c.aktiv && !c.wartung?.ueber_geraet && (
                    <WartungSteuerung
                      pfad={`/api/v1/checks/${c.id}`}
                      name={c.name}
                      wartung={c.wartung}
                      onGeaendert={props.onGeaendert}
                      melden={props.melden}
                    />
                  )}
                  <button className="knopf" onClick={() => speichern(!c.aktiv)}>
                    {c.aktiv ? "Pausieren" : "Fortsetzen"}
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setLoeschen(true)}>
                    Löschen
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

// --- Anlegen und bearbeiten ------------------------------------------------------

export function CheckFormular(props: {
  geraet: Geraet;
  // Geräte desselben Mandanten, zu denen ein Check wechseln kann
  geraete: Geraet[];
  check: Check | null;
  netze: string[];
  // Etappe 18: Vorbelegung aus einer Vorlage, Agent am Gerät und seine lokale Freigabe
  vorlage?: Vorlage | null;
  hatAgent?: boolean;
  // Gerät hat eine SNMP-Abfrage (für „SNMP eigene OID“)
  hatSnmp?: boolean;
  freigabe?: Messwerte["sensoren"] | null;
  // Namen der Checks am Gerät (für die Nummer im Vorschlag, wie die Zentrale)
  vergeben?: string[];
  // Vorlage bearbeiten statt Sensor anlegen: speichert über diese Funktion
  speichern?: (body: { name: string; typ: CheckTyp; ziel: CheckZiel; intervall_sekunden: number; fehlversuche: number }) => Promise<void>;
  titel?: string;
  onFertig: (neueId?: string) => void;
  melden: (e: unknown) => void;
}) {
  const c = props.check;
  const adresse = props.geraet.adresse ?? "";
  const v = !c && props.vorlage ? props.vorlage : null;
  const z: CheckZiel = c?.ziel ?? (v ? setzeAdresse(v.ziel, adresse) : {});
  const t0 = (x: number | undefined) => (x === undefined ? "" : String(x).replace(".", ","));
  // Eigener Name; null = Vorschlag aus Art und Ziel (nur beim Anlegen am Gerät)
  const [eigenerName, setEigenerName] = useState<string | null>(c?.name ?? v?.name ?? (props.speichern ? "" : null));
  const [typ, setTyp] = useState<CheckTyp>(c?.typ ?? v?.typ ?? "ping");
  const [intervall, setIntervall] = useState(c?.intervall_sekunden ?? v?.intervall_sekunden ?? 300);
  // 1.0.6: Fehlversuche bis zum Alarm, 0 = Standard der Zentrale
  const [fehlversuche, setFehlversuche] = useState(c?.fehlversuche ?? v?.fehlversuche ?? 0);
  const [geraetId, setGeraetId] = useState(props.geraet.id);
  // Neuer Check: Adresse des Geräts als Vorschlag, frei änderbar.
  const [host, setHost] = useState(z.host ?? (c || v ? "" : adresse));
  const [port, setPort] = useState(z.port ? String(z.port) : "");
  const [url, setUrl] = useState(z.url ?? "");
  const [status, setStatus] = useState(z.erwarte_status?.join(", ") ?? "");
  const [text, setText] = useState(z.enthaelt ?? "");
  const [verbinde, setVerbinde] = useState(z.verbinde ?? "");
  const [warnung, setWarnung] = useState(String(z.warnung_tage ?? 21));
  const [kritisch, setKritisch] = useState(String(z.kritisch_tage ?? 7));
  const [timeout, setTimeoutS] = useState(z.timeout_s ? String(z.timeout_s) : "");
  const [ca, setCa] = useState(z.ca_pem ?? "");
  // Etappe 18
  const [anzahl, setAnzahl] = useState(t0(z.anzahl));
  const [verlustW, setVerlustW] = useState(t0(z.verlust_warnung));
  const [verlustK, setVerlustK] = useState(t0(z.verlust_kritisch));
  const [rttW, setRttW] = useState(t0(z.antwort_warnung_ms));
  const [rttK, setRttK] = useState(t0(z.antwort_kritisch_ms));
  const [nameFeld, setNameFeld] = useState(z.name ?? "");
  const [server, setServer] = useState(z.server ?? "");
  const [eintrag, setEintrag] = useState<"" | "A" | "AAAA">(z.eintrag ?? "");
  const [erwartet, setErwartet] = useState(z.erwartet?.join(", ") ?? "");
  const [jsonPfad, setJsonPfad] = useState(z.json_pfad ?? "");
  const [vergleich, setVergleich] = useState<"vorhanden" | "zahl" | "gleich">(
    z.gleich !== undefined
      ? "gleich"
      : [z.warnung_ueber, z.kritisch_ueber, z.warnung_unter, z.kritisch_unter].some((x) => x !== undefined)
        ? "zahl"
        : "vorhanden",
  );
  const [wUeber, setWUeber] = useState(t0(z.warnung_ueber));
  const [kUeber, setKUeber] = useState(t0(z.kritisch_ueber));
  const [wUnter, setWUnter] = useState(t0(z.warnung_unter));
  const [kUnter, setKUnter] = useState(t0(z.kritisch_unter));
  const [gleich, setGleich] = useState(z.gleich ?? "");
  const [mind, setMind] = useState(t0(z.mindestens));
  const [hoechst, setHoechst] = useState(t0(z.hoechstens));
  const [pfad, setPfad] = useState(z.pfad ?? "");
  const [ordner, setOrdner] = useState(z.ordner ?? false);
  const [wStd, setWStd] = useState(t0(z.warnung_stunden));
  const [kStd, setKStd] = useState(t0(z.kritisch_stunden));
  const [minGroesse, setMinGroesse] = useState(t0(z.mindestgroesse));
  const [tlsAn, setTlsAn] = useState(z.tls ?? false);
  const [abwW, setAbwW] = useState(t0(z.abweichung_warnung_ms));
  const [abwK, setAbwK] = useState(t0(z.abweichung_kritisch_ms));
  const [oid, setOid] = useState(z.oid ?? "");
  const [rate, setRate] = useState(z.rate ?? false);
  // 0.47.0: SNMP-Tabellenspalte statt einzelnem Wert ("" = einzelner Wert)
  const [spalte, setSpalte] = useState<string>(typ === "snmp_oid" ? (z.zusammenfassung ?? "") : "");
  const [vergleichswert, setVergleichswert] = useState(t0(z.vergleichswert));
  // 1.0.8: Zahl aus Text, Faktor und Einheit
  const [ausText, setAusText] = useState<string>(z.zahl_aus_text ?? "");
  const [zahlNr, setZahlNr] = useState(z.zahl_nr ?? 2);
  const [zahlNach, setZahlNach] = useState(z.zahl_nach ?? "");
  const [faktor, setFaktor] = useState(z.faktor ? String(z.faktor).replace(".", ",") : "");
  const [einheit, setEinheit] = useState(z.einheit ?? "");
  // 1.0.10: Text des Geräts anzeigen
  const [textZeigen, setTextZeigen] = useState(z.text_zeigen ?? false);
  const [objekt, setObjekt] = useState(z.objekt ?? "");
  const [indikator, setIndikator] = useState(z.indikator ?? "");
  const [instanz, setInstanz] = useState(z.instanz ?? "");
  const [zusammenfassung, setZusammenfassung] = useState(z.zusammenfassung ?? "summe");
  const [bezug, setBezug] = useState(z.bezug ?? "");
  const [ausnahmen, setAusnahmen] = useState(z.ausnahmen?.join("\n") ?? "");
  const [fehler, setFehler] = useState("");
  const [sendet, setSendet] = useState(false);
  const amAgent = istAgentArt(typ);

  // Zahl aus einem Feld; leer = nicht gesetzt
  const zahl = (x: string) => (x.trim() === "" ? undefined : Number(x.trim().replace(",", ".")));
  const nurGesetzt = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).filter(([, w]) => w !== undefined && w !== ""));

  const ziel = (): CheckZiel => {
    const t = timeout ? { timeout_s: Number(timeout) } : {};
    const caFeld = ca.trim() ? { ca_pem: ca.trim() + "\n" } : {};
    const codes = status
      .split(/[\s,;]+/)
      .filter(Boolean)
      .map(Number);
    switch (typ) {
      case "ping":
        return nurGesetzt({
          host: host.trim(),
          anzahl: zahl(anzahl),
          verlust_warnung: zahl(verlustW),
          verlust_kritisch: zahl(verlustK),
          antwort_warnung_ms: zahl(rttW),
          antwort_kritisch_ms: zahl(rttK),
          ...t,
        });
      case "tcp":
        return { host: host.trim(), port: Number(port), ...t };
      case "http": {
        return {
          url: url.trim(),
          ...(codes.length ? { erwarte_status: codes } : {}),
          ...(text ? { enthaelt: text } : {}),
          ...t,
          ...caFeld,
        };
      }
      case "tls":
        return {
          host: host.trim(),
          ...(port ? { port: Number(port) } : {}),
          ...(verbinde.trim() ? { verbinde: verbinde.trim() } : {}),
          warnung_tage: Number(warnung.replace(",", ".")),
          kritisch_tage: Number(kritisch.replace(",", ".")),
          ...t,
          ...caFeld,
        };
      case "dns": {
        const e = erwartet.split(/[\s,;]+/).filter(Boolean);
        return nurGesetzt({ name: nameFeld.trim(), server: server.trim(), eintrag, ...(e.length ? { erwartet: e } : {}), ...t });
      }
      case "http_json":
        return nurGesetzt({
          url: url.trim(),
          json_pfad: jsonPfad.trim(),
          ...(codes.length ? { erwarte_status: codes } : {}),
          ...(vergleich === "zahl"
            ? { warnung_ueber: zahl(wUeber), kritisch_ueber: zahl(kUeber), warnung_unter: zahl(wUnter), kritisch_unter: zahl(kUnter) }
            : {}),
          ...(vergleich === "gleich" ? { gleich } : {}),
          ...t,
          ...caFeld,
        });
      case "tcp_banner":
        return nurGesetzt({
          host: host.trim(),
          port: Number(port),
          ...(tlsAn ? { tls: true } : {}),
          ...(text ? { enthaelt: text } : {}),
          ...t,
          ...(tlsAn ? caFeld : {}),
        });
      case "ntp":
        return nurGesetzt({
          host: host.trim(),
          port: port ? Number(port) : undefined,
          abweichung_warnung_ms: zahl(abwW),
          abweichung_kritisch_ms: zahl(abwK),
          ...t,
        });
      case "snmp_oid": {
        // Text anzeigen gilt nur für einen einzelnen Wert ohne Rate und ohne Zahl aus Text
        const text = textZeigen && !spalte && !rate && !ausText;
        return nurGesetzt({
          oid: oid.trim(),
          ...(rate && !spalte ? { rate: true } : {}),
          ...(spalte ? { zusammenfassung: spalte } : {}),
          ...(spalte.startsWith("anzahl_") ? { vergleichswert: zahl(vergleichswert) } : {}),
          ...(vergleich === "zahl" && !text
            ? { warnung_ueber: zahl(wUeber), kritisch_ueber: zahl(kUeber), warnung_unter: zahl(wUnter), kritisch_unter: zahl(kUnter) }
            : {}),
          ...(vergleich === "gleich" && !rate && !spalte && !ausText ? { gleich } : {}),
          ...(ausText && !spalte && !rate
            ? { zahl_aus_text: ausText, ...(ausText === "nte" ? { zahl_nr: zahlNr } : {}), ...(ausText === "nach" ? { zahl_nach: zahlNach } : {}) }
            : {}),
          ...(text ? { text_zeigen: true } : { faktor: zahl(faktor), ...(einheit ? { einheit } : {}) }),
        });
      }
      case "dienst":
      case "docker":
      case "hyperv":
        return { name: nameFeld.trim() };
      case "prozess":
        return nurGesetzt({ name: nameFeld.trim(), mindestens: zahl(mind), hoechstens: zahl(hoechst) });
      case "autodienste": {
        const a = ausnahmen
          .split(/[\n,]/)
          .map((x) => x.trim())
          .filter((x) => x !== "");
        return a.length ? { ausnahmen: a } : {};
      }
      case "leistungsindikator":
        return nurGesetzt({
          objekt: objekt.trim(),
          indikator: indikator.trim(),
          instanz: instanz.trim() || undefined,
          zusammenfassung: instanz.trim() === "*" ? zusammenfassung : undefined,
          bezug: bezug.trim() || undefined,
          warnung_ueber: zahl(wUeber),
          kritisch_ueber: zahl(kUeber),
          warnung_unter: zahl(wUnter),
          kritisch_unter: zahl(kUnter),
        });
      case "datei":
        return nurGesetzt({
          pfad: pfad.trim(),
          ...(ordner ? { ordner: true } : {}),
          warnung_stunden: zahl(wStd),
          kritisch_stunden: zahl(kStd),
          mindestgroesse: ordner ? undefined : zahl(minGroesse),
        });
    }
  };

  const vorschlag = freierName(
    vorschlagName(typ, ziel()),
    (props.vergeben ?? []).filter((n) => n !== c?.name),
  );

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setSendet(true);
    // Leer oder unverändert beim Vorschlag: Die Zentrale bildet den Namen.
    const eigen = (eigenerName ?? "").trim();
    const name = props.speichern ? eigen : eigen === "" || (!c && eigen === vorschlag) ? "" : eigen;
    const body = {
      name,
      typ,
      ziel: ziel(),
      intervall_sekunden: intervall,
      aktiv: c?.aktiv ?? true,
      fehlversuche,
      ...(v ? { herkunft: v.name } : {}),
    };
    try {
      if (props.speichern) {
        await props.speichern({ name, typ, ziel: ziel(), intervall_sekunden: intervall, fehlversuche });
        props.onFertig();
      } else if (c) {
        await api("PUT", `/api/v1/checks/${c.id}`, geraetId !== props.geraet.id ? { ...body, geraet_id: geraetId } : body);
        props.onFertig();
      } else {
        const r = await api<{ id: string }>("POST", `/api/v1/geraete/${props.geraet.id}/checks`, body);
        props.onFertig(r.id);
      }
    } catch (err) {
      // Prüffehler gehören ans Formular, nicht in die allgemeine Meldung oben.
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setSendet(false);
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">
          {props.titel
            ? props.titel
            : c
              ? `„${c.name}“ bearbeiten`
              : v
                ? `Sensor aus „${v.name}“ für „${props.geraet.name}“`
                : `Sensor für „${props.geraet.name}“ anlegen`}
        </h3>
        {props.speichern ? (
          <p className="hinweis formular-voll">
            {"{adresse}"} in Host, Adresse oder DNS-Name steht für die Adresse des Geräts.
            {amAgent ? " Sensoren auf dem Agent messen nur, was am Rechner freigegeben ist (openwacht-agent sensoren …)." : ""}
          </p>
        ) : amAgent ? (
          <AgentHinweis typ={typ} hatAgent={!!props.hatAgent} freigabe={props.freigabe ?? null} />
        ) : typ === "snmp_oid" ? null : props.netze.length === 0 ? (
          <p className="meldung meldung-warnung formular-voll">
            Für Sensoren der Zentrale sind noch keine Netze freigegeben. Bis der Betreiber Netze freigibt (Einstellungen oder Option
            -check-netze), melden diese Sensoren „nicht freigegeben“.
          </p>
        ) : (
          <p className="hinweis formular-voll">
            Diese Sensoren laufen auf der Zentrale und erreichen nur diese Netze: {props.netze.join(", ")}.
          </p>
        )}
        <label className="feld">
          <span>Name{props.speichern ? "" : " (leer = automatisch)"}</span>
          {props.speichern ? (
            <input required maxLength={100} value={eigenerName ?? ""} placeholder="z. B. Intranet-Portal" onChange={(e) => setEigenerName(e.target.value)} />
          ) : (
            <input
              maxLength={100}
              value={eigenerName ?? vorschlag}
              placeholder={vorschlag}
              aria-describedby="name-hinweis"
              onChange={(e) => setEigenerName(e.target.value)}
            />
          )}
          {!props.speichern && (
            <span className="klein" id="name-hinweis">
              Eindeutig je Gerät; ist der Vorschlag vergeben, hängt OpenWacht eine Nummer an.
            </span>
          )}
        </label>
        <label className="feld">
          <span>Art</span>
          <select value={typ} onChange={(e) => setTyp(e.target.value as CheckTyp)}>
            <optgroup label="An der Zentrale">
              {zentraleArten.map((t) => (
                <option key={t} value={t}>
                  {typText[t]}
                </option>
              ))}
            </optgroup>
            <optgroup label="Mit der SNMP-Abfrage">
              <option value="snmp_oid" disabled={!props.hatSnmp && !props.speichern && typ !== "snmp_oid"}>
                {typText.snmp_oid}
                {!props.hatSnmp && !props.speichern ? " (nur mit SNMP)" : ""}
              </option>
            </optgroup>
            <optgroup label="Auf dem Agent">
              {agentArten.map((t) => (
                <option key={t} value={t} disabled={!props.hatAgent && !props.speichern && typ !== t}>
                  {typText[t]}
                  {!props.hatAgent && !props.speichern ? " (nur mit Agent)" : ""}
                </option>
              ))}
            </optgroup>
          </select>
        </label>
        {typ === "snmp_oid" && (
          <p className="klein formular-voll">
            Gelesen mit der SNMP-Abfrage des Geräts (Zentrale oder Sammler), in deren Takt. Texte vom Gerät werden nur verglichen, nie
            angezeigt.
          </p>
        )}
        <label className={typ === "snmp_oid" ? "feld versteckt" : "feld"}>
          <span>Prüfen</span>
          <select value={intervall} onChange={(e) => setIntervall(Number(e.target.value))}>
            {intervalle.map(([w, t]) => (
              <option key={w} value={w}>
                {t}
              </option>
            ))}
            {!intervalle.some(([w]) => w === intervall) && <option value={intervall}>{intervallText(intervall)}</option>}
          </select>
        </label>
        <label className="feld">
          <span>Alarm nach</span>
          <select value={fehlversuche} onChange={(e) => setFehlversuche(Number(e.target.value))}>
            <option value={0}>Standard ({STANDARD_FEHLVERSUCHE} Fehlschläge)</option>
            {Array.from({ length: 10 }, (_, i) => i + 1).map((n) => (
              <option key={n} value={n}>
                {n === 1 ? "1 Fehlschlag (sofort)" : `${n} Fehlschlägen in Folge`}
              </option>
            ))}
          </select>
        </label>

        {(typ === "http" || typ === "http_json") && (
          <label className="feld formular-voll">
            <span>Adresse</span>
            <input
              required
              value={url}
              placeholder={adresse ? `https://${adresse.includes(":") ? `[${adresse}]` : adresse}/` : "https://intranet.example.com/"}
              onChange={(e) => setUrl(e.target.value)}
            />
          </label>
        )}
        {(typ === "ping" || typ === "tcp" || typ === "tls" || typ === "tcp_banner" || typ === "ntp") && (
          <label className="feld">
            <span>{typ === "tls" ? "Name im Zertifikat" : "Host"}</span>
            <input
              required
              value={host}
              placeholder={typ === "tls" ? "dms.example.com" : "10.10.0.20 oder srv-file01.example.com"}
              onChange={(e) => setHost(e.target.value)}
            />
          </label>
        )}
        {(typ === "tcp" || typ === "tls" || typ === "tcp_banner" || typ === "ntp") && (
          <label className="feld">
            <span>Port</span>
            <input
              required={typ === "tcp" || typ === "tcp_banner"}
              inputMode="numeric"
              pattern="[0-9]*"
              value={port}
              placeholder={typ === "tls" ? "443" : typ === "ntp" ? "123" : typ === "tcp_banner" ? "z. B. 25, 993, 22" : ""}
              onChange={(e) => setPort(e.target.value)}
            />
          </label>
        )}
        {typ === "ping" && (
          <>
            <label className="feld">
              <span>Pakete</span>
              <input inputMode="numeric" pattern="[0-9]*" value={anzahl} placeholder="3" onChange={(e) => setAnzahl(e.target.value)} />
            </label>
            <label className="feld">
              <span>Warnung ab Verlust in % (optional)</span>
              <input inputMode="decimal" value={verlustW} onChange={(e) => setVerlustW(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler ab Verlust in % (optional)</span>
              <input inputMode="decimal" value={verlustK} onChange={(e) => setVerlustK(e.target.value)} />
            </label>
            <label className="feld">
              <span>Warnung ab Antwortzeit in ms (optional)</span>
              <input inputMode="decimal" value={rttW} onChange={(e) => setRttW(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler ab Antwortzeit in ms (optional)</span>
              <input inputMode="decimal" value={rttK} onChange={(e) => setRttK(e.target.value)} />
            </label>
          </>
        )}
        {typ === "tls" && (
          <>
            <label className="feld">
              <span>Verbinden mit (optional)</span>
              <input value={verbinde} placeholder="z. B. 10.10.0.21" onChange={(e) => setVerbinde(e.target.value)} />
            </label>
            <label className="feld">
              <span>Warnung ab Tagen Restlaufzeit</span>
              <input inputMode="decimal" value={warnung} onChange={(e) => setWarnung(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler ab Tagen Restlaufzeit</span>
              <input inputMode="decimal" value={kritisch} onChange={(e) => setKritisch(e.target.value)} />
            </label>
          </>
        )}
        {(typ === "http" || typ === "http_json") && (
          <label className="feld">
            <span>Erwartete Status-Codes (optional)</span>
            <input value={status} placeholder="Standard: 200 bis 399" onChange={(e) => setStatus(e.target.value)} />
          </label>
        )}
        {typ === "tcp_banner" && (
          <label className="haken">
            <input type="checkbox" checked={tlsAn} onChange={(e) => setTlsAn(e.target.checked)} />
            <span>Direktes TLS (z. B. IMAPS 993, SMTPS 465)</span>
          </label>
        )}
        {typ === "ntp" && (
          <>
            <label className="feld">
              <span>Warnung ab Abweichung in ms</span>
              <input inputMode="decimal" value={abwW} placeholder="100" onChange={(e) => setAbwW(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler ab Abweichung in ms</span>
              <input inputMode="decimal" value={abwK} placeholder="1000" onChange={(e) => setAbwK(e.target.value)} />
            </label>
          </>
        )}
        {typ === "snmp_oid" && (
          <>
            <label className="feld">
              <span>OID</span>
              <input required value={oid} placeholder="z. B. 1.3.6.1.2.1.1.3.0 (sysUpTime)" onChange={(e) => setOid(e.target.value)} />
            </label>
            <label className="feld">
              <span>Abfrage</span>
              <select
                value={spalte}
                onChange={(e) => {
                  setSpalte(e.target.value);
                  if (e.target.value && vergleich === "gleich") setVergleich("zahl");
                }}
              >
                <option value="">Einzelner Wert</option>
                {Object.entries(spaltenText).map(([k, v]) => (
                  <option key={k} value={k}>
                    Tabellenspalte: {v}
                  </option>
                ))}
              </select>
            </label>
            {spalte.startsWith("anzahl_") && (
              <label className="feld">
                <span>Vergleichswert (ganze Zahl)</span>
                <input
                  required
                  inputMode="numeric"
                  value={vergleichswert}
                  placeholder="z. B. 1 für down"
                  onChange={(e) => setVergleichswert(e.target.value)}
                />
              </label>
            )}
            {!spalte && !ausText && (
              <label className="haken">
                <input type="checkbox" checked={rate} onChange={(e) => setRate(e.target.checked)} />
                <span>Zähler: Rate je Sekunde</span>
              </label>
            )}
            {!spalte && !rate && (
              <label className="feld">
                <span>Zahl aus Text</span>
                <select
                  value={ausText}
                  onChange={(e) => {
                    setAusText(e.target.value);
                    if (e.target.value && vergleich === "gleich") setVergleich("zahl");
                  }}
                >
                  <option value="">nein (der Wert ist eine Zahl oder ein Text zum Vergleichen)</option>
                  <option value="erste">erste Zahl im Text, z. B. „1500RPM“ → 1500</option>
                  <option value="nte">n-te Zahl im Text</option>
                  <option value="nach">Zahl nach einem Text, z. B. nach „10s:“</option>
                </select>
              </label>
            )}
            {!spalte && !rate && !ausText && (
              <label className="haken">
                <input type="checkbox" checked={textZeigen} onChange={(e) => setTextZeigen(e.target.checked)} />
                <span>Text des Geräts anzeigen, z. B. die Firmware-Version</span>
              </label>
            )}
            {!spalte && !rate && !ausText && textZeigen && (
              <p className="klein formular-voll">
                Sonst speichert die Zentrale von einem Text nur einen Prüfwert. Mit diesem Haken speichert sie den zuletzt gelesenen Text
                dieser OID (höchstens 50 Zeichen) und zeigt ihn als Messwert. Nur für Werte ohne Personenbezug einschalten. Schwellen,
                Faktor und Einheit gelten dann nicht; „Wert gleich Text“ geht weiter. Über einen Sammler braucht das den Agent ab 1.0.10.
              </p>
            )}
            {!spalte && !rate && ausText === "nte" && (
              <label className="feld">
                <span>Die wievielte Zahl</span>
                <select value={zahlNr} onChange={(e) => setZahlNr(Number(e.target.value))}>
                  {Array.from({ length: 16 }, (_, i) => i + 1).map((n) => (
                    <option key={n} value={n}>
                      {n}.
                    </option>
                  ))}
                </select>
              </label>
            )}
            {!spalte && !rate && ausText === "nach" && (
              <label className="feld">
                <span>Text vor der Zahl (genau so, höchstens 40 Zeichen)</span>
                <input required maxLength={40} value={zahlNach} placeholder="z. B. 10s:" onChange={(e) => setZahlNach(e.target.value)} />
              </label>
            )}
            {!spalte && !rate && ausText && (
              <p className="klein formular-voll">
                Die Zentrale liest beim Abfragen nur die Zahl heraus und speichert sie; der Text des Geräts wird nicht gespeichert. Steht an
                der Stelle keine Zahl, wird der Sensor „unbekannt“. Über einen Sammler braucht das den Agent ab 1.0.8.
              </p>
            )}
            <label className="feld">
              <span>Faktor (optional)</span>
              <input inputMode="decimal" value={faktor} placeholder="z. B. 0,1" onChange={(e) => setFaktor(e.target.value)} />
            </label>
            <label className="feld">
              <span>Einheit (optional)</span>
              <select value={einheit} onChange={(e) => setEinheit(e.target.value)}>
                <option value="">keine</option>
                {EINHEITEN.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Bewerten</span>
              <select value={vergleich} onChange={(e) => setVergleich(e.target.value as typeof vergleich)}>
                <option value="vorhanden">Wert vorhanden</option>
                <option value="zahl">Zahl mit Schwellen</option>
                {!rate && !spalte && !ausText && <option value="gleich">Wert gleich Text oder Zahl</option>}
              </select>
            </label>
            {spalte && (
              <p className="klein formular-voll">
                Die Spalte wird Zeile für Zeile gelesen (höchstens 2000 Zeilen). Gemeldet wird nur die Kennzahl, keine Namen der Zeilen.
              </p>
            )}
          </>
        )}
        {(typ === "http" || typ === "tcp_banner") && (
          <label className="feld">
            <span>Erwarteter Text (optional)</span>
            <input maxLength={200} value={text} onChange={(e) => setText(e.target.value)} />
          </label>
        )}
        {typ === "http_json" && (
          <>
            <label className="feld">
              <span>JSON-Pfad</span>
              <input
                required
                value={jsonPfad}
                placeholder="z. B. status.temperatur oder werte.0.cpu"
                onChange={(e) => setJsonPfad(e.target.value)}
              />
            </label>
            <label className="feld">
              <span>Bewerten</span>
              <select value={vergleich} onChange={(e) => setVergleich(e.target.value as typeof vergleich)}>
                <option value="vorhanden">Wert vorhanden</option>
                <option value="zahl">Zahl mit Schwellen</option>
                <option value="gleich">Wert gleich Text</option>
              </select>
            </label>
          </>
        )}
        {(typ === "http_json" || typ === "snmp_oid") && (
          <>
            {vergleich === "zahl" && (
              <>
                <label className="feld">
                  <span>Warnung über</span>
                  <input inputMode="decimal" value={wUeber} onChange={(e) => setWUeber(e.target.value)} />
                </label>
                <label className="feld">
                  <span>Fehler über</span>
                  <input inputMode="decimal" value={kUeber} onChange={(e) => setKUeber(e.target.value)} />
                </label>
                <label className="feld">
                  <span>Warnung unter</span>
                  <input inputMode="decimal" value={wUnter} onChange={(e) => setWUnter(e.target.value)} />
                </label>
                <label className="feld">
                  <span>Fehler unter</span>
                  <input inputMode="decimal" value={kUnter} onChange={(e) => setKUnter(e.target.value)} />
                </label>
              </>
            )}
            {vergleich === "gleich" && (
              <label className="feld">
                <span>Erwarteter Wert</span>
                <input maxLength={200} value={gleich} placeholder="z. B. ok oder true" onChange={(e) => setGleich(e.target.value)} />
              </label>
            )}
            <p className="klein formular-voll">
              {typ === "http_json" ? "Texte aus der Antwort" : "Texte vom Gerät"} werden nur verglichen, nie angezeigt. Zahlen erscheinen
              als Messwert.
            </p>
          </>
        )}
        {typ === "dns" && (
          <>
            <label className="feld">
              <span>Name</span>
              <input required value={nameFeld} placeholder="z. B. srv-file01.example.com" onChange={(e) => setNameFeld(e.target.value)} />
            </label>
            <label className="feld">
              <span>DNS-Server (optional)</span>
              <input value={server} placeholder="leer = Resolver der Zentrale" onChange={(e) => setServer(e.target.value)} />
            </label>
            <label className="feld">
              <span>Eintrag</span>
              <select value={eintrag} onChange={(e) => setEintrag(e.target.value as typeof eintrag)}>
                <option value="">A und AAAA</option>
                <option value="A">A (IPv4)</option>
                <option value="AAAA">AAAA (IPv6)</option>
              </select>
            </label>
            <label className="feld">
              <span>Erwartete Adressen (optional)</span>
              <input value={erwartet} placeholder="z. B. 10.10.0.20" onChange={(e) => setErwartet(e.target.value)} />
            </label>
          </>
        )}
        {(typ === "dienst" || typ === "prozess" || typ === "docker" || typ === "hyperv") && (
          <label className="feld">
            <span>
              {typ === "dienst"
                ? "Name des Dienstes"
                : typ === "docker"
                  ? "Name des Containers"
                  : typ === "hyperv"
                    ? "Name der VM"
                    : "Name des Programms"}
            </span>
            <input
              required
              value={nameFeld}
              placeholder={
                typ === "dienst"
                  ? "z. B. ssh, nginx oder Spooler"
                  : typ === "docker"
                    ? "wie bei docker ps, z. B. webapp"
                    : typ === "hyperv"
                      ? "wie im Hyper-V-Manager, z. B. dc01"
                      : "z. B. nginx oder nginx.exe"
              }
              onChange={(e) => setNameFeld(e.target.value)}
            />
          </label>
        )}
        {typ === "autodienste" && (
          <label className="feld formular-voll">
            <span>Ausnahmen (optional, je Zeile ein Dienst- oder Anzeigename, * am Ende für den Anfang)</span>
            <textarea rows={4} value={ausnahmen} placeholder={"z. B. gupdate\nedgeupdate*"} onChange={(e) => setAusnahmen(e.target.value)} />
          </label>
        )}
        {typ === "leistungsindikator" && (
          <>
            <label className="feld">
              <span>Objekt</span>
              <input required value={objekt} placeholder="z. B. SwyxServer" onChange={(e) => setObjekt(e.target.value)} />
            </label>
            <label className="feld">
              <span>Indikator</span>
              <input required value={indikator} placeholder="z. B. Active Calls" onChange={(e) => setIndikator(e.target.value)} />
            </label>
            <label className="feld">
              <span>Instanz (optional)</span>
              <input value={instanz} placeholder="leer = ohne, * = alle" onChange={(e) => setInstanz(e.target.value)} />
            </label>
            {instanz.trim() === "*" && (
              <label className="feld">
                <span>Alle Instanzen zusammenfassen</span>
                <select value={zusammenfassung} onChange={(e) => setZusammenfassung(e.target.value as typeof zusammenfassung)}>
                  <option value="summe">Summe</option>
                  <option value="minimum">Minimum</option>
                  <option value="maximum">Maximum</option>
                  <option value="anzahl">Anzahl Instanzen</option>
                </select>
              </label>
            )}
            <label className="feld">
              <span>Bezug in Prozent (optional)</span>
              <input value={bezug} placeholder="z. B. Licenced users" onChange={(e) => setBezug(e.target.value)} />
            </label>
            <label className="feld">
              <span>Warnung über</span>
              <input inputMode="decimal" value={wUeber} onChange={(e) => setWUeber(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler über</span>
              <input inputMode="decimal" value={kUeber} onChange={(e) => setKUeber(e.target.value)} />
            </label>
            <label className="feld">
              <span>Warnung unter</span>
              <input inputMode="decimal" value={wUnter} onChange={(e) => setWUnter(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler unter</span>
              <input inputMode="decimal" value={kUnter} onChange={(e) => setKUnter(e.target.value)} />
            </label>
            <p className="klein formular-voll">
              Englische Namen wie in der Herstellerdoku; sie gelten auch auf deutschem Windows. Mit „*“ meldet der Agent nur die
              zusammengefasste Zahl, keine Namen der Instanzen.
            </p>
          </>
        )}
        {typ === "prozess" && (
          <>
            <label className="feld">
              <span>Mindestens laufend</span>
              <input inputMode="numeric" pattern="[0-9]*" value={mind} placeholder="1" onChange={(e) => setMind(e.target.value)} />
            </label>
            <label className="feld">
              <span>Höchstens laufend (optional)</span>
              <input inputMode="numeric" pattern="[0-9]*" value={hoechst} onChange={(e) => setHoechst(e.target.value)} />
            </label>
          </>
        )}
        {typ === "datei" && (
          <>
            <label className="feld formular-voll">
              <span>Pfad</span>
              <input
                required
                value={pfad}
                placeholder="z. B. /var/lib/vz/dump oder D:\Backup\nacht.bak"
                onChange={(e) => setPfad(e.target.value)}
              />
            </label>
            <label className="haken">
              <input type="checkbox" checked={ordner} onChange={(e) => setOrdner(e.target.checked)} />
              <span>Ordner: Alter des jüngsten Eintrags</span>
            </label>
            <label className="feld">
              <span>Warnung ab Alter in Stunden</span>
              <input inputMode="decimal" value={wStd} placeholder="z. B. 26" onChange={(e) => setWStd(e.target.value)} />
            </label>
            <label className="feld">
              <span>Fehler ab Alter in Stunden</span>
              <input inputMode="decimal" value={kStd} placeholder="z. B. 50" onChange={(e) => setKStd(e.target.value)} />
            </label>
            {!ordner && (
              <label className="feld">
                <span>Mindestgröße in Bytes (optional)</span>
                <input inputMode="numeric" pattern="[0-9]*" value={minGroesse} onChange={(e) => setMinGroesse(e.target.value)} />
              </label>
            )}
          </>
        )}
        <details className="formular-voll erweitert">
          <summary>Erweitert</summary>
          <div className="formular-zeile">
            {c && props.geraete.length > 1 && (
              <label className="feld">
                <span>Gehört zu Gerät</span>
                <select value={geraetId} onChange={(e) => setGeraetId(e.target.value)}>
                  {props.geraete.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {!amAgent && typ !== "snmp_oid" && (
              <label className="feld">
                <span>Zeitlimit in Sekunden</span>
                <input
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={timeout}
                  placeholder="Standard"
                  onChange={(e) => setTimeoutS(e.target.value)}
                />
              </label>
            )}
            {(typ === "http" || typ === "tls" || typ === "http_json" || (typ === "tcp_banner" && tlsAn)) && (
              <label className="feld feld-breit">
                <span>Eigene Root-CA (PEM, optional)</span>
                <textarea rows={3} value={ca} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => setCa(e.target.value)} />
              </label>
            )}
          </div>
        </details>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={sendet}>
            {c ? "Speichern" : "Anlegen"}
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig()}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

// Hinweis für Sensoren auf dem Agent: Was ist auf dem Rechner freigegeben?
export function AgentHinweis(props: { typ: AgentArt; hatAgent: boolean; freigabe: Messwerte["sensoren"] | null }) {
  if (!props.hatAgent) {
    return <p className="meldung meldung-warnung formular-voll">Sensoren auf dem Agent brauchen ein Gerät mit Agent.</p>;
  }
  const f = props.freigabe;
  const frei = f?.arten.includes(props.typ);
  const befehl = `openwacht-agent sensoren -arten ${props.typ}${
    props.typ === "datei"
      ? " -ordner <Ordner>"
      : props.typ === "docker"
        ? " -docker http://127.0.0.1:<Port>"
        : props.typ === "leistungsindikator"
          ? ' -indikatoren "<Objekt>,<Objekt>"'
          : ""
  }`;
  return (
    <div className={`formular-voll ${frei ? "hinweis" : "meldung meldung-warnung"}`}>
      <p>
        Misst der Agent auf dem Rechner, nur feste Messarten mit Parametern, keine Skripte. Gemessen wird nur, was dort lokal freigegeben
        ist.
      </p>
      {frei ? (
        <p className="klein">
          Freigegeben: {f!.arten.map((a) => typText[a]).join(", ")}
          {f!.ordner?.length ? `; Ordner ${f!.ordner.join(", ")}` : ""}
          {f!.docker ? `; Docker über ${f!.docker}` : ""}
          {f!.indikatoren?.length ? `; Leistungsindikatoren aus ${f!.indikatoren.join(", ")}` : ""}
        </p>
      ) : (
        <p className="klein">
          Auf diesem Rechner noch nicht freigegeben. Als root bzw. Administrator ausführen: <code>{befehl}</code>
        </p>
      )}
      {props.typ === "leistungsindikator" && (
        <p className="klein">
          Nur Windows-Agent. Gelesen wird nur aus den Objekten, die mit <code>-indikatoren</code> freigegeben sind. Meldet der Sensor „kein
          Zugriff“, das Dienstkonto <code>NT SERVICE\openwacht-agent</code> in die Gruppe „Leistungsüberwachungsbenutzer“ aufnehmen.
        </p>
      )}
      {props.typ === "autodienste" && (
        <p className="klein">
          Nur Windows-Agent. Fehler, sobald ein Dienst mit Starttyp „Automatisch“ steht. Dienste mit Auslöser (Starttyp „Automatisch
          (Start durch Auslöser)“) zählen nicht, verzögert startende erst 15 Minuten nach dem Systemstart. Gemeldet werden nur die Namen
          der gestoppten Dienste.
        </p>
      )}
      {props.typ === "hyperv" && (
        <p className="klein">
          Nur Windows-Agent. Der Agent liest Name und Zustand der VMs aus WMI (<code>root\virtualization\v2</code>). Das Dienstkonto{" "}
          <code>NT SERVICE\openwacht-agent</code> braucht dort Leserechte („Konto aktivieren“ in wmimgmt.msc). Reicht das nicht, die Gruppe
          „Hyper-V-Administratoren“; sie erlaubt dem Dienstkonto aber auch, VMs zu steuern.
        </p>
      )}
    </div>
  );
}
