// SPDX-License-Identifier: AGPL-3.0-only

// Zugriff auf die API der Zentrale.
//
// Sicherheit: Die Sitzung steckt in einem HttpOnly-Cookie, an das dieses
// Skript nicht herankommt. Das CSRF-Token liegt nur im Arbeitsspeicher und wird
// nach einem Neuladen über /api/v1/ich neu geholt; es landet nie im
// localStorage.

import type { Kennfarbe } from "./kennfarbe";
export type { Kennfarbe };

let csrfToken = "";

export function setCsrf(token: string | undefined) {
  csrfToken = token ?? "";
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown, extra?: { raw: Blob | FormData; headers: Record<string, string> }): Promise<T> {
  const headers: Record<string, string> = { ...(extra?.headers ?? {}) };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: extra ? extra.raw : body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Die Zentrale ist nicht erreichbar. Netzwerk prüfen und erneut versuchen.");
  }
  if (res.status === 204) return undefined as T;
  let data: Record<string, unknown> = {};
  try {
    data = await res.json();
  } catch {
    // Antwort ohne JSON: Meldung unten
  }
  if (!res.ok) {
    const msg = typeof data.fehler === "string" ? data.fehler : `Unerwartete Antwort der Zentrale (${res.status}).`;
    throw new ApiError(res.status, msg, data);
  }
  return data as T;
}

// --- Typen der API --------------------------------------------------------

export type Rolle = "admin" | "operator" | "leser";

export interface Ich {
  id: string;
  email: string;
  anzeigename: string;
  rollen: { mandant_id: string; mandant: string; rolle: Rolle }[];
  zwei_faktor_aktiv: boolean;
  zwei_faktor_einrichten: boolean;
  // Betreiber der Installation (Seite Einstellungen, Etappe 19)
  betreiber: boolean;
  // Alarm-Mails an sich selbst (Etappe 20)
  alarm_mails: boolean;
  // Hinweise am Rand und Ton (1.0.2); fehlt bei älteren Zentralen
  hinweise_ton?: HinweiseTon;
  // Herkunft des Kontos (Etappe 22a): lokal oder aus dem AD
  quelle: "lokal" | "ldap" | "oidc";
  // noch offene Wiederherstellungscodes (Etappe 30)
  wiederherstellungscodes_offen: number;
  csrf: string;
  version: string;
  commit: string;
}

// Ton bei neuen Ereignissen (1.0.2). Die Klänge erzeugt der Browser.
export type TonStufe = "aus" | "krit" | "warn";
export type Klang = "bling" | "gong" | "doppel";
export interface TonEinstellung {
  ton: TonStufe;
  klang: Klang;
  lautstaerke: number; // 0 … 100
  entwarnung: boolean;
}
export interface HinweiseTon extends TonEinstellung {
  hinweise: boolean;
}

export interface Mandant {
  id: string;
  uebergeordnet_id: string | null;
  name: string;
  rolle: Rolle | "";
}

export interface Benutzer {
  id: string;
  mandant_id: string;
  email: string;
  anzeigename: string;
  deaktiviert: boolean;
  // gesperrt: Tag der automatischen Löschung (1.0.6)
  loescht_am?: string;
  zwei_faktor_aktiv: boolean;
  // aus dem AD (Etappe 22a)
  verzeichnis: boolean;
  rollen: { mandant_id: string; rolle: Rolle }[];
}

export const rollenName: Record<Rolle, string> = {
  admin: "Admin",
  operator: "Operator",
  leser: "Leser",
};

export interface Messwerte {
  erfasst: string;
  hostname: string;
  os: string;
  kernel: string;
  arch: string;
  agent: string;
  laufzeit_s: number;
  cpu: { kerne: number; auslastung_prozent: number; last1: number; last5: number; last15: number; ohne_last?: boolean };
  speicher: { gesamt: number; verfuegbar: number; swap_gesamt: number; swap_frei: number };
  platten: { einhaengepunkt: string; dateisystem: string; gesamt: number; frei: number }[] | null;
  // lokale Freigabe für Sensoren auf dem Agent (Etappe 18)
  sensoren?: { arten: AgentArt[]; ordner?: string[]; docker?: string; indikatoren?: string[] };
}

export interface Agent {
  id: string;
  mandant_id: string;
  geraet_id: string;
  hostname: string;
  // Adresse, von der sich der Agent zuletzt gemeldet hat
  adresse: string | null;
  registriert: string;
  zuletzt_gesehen: string | null;
  gesperrt: string | null;
  zertifikat_bis: string;
  messwerte: Messwerte | null;
  wartung: Wartung | null;
}

export interface AgentToken {
  id: string;
  notiz: string;
  restanzahl: number;
  laeuft_ab: string;
  erstellt: string;
}

export type AgentArt = "dienst" | "prozess" | "datei" | "docker" | "hyperv" | "leistungsindikator" | "autodienste";
export type CheckTyp = "ping" | "tcp" | "http" | "tls" | "dns" | "http_json" | "tcp_banner" | "ntp" | "snmp_oid" | AgentArt;
export type CheckStatus = "ok" | "warn" | "crit" | "unknown";

export interface CheckZiel {
  host?: string;
  port?: number;
  url?: string;
  erwarte_status?: number[];
  enthaelt?: string;
  verbinde?: string;
  warnung_tage?: number;
  kritisch_tage?: number;
  timeout_s?: number;
  ca_pem?: string;
  // Ping (Etappe 18)
  anzahl?: number;
  verlust_warnung?: number;
  verlust_kritisch?: number;
  antwort_warnung_ms?: number;
  antwort_kritisch_ms?: number;
  // DNS; Dienst und Prozess: name
  name?: string;
  server?: string;
  eintrag?: "A" | "AAAA";
  erwartet?: string[];
  // HTTP-JSON
  json_pfad?: string;
  warnung_ueber?: number;
  kritisch_ueber?: number;
  warnung_unter?: number;
  kritisch_unter?: number;
  gleich?: string;
  // Prozess
  mindestens?: number;
  hoechstens?: number;
  // Datei
  pfad?: string;
  ordner?: boolean;
  warnung_stunden?: number;
  kritisch_stunden?: number;
  mindestgroesse?: number;
  // Etappe 18b: TCP-Banner, NTP, SNMP-OID
  tls?: boolean;
  abweichung_warnung_ms?: number;
  abweichung_kritisch_ms?: number;
  oid?: string;
  rate?: boolean;
  // 0.44.0: Windows-Leistungsindikator
  objekt?: string;
  indikator?: string;
  instanz?: string;
  // 0.47.0: bei snmp_oid auch Zusammenfassung einer Tabellenspalte
  zusammenfassung?: "summe" | "minimum" | "maximum" | "anzahl" | "anzahl_gleich" | "anzahl_ungleich";
  bezug?: string;
  vergleichswert?: number;
  // 1.0.8, snmp_oid: Zahl aus einem Text des Geräts, Faktor und Einheit
  zahl_aus_text?: "erste" | "nte" | "nach";
  zahl_nr?: number;
  zahl_nach?: string;
  faktor?: number;
  einheit?: string;
  // 1.0.10, snmp_oid: den Text des Geräts selbst als Messwert anzeigen
  text_zeigen?: boolean;
  // 1.0.5: automatische Windows-Dienste, die nicht zählen
  ausnahmen?: string[];
}

// Vorlagensatz (0.44.0): mehrere eingebaute Vorlagen für eine Anwendung
export interface VorlagenSatz {
  id: string;
  name: string;
  notiz: string;
  sensoren: Vorlage[];
  // nur eigene Sätze (0.46.0)
  mandant_id?: string;
  geaendert?: string;
}

// Sensor-Vorlage (Etappe 18); mandant_id null = eingebaut
export interface Vorlage {
  id: string;
  mandant_id: string | null;
  name: string;
  typ: CheckTyp;
  ziel: CheckZiel;
  intervall_sekunden: number;
  notiz: string;
  am_agent: boolean;
  braucht_adresse: boolean;
  geaendert?: string;
  kennfarbe_id?: string; // 1.0.1: nur in eigenen Vorlagensätzen
  fehlversuche?: number | null; // 1.0.6: null = Standard der Zentrale
}

export interface Check {
  id: string;
  mandant_id: string;
  geraet_id: string;
  name: string;
  typ: CheckTyp;
  ziel: CheckZiel;
  intervall_sekunden: number;
  aktiv: boolean;
  status: CheckStatus | null;
  meldung: string | null;
  messwert: string | null;
  seit: string | null;
  zuletzt: string | null;
  fehler_in_folge: number;
  naechste: string;
  wartung: Wartung | null;
  // Etappe 18: Name der Vorlage (null = eigener Sensor), misst der Agent, ohne frisches Ergebnis
  herkunft: string | null;
  am_agent: boolean;
  veraltet: boolean;
  // 1.0.6: eigene Fehlversuche bis zum Alarm (null = Standard) und die geltende Zahl
  fehlversuche: number | null;
  fehlversuche_gilt: number;
}

// Was die Zentrale meldet (Schalter der Zentrale). Schwellen 0 = aus.
export interface Alarmregeln {
  check_fehlschlaege: number;
  erinnerung_h: number;
  stumm_nach_s: number;
  platte_warn: number;
  platte_krit: number;
  speicher_warn: number;
  speicher_krit: number;
  cpu_warn: number;
  cpu_krit: number;
}

// Laufende Wartung eines Geräts oder Checks: keine neuen Alarme, keine Erinnerungen.
export interface Wartung {
  seit: string;
  bis: string;
  grund: string;
  von: string | null;
  // gehört zum Gerät, nicht zum Check bzw. Agent selbst
  ueber_geraet: boolean;
}

// Ein Gerät (Host): mit Agent, mit Checks oder beidem.
// Gruppe im Baum eines Mandanten (bis 4 Ebenen, Reihenfolge von Hand)
export interface Gruppe {
  id: string;
  mandant_id: string;
  eltern_id: string | null;
  name: string;
  position: number;
}

export interface Geraet {
  id: string;
  mandant_id: string;
  name: string;
  // nur Vorschlag für neue Checks; die Zentrale verbindet sich nicht damit
  adresse: string | null;
  // Gruppe im Gruppenbaum des Mandanten (Etappe 13)
  gruppe_id: string | null;
  erstellt: string;
  agent_id: string | null;
  checks: number;
  // SNMP-Quelle des Geräts, falls eingerichtet
  snmp_id: string | null;
  wartung: Wartung | null;
  // gehört wohl zu diesem Gerät mit Agent (nie automatisch verknüpft)
  vorschlaege: { geraet_id: string; name: string; grund: "name" | "adresse" }[];
  // Etappe 24: Elterngerät und ggf. das ausgefallene Gerät darüber
  abhaengig_von: string | null;
  nicht_erreichbar_wegen: string | null;
}

export type KanalArt = "ntfy" | "mail" | "webhook" | "teams" | "sms";

export interface Alarmkanal {
  id: string;
  mandant_id: string;
  name: string;
  typ: KanalArt;
  // ntfy-Server bzw. Ursprung (https://host) eines Webhooks
  server: string;
  topic: string;
  token_gesetzt: boolean;
  auch_untermandanten: boolean;
  aktiv: boolean;
  alle_benutzer: boolean;
  // mobilnummer: Der Empfänger hat eine Mobilnummer für Alarme hinterlegt (nur SMS)
  empfaenger: { id: string; name: string; abbestellt: boolean; mobilnummer: boolean }[];
  zuletzt_ok: string | null;
  letzter_fehler: string | null;
  letzter_fehler_am: string | null;
  // Etappe 24
  bereitschaft: Bereitschaft | null;
  eskalation: { nach_minuten: number; kanal: string } | null;
  // Etappe 25: Monatsbericht als PDF an die Empfänger (nur Mail)
  monatsbericht: boolean;
  sammeln: boolean; // 1.0.1: Mail und SMS sammeln eine Minute
  // 0.43.0: SMS über ein brevis.one-Gateway (server = https://Gateway)
  sms_benutzer?: string;
  fingerabdruck?: string;
  empfaenger_art?: "benutzer" | "gruppe";
  gruppe?: string;
  anrufen: boolean;
  ueberwachen: boolean;
}

export interface Bereitschaft {
  tage: number[];
  von: string;
  bis: string;
}

export type SensorStatus = CheckStatus | "pause" | "neu";

// Kennfarbe in der Verwaltung, mit Zahl der sichtbaren Zuordnungen
export interface KennfarbeEintrag extends Kennfarbe {
  mandant_id: string;
  verwendet: number;
}

export interface Alarm {
  id: string;
  mandant_id: string;
  check_id: string | null;
  agent_id: string | null;
  snmp_id: string | null;
  gegenstand: string;
  name: string;
  status: Exclude<CheckStatus, "ok">;
  schlimmster: Exclude<CheckStatus, "ok">;
  meldung: string;
  beginn: string;
  geaendert: string;
  ende: string | null;
  bestaetigt_am: string | null;
  bestaetigt_von: string | null;
  kommentar: string | null;
  kennfarbe?: Kennfarbe;
}

export interface Sensor {
  schluessel: string;
  art: "check" | "host" | "snmp";
  quelle_id: string;
  mandant_id: string;
  geraet_id: string;
  // Name des Geräts
  host?: string;
  name: string;
  gegenstand: string;
  status: SensorStatus;
  meldung: string;
  // zuletzt gelesener Wert eines Checks („1500 RPM“, „12 ms“), falls es einen gibt
  messwert?: string;
  seit: string | null;
  alarm: Alarm | null;
  wartung: Wartung | null;
  // Kennfarbe (0.99.2); gilt nur bei Warnung, Kritisch und Bestätigt
  kennfarbe?: Kennfarbe;
  // ausgenommen (0.99.2): Begründung; Status ist dann „pause“
  ausgenommen?: string;
}

// --- SNMP ---------------------------------------------------------------------------

export interface SnmpSchnittstelle {
  index: number;
  name: string;
  alias?: string;
  typ: number;
  geschwindigkeit_bps: number;
  admin_an: boolean;
  status: "up" | "down" | "testing" | "unknown" | "dormant" | "notPresent" | "lowerLayerDown";
  hc: boolean;
  ein_bps: number | null;
  aus_bps: number | null;
  fehler_neu: number | null;
  // 1.0.11: Sekunden seit dem letzten Wechsel des Zustands, falls das Gerät es meldet
  seit_s?: number;
}

// PoE-Port (1.0.10): Zeile aus pethPsePortTable; status 1 aus, 2 sucht, 3 liefert Strom, 4/6 Fehler, 5 Test
export interface SnmpPoePort {
  gruppe: number;
  port: number;
  status: number;
}

// LLDP-Nachbar (1.0.11) an der Schnittstelle mit diesem ifIndex: Name und Port des Nachbarn
export interface SnmpLldpNachbar {
  index: number;
  name?: string;
  port?: string;
}

export interface SnmpMesswerte {
  erfasst: string;
  system: { beschreibung: string; name: string; standort: string; objekt_id: string; laufzeit_s: number };
  cpu?: { kerne: number; auslastung_prozent: number };
  speicher?: { gesamt: number; verfuegbar: number };
  platten: { einhaengepunkt: string; gesamt: number; frei: number }[];
  schnittstellen: SnmpSchnittstelle[];
  poe?: SnmpPoePort[];
  lldp?: SnmpLldpNachbar[];
  synology?: {
    modell: string;
    version: string;
    system: number;
    netzteil: number;
    luefter_system: number;
    luefter_cpu: number;
    temperatur: number | null;
    laufwerke: { name: string; modell: string; status: number; gesundheit: number; temperatur: number | null; rolle?: string }[];
    raids: { name: string; status: number; frei: number; gesamt: number }[];
    update: number;
  };
  usv?: {
    quelle: string;
    modell?: string;
    status: string;
    batteriebetrieb: boolean;
    batterie_schwach: boolean;
    batterie_tauschen: boolean;
    ladung_prozent: number | null;
    restlaufzeit_s: number | null;
    last_prozent: number | null;
  };
  verbrauchsmaterial: { name: string; stand: number; maximum: number; prozent: number | null }[];
  gekuerzt?: string[];
  teilweise?: string[];
  proxmox?: ProxmoxMesswerte;
  fritzbox?: FritzBoxMesswerte;
  ontap?: NetAppMesswerte;
  xapi?: XenServerMesswerte;
  citrix?: CitrixMesswerte;
}

// --- Citrix (Abfragequelle mit version „citrix“, 1.0.6) ------------------------------

export interface CitrixMesswerte {
  fingerabdruck?: string;
  vdas: number;
  registriert: number;
  wartung: number;
  nicht_registriert: number;
  nicht_registriert_namen?: string[];
  fehler_minuten: number;
  fehler?: { code: number; anzahl: number }[];
  fehler_gesamt: number;
}

export interface CitrixInfo {
  vdas: number;
  nicht_registriert: number;
  fehler_gesamt: number;
  fehler_nicht_lesbar?: string;
  fingerabdruck: string;
}

// --- XenServer/XCP-ng (Abfragequelle mit version „xapi“, 0.42.0) --------------------

export interface XenServerMesswerte {
  pool: string;
  produkt: string;
  fingerabdruck?: string;
  master: string;
  ha: { an: boolean; tolerieren: number; plan_fuer: number; ueberbucht: boolean };
  hosts: {
    name: string;
    master: boolean;
    erreichbar: boolean;
    aktiviert: boolean;
    wartung: boolean;
    laufzeit_s: number;
    cpu_prozent?: number;
    ram_gesamt: number;
    ram_frei: number;
    updates?: string;
    ausstehend?: string[];
    messwerte_fehler?: string;
  }[];
  vms: { uuid: string; name: string; zustand: string; host?: string; soll_laufen: boolean; vcpus: number; cpu_prozent?: number; ram: number }[];
  vm_anzahl: { laufend: number; aus: number; angehalten: number; ausgesetzt: number };
  speicher: { name: string; typ: string; geteilt: boolean; gesamt: number; belegt: number; nicht_angebunden?: string[] }[];
}

export interface XenServerInfo {
  pool: string;
  produkt: string;
  master: string;
  hosts: number;
  vms: number;
  speicher: number;
  ha: boolean;
  hosts_mit_messwerten: number;
  fingerabdruck: string;
}

// --- NetApp ONTAP (Abfragequelle mit version „ontap“, 0.41.0) ------------------------

export interface NetAppMesswerte {
  cluster: string;
  version: string;
  fingerabdruck?: string;
  knoten: {
    name: string;
    zustand: string;
    modell?: string;
    laufzeit_s: number;
    ha: boolean;
    partner?: string;
    uebernahme?: string;
    rueckgabe?: string;
    uebertemperatur: boolean;
    luefter_ausgefallen: number;
    netzteile_ausgefallen: number;
  }[];
  aggregate: { name: string; knoten?: string; zustand: string; gesamt: number; belegt: number; iops?: number; latenz_ms?: number }[];
  volumes: { name: string; zustand: string; typ: string; gesamt: number; belegt: number }[];
  platten: { gesamt: number; ersatz: number; auffaellig: { name: string; zustand: string; behaelter: string; modell?: string }[] };
  shelves: {
    id: string;
    modell?: string;
    zustand: string;
    teile: { art: string; id: string; zustand: string }[];
    temperaturen: { id: string; grad?: number; warnung_ab?: number; kritisch_ab?: number; zustand: string }[];
  }[];
  snapmirror: { quelle: string; ziel: string; zustand: string; gesund: boolean; verzoegerung_s?: number; grund?: string }[];
  ems: { zeit: string; name: string; schwere: string; knoten?: string; meldung: string }[];
}

export interface NetAppInfo {
  cluster: string;
  version: string;
  knoten: number;
  aggregate: number;
  volumes: number;
  platten: number;
  shelves: number;
  snapmirror: number;
  fingerabdruck: string;
}

// --- FRITZ!Box (Abfragequelle mit version „tr064“, Etappe 18c) ------------------------

export interface FritzBoxMesswerte {
  modell: string;
  fritzos: string;
  zugang?: string;
  verbindung?: string;
  verbunden: boolean;
  letzter_fehler?: string;
  verbunden_seit_s?: number;
  externe_ip?: string;
  leitung_auf_bps?: number;
  leitung_ab_bps?: number;
  leitung?: string;
  dsl?: { status: string; auf_bps: number; ab_bps: number; auf_max_bps: number; ab_max_bps: number };
  nicht_verfuegbar?: string[];
  nicht_verfuegbar_grund?: string[];
  tls: boolean;
  fingerabdruck?: string;
}

export interface FritzBoxInfo {
  modell: string;
  fritzos: string;
  laufzeit_s: number;
  zugang: string;
  verbunden: boolean;
  nicht_verfuegbar: string[];
  nicht_verfuegbar_grund?: string[];
  fingerabdruck?: string;
}

// --- Proxmox (Abfragequelle mit version „pve“) ----------------------------------------

export interface ProxmoxGast {
  vmid: number;
  typ: "qemu" | "lxc" | "esxi" | "vm";
  name: string;
  status: string;
  vorlage?: boolean;
  beim_booten?: boolean;
  laufzeit_s: number;
  im_backup_job?: boolean;
  backup_ok?: string;
  backup_versucht?: string;
  backup_fehler?: string;
}

export interface ProxmoxMesswerte {
  knoten: string;
  version: string;
  gaeste: ProxmoxGast[];
  speicherorte: { name: string; typ: string; aktiv: boolean; eingeschaltet: boolean; geteilt: boolean; gesamt: number; belegt: number }[];
  thin_pools: { name: string; gesamt: number; belegt: number; metadaten_gesamt: number; metadaten_belegt: number }[];
  backup_jobs_bekannt: boolean;
  aufgaben_bis: string;
  zu_viele_rechte?: string[];
}

export interface ProxmoxInfo {
  knoten: string;
  version: string;
  laufzeit_s: number;
  zu_viele_rechte: string[];
}

export interface Snmp {
  id: string;
  mandant_id: string;
  geraet_id: string;
  version: "1" | "2c" | "3" | "pve" | "tr064" | "vcenter" | "ontap" | "xapi" | "citrix";
  adresse: string;
  port: number;
  // SNMP: Community bzw. v3-Zugangsdaten gespeichert; Proxmox: API-Token gespeichert
  hat_community: boolean;
  // nur v3: Verfahren (z. B. "sha256", "aes")
  v3_auth: string | null;
  v3_priv: string | null;
  // Traps von diesem Gerät annehmen
  traps: boolean;
  intervall_sekunden: number;
  aktiv: boolean;
  ueberwacht: string[];
  erstellt: string;
  geaendert: string;
  naechste: string;
  zuletzt_versucht: string | null;
  zuletzt_ok: string | null;
  fehler: string | null;
  messwerte: SnmpMesswerte | null;
  neustart_am: string | null;
  wartung: Wartung | null;
  // nur Proxmox: hinterlegte CA (null = System-CAs)
  ca: { fingerabdruck: string; name: string; gueltig_bis: string } | null;
  // Agent, der das Gerät als Sammler abfragt; null = die Zentrale
  sammler: string | null;
  sammler_name: string | null;
  // Zugangsprofil (Etappe 27); der Name nur für Admins des Profilmandanten
  profil_id: string | null;
  profil_name: string | null;
}

// SNMP-Zugangsprofil (Etappe 27): Version und Zugangsdaten je Mandant. Die
// Zugangsdaten selbst gibt die Zentrale nie heraus.
export interface SnmpProfil {
  id: string;
  mandant_id: string;
  name: string;
  version: "1" | "2c" | "3";
  v3_auth: string | null;
  v3_priv: string | null;
  geraete: number;
  erstellt: string;
  geaendert: string;
}

// Ein Agent, der auf seinem Rechner als Sammler freigegeben ist.
export interface Sammler {
  id: string;
  mandant_id: string;
  geraet_id: string;
  // Name des Geräts und Hostname, den der Agent meldet
  name: string;
  hostname: string;
  netze: string[];
  geraete: number;
  abgeholt_am: string | null;
}

export interface SnmpSystem {
  beschreibung: string;
  name: string;
  standort: string;
  objekt_id: string;
  laufzeit_s: number;
}

// --- Wandanzeige ------------------------------------------------------------

export interface Anzeige {
  id: string;
  mandant_id: string;
  name: string;
  mit_untermandanten: boolean;
  netz: string | null;
  erstellt: string;
  zuletzt_da: string | null;
  // Ton der Anzeige (1.0.2)
  ton?: TonEinstellung;
}

export type AnzeigeStatus = "ok" | "warn" | "crit" | "quittiert" | "unknown" | "wartung";

export interface AnzeigeKnoten {
  name: string;
  art: "mandant" | "gruppe" | "geraet";
  status: AnzeigeStatus;
  // Kennfarbe des schlimmsten Sensors (0.99.2), nur bei Warnung, Kritisch, Bestätigt
  farbe?: string;
  kennfarbe?: string;
  kinder?: AnzeigeKnoten[];
}

export interface AnzeigeKennfarbe {
  name: string;
  farbe: string;
  geraete: number;
}

export interface AnzeigeDaten {
  anzeige: string;
  stand: string;
  baum: AnzeigeKnoten;
  // Legende (0.99.2); fehlt bei älteren Zentralen
  kennfarben?: AnzeigeKennfarbe[];
  // Ton der Anzeige (1.0.2); fehlt in der Vorschau
  ton?: TonEinstellung;
}

// --- Traps (Etappe 14) ---------------------------------------------------------------

export type TrapWirkung = "warn" | "crit" | "ok" | "ignore";
export type TrapVergleich = "gleich" | "nicht" | "enthaelt" | "beginnt";

export interface TrapRegel {
  id: string;
  mandant_id: string;
  position: number;
  name: string;
  aktiv: boolean;
  gruppe_id: string | null;
  geraet_id: string | null;
  trap_oid: string;
  wert_oid: string | null;
  wert_vergleich: TrapVergleich | null;
  wert: string | null;
  wirkung: TrapWirkung;
  schluessel_oid: string | null;
  dauer_minuten: number;
  beendet: string | null;
  erstellt: string;
  kennfarbe_id: string | null;
}

export interface TrapWert {
  oid: string;
  typ: string;
  wert: string;
}

export interface TrapEintrag {
  id: number;
  empfangen: string;
  version: "1" | "2c" | "3";
  inform: boolean;
  bestaetigt: boolean;
  trap_oid: string;
  trap_name: string;
  werte: TrapWert[];
  regel_id: string | null;
  regel_name: string | null;
  ergebnis: TrapWirkung | "none";
  kennfarbe?: Kennfarbe;
}

export interface TrapZustand {
  regel: string;
  name: string;
  instanz: string;
  status: "warn" | "crit";
  meldung: string;
  bestaetigt: boolean;
  seit: string;
  zuletzt: string;
  anzahl: number;
  bis: string | null;
  kennfarbe?: Kennfarbe | null;
}

// meldungMitWert: Meldung eines Sensors, davor der gelesene Wert, wenn es
// einen gibt („1500 RPM · Wert im Rahmen“).
export function meldungMitWert(s: { meldung?: string | null; messwert?: string | null }): string {
  const m = s.meldung ?? "";
  return s.messwert ? (m ? `${s.messwert} · ${m}` : s.messwert) : m;
}
