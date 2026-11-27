// SPDX-License-Identifier: AGPL-3.0-only

// Navigation über die Adresse im Browser, ohne Router-Bibliothek.
//
// Jede Seite der Seitenleiste hat einen eigenen Pfad; Mandant und „mit
// Untermandanten“ stehen in der Abfrage. So funktionieren Zurück-Taste,
// Lesezeichen und Neuladen. Die Zentrale liefert für jeden Pfad ohne
// Dateiendung index.html.
//
// Alte Pfade aus der Zeit der Reiter (bis Etappe 16) gelten weiter: lesen()
// ordnet sie der neuen Seite zu, useOrt() schreibt die Adresse dann ohne
// neuen Eintrag im Verlauf auf den neuen Pfad um.
//
// Die Werte aus der Adresse sind Eingaben wie jede andere: Der Mandant wird
// nur übernommen, wenn er in der Liste der sichtbaren Mandanten steht, und
// die API prüft ohnehin jede Anfrage selbst.

import { useCallback, useEffect, useState } from "react";
import { mitBasis, ohneBasis } from "./basis";

export type Reiter =
  "dashboard" | "hosts" | "topologie" | "zertifikate" | "alarme" | "berichte" | "vorlagen" | "snmpprofile" | "anzeigen" | "wartung" | "verwaltung" | "einstellungen";
export type VerwaltungsReiter = "mandanten" | "benutzer" | "tokens" | "updates" | "api" | "anmeldung";
export type AlarmReiter = "aktiv" | "protokoll" | "kanaele";
export type GeraetReiter = "uebersicht" | "sensoren";

export interface Ort {
  reiter: Reiter;
  unter: VerwaltungsReiter;
  alarm: AlarmReiter;
  mandant: string;
  // auch Untermandanten zeigen (Standard: ja)
  mitUnter: boolean;
  // gewähltes Gerät auf der Seite Hosts
  geraet: string;
  geraetReiter: GeraetReiter;
}

export const seitenPfad: Record<Reiter, string> = {
  dashboard: "/",
  hosts: "/hosts",
  topologie: "/topologie",
  zertifikate: "/zertifikate",
  alarme: "/alarme",
  berichte: "/berichte",
  vorlagen: "/sensor-vorlagen",
  snmpprofile: "/snmp-profile",
  anzeigen: "/wandanzeigen",
  wartung: "/wartung",
  verwaltung: "/verwaltung",
  einstellungen: "/einstellungen",
};

export const seitenTitel: Record<Reiter, string> = {
  dashboard: "Dashboard",
  hosts: "Hosts",
  topologie: "Topologie",
  zertifikate: "Zertifikate",
  alarme: "Alarme",
  berichte: "Berichte",
  vorlagen: "Sensor-Vorlagen",
  snmpprofile: "SNMP-Profile",
  anzeigen: "Wandanzeigen",
  wartung: "Wartung",
  verwaltung: "Benutzer und Mandanten",
  einstellungen: "Einstellungen",
};

// Gruppen der Seitenleiste (Entwurf B). „bald“ markiert Punkte, die erst mit
// einer späteren Etappe eine Funktion bekommen; ohne Seite sind sie kein Link.
export interface NavPunkt {
  id: Reiter;
  // nur für den Betreiber sichtbar
  betreiber?: boolean;
  text: string;
  bald?: string;
}
export const navGruppen: { titel: string; punkte: NavPunkt[] }[] = [
  {
    titel: "Überwachen",
    punkte: [
      { id: "dashboard", text: "Dashboard" },
      { id: "hosts", text: "Hosts" },
      { id: "topologie", text: "Topologie" },
      { id: "zertifikate", text: "Zertifikate" },
      { id: "alarme", text: "Alarme" },
      { id: "berichte", text: "Berichte" },
    ],
  },
  {
    titel: "Einrichten",
    punkte: [
      { id: "vorlagen", text: "Sensor-Vorlagen" },
      { id: "snmpprofile", text: "SNMP-Profile" },
      { id: "anzeigen", text: "Wandanzeigen" },
      { id: "wartung", text: "Wartung" },
    ],
  },
  {
    titel: "Verwaltung",
    punkte: [
      { id: "verwaltung", text: "Benutzer und Mandanten" },
      { id: "einstellungen", text: "Einstellungen", betreiber: true },
    ],
  },
];

export const verwaltungsListe: { id: VerwaltungsReiter; text: string }[] = [
  { id: "mandanten", text: "Mandanten" },
  { id: "benutzer", text: "Benutzer" },
  { id: "tokens", text: "Agent-Tokens" },
  { id: "updates", text: "Agent-Updates" },
  { id: "api", text: "API-Tokens" },
  { id: "anmeldung", text: "Anmeldung (AD, SSO)" },
];

export const alarmListe: { id: AlarmReiter; text: string }[] = [
  { id: "aktiv", text: "Aktiv" },
  { id: "protokoll", text: "Protokoll" },
  { id: "kanaele", text: "Kanäle" },
];

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function lesen(loc: { pathname: string; search: string }): Ort {
  const teile = ohneBasis(loc.pathname).split("/").filter(Boolean);
  const erstes = teile[0] ?? "";
  let reiter: Reiter = "dashboard";
  let unter: VerwaltungsReiter = "mandanten";
  let alarm: AlarmReiter = "aktiv";
  // Den Reiter Checks gibt es seit Etappe 8 nicht mehr; Checks stehen bei ihrem Gerät.
  if (erstes === "hosts" || erstes === "checks") reiter = "hosts";
  else if (erstes === "topologie") reiter = "topologie";
  else if (erstes === "zertifikate") reiter = "zertifikate";
  else if (erstes === "alarme") {
    reiter = "alarme";
    alarm = alarmListe.find((x) => x.id === teile[1])?.id ?? "aktiv";
  } else if (erstes === "alarmierung") {
    // bis Etappe 16: Reiter „Alarmierung“ mit den Alarmkanälen
    reiter = "alarme";
    alarm = "kanaele";
  } else if (erstes === "sensor-vorlagen") reiter = "vorlagen";
  else if (erstes === "snmp-profile") reiter = "snmpprofile";
  else if (erstes === "wandanzeigen") reiter = "anzeigen";
  else if (erstes === "wartung") reiter = "wartung";
  else if (erstes === "berichte") reiter = "berichte";
  else if (erstes === "einstellungen") reiter = "einstellungen";
  else if (erstes === "verwaltung") {
    // bis Etappe 16: Wandanzeigen unter Verwaltung
    if (teile[1] === "anzeigen") reiter = "anzeigen";
    else {
      reiter = "verwaltung";
      unter = verwaltungsListe.find((x) => x.id === teile[1])?.id ?? "mandanten";
    }
  }
  const q = new URLSearchParams(loc.search);
  const m = (q.get("mandant") ?? "").toLowerCase();
  const g = (q.get("geraet") ?? "").toLowerCase();
  const geraet = reiter === "hosts" && uuid.test(g) ? g : "";
  return {
    reiter,
    unter,
    alarm,
    mandant: uuid.test(m) ? m : "",
    mitUnter: q.get("unter") !== "nein",
    geraet,
    geraetReiter: geraet && q.get("ansicht") === "sensoren" ? "sensoren" : "uebersicht",
  };
}

export function adresse(o: Ort): string {
  let pfad = seitenPfad[o.reiter];
  if (o.reiter === "verwaltung" && o.unter !== "mandanten") pfad += "/" + o.unter;
  if (o.reiter === "alarme" && o.alarm !== "aktiv") pfad += "/" + o.alarm;
  const q = new URLSearchParams();
  if (o.mandant) q.set("mandant", o.mandant);
  if (!o.mitUnter) q.set("unter", "nein");
  if (o.reiter === "hosts" && o.geraet) {
    q.set("geraet", o.geraet);
    if (o.geraetReiter !== "uebersicht") q.set("ansicht", o.geraetReiter);
  }
  const s = q.toString();
  return s ? `${pfad}?${s}` : pfad;
}

function hier() {
  return window.location.pathname + window.location.search;
}

// useOrt liefert den aktuellen Ort und eine Funktion zum Wechseln. Mit
// ersetzen=true entsteht kein neuer Eintrag im Verlauf (z. B. beim
// Korrigieren eines ungültigen Mandanten).
export function useOrt() {
  const [ort, setOrt] = useState<Ort>(() => lesen(window.location));

  // Alte oder unvollständige Adressen auf die heutige Form bringen.
  useEffect(() => {
    const ziel = mitBasis(adresse(lesen(window.location)));
    if (ziel !== hier()) window.history.replaceState(null, "", ziel + window.location.hash);
  }, []);

  useEffect(() => {
    const zurueck = () => setOrt(lesen(window.location));
    window.addEventListener("popstate", zurueck);
    return () => window.removeEventListener("popstate", zurueck);
  }, []);

  const gehe = useCallback((aenderung: Partial<Ort>, ersetzen = false) => {
    const alt = lesen(window.location);
    const neu = { ...alt, ...aenderung };
    // Eine andere Seite oder ein anderer Mandant wählt kein Gerät mehr, außer es ist ausdrücklich genannt.
    // Ein Link ohne Mandant (alt.mandant leer) behält sein Gerät, wenn der Mandant nachgetragen wird.
    if (!("geraet" in aenderung) && (neu.reiter !== alt.reiter || (alt.mandant !== "" && neu.mandant !== alt.mandant))) neu.geraet = "";
    if (!("geraetReiter" in aenderung) && neu.geraet !== alt.geraet) neu.geraetReiter = "uebersicht";
    if (!neu.geraet) neu.geraetReiter = "uebersicht";
    const ziel = mitBasis(adresse(neu));
    if (ziel !== hier()) {
      if (ersetzen) window.history.replaceState(null, "", ziel);
      else window.history.pushState(null, "", ziel);
    }
    setOrt(neu);
  }, []);

  return { ort, gehe };
}
