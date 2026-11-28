// SPDX-License-Identifier: AGPL-3.0-only

// Rückmeldung nach Aktionen (1.0.12): eine kurze Einblendung unten, z. B.
// „Sensor angelegt“ oder „12 Sensoren angelegt“, einheitlich für die ganze
// Oberfläche. Die Texte kommen aus den Schreibaufrufen an die Zentrale (siehe
// regeln) und erscheinen nur direkt nach einer Aktion des Benutzers; was im
// Hintergrund gespeichert wird, meldet nichts. Fehler bleiben bei der
// Fehlermeldung oben.

import { useEffect, useState } from "react";
import { setErfolgsHoerer } from "./api";
import { kurzNachAktion } from "./fuehrung";

type Text = string | ((body: unknown, antwort: unknown) => string | null);

const anzahl = (n: number, eins: string, viele: string) => (n === 1 ? `1 ${eins}` : `${n} ${viele}`);

// Erste passende Regel gewinnt; null = keine Bestätigung.
const regeln: [string, RegExp, Text | null][] = [
  // eigene Anzeige im Formular oder nur technische Zwischenschritte
  ["*", /\/(sitzung|passkeys|zwei-faktor|anzeige\/anmelden|dashboard\/layout|ich\/hinweise-ton|zentrale-update)(\/|$)/, null],
  ["*", /\/(pruefen|test|sms-fingerabdruck|agent-token|agent-tokens|neuer-link|position|reihenfolge)$/, null],
  ["POST", /\/api-tokens$/, null],
  ["POST", /\/mandanten\/[^/]+\/geraete$/, "Gerät angelegt"],
  ["POST", /\/mandanten\/[^/]+\/geraete\/import$/, "Import abgeschlossen"],
  ["PUT", /\/geraete\/[^/]+$/, "Gerät gespeichert"],
  ["DELETE", /\/geraete\/[^/]+$/, "Gerät gelöscht"],
  ["POST", /\/geraete\/gruppe$/, (b) => anzahl(geraeteVon(b), "Gerät einer Gruppe zugeordnet", "Geräte einer Gruppe zugeordnet")],
  ["POST", /\/geraete\/[^/]+\/verschieben$/, "Gerät verschoben"],
  ["POST", /\/geraete\/[^/]+\/zusammenfuehren$/, "Geräte zusammengeführt"],
  ["POST", /\/geraete\/[^/]+\/checks$/, "Sensor angelegt"],
  ["POST", /\/geraete\/[^/]+\/checks\/herkunft-loeschen$/, "Sensoren entfernt"],
  ["PUT", /\/checks\/[^/]+$/, "Sensor gespeichert"],
  ["DELETE", /\/checks\/[^/]+$/, "Sensor gelöscht"],
  ["POST", /\/checks\/[^/]+\/jetzt$/, "Prüfung gestartet"],
  ["POST", /\/snmp\/[^/]+\/jetzt$/, "Abfrage gestartet"],
  ["PUT", /\/(geraete|checks)\/[^/]+\/wartung$/, "Wartung gesetzt"],
  ["DELETE", /\/(geraete|checks)\/[^/]+\/wartung$/, "Wartung beendet"],
  ["POST", /\/sensor-vorlagen\/anwenden$/, (_b, a) => anzahl(zahl(a, "angelegt"), "Sensor angelegt", "Sensoren angelegt")],
  ["POST", /\/sensoren\/ausnehmen$/, (b) => (feld(b, "entfernen") === true ? "Wert entfernt" : "Wert ausgenommen")],
  ["POST", /\/sensoren\/einbeziehen$/, "Wert wird wieder überwacht"],
  ["PUT", /\/geraete\/[^/]+\/(snmp|proxmox|vcenter|netapp|xenserver|citrix|fritzbox)$/, "Abfrage gespeichert"],
  ["DELETE", /\/geraete\/[^/]+\/(snmp|proxmox|vcenter|netapp|xenserver|citrix|fritzbox)$/, "Abfrage entfernt"],
  ["PUT", /\/geraete\/[^/]+\/schwellen$/, "Schwellen gespeichert"],
  ["POST", /\/alarme\/[^/]+\/bestaetigen$/, "Alarm bestätigt"],
  ["POST", /\/agents\/[^/]+\/sperren$/, "Agent gesperrt"],
  ["DELETE", /\/agents\/[^/]+$/, "Agent entfernt"],
  ["PUT", /\/sensoren\/(herkunft-)?kennfarbe$/, "Kennfarbe gesetzt"],
  // allgemein
  ["POST", /\/mandanten\/[^/]+\/[a-z-]+$/, "Angelegt"],
  ["POST", /\/(mandanten|benutzer|trapregeln|wartungsfenster|verzeichnisse|agent-updates)$/, "Angelegt"],
  ["PUT", /./, "Gespeichert"],
  ["DELETE", /./, "Gelöscht"],
];

function feld(x: unknown, k: string): unknown {
  return x && typeof x === "object" ? (x as Record<string, unknown>)[k] : undefined;
}
function zahl(x: unknown, k: string) {
  const v = feld(x, k);
  return typeof v === "number" ? v : 0;
}
function geraeteVon(b: unknown) {
  const v = feld(b, "geraete");
  return Array.isArray(v) ? v.length : 1;
}

export function textFuer(method: string, path: string, body: unknown, antwort: unknown): string | null {
  for (const [m, re, t] of regeln) {
    if ((m === "*" || m === method) && re.test(path)) {
      if (t === null) return null;
      return typeof t === "string" ? t : t(body, antwort);
    }
  }
  return null;
}

type Eintrag = { text: string; mal: number; id: number };
let hoerer: ((e: Eintrag | null) => void) | null = null;
let aktuell: Eintrag | null = null;
let zaehler = 0;
let stummTiefe = 0;
let timer: ReturnType<typeof setTimeout> | undefined;

// bestaetigen zeigt einen Text; derselbe Text kurz hintereinander zählt hoch.
export function bestaetigen(text: string) {
  if (aktuell && aktuell.text === text) aktuell = { ...aktuell, mal: aktuell.mal + 1, id: ++zaehler };
  else aktuell = { text, mal: 1, id: ++zaehler };
  hoerer?.(aktuell);
  clearTimeout(timer);
  timer = setTimeout(() => {
    aktuell = null;
    hoerer?.(null);
  }, 3500);
}

// stumm: Schreibaufrufe darin melden nichts einzeln (Sammelaktionen geben
// danach selbst eine Bestätigung).
export async function stumm<T>(f: () => Promise<T>): Promise<T> {
  stummTiefe++;
  try {
    return await f();
  } finally {
    stummTiefe--;
  }
}

setErfolgsHoerer((method, path, body, antwort) => {
  if (method === "GET" || stummTiefe > 0 || !kurzNachAktion(8000)) return;
  const t = textFuer(method, path.split("?")[0] ?? path, body, antwort);
  if (t) bestaetigen(t);
});

export function Rueckmeldungen() {
  const [e, setE] = useState<Eintrag | null>(aktuell);
  useEffect(() => {
    hoerer = setE;
    return () => {
      hoerer = null;
    };
  }, []);
  return (
    <div className="rueckmeldung-ort" role="status" aria-live="polite">
      {e && (
        <div key={e.id} className="rueckmeldung">
          <span className="rueckmeldung-haken" aria-hidden="true" />
          <span>
            {e.text}
            {e.mal > 1 ? ` (${e.mal}×)` : ""}
          </span>
        </div>
      )}
    </div>
  );
}
