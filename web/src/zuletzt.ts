// SPDX-License-Identifier: AGPL-3.0-only

// Zuletzt geöffnete Geräte (1.0.12) für die Schnellsuche. Nur IDs, nur in
// diesem Browser (localStorage), höchstens acht. Fehlt der Speicher (privates
// Fenster, gesperrt), bleibt die Liste leer.

const schluessel = "openwacht.zuletzt";
const max = 8;

export function zuletztLesen(): string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(schluessel) ?? "[]");
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && /^[0-9a-f-]{36}$/.test(x)).slice(0, max) : [];
  } catch {
    return [];
  }
}

export function zuletztMerken(id: string) {
  if (!/^[0-9a-f-]{36}$/.test(id)) return;
  try {
    localStorage.setItem(schluessel, JSON.stringify([id, ...zuletztLesen().filter((x) => x !== id)].slice(0, max)));
  } catch {
    // ohne Speicher keine Liste
  }
}
