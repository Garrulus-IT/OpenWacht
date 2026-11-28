// SPDX-License-Identifier: AGPL-3.0-only

// Basis-Pfad: OpenWacht kann unter einem Unterpfad laufen (z. B.
// https://firma.example/openwacht/). Der Server nennt ihn in
// <meta name="basis">; leer heißt Wurzel. Eigene Adressen (API, Downloads,
// Links) gehen durch mitBasis(), Pfade für das Routing im Browser durch
// ohneBasis(). Gleiches Vorgehen wie in OpenChronik und OpenPforte.

let gemerkt: string | null = null;

export function basis(): string {
  if (gemerkt === null) {
    // Ohne document (Tests in Node): Wurzel.
    const meta = typeof document === "undefined" ? null : document.querySelector<HTMLMetaElement>('meta[name="basis"]');
    gemerkt = meta?.content ?? "";
  }
  return gemerkt;
}

// mitBasis: eigener Pfad ab „/“ → Pfad mit Basis. Fremde Adressen bleiben.
export function mitBasis(pfad: string): string {
  return pfad.startsWith("/") && !pfad.startsWith("//") ? basis() + pfad : pfad;
}

// ohneBasis: Pfad der Seite ohne Basis, für das Routing.
export function ohneBasis(pfad: string = typeof window === "undefined" ? "/" : window.location.pathname): string {
  const b = basis();
  if (!b) return pfad;
  if (pfad === b) return "/";
  return pfad.startsWith(b + "/") ? pfad.slice(b.length) : pfad;
}
