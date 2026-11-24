// SPDX-License-Identifier: AGPL-3.0-only

// Kleine Darstellungshilfen für Zeiten und Größen.

const zahl = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });

export function bytes(n: number) {
  const einheiten = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  while (n >= 1024 && i < einheiten.length - 1) {
    n /= 1024;
    i++;
  }
  return `${zahl.format(n)} ${einheiten[i]}`;
}

export function vor(iso: string, jetzt: number) {
  const s = Math.max(0, Math.round((jetzt - Date.parse(iso)) / 1000));
  if (s < 60) return "gerade eben";
  const m = Math.round(s / 60);
  if (m < 60) return `vor ${m} Min.`;
  const h = Math.round(m / 60);
  if (h < 48) return `vor ${h} Std.`;
  return `vor ${Math.round(h / 24)} Tagen`;
}
