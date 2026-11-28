// SPDX-License-Identifier: AGPL-3.0-only

// Gemeinsame Anzeigehilfen für Hosts (Agent und SNMP): Zahlen, Laufzeit, Pegel.

export const zahl = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });

export function laufzeit(sek: number) {
  const t = Math.floor(sek / 86400);
  const h = Math.floor((sek % 86400) / 3600);
  if (t > 0) return h > 0 ? `${t} ${t === 1 ? "Tag" : "Tage"}, ${h} Std.` : `${t} ${t === 1 ? "Tag" : "Tage"}`;
  const m = Math.floor((sek % 3600) / 60);
  // ohne „0 Std.“ vorweg (1.0.12)
  if (h === 0) return m > 0 ? `${m} Min.` : "unter 1 Min.";
  return m > 0 ? `${h} Std., ${m} Min.` : `${h} Std.`;
}

export function prozent(belegt: number, gesamt: number) {
  return gesamt > 0 ? (belegt / gesamt) * 100 : 0;
}

// Pegel: grün bis 80 %, Bernstein bis 90 %, darüber rot.
export function Pegel({ wert, titel }: { wert: number; titel: string }) {
  const stufe = wert >= 90 ? "hoch" : wert >= 80 ? "mittel" : "ok";
  return (
    <div className="pegel" title={titel}>
      <div className="pegel-spur">
        <div className={`pegel-fuellung pegel-${stufe}`} style={{ width: `${Math.min(100, Math.max(0, wert))}%` }} />
      </div>
      <span className="pegel-zahl">{zahl.format(wert)} %</span>
    </div>
  );
}

// Bit/s lesbar: „12,3 Mbit/s“.
export function bitrate(bps: number) {
  const stufen: [number, string][] = [
    [1e9, "Gbit/s"],
    [1e6, "Mbit/s"],
    [1e3, "kbit/s"],
  ];
  for (const [f, e] of stufen) if (bps >= f) return `${zahl.format(bps / f)} ${e}`;
  return `${zahl.format(bps)} bit/s`;
}
