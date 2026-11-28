// SPDX-License-Identifier: AGPL-3.0-only

// Hinweis auf Lizenz und Quellcode (GNU AGPL v3, § 13): Wer die Oberfläche
// über das Netz nutzt, bekommt den Quellcode der laufenden Version angeboten.
// Der Lizenztext liegt unverändert unter /lizenzen/AGPL-3.0.txt.

import { mitBasis } from "./basis";

export const QUELLCODE = "https://github.com/garrulus-it/openwacht";

// Adresse des Quellcodes zur laufenden Version (Tag vX.Y.Z), sonst das Repository.
export function quellcodeAdresse(version?: string): string {
  return version && /^\d+\.\d+\.\d+$/.test(version) ? `${QUELLCODE}/tree/v${version}` : QUELLCODE;
}

export function LizenzHinweis(props: { version?: string }) {
  return (
    <p className="lizenz-hinweis">
      Freie Software unter der{" "}
      <a href={mitBasis("/lizenzen/AGPL-3.0.txt")} target="_blank" rel="noopener">
        GNU AGPL v3
      </a>{" "}
      ·{" "}
      <a href={quellcodeAdresse(props.version)} target="_blank" rel="noopener noreferrer">
        Quellcode
      </a>
    </p>
  );
}
