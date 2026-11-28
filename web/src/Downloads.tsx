// SPDX-License-Identifier: AGPL-3.0-only

// Downloads (1.0.14): Agents, MSI, Desktop-App und Agent-Pakete direkt von
// der Zentrale. Die Dateien kommen mit dem Paket der Zentrale und werden mit
// jedem Update der Zentrale mit erneuert; der Download braucht kein Internet.
// Die Zentrale bietet nur an, was zur mitgelieferten SHA256SUMS passt.

import { mitBasis } from "./basis";
import { useQuelle } from "./quelle";

interface Datei {
  name: string;
  art: "agent" | "msi" | "desktop" | "deb" | "rpm";
  arch?: string;
  groesse: number;
  sha256: string;
  signatur?: string;
}
interface System {
  os: string;
  dateien: Datei[];
}

const systemName: Record<string, string> = { windows: "Windows", linux: "Linux", darwin: "macOS", freebsd: "FreeBSD" };

const archName: Record<string, string> = { amd64: "x64 (Intel, AMD)", arm64: "ARM64", armv7: "ARMv7 (z. B. Raspberry Pi)" };

// Reihenfolge und Beschreibung je Art
const artRang: Record<Datei["art"], number> = { msi: 0, desktop: 1, deb: 2, rpm: 3, agent: 4 };
function beschreibung(os: string, d: Datei): string {
  switch (d.art) {
    case "msi":
      return "Agent als Installer (MSI), auch zum Verteilen per GPO oder Intune";
    case "desktop":
      return "Desktop-App für den Infobereich (Alarme, Zustand)";
    case "deb":
      return "Agent als Paket für Debian und Ubuntu";
    case "rpm":
      return "Agent als Paket für RHEL, Rocky, Alma und SUSE";
    default:
      return os === "windows" ? "Agent als Programmdatei (ohne Installer)" : "Agent als Programmdatei";
  }
}

const mb = (n: number) => (n / 1048576).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " MB";

function link(os: string, name: string) {
  return mitBasis(`/api/v1/downloads/${encodeURIComponent(os)}/${encodeURIComponent(name)}`);
}

export function Downloads() {
  const q = useQuelle<{ version: string; systeme: System[] }>("/api/v1/downloads", 300_000);
  if (q.fehler) return <p className="meldung meldung-fehler">{q.fehler}</p>;
  if (!q.daten) {
    return (
      <p className="klein" aria-busy="true">
        Lädt …
      </p>
    );
  }
  const { version, systeme } = q.daten;
  return (
    <section className="ansicht downloads" aria-labelledby="downloads-titel">
      <h1 id="downloads-titel" className="sr-only">
        Downloads
      </h1>
      <p className="klein">
        Agents und Programme zu dieser Zentrale (Version {version}). Die Dateien liegen auf der Zentrale selbst und kommen mit jedem
        Update der Zentrale neu mit; der Download braucht kein Internet. Angeboten wird nur, was zur mitgelieferten Prüfsumme passt.
        Windows-Dateien sind mit dem Code-Signing-Zertifikat von Garrulus IT signiert. Zum Anmelden eines Agents braucht es ein Token
        (Verwaltung → Benutzer und Mandanten → Agent-Tokens).
      </p>
      {systeme.length === 0 ? (
        <p className="leer">
          Auf dieser Zentrale liegen keine Downloads. Sie kommen mit dem Paket der Zentrale (ab 1.0.14); bei einer Installation aus
          einzelnen Dateien gehören sie in den Ordner <code>downloads</code> neben der Zentrale oder in den Ordner aus{" "}
          <code>OPENWACHT_DOWNLOADS</code>.
        </p>
      ) : (
        systeme.map((s) => (
          <div key={s.os} className="downloads-system">
            <h2>{systemName[s.os] ?? s.os}</h2>
            <div className="tabelle-rahmen">
              <table className="tabelle tabelle-kompakt">
                <thead>
                  <tr>
                    <th scope="col">Datei</th>
                    <th scope="col">Architektur</th>
                    <th scope="col">Größe</th>
                    <th scope="col">Prüfsumme (SHA-256)</th>
                    <th scope="col">
                      <span className="sr-only">Herunterladen</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {[...s.dateien]
                    .sort((a, b) => artRang[a.art] - artRang[b.art] || a.name.localeCompare(b.name))
                    .map((d) => (
                      <tr key={d.name}>
                        <td>
                          <div className="name">{beschreibung(s.os, d)}</div>
                          <div className="klein mono">{d.name}</div>
                        </td>
                        <td>{d.arch ? (archName[d.arch] ?? d.arch) : "–"}</td>
                        <td className="zahl">{mb(d.groesse)}</td>
                        <td>
                          <code className="pruefsumme" title={d.sha256}>
                            {d.sha256.slice(0, 16)}…
                          </code>
                        </td>
                        <td className="downloads-aktion">
                          <a className="knopf knopf-klein" href={link(s.os, d.name)} download={d.name}>
                            Herunterladen
                          </a>
                          {d.signatur && (
                            <a className="klein" href={link(s.os, d.signatur)} download={d.signatur} title="Signatur für das Agent-Update">
                              .sig
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        ))
      )}
    </section>
  );
}
