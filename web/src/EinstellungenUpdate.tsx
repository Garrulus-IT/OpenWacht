// SPDX-License-Identifier: AGPL-3.0-only

// Einstellungen › Update der Zentrale (1.0.4). Der Betreiber lädt Paket,
// SHA256SUMS und SHA256SUMS.sig aus demselben Build hoch. Die Zentrale prüft
// Signatur, Prüfsumme, Plattform und Version und legt einen Auftrag ab; den
// Rest macht der getrennte Installationsdienst (root). Die Seite fragt
// danach regelmäßig nach dem Stand. Während des Updates startet die Zentrale
// neu; dann ist sie für eine halbe Minute nicht erreichbar.

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api } from "./api";

interface Ergebnis {
  zeit: string;
  version: string;
  ok: boolean;
  meldung: string;
  ausgabe?: string;
}

interface Stand {
  version: string;
  plattform: string;
  eingerichtet: boolean;
  laeuft: boolean;
  ergebnis?: Ergebnis;
}

type PanelTyp = (props: { titel: string; rechts?: ReactNode; children: ReactNode; id: string }) => ReactNode;

export function UpdatePanel({ Panel }: { Panel: PanelTyp }) {
  const [stand, setStand] = useState<Stand | null>(null);
  const [meldung, setMeldung] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const [code, setCode] = useState("");
  const form = useRef<HTMLFormElement>(null);

  const laden = useCallback(async () => {
    try {
      setStand(await api<Stand>("GET", "/api/v1/zentrale-update"));
    } catch (e) {
      // Während des Neustarts nicht erreichbar: weiter warten.
      setMeldung(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void laden();
  }, [laden]);
  // Solange ein Update läuft, alle 5 Sekunden nachsehen.
  useEffect(() => {
    if (!stand?.laeuft && !arbeitet) return;
    const id = window.setInterval(() => void laden(), 5000);
    return () => window.clearInterval(id);
  }, [stand?.laeuft, arbeitet, laden]);

  const hochladen = async (e: FormEvent) => {
    e.preventDefault();
    if (!form.current) return;
    const fd = new FormData();
    const datei = (name: string) => (form.current?.elements.namedItem(name) as HTMLInputElement | null)?.files?.[0];
    const paket = datei("paket");
    const summen = datei("summen");
    const signatur = datei("signatur");
    if (!paket || !summen || !signatur) {
      setMeldung("Bitte alle drei Dateien wählen.");
      return;
    }
    fd.append("code", code);
    fd.append("summen", summen, "SHA256SUMS");
    fd.append("signatur", signatur, "SHA256SUMS.sig");
    fd.append("paket", paket, paket.name);
    setArbeitet(true);
    setMeldung("Wird hochgeladen und geprüft …");
    try {
      const r = await api<{ version: string }>("POST", "/api/v1/zentrale-update", undefined, { raw: fd, headers: {} });
      setMeldung(`Version ${r.version} geprüft. Der Installationsdienst installiert sie jetzt; die Zentrale startet dabei neu.`);
      setCode("");
      form.current.reset();
      await laden();
    } catch (err) {
      setMeldung(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  if (!stand) return null;
  return (
    <Panel id="einst-update" titel="Update der Zentrale">
      <p>
        Installiert: <strong>{stand.version}</strong> ({stand.plattform})
      </p>
      {!stand.eingerichtet ? (
        <p className="klein">
          Auf dieser Installation nicht eingerichtet: Das geht nur, wenn die Zentrale als Debian-Paket installiert ist. Sonst
          wie im Handbuch, Kapitel 1, „Update“.
        </p>
      ) : stand.laeuft ? (
        <p className="meldung" role="status" aria-busy="true">
          Das Update wird installiert. Die Zentrale startet dabei neu; die Seite lädt den Stand von selbst.
        </p>
      ) : (
        <form ref={form} className="formular formular-flach ton-formular" onSubmit={hochladen}>
          <p className="klein">
            Paket, <code>SHA256SUMS</code> und <code>SHA256SUMS.sig</code> aus demselben Build wählen. Angenommen wird nur ein
            Paket, das mit dem Update-Schlüssel signiert und neuer als die installierte Version ist. Vor Änderungen an der
            Datenbank sichert das Paket selbst; trotzdem vorher einen Snapshot der VM anlegen.
          </p>
          <label className="feld">
            <span>Paket (openwacht-zentrale_…_{stand.plattform}.deb)</span>
            <input type="file" name="paket" accept=".deb" required />
          </label>
          <label className="feld">
            <span>SHA256SUMS</span>
            <input type="file" name="summen" required />
          </label>
          <label className="feld">
            <span>SHA256SUMS.sig</span>
            <input type="file" name="signatur" accept=".sig" required />
          </label>
          <label className="feld feld-schmal">
            <span>Code aus der Authenticator-App (Konten ohne Zwei-Faktor: Passwort)</span>
            <input type="password" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
          <div className="aktionen">
            <button className="knopf knopf-haupt" disabled={arbeitet}>
              Prüfen und installieren
            </button>
          </div>
        </form>
      )}
      {meldung && (
        <p className="klein" role="status">
          {meldung}
        </p>
      )}
      {stand.ergebnis && (
        <div className={stand.ergebnis.ok ? "meldung meldung-erfolg" : "meldung meldung-fehler"} role="status">
          <p>
            Letztes Update ({new Date(stand.ergebnis.zeit).toLocaleString("de-DE")}): {stand.ergebnis.meldung}
          </p>
          {stand.ergebnis.ausgabe && (
            <details>
              <summary>Ausgabe von apt</summary>
              <pre className="befehl">{stand.ergebnis.ausgabe}</pre>
            </details>
          )}
        </div>
      )}
    </Panel>
  );
}
