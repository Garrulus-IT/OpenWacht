// SPDX-License-Identifier: AGPL-3.0-only

// Mehrere Geräte bearbeiten (1.0.12): In Hosts Geräte markieren und für alle
// zusammen eine Vorlage oder einen Vorlagensatz anwenden, eine Wartung setzen
// oder beenden oder sie einer Gruppe zuordnen. Jede Aktion läuft je Gerät mit
// den Rechten des Benutzers; was scheitert, steht danach mit Grund da.

import { useMemo, useState, type FormEvent } from "react";
import { api, type Geraet, type Gruppe } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";
import { bestaetigen, stumm } from "./Rueckmeldung";
import { AnwendenAuf } from "./SensorVorlagen";

export interface MehrfachGeraet {
  g: Geraet;
  // Klasse des Zustandssignals, z. B. „signal-crit“
  signal: string;
}

const dauern: [number, string][] = [
  [30, "30 Minuten"],
  [60, "1 Stunde"],
  [120, "2 Stunden"],
  [240, "4 Stunden"],
  [480, "8 Stunden"],
  [1440, "1 Tag"],
  [4320, "3 Tage"],
];

type Aktion = "" | "vorlage" | "wartung" | "gruppe";
type Fehlschlag = { name: string; grund: string };

export function Mehrfach(props: {
  geraete: MehrfachGeraet[];
  gruppen: Gruppe[];
  bereich: Bereich;
  onGeaendert: () => void;
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const { bereich } = props;
  const [filter, setFilter] = useState("");
  const [wahl, setWahl] = useState<Set<string>>(new Set());
  const [aktion, setAktion] = useState<Aktion>("");
  const [arbeitet, setArbeitet] = useState(false);
  const [fehlschlaege, setFehlschlaege] = useState<Fehlschlag[]>([]);
  // Wartung
  const [dauer, setDauer] = useState(120);
  const [grund, setGrund] = useState("");
  // Gruppe
  const [gruppe, setGruppe] = useState("");

  const pfad = useMemo(() => {
    const nach = new Map(props.gruppen.map((g) => [g.id, g]));
    const f = (id: string | null, tiefe = 0): string => {
      const g = id ? nach.get(id) : undefined;
      if (!g || tiefe > 20) return "";
      const oben = f(g.eltern_id, tiefe + 1);
      return oben ? `${oben} / ${g.name}` : g.name;
    };
    return f;
  }, [props.gruppen]);

  const pflegbar = props.geraete.filter((x) => darfPflegen(bereich, x.g.mandant_id));
  const sichtbar = pflegbar
    .filter((x) => {
      const q = filter.trim().toLowerCase();
      return !q || `${x.g.name} ${x.g.adresse ?? ""} ${pfad(x.g.gruppe_id)}`.toLowerCase().includes(q);
    })
    .sort((a, b) => a.g.name.localeCompare(b.g.name, "de"));
  const markiert = pflegbar.filter((x) => wahl.has(x.g.id)).map((x) => x.g);
  const mandanteDerWahl = new Set(markiert.map((g) => g.mandant_id));
  const alleSichtbarenMarkiert = sichtbar.length > 0 && sichtbar.every((x) => wahl.has(x.g.id));

  const umschalten = (id: string, an: boolean) => {
    const n = new Set(wahl);
    if (an) n.add(id);
    else n.delete(id);
    setWahl(n);
  };

  // jeGeraet führt eine Aktion für alle markierten Geräte aus und sammelt Fehler.
  const jeGeraet = async (ziele: Geraet[], f: (g: Geraet) => Promise<unknown>, erfolg: (n: number) => string) => {
    setArbeitet(true);
    setFehlschlaege([]);
    const fehler: Fehlschlag[] = [];
    let ok = 0;
    await stumm(async () => {
      for (const g of ziele) {
        try {
          await f(g);
          ok++;
        } catch (e) {
          fehler.push({ name: g.name, grund: e instanceof Error ? e.message : String(e) });
        }
      }
    });
    setFehlschlaege(fehler);
    setArbeitet(false);
    if (ok > 0) bestaetigen(erfolg(ok));
    if (fehler.length === 0) setAktion("");
    props.onGeaendert();
  };

  const geraeteText = (n: number) => (n === 1 ? "1 Gerät" : `${n} Geräte`);

  const wartungSetzen = (e: FormEvent) => {
    e.preventDefault();
    void jeGeraet(
      markiert,
      (g) => api("PUT", `/api/v1/geraete/${g.id}/wartung`, { minuten: dauer, grund: grund.trim() }),
      (n) => `Wartung für ${geraeteText(n)} gesetzt`,
    );
  };
  const wartungEnde = () =>
    void jeGeraet(
      markiert.filter((g) => g.wartung),
      (g) => api("DELETE", `/api/v1/geraete/${g.id}/wartung`),
      (n) => `Wartung für ${geraeteText(n)} beendet`,
    );
  const gruppeSetzen = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    setFehlschlaege([]);
    try {
      await stumm(() => api("POST", "/api/v1/geraete/gruppe", { geraete: markiert.map((g) => g.id), gruppe_id: gruppe }));
      bestaetigen(gruppe ? `${geraeteText(markiert.length)} der Gruppe zugeordnet` : `${geraeteText(markiert.length)} aus der Gruppe genommen`);
      setAktion("");
      props.onGeaendert();
    } catch (err) {
      setFehlschlaege([{ name: geraeteText(markiert.length), grund: err instanceof Error ? err.message : String(err) }]);
    } finally {
      setArbeitet(false);
    }
  };

  const gruppenDerWahl = props.gruppen
    .filter((g) => mandanteDerWahl.size === 1 && mandanteDerWahl.has(g.mandant_id))
    .map((g) => ({ g, p: pfad(g.id) }))
    .sort((a, b) => a.p.localeCompare(b.p, "de"));

  return (
    <div className="mehrfach">
      <div className="mehrfach-kopf">
        <h2 className="klein-titel">Mehrere Geräte bearbeiten</h2>
        <input
          type="search"
          className="mehrfach-filter"
          placeholder="Name, Adresse oder Gruppe filtern"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Geräte filtern"
        />
        <label className="haken">
          <input
            type="checkbox"
            checked={alleSichtbarenMarkiert}
            onChange={(e) => {
              const n = new Set(wahl);
              for (const x of sichtbar) {
                if (e.target.checked) n.add(x.g.id);
                else n.delete(x.g.id);
              }
              setWahl(n);
            }}
          />
          <span>{filter.trim() ? "alle gefilterten" : "alle"}</span>
        </label>
      </div>
      {pflegbar.length < props.geraete.length && (
        <p className="klein">Geräte, die du nur lesen darfst, stehen hier nicht.</p>
      )}

      <ul className="mehrfach-liste" aria-label="Geräte">
        {sichtbar.map(({ g, signal }) => (
          <li key={g.id}>
            <label className={`mehrfach-geraet${wahl.has(g.id) ? " markiert" : ""}`}>
              <input type="checkbox" checked={wahl.has(g.id)} onChange={(e) => umschalten(g.id, e.target.checked)} />
              <span className={`signal ${signal}`} aria-hidden="true" />
              <span className="mehrfach-name">{g.name}</span>
              <span className="mehrfach-zusatz">
                {[g.adresse, pfad(g.gruppe_id), bereich.mehrere ? mandantName(bereich, g.mandant_id) : "", g.wartung ? "in Wartung" : ""]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
            </label>
          </li>
        ))}
        {sichtbar.length === 0 && <li className="klein">Kein Gerät passt zum Filter.</li>}
      </ul>

      {aktion === "vorlage" && markiert.length > 0 && (
        <AnwendenAuf
          geraete={markiert}
          melden={props.melden}
          onFertig={() => {
            setAktion("");
            props.onGeaendert();
          }}
        />
      )}

      {aktion === "wartung" && markiert.length > 0 && (
        <div className="einschub">
          <form className="formular formular-flach" onSubmit={wartungSetzen}>
            <h3 className="einschub-titel">Wartung für {geraeteText(markiert.length)}</h3>
            <label className="feld">
              <span>Dauer</span>
              <select value={dauer} onChange={(e) => setDauer(Number(e.target.value))}>
                {dauern.map(([m, t]) => (
                  <option key={m} value={m}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Grund (optional)</span>
              <input maxLength={200} value={grund} placeholder="z. B. Firmware-Update" onChange={(e) => setGrund(e.target.value)} />
            </label>
            <p className="klein formular-voll">Während der Wartung melden die Geräte keine Alarme; offene Alarme bleiben stehen.</p>
            <div className="aktionen">
              <button className="knopf knopf-haupt" disabled={arbeitet}>
                Wartung setzen
              </button>
              <button type="button" className="knopf" onClick={() => setAktion("")}>
                Abbrechen
              </button>
            </div>
          </form>
        </div>
      )}

      {aktion === "gruppe" && markiert.length > 0 && (
        <div className="einschub">
          <form className="formular formular-flach" onSubmit={(e) => void gruppeSetzen(e)}>
            <h3 className="einschub-titel">{geraeteText(markiert.length)} einer Gruppe zuordnen</h3>
            {mandanteDerWahl.size > 1 ? (
              <p className="meldung meldung-fehler formular-voll" role="alert">
                Die markierten Geräte liegen in verschiedenen Mandanten. Gruppen gibt es je Mandant: bitte nur Geräte eines Mandanten markieren.
              </p>
            ) : (
              <label className="feld formular-voll">
                <span>Gruppe</span>
                <select value={gruppe} onChange={(e) => setGruppe(e.target.value)}>
                  <option value="">Keine Gruppe</option>
                  {gruppenDerWahl.map(({ g, p }) => (
                    <option key={g.id} value={g.id}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="aktionen">
              <button className="knopf knopf-haupt" disabled={arbeitet || mandanteDerWahl.size > 1}>
                Zuordnen
              </button>
              <button type="button" className="knopf" onClick={() => setAktion("")}>
                Abbrechen
              </button>
            </div>
          </form>
        </div>
      )}

      {fehlschlaege.length > 0 && (
        <div className="meldung meldung-fehler" role="alert">
          <p>Nicht bei allen Geräten geklappt:</p>
          <ul className="klein">
            {fehlschlaege.map((f, i) => (
              <li key={i}>
                {f.name}: {f.grund}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="ordnen-leiste mehrfach-leiste" role="region" aria-label="Markierte Geräte">
        <strong>{markiert.length === 0 ? "Nichts markiert" : `${geraeteText(markiert.length)} markiert`}</strong>
        <button className="knopf" disabled={markiert.length === 0 || arbeitet} onClick={() => setAktion("vorlage")}>
          Vorlage anwenden …
        </button>
        <button className="knopf" disabled={markiert.length === 0 || arbeitet} onClick={() => setAktion("wartung")}>
          Wartung …
        </button>
        <button className="knopf" disabled={!markiert.some((g) => g.wartung) || arbeitet} onClick={wartungEnde}>
          Wartung beenden
        </button>
        <button className="knopf" disabled={markiert.length === 0 || arbeitet} onClick={() => setAktion("gruppe")}>
          Gruppe …
        </button>
        <span className="mehrfach-rechts">
          {markiert.length > 0 && (
            <button className="knopf-text" onClick={() => setWahl(new Set())}>
              Markierung aufheben
            </button>
          )}
          <button className="knopf knopf-haupt" onClick={props.onFertig}>
            Fertig
          </button>
        </span>
      </div>
    </div>
  );
}
