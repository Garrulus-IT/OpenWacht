// SPDX-License-Identifier: AGPL-3.0-only

// Seite „Einstellungen“ (Etappe 19), nur für den Betreiber: Netzfreigabe,
// Alarmziele, Totmannschalter und Schwellen der Installation, dazu Netze und
// Schwellen je Mandant. Was per Startoption gesetzt ist, gilt und ist hier
// gesperrt. Netzfreigabe, Alarmziele und Totmann verlangen beim Speichern
// einen frischen Code aus der Authenticator-App (ohne 2FA: das Passwort).

import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { bestaetigungFertig, CodeFeld } from "./Bestaetigung";
import { AufbewahrungPanel } from "./EinstellungenAufbewahrung";
import { InstallationPanels } from "./EinstellungenInstallation";
import { api, type Ich } from "./api";
import { ausEingabe, schwelleText, schwellenFelder, SchwellenFelder, zuEingabe, type SchwellenWerte } from "./Schwellen";

interface Wert<T> {
  wert: T;
  quelle: "startoption" | "einstellung" | "standard";
}

interface MandantEinstellung {
  id: string;
  eltern: string | null;
  name: string;
  netze: string[] | null;
  schwellen: SchwellenWerte;
}

interface Antwort {
  global: Record<string, Wert<unknown>>;
  mandanten: MandantEinstellung[];
  standard: SchwellenWerte;
}

const quelleText = { startoption: "per Startoption", einstellung: "hier eingestellt", standard: "Standard" };

function Quelle({ q }: { q: Wert<unknown>["quelle"] }) {
  return <span className={`marke quelle-${q}`}>{quelleText[q]}</span>;
}

function zeilen(t: string): string[] {
  return t
    .split(/[\n,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function Panel(props: { titel: string; rechts?: ReactNode; children: ReactNode; id: string }) {
  return (
    <section className="panel einstellungen-panel" aria-labelledby={props.id}>
      <div className="panel-kopf">
        <h2 className="panel-titel" id={props.id}>
          {props.titel}
        </h2>
        {props.rechts}
      </div>
      <div className="panel-inhalt">{props.children}</div>
    </section>
  );
}

// Zwei-Faktor-Pflicht für lokale Konten (Etappe 22a). Die Entscheidung trifft
// der Betreiber; ohne Pflicht bestätigen Konten ohne 2FA mit ihrem Passwort.
const pflichtText: Record<string, string> = {
  admins: "Pflicht für Admins (empfohlen)",
  alle: "Pflicht für alle lokalen Konten",
  freiwillig: "freiwillig – jedes Konto entscheidet selbst (nur für rein interne Installationen)",
};

function ZweiFaktorPanel() {
  const [wert, setWert] = useState("");
  const [neu, setNeu] = useState("");
  const [code, setCode] = useState("");
  const [meldung, setMeldung] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  useEffect(() => {
    api<{ zwei_faktor: string }>("GET", "/api/v1/einstellungen/anmeldung")
      .then((r) => {
        setWert(r.zwei_faktor);
        setNeu(r.zwei_faktor);
      })
      .catch((e: unknown) => setMeldung(e instanceof Error ? e.message : String(e)));
  }, []);
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      await api("PUT", "/api/v1/einstellungen/anmeldung", { zwei_faktor: neu, code });
      setWert(neu);
      setCode("");
      setMeldung("Gespeichert.");
    } catch (err) {
      setMeldung(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <Panel id="einst-zweifaktor" titel="Zwei-Faktor-Anmeldung">
      <p className="klein">
        Gilt für lokale Konten. Für Konten aus dem AD entscheidet die jeweilige Anbindung (Verwaltung › Anmeldung über AD). Ohne zweiten
        Faktor reicht ein erbeutetes Passwort für die Anmeldung. Der Betreiber braucht die Zwei-Faktor-Anmeldung immer.
      </p>
      {wert && (
        <form onSubmit={speichern}>
          <fieldset className="feld-gruppe">
            <legend>Zwei-Faktor-Anmeldung ist …</legend>
            {Object.entries(pflichtText).map(([k, t]) => (
              <label className="feld-check" key={k}>
                <input type="radio" name="zweifaktor" checked={neu === k} onChange={() => setNeu(k)} />
                <span>{t}</span>
              </label>
            ))}
          </fieldset>
          {neu !== wert && (
            <>
              <CodeFeld wert={code} setWert={setCode} id="einst-zweifaktor-code" />
              <div className="knopf-reihe">
                <button className="knopf knopf-haupt" disabled={arbeitet || !bestaetigungFertig(code)}>
                  Speichern
                </button>
              </div>
            </>
          )}
        </form>
      )}
      {meldung && (
        <p className="klein" role="status">
          {meldung}
        </p>
      )}
    </Panel>
  );
}

// Anmelde-Domänen und NetBIOS-Namen von Untermandanten (Etappe 30, M1): Erst
// nach der Freigabe leitet die Zentrale Anmeldungen an deren Verzeichnis.
interface Antrag {
  verzeichnis: string;
  verzeichnis_name: string;
  mandant: string;
  art: "domaene" | "netbios";
  wert: string;
  status: "beantragt" | "freigegeben" | "abgelehnt";
  beantragt: string;
  konflikt: boolean;
}

const antragStatus: Record<Antrag["status"], string> = { beantragt: "beantragt", freigegeben: "freigegeben", abgelehnt: "abgelehnt" };

function AnmeldeDomaenenPanel() {
  const [liste, setListe] = useState<Antrag[] | null>(null);
  const [wahl, setWahl] = useState<{ a: Antrag; freigeben: boolean } | null>(null);
  const [code, setCode] = useState("");
  const [meldung, setMeldung] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const laden = useCallback(async () => {
    try {
      setListe((await api<{ antraege: Antrag[] }>("GET", "/api/v1/einstellungen/anmeldedomaenen")).antraege);
    } catch (e) {
      setMeldung(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void laden();
  }, [laden]);
  const entscheiden = async (e: FormEvent) => {
    e.preventDefault();
    if (!wahl) return;
    setArbeitet(true);
    try {
      await api("POST", "/api/v1/einstellungen/anmeldedomaenen", {
        verzeichnis: wahl.a.verzeichnis,
        art: wahl.a.art,
        wert: wahl.a.wert,
        freigeben: wahl.freigeben,
        code,
      });
      setMeldung(`${wahl.a.wert}: ${wahl.freigeben ? "freigegeben" : "abgelehnt"}.`);
      setWahl(null);
      setCode("");
      await laden();
    } catch (err) {
      setCode("");
      setMeldung(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };
  const offen = liste?.filter((a) => a.status === "beantragt").length ?? 0;
  return (
    <Panel id="einst-domaenen" titel="Anmelde-Domänen" rechts={offen > 0 ? <span className="marke">{offen} offen</span> : undefined}>
      <p className="klein">
        Domänen (name@domäne) und NetBIOS-Namen, die Untermandanten für ihre AD- oder SSO-Anbindung eintragen, gelten erst nach deiner
        Freigabe. Sonst könnte ein Mandant Anmeldungen fremder Domänen samt Passwort auf seinen eigenen Server leiten. Anbindungen des
        Hauptmandanten gelten sofort.
      </p>
      {liste === null && !meldung && <p className="klein">Lädt …</p>}
      {liste && liste.length === 0 && <p className="leer">Keine Anbindungen von Untermandanten.</p>}
      {liste && liste.length > 0 && (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Anmeldung mit</th>
              <th scope="col">Mandant · Anbindung</th>
              <th scope="col">Zustand</th>
              <th scope="col">
                <span className="sr-only">Aktionen</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {liste.map((a) => (
              <tr key={a.verzeichnis + a.art + a.wert}>
                <td className="mono">{a.art === "domaene" ? "name@" + a.wert : a.wert + "\\name"}</td>
                <td>
                  {a.mandant} · {a.verzeichnis_name}
                </td>
                <td>
                  {antragStatus[a.status]}
                  {a.konflikt && a.status !== "freigegeben" && <span className="klein"> · schon für eine andere Anbindung frei</span>}
                </td>
                <td>
                  <div className="knopf-reihe">
                    {a.status !== "freigegeben" && (
                      <button className="knopf" disabled={a.konflikt} onClick={() => setWahl({ a, freigeben: true })}>
                        Freigeben
                      </button>
                    )}
                    {a.status !== "abgelehnt" && (
                      <button className="knopf" onClick={() => setWahl({ a, freigeben: false })}>
                        {a.status === "freigegeben" ? "Entziehen" : "Ablehnen"}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {wahl && (
        <form onSubmit={entscheiden}>
          <p className="klein">
            {wahl.a.art === "domaene" ? "name@" + wahl.a.wert : wahl.a.wert + "\\name"} für „{wahl.a.verzeichnis_name}“ ({wahl.a.mandant}){" "}
            {wahl.freigeben ? "freigeben" : wahl.a.status === "freigegeben" ? "entziehen" : "ablehnen"}?
          </p>
          <CodeFeld wert={code} setWert={setCode} id="einst-domaenen-code" />
          <div className="knopf-reihe">
            <button className="knopf knopf-haupt" disabled={arbeitet || !bestaetigungFertig(code)}>
              {wahl.freigeben ? "Freigeben" : "Bestätigen"}
            </button>
            <button type="button" className="knopf" onClick={() => setWahl(null)}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
      {meldung && (
        <p className="klein" role="status">
          {meldung}
        </p>
      )}
    </Panel>
  );
}

export function Einstellungen(props: { ich: Ich; melden: (e: unknown) => void }) {
  const [d, setD] = useState<Antwort | null>(null);
  const [fehler, setFehler] = useState("");
  const laden = useCallback(async () => {
    try {
      setD(await api<Antwort>("GET", "/api/v1/einstellungen"));
      setFehler("");
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    if (props.ich.betreiber) void laden();
  }, [laden, props.ich.betreiber]);

  if (!props.ich.betreiber) {
    return (
      <section className="ansicht" aria-labelledby="einst-titel">
        <h1 id="einst-titel" className="sr-only">
          Einstellungen
        </h1>
        <p className="leer">
          Die Einstellungen der Installation pflegt nur der Betreiber. Festgelegt wird er auf der Zentrale mit
          <code> openwacht-zentrale betreiber -email …</code> (als Eigentümer der Datenbank), Zwei-Faktor-Anmeldung ist Pflicht.
        </p>
      </section>
    );
  }
  return (
    <section className="ansicht einstellungen" aria-labelledby="einst-titel">
      <h1 id="einst-titel" className="sr-only">
        Einstellungen
      </h1>
      {fehler && (
        <p className="meldung meldung-fehler" role="alert">
          {fehler}
        </p>
      )}
      {!d && !fehler && <p className="klein">Lädt …</p>}
      {d && (
        <>
          <p className="hinweis klein">
            Gilt für die ganze Installation. Was per Startoption in der Unit steht, gilt und lässt sich hier nicht ändern; nimmst du die
            Option heraus, gilt der Wert von hier (beim ersten Start mit 0.19 übernommen).
          </p>
          <div className="einstellungen-raster">
            <InstallationPanels Panel={Panel} />
            <ZweiFaktorPanel />
            <ListePanel
              id="einst-netze"
              titel="Netzfreigabe"
              feld="netze"
              d={d}
              beschreibung="Netze, die Sensoren, SNMP, Proxmox und FRITZ!Box von der Zentrale aus erreichen dürfen. Eine Zeile je Netz (10.10.0.0/16) oder Adresse. Loopback und Link-Local nur mit einem Eintrag darin."
              leerText="keine – kein Sensor der Zentrale erreicht etwas"
              onGespeichert={laden}
            />
            <ListePanel
              id="einst-ziele"
              titel="Alarmziele"
              feld="alarmziele"
              d={d}
              beschreibung="ntfy-Server und Webhook-Ziele, die Mandanten für Alarmkanäle wählen dürfen. Eine Zeile je Server, z. B. https://ntfy.example, http://127.0.0.1:2586 (http nur für Loopback) oder für Teams https://prod-12.westeurope.logic.azure.com. Mit Pfad gilt nur dieser Pfad und alles darunter."
              leerText="keine – es gehen keine Alarme hinaus"
              onGespeichert={laden}
            />
            <TotmannPanel d={d} onGespeichert={laden} />
            <MailPanel />
            <SchwellenGlobal d={d} onGespeichert={laden} />
          </div>
          <AnmeldeDomaenenPanel />
          <MandantenPanel d={d} onGespeichert={laden} />
          <AufbewahrungPanel Panel={Panel} />
        </>
      )}
    </section>
  );
}

function ListePanel(props: {
  id: string;
  titel: string;
  feld: "netze" | "alarmziele";
  d: Antwort;
  beschreibung: string;
  leerText: string;
  onGespeichert: () => Promise<void>;
}) {
  const w = props.d.global[props.feld] as Wert<string[]>;
  const [text, setText] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const gesperrt = w.quelle === "startoption";

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    if (text === null) return;
    setArbeitet(true);
    setFehler("");
    try {
      await api("PUT", "/api/v1/einstellungen", { [props.feld]: zeilen(text), code });
      setText(null);
      setCode("");
      await props.onGespeichert();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <Panel id={props.id} titel={props.titel} rechts={<Quelle q={w.quelle} />}>
      <p className="klein">{props.beschreibung}</p>
      {text === null ? (
        <>
          {w.wert.length ? (
            <ul className="einstellungen-liste">
              {w.wert.map((x) => (
                <li key={x}>
                  <code>{x}</code>
                </li>
              ))}
            </ul>
          ) : (
            <p className="leer klein">{props.leerText}</p>
          )}
          {!gesperrt && (
            <div className="aktionen">
              <button className="knopf" onClick={() => setText(w.wert.join("\n"))}>
                Ändern
              </button>
            </div>
          )}
        </>
      ) : (
        <form className="formular" onSubmit={speichern} aria-label={`${props.titel} ändern`}>
          <label className="feld feld-breit" htmlFor={`${props.id}-text`}>
            <span>{props.titel} (eine Zeile je Eintrag)</span>
            <textarea id={`${props.id}-text`} rows={5} value={text} spellCheck={false} onChange={(e) => setText(e.target.value)} />
          </label>
          {props.feld === "netze" && (
            <p className="hinweis klein">
              Vorsicht: Über diese Netze können Admins aller Mandanten Ziele von der Zentrale aus abfragen. Je Mandant lässt sich unten
              weiter eingrenzen.
            </p>
          )}
          <CodeFeld wert={code} setWert={setCode} id={`${props.id}-code`} />
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="aktionen">
            <button className="knopf knopf-haupt" disabled={arbeitet}>
              Speichern
            </button>
            <button type="button" className="knopf" onClick={() => setText(null)}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
    </Panel>
  );
}

function TotmannPanel(props: { d: Antwort; onGespeichert: () => Promise<void> }) {
  const w = props.d.global.totmann as Wert<{ an: boolean; host?: string }>;
  const [modus, setModus] = useState<"" | "setzen" | "aus">("");
  const [url, setUrl] = useState("");
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const gesperrt = w.quelle === "startoption";

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    setFehler("");
    try {
      await api("PUT", "/api/v1/einstellungen", { totmann: modus === "aus" ? "" : url.trim(), code });
      setModus("");
      setUrl("");
      setCode("");
      await props.onGespeichert();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <Panel id="einst-totmann" titel="Totmannschalter" rechts={<Quelle q={w.quelle} />}>
      <p className="klein">
        Die Zentrale meldet sich regelmäßig bei healthchecks.io. Bleibt die Meldung aus, schickt der Dienst eine Mail. Die Ping-Adresse
        liegt verschlüsselt in der Datenbank und wird nie angezeigt.
      </p>
      <p>
        {w.wert.an ? (
          <>
            <span className="marke marke-ok">an</span> {w.wert.host && <span className="klein">an {w.wert.host}</span>}
          </>
        ) : (
          <span className="marke marke-warn">aus – fällt die Zentrale aus, merkt das niemand</span>
        )}
      </p>
      {!gesperrt && !modus && (
        <div className="aktionen">
          <button className="knopf" onClick={() => setModus("setzen")}>
            {w.wert.an ? "Neue Ping-Adresse" : "Einschalten"}
          </button>
          {w.wert.an && (
            <button className="knopf knopf-gefahr" onClick={() => setModus("aus")}>
              Ausschalten
            </button>
          )}
        </div>
      )}
      {modus && (
        <form className="formular" onSubmit={speichern} aria-label="Totmannschalter ändern">
          {modus === "setzen" ? (
            <label className="feld feld-breit" htmlFor="einst-totmann-url">
              <span>Ping-Adresse</span>
              <input
                id="einst-totmann-url"
                type="password"
                autoComplete="off"
                required
                maxLength={500}
                placeholder="https://hc-ping.com/…"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>
          ) : (
            <p>Totmannschalter ausschalten?</p>
          )}
          <CodeFeld wert={code} setWert={setCode} id="einst-totmann-code" />
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="aktionen">
            <button className={`knopf ${modus === "aus" ? "knopf-gefahr" : "knopf-haupt"}`} disabled={arbeitet}>
              {modus === "aus" ? "Ausschalten" : "Speichern"}
            </button>
            <button type="button" className="knopf" onClick={() => setModus("")}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
    </Panel>
  );
}

function SchwellenGlobal(props: { d: Antwort; onGespeichert: () => Promise<void> }) {
  const g = props.d.global;
  const gesperrt: Record<string, boolean> = {};
  const eigene: SchwellenWerte = {};
  for (const f of schwellenFelder) {
    const w = g[f.id] as Wert<number>;
    gesperrt[f.id] = w.quelle === "startoption";
    eigene[f.id] = w.quelle === "einstellung" || w.quelle === "startoption" ? w.wert : null;
  }
  const [eingabe, setEingabe] = useState<Record<string, string> | null>(null);
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    if (!eingabe) return;
    const { werte, fehler } = ausEingabe(eingabe);
    if (fehler) {
      setFehler(fehler);
      return;
    }
    for (const f of schwellenFelder) if (gesperrt[f.id]) delete werte[f.id];
    setArbeitet(true);
    setFehler("");
    try {
      await api("PUT", "/api/v1/einstellungen", { schwellen: werte });
      setEingabe(null);
      await props.onGespeichert();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <Panel id="einst-schwellen" titel="Schwellen für Hosts">
      <p className="klein">Platte, RAM und CPU (Mittel über 15 Minuten) in Prozent, 0 = aus. Mandanten und Geräte können abweichen.</p>
      {!eingabe ? (
        <>
          <table className="tabelle tabelle-kompakt schwellen-tabelle">
            <tbody>
              {schwellenFelder.map((f) => {
                const w = g[f.id] as Wert<number>;
                return (
                  <tr key={f.id}>
                    <th scope="row">{f.text}</th>
                    <td>{schwelleText(f.id, w.wert)}</td>
                    <td>
                      <Quelle q={w.quelle} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="aktionen">
            <button className="knopf" onClick={() => setEingabe(zuEingabe(eigene))}>
              Ändern
            </button>
          </div>
        </>
      ) : (
        <form className="formular" onSubmit={speichern} aria-label="Schwellen ändern">
          <SchwellenFelder eingabe={eingabe} setEingabe={setEingabe} geerbt={props.d.standard} gesperrt={gesperrt} idPraefix="einst-sw" />
          <p className="hinweis klein">Leer = Standard.</p>
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="aktionen">
            <button className="knopf knopf-haupt" disabled={arbeitet}>
              Speichern
            </button>
            <button type="button" className="knopf" onClick={() => setEingabe(null)}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
    </Panel>
  );
}

function MandantenPanel(props: { d: Antwort; onGespeichert: () => Promise<void> }) {
  const nachId = useMemo(() => new Map(props.d.mandanten.map((m) => [m.id, m])), [props.d.mandanten]);
  // Baum in Reihenfolge mit Tiefe
  const reihe = useMemo(() => {
    const kinder = new Map<string | null, MandantEinstellung[]>();
    for (const m of props.d.mandanten) {
      const k = m.eltern && nachId.has(m.eltern) ? m.eltern : null;
      kinder.set(k, [...(kinder.get(k) ?? []), m]);
    }
    const out: { m: MandantEinstellung; tiefe: number }[] = [];
    const geh = (id: string | null, tiefe: number) => {
      for (const m of kinder.get(id) ?? []) {
        out.push({ m, tiefe });
        if (tiefe < 20) geh(m.id, tiefe + 1);
      }
    };
    geh(null, 0);
    return out;
  }, [props.d.mandanten, nachId]);
  const [offen, setOffen] = useState("");

  // Was ohne eigenen Eintrag gilt: der nächste Vorfahr mit Wert, sonst global.
  const geerbt = (m: MandantEinstellung): SchwellenWerte => {
    const out: SchwellenWerte = {};
    for (const f of schwellenFelder) {
      let p = m.eltern ? nachId.get(m.eltern) : undefined;
      let v: number | null = null;
      for (let i = 0; p && i < 20 && v === null; i++) {
        v = p.schwellen[f.id] ?? null;
        p = p.eltern ? nachId.get(p.eltern) : undefined;
      }
      out[f.id] = v ?? ((props.d.global[f.id] as Wert<number>).wert as number);
    }
    return out;
  };
  const netzKette = (m: MandantEinstellung): string[][] => {
    const out: string[][] = [];
    for (let p: MandantEinstellung | undefined = m, i = 0; p && i < 20; p = p.eltern ? nachId.get(p.eltern) : undefined, i++) {
      if (p.netze) out.push(p.netze);
    }
    return out;
  };

  return (
    <Panel id="einst-mandanten" titel="Je Mandant">
      <p className="klein">
        Eigene Netze grenzen nur ein: Ein Sensor eines Mandanten erreicht eine Adresse nur, wenn sie global freigegeben ist und in den
        Netzen dieses Mandanten und aller darüber liegt. Schwellen erben Untermandanten, Geräte können eigene haben (Aktionsmenü am Gerät).
      </p>
      <table className="tabelle einstellungen-mandanten">
        <thead>
          <tr>
            <th scope="col">Mandant</th>
            <th scope="col">Netze</th>
            <th scope="col">Schwellen</th>
            <th scope="col">
              <span className="sr-only">Aktion</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {reihe.map(({ m, tiefe }) => {
            const eigene = schwellenFelder.filter((f) => m.schwellen[f.id] !== null && m.schwellen[f.id] !== undefined);
            const kette = netzKette(m);
            return (
              <MandantZeile
                key={m.id}
                m={m}
                tiefe={tiefe}
                offen={offen === m.id}
                onOffen={(x) => setOffen(x ? m.id : "")}
                geerbt={geerbt(m)}
                netzText={
                  m.netze
                    ? m.netze.length
                      ? m.netze.join(", ")
                      : "keine (gesperrt)"
                    : kette.length
                      ? "erbt Eingrenzung"
                      : "alle freigegebenen"
                }
                schwellenText={eigene.length ? eigene.map((f) => `${f.text} ${schwelleText(f.id, m.schwellen[f.id])}`).join(", ") : "erbt"}
                onGespeichert={props.onGespeichert}
              />
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}

function MandantZeile(props: {
  m: MandantEinstellung;
  tiefe: number;
  offen: boolean;
  onOffen: (x: boolean) => void;
  geerbt: SchwellenWerte;
  netzText: string;
  schwellenText: string;
  onGespeichert: () => Promise<void>;
}) {
  const m = props.m;
  const [eigeneNetze, setEigeneNetze] = useState(m.netze !== null);
  const [netze, setNetze] = useState((m.netze ?? []).join("\n"));
  const [eingabe, setEingabe] = useState(() => zuEingabe(m.schwellen));
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  // Beim Öffnen den gespeicherten Stand übernehmen (nach dem Speichern neu geladen).
  useEffect(() => {
    if (!props.offen) return;
    setEigeneNetze(m.netze !== null);
    setNetze((m.netze ?? []).join("\n"));
    setEingabe(zuEingabe(m.schwellen));
    setCode("");
    setFehler("");
  }, [props.offen, m]);
  const neueNetze = eigeneNetze ? zeilen(netze) : null;
  const netzeGeaendert =
    JSON.stringify(neueNetze === null ? null : [...neueNetze].sort()) !== JSON.stringify(m.netze === null ? null : [...m.netze].sort());

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    const { werte, fehler } = ausEingabe(eingabe);
    if (fehler) {
      setFehler(fehler);
      return;
    }
    setArbeitet(true);
    setFehler("");
    try {
      await api("PUT", `/api/v1/einstellungen/mandanten/${m.id}`, {
        netze: neueNetze,
        schwellen: werte,
        ...(netzeGeaendert ? { code } : {}),
      });
      setCode("");
      props.onOffen(false);
      await props.onGespeichert();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <>
      <tr>
        <th scope="row" className="name" style={{ paddingInlineStart: `${0.6 + props.tiefe * 1.1}rem` }}>
          {m.name}
        </th>
        <td className="klein">{props.netzText}</td>
        <td className="klein">{props.schwellenText}</td>
        <td>
          <button className="knopf-text" aria-expanded={props.offen} onClick={() => props.onOffen(!props.offen)}>
            {props.offen ? "Schließen" : "Bearbeiten"}
          </button>
        </td>
      </tr>
      {props.offen && (
        <tr className="mandant-formular-zeile">
          <td colSpan={4}>
            <form className="formular" onSubmit={speichern} aria-label={`Einstellungen für ${m.name}`}>
              <label className="feld-check">
                <input type="checkbox" checked={eigeneNetze} onChange={(e) => setEigeneNetze(e.target.checked)} />
                <span>Netze für „{m.name}“ eingrenzen</span>
              </label>
              {eigeneNetze && (
                <label className="feld feld-breit" htmlFor={`mn-${m.id}`}>
                  <span>Netze (eine Zeile je Netz; leer = dieser Mandant erreicht nichts)</span>
                  <textarea id={`mn-${m.id}`} rows={3} spellCheck={false} value={netze} onChange={(e) => setNetze(e.target.value)} />
                </label>
              )}
              <SchwellenFelder eingabe={eingabe} setEingabe={setEingabe} geerbt={props.geerbt} idPraefix={`ms-${m.id}`} />
              {netzeGeaendert && <CodeFeld wert={code} setWert={setCode} id={`mc-${m.id}`} />}
              {fehler && (
                <p className="meldung meldung-fehler" role="alert">
                  {fehler}
                </p>
              )}
              <div className="aktionen">
                <button className="knopf knopf-haupt" disabled={arbeitet}>
                  Speichern
                </button>
                <button type="button" className="knopf" onClick={() => props.onOffen(false)}>
                  Abbrechen
                </button>
              </div>
            </form>
          </td>
        </tr>
      )}
    </>
  );
}

interface MailEinstellung {
  eingerichtet: boolean;
  server?: string;
  port?: number;
  tls?: "starttls" | "tls" | "keine";
  absender?: string;
  benutzer?: string | null;
  passwort_gesetzt?: boolean;
  ca?: string | null;
}

// SMTP-Relay für alle Alarm-Mails (Etappe 20). Ändern nur mit Code.
function MailPanel() {
  const [m, setM] = useState<MailEinstellung | null>(null);
  const [bearbeiten, setBearbeiten] = useState<"" | "setzen" | "aus">("");
  const [server, setServer] = useState("");
  const [port, setPort] = useState("587");
  const [tls, setTls] = useState<"starttls" | "tls" | "keine">("starttls");
  const [absender, setAbsender] = useState("");
  const [benutzer, setBenutzer] = useState("");
  const [passwort, setPasswort] = useState("");
  const [ca, setCa] = useState("");
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [info, setInfo] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const laden = useCallback(async () => {
    try {
      setM(await api<MailEinstellung>("GET", "/api/v1/einstellungen/mail"));
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void laden();
  }, [laden]);

  const oeffnen = () => {
    setServer(m?.server ?? "");
    setPort(String(m?.port ?? 587));
    setTls(m?.tls ?? "starttls");
    setAbsender(m?.absender ?? "");
    setBenutzer(m?.benutzer ?? "");
    setPasswort("");
    setCa(m?.ca ?? "");
    setCode("");
    setFehler("");
    setInfo("");
    setBearbeiten("setzen");
  };

  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    setFehler("");
    try {
      const body: Record<string, unknown> =
        bearbeiten === "aus"
          ? { aus: true, code }
          : { server: server.trim(), port: Number(port), tls, absender: absender.trim(), benutzer: benutzer.trim(), ca, code };
      if (bearbeiten === "setzen" && passwort) body.passwort = passwort;
      await api("PUT", "/api/v1/einstellungen/mail", body);
      setBearbeiten("");
      await laden();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  const testen = async () => {
    setArbeitet(true);
    setFehler("");
    setInfo("");
    try {
      const r = await api<{ an: string }>("POST", "/api/v1/einstellungen/mail/test");
      setInfo(`Testmail an ${r.an} gesendet.`);
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  const tlsText = { starttls: "STARTTLS", tls: "TLS von Anfang an", keine: "keine (nur Loopback)" };

  return (
    <Panel id="einst-mail" titel="Mail (SMTP)">
      <p className="klein">
        Relay für alle Alarm-Mails. Empfänger sind Benutzerkonten, die Mandanten-Admins in ihren Mail-Kanälen auswählen. Das Passwort liegt
        verschlüsselt in der Datenbank und wird nie angezeigt.
      </p>
      {m === null ? (
        !fehler && <p className="klein">Lädt …</p>
      ) : m.eingerichtet ? (
        <dl className="eckdaten">
          <div>
            <dt>Server</dt>
            <dd className="umbruch">
              {m.server}:{m.port}
            </dd>
          </div>
          <div>
            <dt>Verschlüsselung</dt>
            <dd>{tlsText[m.tls ?? "starttls"]}</dd>
          </div>
          <div>
            <dt>Absender</dt>
            <dd className="umbruch">{m.absender}</dd>
          </div>
          <div>
            <dt>Anmeldung</dt>
            <dd>{m.benutzer ? `${m.benutzer}${m.passwort_gesetzt ? ", Passwort hinterlegt" : ", ohne Passwort"}` : "ohne"}</dd>
          </div>
          {m.ca && (
            <div>
              <dt>Eigene CA</dt>
              <dd>hinterlegt</dd>
            </div>
          )}
        </dl>
      ) : (
        <p>
          <span className="marke marke-warn">nicht eingerichtet – Mail-Kanäle senden nichts</span>
        </p>
      )}
      {info && (
        <p className="meldung meldung-erfolg" role="status">
          {info}
        </p>
      )}
      {!bearbeiten && m && (
        <div className="aktionen">
          <button className="knopf" onClick={oeffnen}>
            {m.eingerichtet ? "Ändern" : "Einrichten"}
          </button>
          {m.eingerichtet && (
            <>
              <button className="knopf" disabled={arbeitet} onClick={() => void testen()}>
                Testmail an mich
              </button>
              <button
                className="knopf knopf-gefahr"
                onClick={() => {
                  setCode("");
                  setFehler("");
                  setBearbeiten("aus");
                }}
              >
                Ausschalten
              </button>
            </>
          )}
        </div>
      )}
      {bearbeiten && (
        <form className="formular" onSubmit={speichern} aria-label="Mail-Einstellung ändern">
          {bearbeiten === "aus" ? (
            <p>Mailversand ausschalten? Mail-Kanäle melden dann einen Fehler.</p>
          ) : (
            <>
              <label className="feld" htmlFor="mail-server">
                <span>Server</span>
                <input
                  id="mail-server"
                  required
                  maxLength={253}
                  placeholder="mail.example.com"
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
                />
              </label>
              <label className="feld" htmlFor="mail-port">
                <span>Port</span>
                <input
                  id="mail-port"
                  required
                  inputMode="numeric"
                  pattern="[0-9]{1,5}"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                />
              </label>
              <label className="feld" htmlFor="mail-tls">
                <span>Verschlüsselung</span>
                <select
                  id="mail-tls"
                  value={tls}
                  onChange={(e) => {
                    const v = e.target.value as "starttls" | "tls" | "keine";
                    setTls(v);
                    if (v === "tls" && port === "587") setPort("465");
                    if (v === "starttls" && port === "465") setPort("587");
                  }}
                >
                  <option value="starttls">STARTTLS (meist Port 587)</option>
                  <option value="tls">TLS von Anfang an (meist Port 465)</option>
                  <option value="keine">keine (nur Relay auf Loopback)</option>
                </select>
              </label>
              <label className="feld" htmlFor="mail-absender">
                <span>Absender</span>
                <input
                  id="mail-absender"
                  type="email"
                  required
                  maxLength={254}
                  placeholder="openwacht@example.com"
                  value={absender}
                  onChange={(e) => setAbsender(e.target.value)}
                />
              </label>
              <label className="feld" htmlFor="mail-benutzer">
                <span>Benutzer (optional)</span>
                <input
                  id="mail-benutzer"
                  autoComplete="off"
                  maxLength={254}
                  value={benutzer}
                  onChange={(e) => setBenutzer(e.target.value)}
                />
              </label>
              <label className="feld" htmlFor="mail-passwort">
                <span>Passwort {m?.passwort_gesetzt ? "(leer lassen = unverändert)" : "(optional)"}</span>
                <input
                  id="mail-passwort"
                  type="password"
                  autoComplete="new-password"
                  maxLength={512}
                  value={passwort}
                  placeholder={m?.passwort_gesetzt ? "••••••••" : ""}
                  onChange={(e) => setPasswort(e.target.value)}
                />
              </label>
              <label className="feld feld-breit" htmlFor="mail-ca">
                <span>Eigene CA (PEM, optional, für ein internes Relay)</span>
                <textarea
                  id="mail-ca"
                  rows={3}
                  spellCheck={false}
                  value={ca}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  onChange={(e) => setCa(e.target.value)}
                />
              </label>
            </>
          )}
          <CodeFeld wert={code} setWert={setCode} id="einst-mail-code" />
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="aktionen">
            <button className={`knopf ${bearbeiten === "aus" ? "knopf-gefahr" : "knopf-haupt"}`} disabled={arbeitet}>
              {bearbeiten === "aus" ? "Ausschalten" : "Speichern"}
            </button>
            <button type="button" className="knopf" onClick={() => setBearbeiten("")}>
              Abbrechen
            </button>
          </div>
        </form>
      )}
      {fehler && !bearbeiten && (
        <p className="meldung meldung-fehler" role="alert">
          {fehler}
        </p>
      )}
    </Panel>
  );
}
