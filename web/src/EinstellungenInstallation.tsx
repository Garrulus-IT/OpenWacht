// SPDX-License-Identifier: AGPL-3.0-only

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api } from "./api";
import { bestaetigungFertig, CodeFeld } from "./Bestaetigung";
import { mitBasis } from "./basis";

// Einstellungen → Installation und HTTPS (Etappe 21a).

interface HttpsInfo {
  aktiv: boolean;
  art?: "einrichtung" | "eigene-ca" | "hochgeladen";
  namen?: string[];
  gueltig_bis?: string;
  fingerabdruck?: string;
  aussteller?: string;
  ca_fingerabdruck?: string;
  ca_gueltig_bis?: string;
}

interface Installation {
  adresse: string;
  namen: string[] | null;
  zeitzone: string;
  sicherung: { uhr: number; tage: number };
  https: HttpsInfo;
  audit_tage: number | null;
}

// Audit-Log (Etappe 31): Prüfung der Hash-Kette, Export, Aufbewahrung.
interface AuditZustand {
  aufbewahrung_tage: number | null;
  geprueft: {
    zeit: string;
    ok: boolean;
    bruch: number | null;
    eintraege: number;
    erste: number | null;
    letzte: number | null;
    letzter_hash?: string;
  } | null;
  gekuerzt: { zeit: string; anzahl: number } | null;
  export: { ziel: "datei" | "syslog"; ort: string; stand: number | null; fehler: string | null; fehler_seit: string | null }[];
}

const auditStufen: { tage: number | null; text: string }[] = [
  { tage: null, text: "unbegrenzt" },
  { tage: 365, text: "1 Jahr" },
  { tage: 730, text: "2 Jahre" },
  { tage: 1095, text: "3 Jahre" },
  { tage: 1825, text: "5 Jahre" },
  { tage: 3650, text: "10 Jahre" },
];

function auditText(t: number | null) {
  return auditStufen.find((x) => x.tage === t)?.text ?? `${t} Tage`;
}

interface Sicherung {
  beginn: string;
  ende: string;
  datei: string | null;
  groesse: number | null;
  ok: boolean;
  meldung: string | null;
  geloescht: string | null;
}

function groesse(b: number | null) {
  if (b === null) return "–";
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

function datum(s?: string) {
  return s ? new Date(s).toLocaleDateString("de-DE") : "–";
}

export function InstallationPanels(props: {
  Panel: (p: { titel: string; id: string; rechts?: ReactNode; children: ReactNode }) => ReactNode;
}) {
  const { Panel } = props;
  const [d, setD] = useState<Installation | null>(null);
  const [fehler, setFehler] = useState("");
  const [info, setInfo] = useState("");
  const [bearbeiten, setBearbeiten] = useState(false);
  const [zone, setZone] = useState("");
  const [uhr, setUhr] = useState(0);
  const [tage, setTage] = useState(14);
  const [https, setHttps] = useState<"" | "eigene-ca" | "hochgeladen">("");
  const [zert, setZert] = useState("");
  const [schl, setSchl] = useState("");
  const [code, setCode] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const [adrForm, setAdrForm] = useState(false);
  const [adressen, setAdressen] = useState("");
  const [adrCode, setAdrCode] = useState("");
  const [adrZert, setAdrZert] = useState("");
  const [adrSchl, setAdrSchl] = useState("");
  const [sicherungen, setSicherungen] = useState<Sicherung[] | null>(null);
  const [auditTage, setAuditTage] = useState<number | null>(null);
  const [audit, setAudit] = useState<AuditZustand | null>(null);
  const [agentCA, setAgentCA] = useState<AgentCAZustand | null>(null);

  const laden = useCallback(async () => {
    try {
      setD(await api<Installation>("GET", "/api/v1/einstellungen/installation"));
      setSicherungen((await api<{ sicherungen: Sicherung[] }>("GET", "/api/v1/einstellungen/sicherungen")).sicherungen);
      setAudit(await api<AuditZustand>("GET", "/api/v1/einstellungen/audit"));
      setAgentCA(await api<AgentCAZustand>("GET", "/api/v1/einstellungen/agent-ca"));
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void laden();
  }, [laden]);

  const lauf = async (f: () => Promise<void>) => {
    setArbeitet(true);
    setFehler("");
    setInfo("");
    try {
      await f();
      await laden();
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    } finally {
      setArbeitet(false);
    }
  };

  const speichern = (e: FormEvent) => {
    e.preventDefault();
    void lauf(async () => {
      await api("PUT", "/api/v1/einstellungen/installation", { zeitzone: zone.trim(), sicherung: { uhr, tage }, audit_tage: auditTage });
      setBearbeiten(false);
    });
  };

  const adresseSpeichern = (e: FormEvent) => {
    e.preventDefault();
    void lauf(async () => {
      const r = await api<{ adresse: string; neustart: boolean }>("PUT", "/api/v1/einstellungen/adresse", {
        adressen: adressen.split(/[\s,;]+/).filter(Boolean),
        code: adrCode,
        zertifikat: adrZert,
        schluessel: adrSchl,
      });
      setAdrForm(false);
      setAdrCode("");
      setAdrSchl("");
      setInfo(
        r.neustart
          ? `Gespeichert. Die Zentrale startet neu (etwa 15 Sekunden) und ist dann unter ${r.adresse} erreichbar.`
          : `Gespeichert. Bitte die Zentrale neu starten (systemctl restart openwacht-zentrale); danach gilt ${r.adresse}.`,
      );
    });
  };

  const httpsSpeichern = (art: "erneuern" | "eigene-ca" | "hochgeladen") =>
    lauf(async () => {
      await api("PUT", "/api/v1/einstellungen/https", { art, zertifikat: zert, schluessel: schl, code });
      setHttps("");
      setSchl("");
      setCode("");
      setInfo(
        art === "eigene-ca"
          ? "Neue Wurzel erzeugt. Bitte auf PC und Handy neu installieren (die alte gilt nicht mehr)."
          : "Gespeichert. Neue Verbindungen benutzen das neue Zertifikat.",
      );
    });

  if (!d) return fehler ? <p className="meldung meldung-fehler">{fehler}</p> : null;
  const h = d.https;
  return (
    <>
      <Panel
        id="einst-installation"
        titel="Installation"
        rechts={
          !bearbeiten && (
            <button
              className="knopf knopf-klein"
              onClick={() => {
                setZone(d.zeitzone);
                setUhr(d.sicherung.uhr);
                setTage(d.sicherung.tage);
                setAuditTage(d.audit_tage);
                setBearbeiten(true);
              }}
            >
              Bearbeiten
            </button>
          )
        }
      >
        {!bearbeiten ? (
          <dl className="zusammenfassung">
            <dt>Oberfläche</dt>
            <dd>{d.adresse}</dd>
            <dt>Adressen</dt>
            <dd>{d.namen?.join(", ") || "per Startoption"}</dd>
            <dt>Zeitzone</dt>
            <dd>{d.zeitzone}</dd>
            <dt>Sicherung</dt>
            <dd>
              täglich {String(d.sicherung.uhr).padStart(2, "0")}:05, {d.sicherung.tage} Tage aufbewahren
            </dd>
            <dt>Audit-Log</dt>
            <dd>{auditText(d.audit_tage)} aufbewahren</dd>
          </dl>
        ) : (
          <form className="formular" onSubmit={speichern}>
            <label className="feld">
              <span>Zeitzone</span>
              <input value={zone} onChange={(e) => setZone(e.target.value)} placeholder="Europe/Berlin" />
            </label>
            <label className="feld">
              <span>Sicherung, Uhrzeit</span>
              <select value={uhr} onChange={(e) => setUhr(Number(e.target.value))}>
                {Array.from({ length: 24 }, (_, i) => (
                  <option key={i} value={i}>
                    {String(i).padStart(2, "0")}:05
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Aufbewahren (Tage)</span>
              <input inputMode="numeric" value={tage} onChange={(e) => setTage(Number(e.target.value.replace(/\D/g, "")) || 0)} />
            </label>
            <label className="feld">
              <span>Audit-Log aufbewahren</span>
              <select value={auditTage ?? ""} onChange={(e) => setAuditTage(e.target.value === "" ? null : Number(e.target.value))}>
                {auditStufen.map((x) => (
                  <option key={x.text} value={x.tage ?? ""}>
                    {x.text}
                  </option>
                ))}
              </select>
              <small className="klein">
                Ältere Einträge löscht die Zentrale nach der täglichen Prüfung, nur am Anfang der Kette und erst, wenn sie exportiert sind.
              </small>
            </label>
            <div className="knopf-reihe">
              <button type="button" className="knopf" onClick={() => setBearbeiten(false)}>
                Abbrechen
              </button>
              <button className="knopf knopf-haupt" disabled={arbeitet}>
                Speichern
              </button>
            </div>
          </form>
        )}
        {h.aktiv && !adrForm && !bearbeiten && (
          <button
            className="knopf knopf-klein"
            onClick={() => {
              setAdressen((d.namen ?? []).join("\n"));
              setAdrForm(true);
            }}
          >
            Adresse ändern …
          </button>
        )}
        {adrForm && (
          <form className="formular" onSubmit={adresseSpeichern}>
            <p className="hinweis">
              Neue Namen bzw. IP-Adressen der Zentrale, eine pro Zeile; die erste ist die Adresse der Oberfläche.{" "}
              {h.art === "hochgeladen"
                ? "Dazu gehört ein Zertifikat für die neuen Namen."
                : "Es gibt eine neue Wurzel, die auf allen PCs und Handys neu installiert werden muss."}{" "}
              Agents erreichen die Zentrale weiter unter der Adresse, mit der sie registriert sind; fällt ein alter Name weg, müssen sie neu
              registriert werden. Die Zentrale startet danach neu.
            </p>
            <label className="feld">
              <span>Adressen</span>
              <textarea rows={3} value={adressen} onChange={(e) => setAdressen(e.target.value)} />
            </label>
            {h.art === "hochgeladen" && (
              <>
                <label className="feld">
                  <span>Zertifikat mit Kette (PEM)</span>
                  <textarea rows={4} value={adrZert} onChange={(e) => setAdrZert(e.target.value)} />
                </label>
                <label className="feld">
                  <span>Privater Schlüssel (PEM)</span>
                  <textarea rows={3} value={adrSchl} onChange={(e) => setAdrSchl(e.target.value)} />
                </label>
              </>
            )}
            <CodeFeld wert={adrCode} setWert={setAdrCode} id="adresse-code" />
            <div className="knopf-reihe">
              <button type="button" className="knopf" onClick={() => setAdrForm(false)}>
                Abbrechen
              </button>
              <button className="knopf knopf-haupt" disabled={arbeitet || !bestaetigungFertig(adrCode)}>
                Adresse speichern
              </button>
            </div>
          </form>
        )}
      </Panel>
      <Panel id="einst-sicherungen" titel="Sicherungen">
        <p className="klein">
          Ordner /var/backups/openwacht auf der Zentrale. Zurückholen: sudo openwacht-zentrale wiederherstellen (Runbook). Der Hauptschlüssel
          gehört getrennt in den Passwortmanager.
        </p>
        {sicherungen === null ? null : sicherungen.length === 0 ? (
          <p className="klein">Noch keine Sicherung gelaufen.</p>
        ) : (
          <table className="tabelle">
            <thead>
              <tr>
                <th>Zeit</th>
                <th>Datei</th>
                <th>Größe</th>
                <th>Zustand</th>
              </tr>
            </thead>
            <tbody>
              {sicherungen.slice(0, 20).map((b) => (
                <tr key={b.beginn}>
                  <td>{new Date(b.beginn).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}</td>
                  <td className="abdruck">{b.datei ?? "–"}</td>
                  <td>{groesse(b.groesse)}</td>
                  <td>
                    {b.ok ? (
                      b.geloescht ? (
                        "gelöscht (Aufbewahrung)"
                      ) : (
                        "vorhanden"
                      )
                    ) : (
                      <span className="meldung-text-fehler">Fehler: {b.meldung}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      {audit && <AuditPanel Panel={Panel} a={audit} />}
      {agentCA && <AgentCAPanel Panel={Panel} a={agentCA} />}
      <Panel id="einst-https" titel="HTTPS">
        {!h.aktiv ? (
          <p className="klein">TLS macht ein Reverse Proxy oder eine Startoption (-tls-zertifikat); hier gibt es nichts einzustellen.</p>
        ) : (
          <>
            <dl className="zusammenfassung">
              <dt>Art</dt>
              <dd>
                {h.art === "eigene-ca" ? "eigene OpenWacht-Wurzel" : h.art === "hochgeladen" ? "hochgeladenes Zertifikat" : "vorläufig"}
              </dd>
              <dt>Gilt für</dt>
              <dd>{h.namen?.join(", ")}</dd>
              <dt>Gültig bis</dt>
              <dd>
                {datum(h.gueltig_bis)}
                {h.art === "eigene-ca" && " (erneuert sich 30 Tage vorher selbst)"}
              </dd>
              <dt>Aussteller</dt>
              <dd>{h.aussteller}</dd>
              {h.ca_fingerabdruck && (
                <>
                  <dt>Wurzel (SHA-256)</dt>
                  <dd>
                    <code className="abdruck">{h.ca_fingerabdruck}</code>
                  </dd>
                </>
              )}
            </dl>
            {h.art === "eigene-ca" && (
              <p>
                <a className="knopf knopf-klein" href={mitBasis("/openwacht-wurzel.crt")} download>
                  Wurzelzertifikat laden
                </a>
              </p>
            )}
            {info && <p className="meldung meldung-ok">{info}</p>}
            {https === "" ? (
              <div className="knopf-reihe">
                {h.art === "eigene-ca" && (
                  <button className="knopf knopf-klein" disabled={arbeitet} onClick={() => void httpsSpeichern("erneuern")}>
                    Serverzertifikat erneuern
                  </button>
                )}
                <button className="knopf knopf-klein" onClick={() => setHttps("eigene-ca")}>
                  Neue Wurzel …
                </button>
                <button className="knopf knopf-klein" onClick={() => setHttps("hochgeladen")}>
                  Eigenes hochladen …
                </button>
              </div>
            ) : (
              <form
                className="formular"
                onSubmit={(e) => {
                  e.preventDefault();
                  void httpsSpeichern(https);
                }}
              >
                {https === "eigene-ca" ? (
                  <p className="hinweis">
                    Erzeugt eine neue Wurzel für {h.namen?.join(", ")}. Danach muss sie auf allen PCs und Handys neu installiert werden.
                  </p>
                ) : (
                  <>
                    <label className="feld">
                      <span>Zertifikat mit Kette (PEM)</span>
                      <textarea rows={5} value={zert} onChange={(e) => setZert(e.target.value)} />
                    </label>
                    <label className="feld">
                      <span>Privater Schlüssel (PEM)</span>
                      <textarea rows={4} value={schl} onChange={(e) => setSchl(e.target.value)} />
                    </label>
                  </>
                )}
                <CodeFeld wert={code} setWert={setCode} id="https-code" />
                <div className="knopf-reihe">
                  <button type="button" className="knopf" onClick={() => setHttps("")}>
                    Abbrechen
                  </button>
                  <button className="knopf knopf-haupt" disabled={arbeitet || !bestaetigungFertig(code)}>
                    {https === "eigene-ca" ? "Neue Wurzel erzeugen" : "Hochladen"}
                  </button>
                </div>
              </form>
            )}
          </>
        )}
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
      </Panel>
    </>
  );
}

// Etappe 32: Agent-CAs mit Laufzeit; der Wechsel läuft in der Shell
// (openwacht-zentrale agent-ca), weil er den Hauptschlüssel braucht.
interface AgentCAEintrag {
  zustand: "aktiv" | "neu" | "alt";
  fingerabdruck: string;
  name: string;
  gueltig_bis: string;
  agents_kennen: number;
  agents_mit_zertifikat: number;
}

interface AgentCAZustand {
  cas: AgentCAEintrag[];
  agents: number;
  agents_ohne_meldung: number;
  geladen: string[];
}

const caZustand: Record<AgentCAEintrag["zustand"], string> = {
  aktiv: "aktiv (stellt aus)",
  neu: "neu (wird verteilt)",
  alt: "alt (gilt noch)",
};

function restTage(bis: string): number {
  return Math.floor((new Date(bis).getTime() - Date.now()) / 86400000);
}

function AgentCAPanel(props: {
  Panel: (p: { titel: string; id: string; rechts?: ReactNode; children: ReactNode }) => ReactNode;
  a: AgentCAZustand;
}) {
  const { Panel, a } = props;
  const neuGeladen = a.cas.some((c) => !a.geladen.includes(c.fingerabdruck)) || a.geladen.length !== a.cas.length;
  return (
    <Panel id="einst-agent-ca" titel="Agent-CA">
      <p className="klein">
        Die Agent-CA stellt die Zertifikate der Agents und des Agent-Ports aus. Wechsel in drei Schritten mit{" "}
        <code>sudo openwacht-zentrale agent-ca -neu</code>, <code>-umstellen</code> und <code>-alte-entfernen</code> (Handbuch Kapitel 14).
        Gezählt werden {a.agents} Agent(s) mit Meldung in den letzten 30 Tagen
        {a.agents_ohne_meldung > 0 ? `, ${a.agents_ohne_meldung} ohne Meldung` : ""}.
      </p>
      {neuGeladen && (
        <p className="klein meldung-text-fehler" role="status">
          Die Zentrale nutzt noch den Stand vor der letzten Änderung: neu starten (systemctl restart openwacht-zentrale).
        </p>
      )}
      <table className="tabelle">
        <thead>
          <tr>
            <th>CA</th>
            <th>Gültig bis</th>
            <th>Agents</th>
          </tr>
        </thead>
        <tbody>
          {a.cas.map((c) => {
            const tage = restTage(c.gueltig_bis);
            return (
              <tr key={c.fingerabdruck}>
                <td>
                  <strong>{caZustand[c.zustand]}</strong>
                  <br />
                  {c.name}
                  <br />
                  <span className="abdruck klein">{c.fingerabdruck}</span>
                </td>
                <td>
                  {datum(c.gueltig_bis)}
                  {tage < 365 && <span className={tage < 90 ? " meldung-text-fehler" : ""}> (noch {tage} Tage)</span>}
                </td>
                <td>
                  kennen sie: {c.agents_kennen} von {a.agents}
                  <br />
                  Zertifikat von ihr: {c.agents_mit_zertifikat}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}

function AuditPanel(props: {
  Panel: (p: { titel: string; id: string; rechts?: ReactNode; children: ReactNode }) => ReactNode;
  a: AuditZustand;
}) {
  const { Panel, a } = props;
  const g = a.geprueft;
  const zeit = (s: string) => new Date(s).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
  return (
    <Panel
      id="einst-audit"
      titel="Audit-Log"
      rechts={
        <a className="knopf knopf-klein" href={mitBasis("/api/v1/audit/export?anzahl=5000")} download="openwacht-audit.jsonl">
          Exportieren
        </a>
      }
    >
      {g && !g.ok && (
        <p className="meldung meldung-fehler" role="alert">
          Die Hash-Kette ist ab Eintrag {g.bruch} gebrochen. Einträge wurden verändert oder gelöscht. Mit{" "}
          <code>openwacht-zentrale audit-pruefen -datei …</code> gegen einen Export prüfen.
        </p>
      )}
      <dl className="zusammenfassung">
        <dt>Geprüft</dt>
        <dd>
          {g ? (
            <>
              {zeit(g.zeit)}: {g.ok ? "Kette in Ordnung" : "Kette gebrochen"}, {g.eintraege} Einträge
              {g.erste !== null && g.letzte !== null && ` (Nr. ${g.erste} bis ${g.letzte})`}
            </>
          ) : (
            "noch nicht (täglich, erster Lauf kurz nach dem Start)"
          )}
        </dd>
        {g?.letzter_hash && (
          <>
            <dt>Letzter Hash</dt>
            <dd>
              <code className="umbruch hash-klein">{g.letzter_hash}</code>
            </dd>
          </>
        )}
        <dt>Aufbewahrung</dt>
        <dd>
          {auditText(a.aufbewahrung_tage)}
          {a.gekuerzt && `, zuletzt gekürzt ${zeit(a.gekuerzt.zeit)} (insgesamt ${a.gekuerzt.anzahl} Einträge)`}
        </dd>
        <dt>Fortlaufender Export</dt>
        <dd>
          {a.export.length === 0
            ? "aus (Startoptionen -audit-datei bzw. -audit-syslog)"
            : a.export.map((x) => (
                <div key={x.ziel}>
                  {x.ziel === "datei" ? "Datei" : "Syslog über TLS"} {x.ort}: bis Nr. {x.stand ?? 0}
                  {x.fehler && (
                    <span className="marke marke-crit">
                      {" "}
                      Fehler seit {x.fehler_seit ? zeit(x.fehler_seit) : "?"}: {x.fehler}
                    </span>
                  )}
                </div>
              ))}
        </dd>
      </dl>
      <p className="hinweis klein">
        Jeder Eintrag trägt seine Folgenummer und den Hash seines Vorgängers. Einen Export außerhalb der Zentrale aufbewahren: Er ist der
        Anker, gegen den sich die Datenbank später prüfen lässt.
      </p>
    </Panel>
  );
}
