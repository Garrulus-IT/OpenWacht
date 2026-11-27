// SPDX-License-Identifier: AGPL-3.0-only

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type Bereitschaft, type Alarmkanal, type Alarmregeln, type KanalArt, type Mandant } from "./api";
import { vor } from "./zeit";
import { mandantName, rolleIn, type Bereich } from "./bereich";

// Anzeigezustand eines Kanals
type Anzeige = "ok" | "crit" | "neu" | "pause";

function anzeige(k: Alarmkanal): Anzeige {
  if (!k.aktiv) return "pause";
  if (k.letzter_fehler) return "crit";
  return k.zuletzt_ok ? "ok" : "neu";
}

const artName: Record<KanalArt, string> = { ntfy: "ntfy", mail: "Mail", webhook: "Webhook", teams: "Teams", sms: "SMS (brevis.one)" };

// Kurzbeschreibung unter dem Namen
function ziel(k: Alarmkanal): string {
  switch (k.typ) {
    case "ntfy":
      return `ntfy · ${k.topic}`;
    case "mail":
      return k.alle_benutzer
        ? "Mail · alle Benutzer"
        : `Mail · ${k.empfaenger.length} ${k.empfaenger.length === 1 ? "Empfänger" : "Empfänger"}`;
    case "sms":
      return k.empfaenger_art === "gruppe" ? `SMS · Gruppe ${k.gruppe ?? ""}` : `SMS · ${k.empfaenger.length} Empfänger`;
    default:
      return `${artName[k.typ]} · ${k.server.replace(/^https?:\/\//, "")}`;
  }
}

interface Props {
  bereich: Bereich;
  melden: (e: unknown) => void;
}

export function Alarme({ bereich, melden }: Props) {
  const mandant = bereich.mandant;
  // Kanäle enthalten Zugangsdaten: pflegen dürfen nur Admins.
  const admin = rolleIn(bereich, mandant.id) === "admin";
  const [kanaele, setKanaele] = useState<Alarmkanal[] | null>(null);
  const [ziele, setZiele] = useState<string[]>([]);
  const [regeln, setRegeln] = useState<Alarmregeln | null>(null);
  const [mail, setMail] = useState(false);
  const [jetzt, setJetzt] = useState(Date.now());
  const [offen, setOffen] = useState("");
  const [formular, setFormular] = useState<Alarmkanal | "neu" | null>(null);
  const [geheimnis, setGeheimnis] = useState<{ name: string; wert: string } | null>(null);

  const laden = useCallback(async () => {
    try {
      const r = await api<{ kanaele: Alarmkanal[]; ziele: string[]; regeln: Alarmregeln; mail_eingerichtet: boolean }>(
        "GET",
        bereich.mehrere ? "/api/v1/alarm-kanaele" : `/api/v1/alarm-kanaele?mandant=${mandant.id}`,
      );
      setKanaele(r.kanaele.filter((k) => bereich.ids.has(k.mandant_id)));
      setZiele(r.ziele);
      setRegeln(r.regeln);
      setMail(r.mail_eingerichtet);
      setJetzt(Date.now());
    } catch (e) {
      melden(e);
    }
  }, [bereich, mandant.id, melden]);

  useEffect(() => {
    setFormular(null);
    setOffen("");
    void laden();
    const t = setInterval(() => {
      if (!document.hidden) void laden();
    }, 30000);
    return () => clearInterval(t);
  }, [laden]);

  return (
    <section aria-labelledby="alarme-titel" className="checks">
      <div className="abschnitt-kopf">
        <h2 id="alarme-titel" className="abschnitt">
          Alarmkanäle
        </h2>
        {admin && !formular && (
          <button className="knopf" onClick={() => setFormular("neu")}>
            Kanal anlegen
          </button>
        )}
      </div>

      <MeineMails melden={melden} />
      <MeineMobilnummer melden={melden} />

      {geheimnis && (
        <div className="meldung meldung-erfolg geheimnis" role="status">
          <p>
            Webhook „{geheimnis.name}“ angelegt. Signaturschlüssel für den Empfänger (wird nur jetzt angezeigt, bitte gleich übernehmen):
          </p>
          <pre className="befehl">{geheimnis.wert}</pre>
          <p className="klein">
            Jede Anfrage trägt die Kopfzeilen webhook-id, webhook-timestamp und webhook-signature nach „Standard Webhooks“ (HMAC-SHA256 über
            „id.timestamp.rumpf“).
          </p>
          <button className="knopf" onClick={() => setGeheimnis(null)}>
            Übernommen, ausblenden
          </button>
        </div>
      )}

      {formular && (
        <KanalFormular
          mandant={mandant}
          kanal={formular === "neu" ? null : formular}
          ziele={ziele}
          mail={mail}
          onFertig={(neu, wert, name) => {
            setFormular(null);
            if (neu) setOffen(neu);
            if (neu && wert) setGeheimnis({ name: name ?? "", wert });
            void laden();
          }}
        />
      )}

      {kanaele === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : kanaele.length === 0 ? (
        !formular && (
          <p className="leer">
            {admin
              ? "Noch keine Alarmkanäle. Ein Kanal meldet per ntfy, Mail, Webhook, Teams oder SMS, sobald ein Sensor fehlschlägt, ein Host sich nicht mehr meldet, eine Platte vollläuft oder wieder alles in Ordnung ist."
              : "Für diesen Mandanten sind keine Alarmkanäle eingerichtet."}
          </p>
        )
      ) : (
        <ul className="host-liste">
          {kanaele.map((k) => (
            <KanalZeile
              key={k.id}
              k={k}
              alle={kanaele ?? []}
              jetzt={jetzt}
              offen={offen === k.id}
              onUmschalten={() => setOffen(offen === k.id ? "" : k.id)}
              admin={rolleIn(bereich, k.mandant_id) === "admin"}
              mandant={bereich.mehrere ? mandantName(bereich, k.mandant_id) : ""}
              onBearbeiten={() => setFormular(k)}
              onGeaendert={laden}
              melden={melden}
            />
          ))}
        </ul>
      )}

      {regeln && <Regeln r={regeln} />}
    </section>
  );
}

// Alarm-Mails für sich selbst an- oder abbestellen.
function MeineMails({ melden }: { melden: (e: unknown) => void }) {
  const [an, setAn] = useState<boolean | null>(null);
  useEffect(() => {
    api<{ alarm_mails: boolean }>("GET", "/api/v1/ich")
      .then((r) => setAn(r.alarm_mails))
      .catch(melden);
  }, [melden]);
  if (an === null) return null;
  return (
    <label className="haken meine-mails">
      <input
        type="checkbox"
        checked={an}
        onChange={async (e) => {
          const neu = e.target.checked;
          try {
            await api("PUT", "/api/v1/ich/alarm-mails", { an: neu });
            setAn(neu);
          } catch (err) {
            melden(err);
          }
        }}
      />
      <span>Alarm-Mails an mich senden (gilt für alle Mail-Kanäle, in denen ich Empfänger bin)</span>
    </label>
  );
}

// Mobilnummer für Alarme (0.43.0): freiwillig, nur für SMS-Kanäle, an denen
// man Empfänger ist. Andere sehen nur, ob eine Nummer hinterlegt ist.
function MeineMobilnummer({ melden }: { melden: (e: unknown) => void }) {
  const [nummer, setNummer] = useState<string | null>(null);
  const [eingabe, setEingabe] = useState("");
  const [stand, setStand] = useState("");
  useEffect(() => {
    api<{ nummer: string | null }>("GET", "/api/v1/ich/alarm-mobilnummer")
      .then((r) => {
        setNummer(r.nummer ?? "");
        setEingabe(r.nummer ?? "");
      })
      .catch(melden);
  }, [melden]);
  if (nummer === null) return null;
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    setStand("");
    try {
      const r = await api<{ nummer: string | null }>("PUT", "/api/v1/ich/alarm-mobilnummer", { nummer: eingabe.trim() });
      setNummer(r.nummer ?? "");
      setEingabe(r.nummer ?? "");
      setStand(r.nummer ? "Gespeichert." : "Entfernt.");
    } catch (err) {
      setStand(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <form className="meine-mobilnummer" onSubmit={speichern}>
      <label className="feld">
        <span>Mobilnummer für Alarme (freiwillig, nur für SMS-Kanäle, in denen ich Empfänger bin)</span>
        <input
          type="tel"
          autoComplete="tel"
          inputMode="tel"
          maxLength={30}
          value={eingabe}
          placeholder="+49 170 1234567"
          onChange={(e) => setEingabe(e.target.value)}
        />
      </label>
      <button className="knopf" disabled={eingabe.trim() === nummer}>
        {eingabe.trim() === "" && nummer ? "Entfernen" : "Speichern"}
      </button>
      {stand && (
        <span className="klein" role="status">
          {stand}
        </span>
      )}
    </form>
  );
}

// Fingerabdruck als AB:CD:… zum Vergleich mit der Anzeige des Gateways.
function pinAnzeige(pin: string): string {
  return (pin.toUpperCase().match(/.{2}/g) ?? []).join(":");
}

// Regeln: was gemeldet wird.
function Regeln({ r }: { r: Alarmregeln }) {
  const schwelle = (warn: number, krit: number, was: string) => {
    if (!warn && !krit) return `${was}: nicht überwacht.`;
    const teile = [warn ? `Warnung ab ${warn} %` : "", krit ? `kritisch ab ${krit} %` : ""].filter(Boolean);
    return `${was}: ${teile.join(", ")} belegt.`;
  };
  const min = Math.round(r.stumm_nach_s / 60);
  return (
    <details className="erweitert regeln">
      <summary>Was gemeldet wird</summary>
      <ul className="hinweis">
        <li>
          Sensoren (Ping, Ports, Webseiten …): kritisch nach {r.check_fehlschlaege} Fehlschlägen in Folge, je Sensor unter „Alarm nach“
          änderbar; Warnungen sofort.
        </li>
        <li>
          Hosts: wenn sich ein Agent {min} {min === 1 ? "Minute" : "Minuten"} lang nicht meldet. Gesperrte Agents nie.
        </li>
        <li>{schwelle(r.platte_warn, r.platte_krit, "Platten")} Netzwerkfreigaben nicht.</li>
        <li>{schwelle(r.speicher_warn, r.speicher_krit, "Arbeitsspeicher")}</li>
        <li>
          {!r.cpu_warn && !r.cpu_krit
            ? "CPU: nicht überwacht."
            : `CPU: ${[r.cpu_warn ? `Warnung ab ${r.cpu_warn} %` : "", r.cpu_krit ? `kritisch ab ${r.cpu_krit} %` : ""].filter(Boolean).join(", ")} Auslastung im Mittel über 15 Minuten.`}
        </li>
        <li>Wartung: Hosts und Sensoren in Wartung melden keine neuen Probleme und keine Erinnerungen, Entwarnungen schon.</li>
        <li>
          Entwarnung, sobald alles wieder in Ordnung ist (Messwerte 2 Prozentpunkte unter der Schwelle).
          {r.erinnerung_h > 0 && ` Besteht ein Fehler weiter, kommt nach ${r.erinnerung_h} Stunden eine Erinnerung.`}
        </li>
        <li>
          Mail: eine Nachricht je Ereignis mit Gerät, Sensor, seit wann, weiteren Problemen am Gerät und einem Graphen der letzten 24
          Stunden; ab 10 Ereignissen auf einmal eine Sammelmail.
        </li>
      </ul>
      <p className="hinweis klein">Die Schwellen stellt der Betreiber unter Einstellungen ein (global, je Mandant, je Gerät).</p>
    </details>
  );
}

// Rumpf für PUT ohne geänderte Zugangsdaten (Pausieren, Fortsetzen).
function rumpf(k: Alarmkanal, aktiv: boolean): Record<string, unknown> {
  const b: Record<string, unknown> = { name: k.name, auch_untermandanten: k.auch_untermandanten, aktiv };
  if (k.typ === "ntfy") Object.assign(b, { server: k.server, topic: k.topic });
  if (k.typ === "mail") b.alle_benutzer = k.alle_benutzer;
  if (k.typ === "sms")
    Object.assign(b, {
      server: k.server,
      sms_benutzer: k.sms_benutzer,
      fingerabdruck: k.fingerabdruck,
      empfaenger_art: k.empfaenger_art,
      gruppe: k.gruppe ?? "",
      anrufen: k.anrufen,
      ueberwachen: k.ueberwachen,
    });
  return b;
}

const tagNamen = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];

function bereitschaftText(b: Bereitschaft): string {
  const tage = b.tage.length === 7 ? "täglich" : b.tage.map((t) => tagNamen[t - 1]).join(", ");
  return `${tage} ${b.von}–${b.bis} Uhr`;
}

// Bereitschaft und Eskalation eines Kanals (Etappe 24).
function Zustellung(props: { k: Alarmkanal; alle: Alarmkanal[]; onFertig: () => void; melden: (e: unknown) => void }) {
  const { k } = props;
  const [mitZeit, setMitZeit] = useState(k.bereitschaft !== null);
  const [tage, setTage] = useState<number[]>(k.bereitschaft?.tage ?? [1, 2, 3, 4, 5]);
  const [von, setVon] = useState(k.bereitschaft?.von ?? "07:00");
  const [bis, setBis] = useState(k.bereitschaft?.bis ?? "17:00");
  const andere = props.alle.filter((x) => x.mandant_id === k.mandant_id && x.id !== k.id);
  const [ziel, setZiel] = useState(k.eskalation?.kanal ?? "");
  const [minuten, setMinuten] = useState(String(k.eskalation?.nach_minuten ?? 30));
  const [bericht, setBericht] = useState(k.monatsbericht);
  const kannSammeln = k.typ === "mail" || k.typ === "sms";
  const [sammeln, setSammeln] = useState(k.sammeln);
  const speichern = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api("PUT", `/api/v1/alarm-kanaele/${k.id}/zustellung`, {
        bereitschaft: mitZeit ? { tage, von, bis } : null,
        eskalation: ziel ? { nach_minuten: Number(minuten), kanal: ziel } : null,
        monatsbericht: k.typ === "mail" && bericht,
        ...(kannSammeln ? { sammeln } : {}),
      });
      props.onFertig();
    } catch (err) {
      props.melden(err);
    }
  };
  return (
    <form className="formular formular-flach" onSubmit={speichern} aria-label="Zustellung">
      <fieldset className="feld-gruppe formular-voll">
        <legend>Bereitschaft</legend>
        <label className="feld-check">
          <input type="checkbox" checked={mitZeit} onChange={(e) => setMitZeit(e.target.checked)} />
          <span>Nur zu bestimmten Zeiten melden (sonst warten Meldungen, bis die Zeit beginnt)</span>
        </label>
        {mitZeit && (
          <>
            <div className="formular-zeile">
              {tagNamen.map((n, i) => (
                <label className="feld-check" key={n}>
                  <input
                    type="checkbox"
                    checked={tage.includes(i + 1)}
                    onChange={(e) => setTage(e.target.checked ? [...tage, i + 1].sort() : tage.filter((t) => t !== i + 1))}
                  />
                  <span>{n}</span>
                </label>
              ))}
            </div>
            <div className="formular-zeile">
              <label className="feld">
                <span>von</span>
                <input type="time" required value={von} onChange={(e) => setVon(e.target.value)} />
              </label>
              <label className="feld">
                <span>bis (früher als „von“ = über Mitternacht)</span>
                <input type="time" required value={bis} onChange={(e) => setBis(e.target.value)} />
              </label>
            </div>
          </>
        )}
      </fieldset>
      <fieldset className="feld-gruppe formular-voll">
        <legend>Eskalation</legend>
        <div className="formular-zeile">
          <label className="feld">
            <span>Unbestätigte Alarme zusätzlich an</span>
            <select value={ziel} onChange={(e) => setZiel(e.target.value)}>
              <option value="">nicht eskalieren</option>
              {andere.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
          </label>
          {ziel && (
            <label className="feld">
              <span>nach Minuten</span>
              <input type="number" min={5} max={1440} required value={minuten} onChange={(e) => setMinuten(e.target.value)} />
            </label>
          )}
        </div>
      </fieldset>
      {kannSammeln && (
        <fieldset className="feld-gruppe formular-voll">
          <legend>Sammeln</legend>
          <label className="feld-check">
            <input type="checkbox" checked={sammeln} onChange={(e) => setSammeln(e.target.checked)} />
            <span>
              Meldungen 1 Minute sammeln und gemeinsam schicken ({k.typ === "mail" ? "eine Mail" : "eine SMS"} statt vieler,
              Entwarnungen inklusive). Ist ein Sensor innerhalb der Minute wieder OK, kommt keine Meldung.
            </span>
          </label>
        </fieldset>
      )}
      {k.typ === "mail" && (
        <fieldset className="feld-gruppe formular-voll">
          <legend>Monatsbericht</legend>
          <label className="feld-check">
            <input type="checkbox" checked={bericht} onChange={(e) => setBericht(e.target.checked)} />
            <span>Am Monatsanfang den Bericht des Vormonats als PDF an die Empfänger (jeder mit seinen eigenen Rechten)</span>
          </label>
        </fieldset>
      )}
      <div className="aktionen">
        <button className="knopf knopf-haupt">Speichern</button>
        <button type="button" className="knopf" onClick={props.onFertig}>
          Abbrechen
        </button>
      </div>
    </form>
  );
}

function KanalZeile(props: {
  k: Alarmkanal;
  alle: Alarmkanal[];
  jetzt: number;
  offen: boolean;
  onUmschalten: () => void;
  admin: boolean;
  mandant: string;
  onBearbeiten: () => void;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
}) {
  const { k, jetzt, offen } = props;
  const a = anzeige(k);
  const [loeschen, setLoeschen] = useState(false);
  const [zustellung, setZustellung] = useState(false);
  const [test, setTest] = useState<{ art: "laeuft" } | { art: "ok" } | { art: "fehler"; text: string } | null>(null);
  const detailId = `kanal-${k.id}`;

  const aktion = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      props.onGeaendert();
    } catch (e) {
      props.melden(e);
    }
  };
  const testen = async () => {
    setTest({ art: "laeuft" });
    try {
      await api("POST", `/api/v1/alarm-kanaele/${k.id}/test`);
      setTest({ art: "ok" });
    } catch (e) {
      setTest({ art: "fehler", text: e instanceof Error ? e.message : String(e) });
    }
    props.onGeaendert();
  };

  const stand =
    a === "pause"
      ? "pausiert"
      : a === "crit"
        ? `Versand gestört: ${k.letzter_fehler}`
        : a === "ok"
          ? `zuletzt gesendet ${vor(k.zuletzt_ok!, jetzt)}`
          : "noch nichts gesendet";
  const testText: Record<KanalArt, string> = {
    ntfy: `Testnachricht gesendet. Sie sollte gleich auf den Geräten erscheinen, die „${k.topic}“ abonniert haben.`,
    mail: "Testmail an die Empfänger gesendet.",
    webhook: "Test-Anfrage gesendet und angenommen.",
    teams: "Testnachricht gesendet. Sie sollte gleich im Teams-Kanal erscheinen.",
    sms: "Test-SMS gesendet. Das Gateway hat sie angenommen; sie sollte gleich auf den Handys ankommen.",
  };

  return (
    <li className={`host check-${a === "crit" ? "crit" : a}`}>
      <button className="host-kopf check-kopf" aria-expanded={offen} aria-controls={detailId} onClick={props.onUmschalten}>
        <span className="host-name">
          <span className={`signal signal-${a}`} aria-hidden="true" />
          <span>
            <span className="name">{k.name}</span>
            <span className="klein">
              {props.mandant && <span className="mandant-marke">{props.mandant}</span>}
              {ziel(k)}
              {k.auch_untermandanten ? " · mit Untermandanten" : ""}
            </span>
          </span>
        </span>
        <span className="check-stand">
          <span className="check-meldung">{stand}</span>
          {a === "crit" && k.letzter_fehler_am && (
            <span className="klein">seit {vor(k.letzter_fehler_am, jetzt).replace(/^vor /, "")}</span>
          )}
        </span>
      </button>

      {offen && (
        <div className="host-detail" id={detailId}>
          <dl className="eckdaten">
            <div>
              <dt>Art</dt>
              <dd>{artName[k.typ]}</dd>
            </div>
            {k.typ === "ntfy" && (
              <>
                <div>
                  <dt>Server</dt>
                  <dd className="umbruch">{k.server}</dd>
                </div>
                <div>
                  <dt>Topic</dt>
                  <dd className="umbruch">{k.topic}</dd>
                </div>
                <div>
                  <dt>Zugangstoken</dt>
                  <dd>{k.token_gesetzt ? "hinterlegt (wird nicht angezeigt)" : "keins"}</dd>
                </div>
              </>
            )}
            {(k.typ === "webhook" || k.typ === "teams") && (
              <div>
                <dt>Ziel</dt>
                <dd className="umbruch">{k.server} (vollständige URL hinterlegt, wird nicht angezeigt)</dd>
              </div>
            )}
            {k.typ === "webhook" && (
              <div>
                <dt>Signatur</dt>
                <dd>HMAC-SHA256 nach „Standard Webhooks“; der Schlüssel wurde beim Anlegen einmal angezeigt</dd>
              </div>
            )}
            {k.typ === "sms" && (
              <>
                <div>
                  <dt>Gateway</dt>
                  <dd className="umbruch">
                    {k.server} · Benutzer {k.sms_benutzer} (Passwort hinterlegt, wird nicht angezeigt)
                  </dd>
                </div>
                <div>
                  <dt>Zertifikat</dt>
                  <dd className="umbruch klein">{pinAnzeige(k.fingerabdruck ?? "")}</dd>
                </div>
                <div>
                  <dt>Empfänger</dt>
                  <dd>
                    {k.empfaenger_art === "gruppe"
                      ? `Gruppe „${k.gruppe}“ auf dem Gateway`
                      : k.empfaenger.length === 0
                        ? "niemand ausgewählt"
                        : k.empfaenger.map((e) => e.name + (e.mobilnummer ? "" : " (keine Mobilnummer)")).join(", ")}
                  </dd>
                </div>
                <div>
                  <dt>Anruf</dt>
                  <dd>{k.anrufen ? "bei neuen kritischen Problemen zusätzlich anrufen" : "nein"}</dd>
                </div>
                <div>
                  <dt>Gateway überwachen</dt>
                  <dd>{k.ueberwachen ? "ja, Hinweis über die anderen Kanäle, wenn es nicht erreichbar ist" : "nein"}</dd>
                </div>
              </>
            )}
            {k.typ === "mail" && (
              <div>
                <dt>Empfänger</dt>
                <dd>
                  {k.alle_benutzer
                    ? "alle Benutzer mit einer Rolle in diesem Mandanten"
                    : k.empfaenger.length === 0
                      ? "niemand ausgewählt"
                      : k.empfaenger.map((e) => e.name + (e.abbestellt ? " (abbestellt)" : "")).join(", ")}
                </dd>
              </div>
            )}
            <div>
              <dt>Meldet</dt>
              <dd>
                {k.auch_untermandanten
                  ? "Sensoren und Hosts dieses Mandanten und aller Untermandanten"
                  : "nur Sensoren und Hosts dieses Mandanten"}
              </dd>
            </div>
            {(k.typ === "mail" || k.typ === "sms") && (
              <div>
                <dt>Sammeln</dt>
                <dd>{k.sammeln ? "1 Minute, dann gemeinsam" : "nein, jede Meldung sofort"}</dd>
              </div>
            )}
            {k.typ === "mail" && (
              <div>
                <dt>Monatsbericht</dt>
                <dd>{k.monatsbericht ? "ja, als PDF am Monatsanfang" : "nein"}</dd>
              </div>
            )}
            <div>
              <dt>Bereitschaft</dt>
              <dd>{k.bereitschaft ? bereitschaftText(k.bereitschaft) : "immer"}</dd>
            </div>
            {k.eskalation && (
              <div>
                <dt>Eskalation</dt>
                <dd>
                  nach {k.eskalation.nach_minuten} Min. unbestätigt an „{props.alle.find((x) => x.id === k.eskalation?.kanal)?.name ?? "?"}“
                </dd>
              </div>
            )}
            {k.zuletzt_ok && (
              <div>
                <dt>Zuletzt erfolgreich</dt>
                <dd>{vor(k.zuletzt_ok, jetzt)}</dd>
              </div>
            )}
          </dl>
          {test?.art === "ok" && (
            <p className="meldung meldung-erfolg" role="status">
              {testText[k.typ]}
            </p>
          )}
          {test?.art === "fehler" && (
            <p className="meldung meldung-fehler" role="alert">
              {test.text}
            </p>
          )}
          {zustellung && (
            <Zustellung
              k={k}
              alle={props.alle}
              onFertig={() => {
                setZustellung(false);
                props.onGeaendert();
              }}
              melden={props.melden}
            />
          )}
          {props.admin && !zustellung && (
            <div className="aktionen">
              {loeschen ? (
                <div className="bestaetigung" role="alertdialog" aria-label="Kanal löschen">
                  <p>„{k.name}“ löschen? Danach gehen keine Alarme mehr über diesen Kanal.</p>
                  <div className="aktionen">
                    <button className="knopf knopf-gefahr" onClick={() => aktion(() => api("DELETE", `/api/v1/alarm-kanaele/${k.id}`))}>
                      Löschen
                    </button>
                    <button className="knopf" onClick={() => setLoeschen(false)}>
                      Abbrechen
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <button className="knopf knopf-haupt" disabled={test?.art === "laeuft"} onClick={() => void testen()}>
                    {test?.art === "laeuft" ? "Wird gesendet …" : "Test senden"}
                  </button>
                  <button className="knopf" onClick={props.onBearbeiten}>
                    Bearbeiten
                  </button>
                  <button className="knopf" onClick={() => setZustellung(true)}>
                    Bereitschaft und Eskalation
                  </button>
                  <button className="knopf" onClick={() => aktion(() => api("PUT", `/api/v1/alarm-kanaele/${k.id}`, rumpf(k, !k.aktiv)))}>
                    {k.aktiv ? "Pausieren" : "Fortsetzen"}
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setLoeschen(true)}>
                    Löschen
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

// --- Anlegen und bearbeiten ------------------------------------------------------

interface Kandidat {
  id: string;
  name: string;
  email: string;
  rolle: string;
  abbestellt: boolean;
  mobilnummer: boolean;
}

function KanalFormular(props: {
  mandant: Mandant;
  kanal: Alarmkanal | null;
  ziele: string[];
  mail: boolean;
  onFertig: (neueId?: string, geheimnis?: string, name?: string) => void;
}) {
  const k = props.kanal;
  const [art, setArt] = useState<KanalArt>(k?.typ ?? "ntfy");
  const [name, setName] = useState(k?.name ?? "");
  const ntfyZiele = props.ziele;
  const [server, setServer] = useState(k?.typ === "ntfy" ? k.server : (ntfyZiele[0] ?? ""));
  const [topic, setTopic] = useState(k?.topic ?? "");
  const [token, setToken] = useState("");
  const [tokenWeg, setTokenWeg] = useState(false);
  const [url, setUrl] = useState("");
  const [kinder, setKinder] = useState(k?.auch_untermandanten ?? false);
  const [alle, setAlle] = useState(k?.alle_benutzer ?? false);
  const [auswahl, setAuswahl] = useState<Set<string>>(new Set(k?.empfaenger.map((e) => e.id) ?? []));
  const [kandidaten, setKandidaten] = useState<Kandidat[] | null>(null);
  // SMS (0.43.0)
  const smsZiele = props.ziele.filter((z) => z.startsWith("https://"));
  const [gateway, setGateway] = useState(k?.typ === "sms" ? k.server : (smsZiele[0] ?? ""));
  const [smsBenutzer, setSmsBenutzer] = useState(k?.sms_benutzer ?? "");
  const [passwort, setPasswort] = useState("");
  const [pin, setPin] = useState(k?.fingerabdruck ?? "");
  const [pinStand, setPinStand] = useState("");
  const [empfaengerArt, setEmpfaengerArt] = useState<"benutzer" | "gruppe">(k?.empfaenger_art ?? "benutzer");
  const [gruppe, setGruppe] = useState(k?.gruppe ?? "");
  const [anrufen, setAnrufen] = useState(k?.anrufen ?? false);
  const [ueberwachen, setUeberwachen] = useState(k?.ueberwachen ?? true);
  const [fehler, setFehler] = useState("");
  const [sendet, setSendet] = useState(false);
  const serverNeu = k !== null && k.typ === "ntfy" && server !== k.server;
  // Server nicht (mehr) freigegeben: trotzdem anzeigen, damit die Auswahl stimmt.
  const serverListe = k?.typ === "ntfy" && !ntfyZiele.includes(k.server) ? [k.server, ...ntfyZiele] : ntfyZiele;
  const hook = art === "webhook" || art === "teams";
  // Beim Bearbeiten gehört der Kanal evtl. zu einem anderen Mandanten der Auswahl.
  const mandantId = k?.mandant_id ?? props.mandant.id;

  const zugangNeu = k !== null && k.typ === "sms" && (gateway !== k.server || smsBenutzer !== k.sms_benutzer || pin !== k.fingerabdruck);
  const gatewayListe = k?.typ === "sms" && !smsZiele.includes(k.server) ? [k.server, ...smsZiele] : smsZiele;
  const fingerabdruckHolen = async () => {
    setPinStand("Verbinde …");
    try {
      const r = await api<{ fingerabdruck: string; anzeige: string }>("POST", `/api/v1/mandanten/${mandantId}/alarm-kanaele/sms-fingerabdruck`, {
        server: gateway,
      });
      setPin(r.fingerabdruck);
      setPinStand("Übernommen. Bitte mit dem Zertifikat in der Oberfläche des Gateways vergleichen.");
    } catch (err) {
      setPinStand(err instanceof Error ? err.message : String(err));
    }
  };

  useEffect(() => {
    if (!(art === "mail" || (art === "sms" && empfaengerArt === "benutzer")) || kandidaten) return;
    api<{ benutzer: Kandidat[] }>("GET", `/api/v1/mandanten/${mandantId}/alarm-empfaenger`)
      .then((r) => setKandidaten(r.benutzer))
      .catch((e) => setFehler(e instanceof Error ? e.message : String(e)));
  }, [art, empfaengerArt, kandidaten, mandantId]);

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setSendet(true);
    const body: Record<string, unknown> = { art, name, auch_untermandanten: kinder, aktiv: k?.aktiv ?? true };
    if (art === "ntfy") {
      Object.assign(body, { server, topic: topic.trim() });
      // Token: leer lassen = unverändert; nur bei neuer Eingabe oder „entfernen“ mitschicken.
      if (token) body.token = token;
      else if (tokenWeg) body.token = "";
    } else if (art === "mail") {
      body.alle_benutzer = alle;
      body.empfaenger = alle ? [] : [...auswahl];
    } else if (art === "sms") {
      Object.assign(body, {
        server: gateway,
        sms_benutzer: smsBenutzer.trim(),
        fingerabdruck: pin,
        empfaenger_art: empfaengerArt,
        gruppe: empfaengerArt === "gruppe" ? gruppe.trim() : "",
        anrufen,
        ueberwachen,
      });
      if (passwort) body.passwort = passwort;
      if (empfaengerArt === "benutzer") body.empfaenger = [...auswahl];
    } else if (url.trim()) {
      body.url = url.trim();
    }
    try {
      if (k) {
        await api("PUT", `/api/v1/alarm-kanaele/${k.id}`, body);
        props.onFertig();
      } else {
        const r = await api<{ id: string; geheimnis?: string }>("POST", `/api/v1/mandanten/${props.mandant.id}/alarm-kanaele`, body);
        props.onFertig(r.id, r.geheimnis, name);
      }
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setSendet(false);
  };

  const zieleText = props.ziele.length ? props.ziele.join(", ") : "noch keine";
  const gesperrt =
    (art === "ntfy" && props.ziele.length === 0) || (hook && props.ziele.length === 0) || (art === "sms" && smsZiele.length === 0);

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{k ? `„${k.name}“ bearbeiten` : "Alarmkanal anlegen"}</h3>
        {!k && (
          <fieldset className="formular-voll kanal-art">
            <legend>Art</legend>
            {(["ntfy", "mail", "webhook", "teams", "sms"] as KanalArt[]).map((a) => (
              <label key={a} className="haken">
                <input type="radio" name="art" value={a} checked={art === a} onChange={() => setArt(a)} />
                <span>{artName[a]}</span>
              </label>
            ))}
          </fieldset>
        )}

        {art === "ntfy" &&
          (props.ziele.length === 0 ? (
            <p className="meldung meldung-warnung formular-voll">
              Es sind noch keine Alarmziele freigegeben. Der Betreiber trägt sie unter Einstellungen → Alarmziele ein.
            </p>
          ) : (
            <p className="hinweis formular-voll">
              Meldungen gehen per ntfy an alle Geräte, die das Topic abonniert haben. Freigegeben sind nur die Server, die der Betreiber
              eingetragen hat.
            </p>
          ))}
        {art === "mail" && (
          <p className={`formular-voll ${props.mail ? "hinweis" : "meldung meldung-warnung"}`}>
            {props.mail
              ? "Mails gehen an Benutzerkonten mit einer Rolle in diesem Mandanten. Jeder kann Alarm-Mails für sich abbestellen."
              : "Der Betreiber hat den Mailversand noch nicht eingerichtet (Einstellungen → Mail). Der Kanal lässt sich trotzdem anlegen."}
          </p>
        )}
        {art === "webhook" && (
          <p className="hinweis formular-voll">
            OpenWacht schickt je Durchlauf ein JSON (typ „openwacht.alarm“) per POST, signiert nach „Standard Webhooks“. Der Host muss als
            Alarmziel freigegeben sein. Freigegeben: {zieleText}.
          </p>
        )}
        {art === "teams" && (
          <p className="hinweis formular-voll">
            In Teams am Kanal: Workflows → „Bei Eingang einer Webhookanforderung in einem Kanal posten“, die angezeigte URL hier einfügen.
            Der Host der URL (z. B. https://prod-12.westeurope.logic.azure.com) muss als Alarmziel freigegeben sein. Freigegeben:{" "}
            {zieleText}.
          </p>
        )}

        {art === "sms" &&
          (smsZiele.length === 0 ? (
            <p className="meldung meldung-warnung formular-voll">
              Es ist noch kein Gateway als Alarmziel freigegeben. Der Betreiber trägt es unter Einstellungen → Alarmziele ein (z. B.
              https://10.20.0.60).
            </p>
          ) : (
            <p className="hinweis formular-voll">
              SMS über ein brevis.one-Gateway. Auf dem Gateway einen eigenen Systembenutzer nur mit dem Recht „Zugriff auf die HTTP API“
              anlegen, nicht admin. OpenWacht sendet immer per POST und prüft den Fingerabdruck des Zertifikats. Eine SMS je Durchlauf, höchstens
              160 Zeichen.
            </p>
          ))}

        <label className="feld">
          <span>Name</span>
          <input
            required
            maxLength={100}
            value={name}
            placeholder={art === "mail" ? "z. B. Bereitschaft per Mail" : "z. B. Bereitschaftshandy"}
            onChange={(e) => setName(e.target.value)}
          />
        </label>

        {art === "ntfy" && (
          <>
            <label className="feld">
              <span>ntfy-Server</span>
              <select required value={server} onChange={(e) => setServer(e.target.value)}>
                {serverListe.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>Topic</span>
              <input
                required
                maxLength={64}
                pattern="[\-_A-Za-z0-9]+"
                title="Buchstaben, Ziffern, - und _"
                value={topic}
                placeholder="z. B. it-betrieb-alarme"
                onChange={(e) => setTopic(e.target.value)}
              />
            </label>
            <label className="feld">
              <span>Zugangstoken {k?.token_gesetzt && !serverNeu ? "(leer lassen = unverändert)" : "(optional)"}</span>
              <input
                type="password"
                autoComplete="off"
                maxLength={200}
                value={token}
                disabled={tokenWeg}
                placeholder={k?.token_gesetzt && !serverNeu ? "••••••••" : "tk_…"}
                onChange={(e) => setToken(e.target.value)}
              />
            </label>
            {k?.token_gesetzt && !serverNeu && (
              <label className="haken formular-voll">
                <input type="checkbox" checked={tokenWeg} onChange={(e) => setTokenWeg(e.target.checked)} />
                <span>Hinterlegtes Token entfernen</span>
              </label>
            )}
            {k?.token_gesetzt && serverNeu && !token && (
              <p className="meldung meldung-warnung formular-voll">
                Beim Wechsel des Servers wird das hinterlegte Token entfernt, damit es nicht an den neuen Server geht. Bei Bedarf neu
                eingeben.
              </p>
            )}
          </>
        )}

        {hook && (
          <label className="feld formular-voll">
            <span>{k ? "Neue URL (leer lassen = unverändert)" : "URL"}</span>
            <input
              type="url"
              required={!k}
              autoComplete="off"
              spellCheck={false}
              maxLength={2000}
              value={url}
              placeholder={art === "teams" ? "https://…logic.azure.com/workflows/…" : "https://hooks.example.com/openwacht"}
              onChange={(e) => setUrl(e.target.value)}
            />
          </label>
        )}

        {art === "sms" && (
          <>
            <label className="feld">
              <span>Gateway</span>
              <select required value={gateway} onChange={(e) => setGateway(e.target.value)}>
                {gatewayListe.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
              </select>
            </label>
            <label className="feld">
              <span>API-Benutzer</span>
              <input
                required
                maxLength={64}
                autoComplete="off"
                spellCheck={false}
                value={smsBenutzer}
                placeholder="z. B. openwacht-api"
                onChange={(e) => setSmsBenutzer(e.target.value)}
              />
            </label>
            <label className="feld">
              <span>{k && !zugangNeu ? "Passwort (leer lassen = unverändert)" : "Passwort"}</span>
              <input
                type="password"
                required={!k || zugangNeu}
                autoComplete="new-password"
                maxLength={128}
                value={passwort}
                placeholder={k && !zugangNeu ? "••••••••" : ""}
                onChange={(e) => setPasswort(e.target.value)}
              />
            </label>
            <div className="feld formular-voll">
              <span>Fingerabdruck des Zertifikats (SHA-256)</span>
              <div className="zeile-knopf">
                <input
                  required
                  spellCheck={false}
                  autoComplete="off"
                  aria-label="Fingerabdruck des Zertifikats"
                  value={pinAnzeige(pin.replace(/[^0-9a-fA-F]/g, "")) || pin}
                  placeholder="mit „Fingerabdruck holen“ übernehmen"
                  onChange={(e) => setPin(e.target.value.replace(/[^0-9a-fA-F]/g, "").toLowerCase())}
                />
                <button type="button" className="knopf" disabled={!gateway} onClick={() => void fingerabdruckHolen()}>
                  Fingerabdruck holen
                </button>
              </div>
              {pinStand && (
                <span className="klein" role="status">
                  {pinStand}
                </span>
              )}
            </div>
            {k && zugangNeu && !passwort && (
              <p className="meldung meldung-warnung formular-voll">
                Bei neuem Gateway, Benutzer oder Fingerabdruck bitte das Passwort neu eingeben. Es geht nie an ein anderes Gateway.
              </p>
            )}
            <fieldset className="formular-voll kanal-art">
              <legend>Empfänger</legend>
              <label className="haken">
                <input type="radio" name="empfaenger-art" checked={empfaengerArt === "benutzer"} onChange={() => setEmpfaengerArt("benutzer")} />
                <span>Benutzer mit Mobilnummer (höchstens 20)</span>
              </label>
              <label className="haken">
                <input type="radio" name="empfaenger-art" checked={empfaengerArt === "gruppe"} onChange={() => setEmpfaengerArt("gruppe")} />
                <span>Gruppe auf dem Gateway</span>
              </label>
            </fieldset>
            {empfaengerArt === "gruppe" && (
              <label className="feld">
                <span>Gruppe (ID oder Name auf dem Gateway)</span>
                <input
                  required
                  maxLength={64}
                  value={gruppe}
                  placeholder="z. B. 3 oder Bereitschaft"
                  onChange={(e) => setGruppe(e.target.value)}
                />
              </label>
            )}
            {empfaengerArt === "benutzer" && (
              <fieldset className="formular-voll empfaenger">
                <legend>Benutzer</legend>
                {kandidaten === null ? (
                  <p className="klein" aria-busy="true">
                    Lädt …
                  </p>
                ) : kandidaten.length === 0 ? (
                  <p className="klein">In diesem Mandanten hat noch niemand eine Rolle.</p>
                ) : (
                  <ul className="auswahl-liste">
                    {kandidaten.map((c) => (
                      <li key={c.id}>
                        <label className="haken">
                          <input
                            type="checkbox"
                            checked={auswahl.has(c.id)}
                            disabled={!auswahl.has(c.id) && auswahl.size >= 20}
                            onChange={(e) => {
                              const n = new Set(auswahl);
                              if (e.target.checked) n.add(c.id);
                              else n.delete(c.id);
                              setAuswahl(n);
                            }}
                          />
                          <span>
                            {c.name} <span className="klein">{c.email}</span>
                            {!c.mobilnummer && <span className="klein"> · keine Mobilnummer hinterlegt</span>}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="klein">Jeder trägt seine Nummer selbst unter „Mobilnummer für Alarme“ ein.</p>
              </fieldset>
            )}
            <label className="haken formular-voll">
              <input type="checkbox" checked={anrufen} onChange={(e) => setAnrufen(e.target.checked)} />
              <span>Bei neuen kritischen Problemen zusätzlich anrufen (Gerät ab 2021, SIM mit Sprache)</span>
            </label>
            <label className="haken formular-voll">
              <input type="checkbox" checked={ueberwachen} onChange={(e) => setUeberwachen(e.target.checked)} />
              <span>Gateway überwachen: Hinweis über die anderen Kanäle, wenn es nicht erreichbar ist</span>
            </label>
          </>
        )}

        {art === "mail" && (
          <fieldset className="formular-voll empfaenger">
            <legend>Empfänger</legend>
            <label className="haken">
              <input type="checkbox" checked={alle} onChange={(e) => setAlle(e.target.checked)} />
              <span>Alle Benutzer mit einer Rolle in {props.mandant.name} (auch künftige)</span>
            </label>
            {!alle &&
              (kandidaten === null ? (
                <p className="klein" aria-busy="true">
                  Lädt …
                </p>
              ) : kandidaten.length === 0 ? (
                <p className="klein">In diesem Mandanten hat noch niemand eine Rolle.</p>
              ) : (
                <ul className="auswahl-liste">
                  {kandidaten.map((c) => (
                    <li key={c.id}>
                      <label className="haken">
                        <input
                          type="checkbox"
                          checked={auswahl.has(c.id)}
                          onChange={(e) => {
                            const n = new Set(auswahl);
                            if (e.target.checked) n.add(c.id);
                            else n.delete(c.id);
                            setAuswahl(n);
                          }}
                        />
                        <span>
                          {c.name} <span className="klein">{c.email}</span>
                          {c.abbestellt && <span className="klein"> · hat Alarm-Mails abbestellt</span>}
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              ))}
          </fieldset>
        )}

        <label className="haken formular-voll">
          <input type="checkbox" checked={kinder} onChange={(e) => setKinder(e.target.checked)} />
          <span>Auch Alarme aller Untermandanten von {props.mandant.name} melden</span>
        </label>
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={sendet || gesperrt}>
            {k ? "Speichern" : "Anlegen"}
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig()}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
