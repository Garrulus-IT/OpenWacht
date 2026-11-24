// SPDX-License-Identifier: AGPL-3.0-only

// FRITZ!Box eines Geräts (Etappe 18c): Internetverbindung, DSL, Verkehr und
// Laufzeit über TR-064; Einrichten mit „Verbindung prüfen“.
//
// Benutzer und Passwort verlassen die Zentrale nie wieder: Die Liste sagt nur,
// ob Zugangsdaten gespeichert sind. Einrichten, ändern und entfernen dürfen
// nur Admins. Die Zentrale ruft nur eine feste Liste lesender Aktionen auf.

import { useState, type FormEvent } from "react";
import { api, type FritzBoxInfo, type Geraet, type Snmp } from "./api";
import { SnmpVerlauf } from "./Verlauf";
import { bitrate, laufzeit } from "./Pegel";
import { vor } from "./zeit";

const teilText: Record<string, string> = {
  Gerät: "Modell und Laufzeit",
  Leitung: "Leitungskapazität",
  Verkehr: "Verkehr",
  Verbindung: "Internetverbindung",
  "Externe IP": "externe IP-Adresse",
  DSL: "DSL-Werte",
};

const zugangText: Record<string, string> = {
  DSL: "DSL",
  Ethernet: "Ethernet (Kabel, Glasfaser-Modem oder IP-Client)",
  "X_AVM-DE_Fiber": "Glasfaser",
  "X_AVM-DE_UMTS": "Mobilfunk",
};

// AB:CD:… aus 64 Hexziffern
// fehltText: „Nicht verfügbar: …“ mit dem Grund je Teil. Den Hinweis auf das
// Recht gibt es nur, wenn die Box wirklich 606 (Recht fehlt) gemeldet hat.
export function fehltText(teile: string[], gruende: string[] | undefined) {
  const g = gruende ?? [];
  const recht = g.length === 0 || g.some((x) => x.includes("(606)"));
  return (
    `Nicht verfügbar: ${teile.map((t) => teilText[t] ?? t).join(", ")}.` +
    (g.length > 0 ? ` Antwort der Box: ${g.join("; ")}.` : "") +
    (recht ? " Dafür braucht das Konto das Recht „FRITZ!Box Einstellungen“." : "")
  );
}

export function abdruck(hex: string) {
  return (hex.match(/../g) ?? []).join(":").toUpperCase();
}

export function fritzKurz(q: Snmp) {
  const f = q.messwerte?.fritzbox;
  if (!q.aktiv) return "FRITZ!Box-Abfrage ausgeschaltet";
  if (!f) return q.fehler ? `FRITZ!Box: ${q.fehler}` : "FRITZ!Box: noch nicht abgefragt";
  const teile = [f.modell || "FRITZ!Box"];
  if (f.verbindung) teile.push(f.verbunden ? "Internet verbunden" : "Internet getrennt");
  if (q.fehler) teile.push("letzte Abfrage gescheitert");
  return teile.join(", ");
}

export function FritzBoxTeil(props: {
  q: Snmp;
  g: Geraet;
  darfAdmin: boolean;
  darfPflegen: boolean;
  jetzt: number;
  onBearbeiten: () => void;
  onGeaendert: () => void;
  melden: (e: unknown) => void;
  // Etappe 19: Knöpfe stehen im Aktionsmenü des Geräts; hier nur noch die
  // Rückfrage zum Entfernen, geöffnet von außen.
  ohneAktionen?: boolean;
  entfernen?: boolean;
  onEntfernenEnde?: () => void;
}) {
  const { q, jetzt } = props;
  const m = q.messwerte;
  const f = m?.fritzbox;
  const wan = m?.schnittstellen.find((i) => i.name === "WAN");
  const [eigenEntfernen, setEigenEntfernen] = useState(false);
  const entfernen = props.ohneAktionen ? !!props.entfernen : eigenEntfernen;
  const setEntfernen = (x: boolean) => {
    if (!props.ohneAktionen) setEigenEntfernen(x);
    else if (!x) props.onEntfernenEnde?.();
  };
  const fehlt = f?.nicht_verfuegbar ?? [];

  return (
    <div className="geraet-snmp geraet-fritzbox">
      <h3 className="klein-titel">
        {f?.modell || "FRITZ!Box"}
        {f?.fritzos ? ` · FRITZ!OS ${f.fritzos}` : ""}
        {!q.aktiv && <span className="marke marke-ende">ausgeschaltet</span>}
      </h3>
      <p className="klein">
        {q.adresse}:{q.port}, alle {q.intervall_sekunden} s{q.zuletzt_ok ? `, zuletzt beantwortet ${vor(q.zuletzt_ok, jetzt)}` : ""}
        {!q.hat_community && " · keine Zugangsdaten gespeichert"}
        {f && (f.tls ? ` · HTTPS, Zertifikat ${abdruck(f.fingerabdruck ?? "").slice(0, 23)}…` : " · HTTP im LAN")}
      </p>
      {q.fehler && (
        <p className="meldung meldung-fehler" role="status">
          Letzte Abfrage: {q.fehler}
        </p>
      )}
      {fehlt.length > 0 && (
        <p className="meldung meldung-warnung">
          {fehltText(fehlt, f?.nicht_verfuegbar_grund)}
        </p>
      )}

      {m && f && (
        <dl className="eckdaten">
          <div>
            <dt>Internet</dt>
            <dd className={f.verbindung && !f.verbunden ? "text-crit" : undefined}>
              {!f.verbindung
                ? "nicht verfügbar"
                : f.verbunden
                  ? `verbunden${f.verbunden_seit_s ? ` seit ${laufzeit(f.verbunden_seit_s).replace(/\.$/, "")}` : ""}`
                  : `getrennt (${f.verbindung})${f.letzter_fehler && f.letzter_fehler !== "ERROR_NONE" ? `, ${f.letzter_fehler}` : ""}`}
            </dd>
          </div>
          {f.externe_ip && (
            <div>
              <dt>Externe IP</dt>
              <dd className="mono">{f.externe_ip}</dd>
            </div>
          )}
          {f.zugang && (
            <div>
              <dt>Zugang</dt>
              <dd>{zugangText[f.zugang] ?? f.zugang}</dd>
            </div>
          )}
          {f.dsl && (
            <div>
              <dt>DSL-Sync</dt>
              <dd>
                {f.dsl.status === "Up" ? (
                  <>
                    ↓ {bitrate(f.dsl.ab_bps)} · ↑ {bitrate(f.dsl.auf_bps)}
                    {f.dsl.ab_max_bps > 0 && (
                      <span className="klein">
                        {" "}
                        (Leitungskapazität ↓ {bitrate(f.dsl.ab_max_bps)} · ↑ {bitrate(f.dsl.auf_max_bps)})
                      </span>
                    )}
                  </>
                ) : (
                  <span className="text-crit">{f.dsl.status}</span>
                )}
              </dd>
            </div>
          )}
          {!f.dsl && (f.leitung_ab_bps ?? 0) > 0 && (
            <div>
              <dt>Leitung</dt>
              <dd>
                ↓ {bitrate(f.leitung_ab_bps ?? 0)} · ↑ {bitrate(f.leitung_auf_bps ?? 0)}
              </dd>
            </div>
          )}
          {wan && (
            <div>
              <dt>Verkehr jetzt</dt>
              <dd>{wan.ein_bps === null || wan.aus_bps === null ? "ab der nächsten Abfrage" : `↓ ${bitrate(wan.ein_bps)} · ↑ ${bitrate(wan.aus_bps)}`}</dd>
            </div>
          )}
          {m.system.laufzeit_s > 0 && (
            <div>
              <dt>Läuft seit</dt>
              <dd>
                {laufzeit(m.system.laufzeit_s)}
                {q.neustart_am && ` (Neustart erkannt ${vor(q.neustart_am, jetzt)})`}
              </dd>
            </div>
          )}
        </dl>
      )}

      {m && <SnmpVerlauf snmpId={q.id} schnittstellen={wan ? ["WAN"] : []} />}

      {(props.darfPflegen || props.darfAdmin) && (!props.ohneAktionen || entfernen) && (
        <div className="aktionen">
          {entfernen ? (
            <div className="bestaetigung" role="alertdialog" aria-label="FRITZ!Box-Abfrage entfernen">
              <p>
                FRITZ!Box-Abfrage für „{props.g.name}“ entfernen? Zugangsdaten, Verlauf und Meldezustand gehen verloren; das Alarmprotokoll
                bleibt. Das Konto in der FRITZ!Box bitte zusätzlich löschen.
              </p>
              <div className="aktionen">
                <button
                  className="knopf knopf-gefahr"
                  onClick={async () => {
                    try {
                      await api("DELETE", `/api/v1/geraete/${props.g.id}/fritzbox`);
                      props.onGeaendert();
                    } catch (e) {
                      props.melden(e);
                    }
                    setEntfernen(false);
                  }}
                >
                  Entfernen
                </button>
                <button className="knopf" onClick={() => setEntfernen(false)}>
                  Abbrechen
                </button>
              </div>
            </div>
          ) : (
            <>
              {props.darfPflegen && q.aktiv && (
                <button
                  className="knopf"
                  onClick={async () => {
                    try {
                      await api("POST", `/api/v1/snmp/${q.id}/jetzt`);
                      setTimeout(props.onGeaendert, 2500);
                    } catch (e) {
                      props.melden(e);
                    }
                  }}
                >
                  Jetzt abfragen
                </button>
              )}
              {props.darfAdmin && (
                <>
                  <button className="knopf" onClick={props.onBearbeiten}>
                    FRITZ!Box bearbeiten
                  </button>
                  <button className="knopf knopf-gefahr" onClick={() => setEntfernen(true)}>
                    FRITZ!Box entfernen
                  </button>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// --- Einrichten und bearbeiten ---------------------------------------------------------

type Pruefung = { ok: true; fritzbox: FritzBoxInfo } | { ok: false; fehler: string; fingerabdruck_neu?: string };

export function FritzBoxFormular(props: { g: Geraet; q: Snmp | null; onFertig: () => void; melden: (e: unknown) => void }) {
  const q = props.q;
  const gespeichert = q?.messwerte?.fritzbox;
  const [adresse, setAdresse] = useState(q?.adresse ?? props.g.adresse ?? "");
  const [https, setHttps] = useState(gespeichert?.tls ?? q?.port === 49443);
  const [port, setPort] = useState(q ? String(q.port) : "");
  const [benutzer, setBenutzer] = useState("");
  const [passwort, setPasswort] = useState("");
  // leer = beim Ändern der gespeicherte Fingerabdruck
  const [abdruckFeld, setAbdruckFeld] = useState("");
  const [intervall, setIntervall] = useState(String(q?.intervall_sekunden ?? 60));
  const [aktiv, setAktiv] = useState(q?.aktiv ?? true);
  const [fehler, setFehler] = useState("");
  const [pruefung, setPruefung] = useState<Pruefung | null>(null);
  const [prueft, setPrueft] = useState(false);
  const standardPort = https ? 49443 : 49000;
  const portZahl = Number(port) || standardPort;
  const zielNeu = !q || adresse.trim() !== q.adresse || portZahl !== q.port || https !== (gespeichert?.tls ?? q.port === 49443);

  const daten = () => {
    const d: Record<string, unknown> = {
      adresse: adresse.trim(),
      port: portZahl,
      https,
      intervall_sekunden: Number(intervall) || 60,
      aktiv,
    };
    if (benutzer.trim() || passwort) {
      d.benutzer = benutzer.trim();
      d.passwort = passwort;
    }
    if (https && abdruckFeld.trim()) d.fingerabdruck = abdruckFeld.trim();
    return d;
  };
  const pruefen = async () => {
    setFehler("");
    setPruefung(null);
    setPrueft(true);
    try {
      setPruefung(await api<Pruefung>("POST", `/api/v1/geraete/${props.g.id}/fritzbox/pruefen`, daten()));
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
    setPrueft(false);
  };
  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      await api("PUT", `/api/v1/geraete/${props.g.id}/fritzbox`, daten());
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };
  const neuerAbdruck = pruefung && !pruefung.ok ? pruefung.fingerabdruck_neu : undefined;
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">{q ? "FRITZ!Box bearbeiten" : `FRITZ!Box für „${props.g.name}“ einrichten`}</h3>
        <details className="formular-voll hinweis">
          <summary>Konto und TR-064 in der FRITZ!Box einrichten</summary>
          <ol className="klein">
            <li>
              Heimnetz → Netzwerk → Netzwerkeinstellungen: „Zugriff für Anwendungen zulassen“ einschalten (TR-064, nur aus dem
              Heimnetz).
            </li>
            <li>
              System → FRITZ!Box-Benutzer → Benutzer hinzufügen, z. B. <span className="mono">openwacht</span>, mit eigenem, langem
              Passwort. Recht: nur „FRITZ!Box Einstellungen“, alle anderen aus, „Zugang auch aus dem Internet“ aus.
            </li>
          </ol>
          <p className="klein">
            TR-064 kennt kein reines Leserecht: Ohne „FRITZ!Box Einstellungen“ liefert die Box fast keine Werte. Das Konto könnte damit
            Einstellungen ändern. OpenWacht ruft nur eine feste Liste lesender Aktionen auf, speichert das Passwort verschlüsselt und
            gebunden an Adresse und Port; pflegen dürfen es nur Admins.
          </p>
        </details>
        <label className="feld">
          <span>Adresse der FRITZ!Box</span>
          <input
            required
            maxLength={253}
            value={adresse}
            placeholder="192.168.178.1 oder fritz.box"
            onChange={(e) => setAdresse(e.target.value)}
          />
        </label>
        <label className="feld feld-schmal">
          <span>Port</span>
          <input inputMode="numeric" pattern="[0-9]*" value={port} placeholder={String(standardPort)} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label className="haken formular-voll">
          <input
            type="checkbox"
            checked={https}
            onChange={(e) => {
              setHttps(e.target.checked);
              // Standard-Port mitwechseln, ein eigener bleibt
              if (port === "" || port === String(standardPort)) setPort(e.target.checked ? "49443" : "49000");
            }}
          />
          <span>HTTPS (Port 49443; das Zertifikat der Box wird über seinen Fingerabdruck geprüft)</span>
        </label>
        <label className="feld">
          <span>Benutzer{q ? " (leer = unverändert)" : ""}</span>
          <input
            autoComplete="off"
            spellCheck={false}
            required={!q || zielNeu || passwort !== ""}
            maxLength={64}
            value={benutzer}
            placeholder={q ? "unverändert" : "openwacht"}
            onChange={(e) => setBenutzer(e.target.value)}
          />
        </label>
        <label className="feld">
          <span>Passwort{zielNeu && q ? " (bei neuer Adresse, neuem Port oder HTTPS-Wechsel neu eingeben)" : q ? " (leer = unverändert)" : ""}</span>
          <input
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            required={!q || zielNeu || benutzer.trim() !== ""}
            maxLength={128}
            value={passwort}
            placeholder={q ? "••••••••" : ""}
            onChange={(e) => setPasswort(e.target.value)}
          />
        </label>
        {https && (
          <label className="feld formular-voll">
            <span>
              Fingerabdruck des Zertifikats (SHA-256)
              {gespeichert?.fingerabdruck && !zielNeu ? " (leer = unverändert)" : " (über „Verbindung prüfen“ holen)"}
            </span>
            <input
              spellCheck={false}
              className="mono"
              maxLength={100}
              value={abdruckFeld}
              placeholder={gespeichert?.fingerabdruck ? abdruck(gespeichert.fingerabdruck) : "AB:CD:…"}
              onChange={(e) => setAbdruckFeld(e.target.value)}
            />
          </label>
        )}
        <label className="feld feld-schmal">
          <span>Abfrage alle</span>
          <select value={intervall} onChange={(e) => setIntervall(e.target.value)}>
            {[30, 60, 120, 300, 600, 900, 1800, 3600].map((s) => (
              <option key={s} value={s}>
                {s < 60 ? `${s} Sekunden` : s < 3600 ? `${s / 60} Min.` : "1 Std."}
              </option>
            ))}
          </select>
        </label>
        {q && (
          <label className="haken formular-voll">
            <input type="checkbox" checked={aktiv} onChange={(e) => setAktiv(e.target.checked)} />
            <span>Abfrage eingeschaltet</span>
          </label>
        )}
        {pruefung &&
          (pruefung.ok ? (
            <p
              className={`meldung ${pruefung.fritzbox.nicht_verfuegbar.length ? "meldung-warnung" : "meldung-ok"} formular-voll`}
              role="status"
            >
              Verbunden mit {pruefung.fritzbox.modell || "der FRITZ!Box"}
              {pruefung.fritzbox.fritzos ? `, FRITZ!OS ${pruefung.fritzbox.fritzos}` : ""}
              {pruefung.fritzbox.laufzeit_s > 0 ? `, läuft seit ${laufzeit(pruefung.fritzbox.laufzeit_s).replace(/\.$/, "")}` : ""}.{" "}
              {pruefung.fritzbox.verbunden ? "Internet verbunden." : "Internet nicht verbunden."}
              {pruefung.fritzbox.nicht_verfuegbar.length > 0 &&
                ` ${fehltText(pruefung.fritzbox.nicht_verfuegbar, pruefung.fritzbox.nicht_verfuegbar_grund)}`}
            </p>
          ) : neuerAbdruck ? (
            <div className="meldung meldung-warnung formular-voll" role="status">
              <p>
                {pruefung.fehler} Die FRITZ!Box zeigt dieses Zertifikat:
                <br />
                <span className="mono umbruch">{neuerAbdruck}</span>
              </p>
              <p className="klein">
                Zum Vergleich im Browser https://{adresse.trim() || "fritz.box"} öffnen und den SHA-256-Fingerabdruck des Zertifikats
                ansehen. Nur übernehmen, wenn er übereinstimmt.
              </p>
              <button type="button" className="knopf" onClick={() => setAbdruckFeld(neuerAbdruck)}>
                Fingerabdruck übernehmen
              </button>
            </div>
          ) : (
            <p className="meldung meldung-fehler formular-voll" role="status">
              Keine Verbindung: {pruefung.fehler}
            </p>
          ))}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">Speichern</button>
          <button type="button" className="knopf" disabled={prueft} onClick={() => void pruefen()}>
            {prueft ? "Prüft …" : "Verbindung prüfen"}
          </button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
