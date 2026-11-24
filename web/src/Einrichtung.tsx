// SPDX-License-Identifier: AGPL-3.0-only

import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError } from "./api";
import { Wortmarke } from "./Wortmarke";
import { QRCode } from "./ZweiFaktor";

// Einrichtungsassistent (Etappe 21a). Erreichbar nur über den Link aus
// `openwacht-zentrale installieren` (…/einrichtung#<Token>). Das Token wird
// gegen ein HttpOnly-Cookie getauscht und aus der Adresszeile entfernt.

// vollerName: ein DNS-Name mit Punkt, keine IP-Adresse (openwacht.firma.example ja, openwacht und 10.0.0.5 nein).
function vollerName(a: string): boolean {
  return a.includes(".") && !/^[0-9.]+$/.test(a) && !a.includes(":");
}

interface Vorschlaege {
  adressen: string[] | null; // null bei älteren Zentralen, wenn die Adressen nicht lesbar waren
  netze: string[] | null;
  zeitzone: string;
  sicherung: { uhr: number; tage: number };
  token_gueltig_min: number;
  zwei_faktor_fuer?: string;
  https?: HttpsInfo;
}

interface HttpsInfo {
  art: "eigene-ca" | "hochgeladen";
  namen: string[];
  fingerabdruck: string;
  ca_fingerabdruck?: string;
  gueltig_bis: string;
  aussteller: string;
}

type Tls = "starttls" | "tls" | "keine";

const SCHRITTE = [
  "Mandant",
  "Erster Admin",
  "Adresse",
  "HTTPS",
  "Zeitzone",
  "Netzfreigabe",
  "Mail",
  "Sicherung",
  "Zusammenfassung",
] as const;

function liste(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// Grobe Einschätzung für die Anzeige; verbindlich prüft die Zentrale
// (mindestens 12 Zeichen, nicht die E-Mail-Adresse).
function staerke(pw: string): { wert: number; text: string } {
  if (pw.length === 0) return { wert: 0, text: "" };
  let klassen = 0;
  for (const re of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]) if (re.test(pw)) klassen++;
  if (pw.length < 12) return { wert: 1, text: "zu kurz (mindestens 12 Zeichen)" };
  const punkte = Math.min(4, Math.floor(pw.length / 6) + klassen - 2);
  if (punkte <= 1) return { wert: 2, text: "schwach" };
  if (punkte === 2) return { wert: 3, text: "mittel" };
  return { wert: 4, text: "stark" };
}

function zeitzonen(): string[] {
  try {
    const f = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
    if (f) return f("timeZone");
  } catch {
    // ältere Browser
  }
  return ["Europe/Berlin", "Europe/Vienna", "Europe/Zurich", "UTC"];
}

function Fehler({ text }: { text: string }) {
  if (!text) return null;
  return (
    <p className="meldung meldung-fehler" role="alert">
      {text}
    </p>
  );
}

export function Einrichtung() {
  const [laden, setLaden] = useState(true);
  const [sperre, setSperre] = useState<{ text: string; fertig: boolean } | null>(null);
  const [v, setV] = useState<Vorschlaege | null>(null);
  const [schritt, setSchritt] = useState(0);
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  // Felder
  const [mandant, setMandant] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [totp, setTotp] = useState<{ geheimnis: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [totpFuer, setTotpFuer] = useState("");
  const [adressen, setAdressen] = useState("");
  const [httpsArt, setHttpsArt] = useState<"eigene-ca" | "hochgeladen">("eigene-ca");
  const [zert, setZert] = useState("");
  const [schl, setSchl] = useState("");
  const [https, setHttps] = useState<HttpsInfo | null>(null);
  const [zone, setZone] = useState("Europe/Berlin");
  const [netze, setNetze] = useState("");
  const [mailAn, setMailAn] = useState(false);
  const [mServer, setMServer] = useState("");
  const [mPort, setMPort] = useState("587");
  const [mTls, setMTls] = useState<Tls>("starttls");
  const [mAbs, setMAbs] = useState("");
  const [mBen, setMBen] = useState("");
  const [mPw, setMPw] = useState("");
  const [mTest, setMTest] = useState("");
  const [uhr, setUhr] = useState(0);
  const [tage, setTage] = useState(14);
  const [ergebnis, setErgebnis] = useState<{ adresse: string; https: HttpsInfo } | null>(null);

  const uebernehmen = (d: Vorschlaege) => {
    setV(d);
    setAdressen((d.adressen ?? []).join("\n"));
    setNetze((d.netze ?? []).join("\n"));
    setZone(d.zeitzone);
    setUhr(d.sicherung.uhr);
    setTage(d.sicherung.tage);
    if (d.zwei_faktor_fuer) setTotpFuer(d.zwei_faktor_fuer);
    if (d.https) setHttps(d.https);
  };

  useEffect(() => {
    const token = window.location.hash.replace(/^#/, "");
    const start = token ? api<Vorschlaege>("POST", "/api/v1/einrichtung/start", { token }) : api<Vorschlaege>("GET", "/api/v1/einrichtung");
    start
      .then((d) => {
        uebernehmen(d);
        if (token) window.history.replaceState(null, "", "/einrichtung");
      })
      .catch((e) => {
        const fertig = e instanceof ApiError && e.status === 410;
        setSperre({
          fertig,
          text: fertig
            ? "Die Einrichtung ist abgeschlossen."
            : token
              ? e.message
              : "Bitte den Einrichtungslink aus der Installation öffnen (er endet auf #…). Einen neuen gibt sudo openwacht-zentrale einrichtungslink aus.",
        });
      })
      .finally(() => setLaden(false));
  }, []);

  const zonen = useMemo(zeitzonen, []);
  const st = staerke(pw);
  const adressListe = liste(adressen);
  const mailDaten = () => ({
    server: mServer.trim(),
    port: Number(mPort),
    tls: mTls,
    absender: mAbs.trim(),
    benutzer: mBen.trim(),
    passwort: mPw,
  });

  const lauf = async (f: () => Promise<void>) => {
    setFehler("");
    setArbeitet(true);
    try {
      await f();
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    } finally {
      setArbeitet(false);
    }
  };

  const totpBeginnen = () =>
    lauf(async () => {
      const d = await api<{ geheimnis: string; uri: string }>("POST", "/api/v1/einrichtung/zwei-faktor", { email });
      setTotp(d);
      setTotpFuer("");
      setCode("");
    });

  const totpPruefen = () =>
    lauf(async () => {
      const r = await api<{ email: string }>("POST", "/api/v1/einrichtung/zwei-faktor/pruefen", { code });
      setTotpFuer(r.email);
      setTotp(null);
    });

  const httpsErzeugen = () =>
    lauf(async () => {
      const r = await api<HttpsInfo>("POST", "/api/v1/einrichtung/https", {
        art: httpsArt,
        adressen: adressListe,
        zertifikat: zert,
        schluessel: schl,
      });
      setHttps(r);
      setSchl("");
    });

  const testmail = () =>
    lauf(async () => {
      setMTest("");
      const r = await api<{ an: string }>("POST", "/api/v1/einrichtung/testmail", { mail: mailDaten(), an: email });
      setMTest(`Testmail an ${r.an} verschickt. Bitte im Postfach nachsehen.`);
    });

  const fertig = () =>
    lauf(async () => {
      const r = await api<{ adresse: string; https: HttpsInfo }>("POST", "/api/v1/einrichtung/fertig", {
        mandant,
        admin: { name, email, passwort: pw },
        adressen: adressListe,
        zeitzone: zone,
        netze: liste(netze),
        mail: mailAn ? mailDaten() : null,
        sicherung: { uhr, tage },
      });
      setPw("");
      setPw2("");
      setMPw("");
      setErgebnis(r);
    });

  const httpsPasst = https !== null && https.namen.join(",") === adressListe.join(",");
  const emailNorm = email.trim().toLowerCase();

  // Darf man weiter? (Grobe Prüfung; die Zentrale prüft alles bei „Fertig“.)
  const weiterGesperrt = (() => {
    switch (schritt) {
      case 0:
        return mandant.trim() === "";
      case 1:
        return name.trim() === "" || pw.length < 12 || pw !== pw2 || totpFuer === "" || totpFuer !== emailNorm;
      case 2:
        return adressListe.length === 0;
      case 3:
        return !httpsPasst;
      case 6:
        return mailAn && (mServer.trim() === "" || mAbs.trim() === "");
      default:
        return false;
    }
  })();

  const weiter = (e: FormEvent) => {
    e.preventDefault();
    if (weiterGesperrt || arbeitet) return;
    setFehler("");
    if (schritt < SCHRITTE.length - 1) setSchritt(schritt + 1);
    else void fertig();
  };

  if (laden) return <div className="seite-mittig" aria-busy="true" />;

  if (sperre) {
    return (
      <main className="seite-mittig">
        <div className="tafel tafel-breit">
          <Wortmarke />
          <h1 className="titel">Einrichtung</h1>
          <p className={sperre.fertig ? "meldung meldung-ok" : "meldung meldung-fehler"} role="alert">
            {sperre.text}
          </p>
          {sperre.fertig && (
            <a className="knopf knopf-haupt" href="/">
              Zur Anmeldung
            </a>
          )}
        </div>
      </main>
    );
  }

  if (ergebnis) {
    const ca = ergebnis.https.art === "eigene-ca";
    return (
      <main className="seite-mittig">
        <div className="tafel tafel-breit assistent">
          <Wortmarke />
          <h1 className="titel">OpenWacht ist eingerichtet</h1>
          <p className="meldung meldung-ok">
            Hauptmandant, Admin und Einstellungen sind gespeichert. Der Einrichtungslink gilt nicht mehr.
          </p>
          {ca ? (
            <>
              <h2 className="untertitel">Wurzelzertifikat installieren</h2>
              <p>
                Damit der Browser der Zentrale vertraut, installierst du die OpenWacht-Wurzel einmal auf jedem PC und Handy. Sie gilt nur
                für {ergebnis.https.namen.join(", ")}, nicht für andere Seiten.
              </p>
              <p>
                <a className="knopf" href="/openwacht-wurzel.crt" download>
                  Wurzelzertifikat laden
                </a>
              </p>
              <p className="klein">Fingerabdruck (SHA-256) zum Vergleichen:</p>
              <code className="schluessel abdruck">{ergebnis.https.ca_fingerabdruck}</code>
              <ul className="klein">
                <li>
                  Windows: Doppelklick → Zertifikat installieren → Lokaler Computer → „Vertrauenswürdige Stammzertifizierungsstellen“.
                </li>
                <li>
                  iPhone: Datei öffnen, Profil installieren, dann Einstellungen → Allgemein → Info → Zertifikatsvertrauenseinstellungen →
                  einschalten.
                </li>
              </ul>
            </>
          ) : (
            <p>Die Zentrale benutzt dein hochgeladenes Zertifikat.</p>
          )}
          <a className="knopf knopf-haupt" href={ergebnis.adresse}>
            Zur Anmeldung ({ergebnis.adresse})
          </a>
          <p className="klein">Anmelden mit E-Mail, Passwort und Code aus der Authenticator-App.</p>
        </div>
      </main>
    );
  }

  let inhalt: ReactNode = null;
  switch (schritt) {
    case 0:
      inhalt = (
        <>
          <p className="hinweis">
            Der Hauptmandant steht ganz oben im Baum, zum Beispiel die IT. Darunter legst du später Untermandanten an.
          </p>
          <label className="feld">
            <span>Name des Hauptmandanten</span>
            <input value={mandant} onChange={(e) => setMandant(e.target.value)} maxLength={100} placeholder="IT" autoFocus />
          </label>
        </>
      );
      break;
    case 1:
      inhalt = (
        <>
          <p className="hinweis">Der erste Admin ist Admin des Hauptmandanten und Betreiber (Seite Einstellungen).</p>
          <label className="feld">
            <span>Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} autoComplete="name" />
          </label>
          <label className="feld">
            <span>E-Mail</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
          </label>
          <label className="feld">
            <span>Passwort</span>
            <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
          </label>
          {pw && (
            <div className="staerke" data-wert={st.wert} aria-live="polite">
              <span className="staerke-balken">
                <span style={{ width: `${st.wert * 25}%` }} />
              </span>
              <span className="klein">{st.text}</span>
            </div>
          )}
          <label className="feld">
            <span>Passwort wiederholen</span>
            <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />
          </label>
          {pw2 && pw !== pw2 && <p className="klein">Die beiden Eingaben stimmen nicht überein.</p>}
          <h2 className="untertitel">Zwei-Faktor-Anmeldung</h2>
          {totpFuer && totpFuer === emailNorm ? (
            <p className="meldung meldung-ok">Eingerichtet für {totpFuer}.</p>
          ) : totp ? (
            <>
              <div className="zweifa-reihe">
                <div className="qr-rahmen">
                  <QRCode text={totp.uri} />
                </div>
                <div className="zweifa-text">
                  <p>Scanne den Code mit der Authenticator-App oder gib den Schlüssel von Hand ein:</p>
                  <code className="schluessel">{totp.geheimnis.match(/.{1,4}/g)?.join(" ")}</code>
                </div>
              </div>
              <label className="feld">
                <span>Code aus der App</span>
                <input
                  className="code-eingabe"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                />
              </label>
              <button type="button" className="knopf" disabled={arbeitet || code.length !== 6} onClick={() => void totpPruefen()}>
                Code prüfen
              </button>
            </>
          ) : (
            <button type="button" className="knopf" disabled={arbeitet || !email.includes("@")} onClick={() => void totpBeginnen()}>
              Zwei-Faktor-Anmeldung einrichten
            </button>
          )}
          {totpFuer && totpFuer !== emailNorm && (
            <p className="klein">Die E-Mail-Adresse hat sich geändert: bitte die Zwei-Faktor-Anmeldung neu einrichten.</p>
          )}
        </>
      );
      break;
    case 2:
      inhalt = (
        <>
          <p className="hinweis">
            Unter diesen Namen bzw. Adressen erreichen Browser und Agents die Zentrale. Die erste ist die Adresse der Oberfläche; alle
            stehen im HTTPS-Zertifikat. Eine pro Zeile.
          </p>
          <label className="feld">
            <span>Adressen</span>
            <textarea
              rows={4}
              value={adressen}
              onChange={(e) => setAdressen(e.target.value)}
              placeholder={"openwacht.example.com\n10.10.0.5"}
            />
          </label>
          {adressListe.length > 0 && <p className="klein">Oberfläche: https://{adressListe[0]}</p>}
          {adressListe.length > 0 && !adressListe.some(vollerName) && (
            <p className="meldung meldung-warnung">
              Kein vollständiger Name dabei (z. B. openwacht.firma.example). Browser und Agents im Netz erreichen die Zentrale meist nur
              darüber; fehlt er im Zertifikat, warnt der Browser. Den Namen aus dem DNS bzw. Router hier zuerst eintragen.
            </p>
          )}
        </>
      );
      break;
    case 3:
      inhalt = (
        <>
          <fieldset className="feld-gruppe">
            <legend>Zertifikat für {adressListe.join(", ")}</legend>
            <label className="feld-check">
              <input type="radio" name="https" checked={httpsArt === "eigene-ca"} onChange={() => setHttpsArt("eigene-ca")} />
              <span>Selbst erzeugen (eigene OpenWacht-Wurzel, gilt nur für diese Adressen, erneuert sich selbst)</span>
            </label>
            <label className="feld-check">
              <input type="radio" name="https" checked={httpsArt === "hochgeladen"} onChange={() => setHttpsArt("hochgeladen")} />
              <span>Eigenes Zertifikat hochladen (z. B. von der Firmen-CA)</span>
            </label>
          </fieldset>
          {httpsArt === "hochgeladen" && (
            <>
              <label className="feld">
                <span>Zertifikat mit Kette (PEM)</span>
                <textarea rows={5} value={zert} onChange={(e) => setZert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
              </label>
              <label className="feld">
                <span>Privater Schlüssel (PEM)</span>
                <textarea rows={4} value={schl} onChange={(e) => setSchl(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
              </label>
            </>
          )}
          <button type="button" className="knopf" disabled={arbeitet} onClick={() => void httpsErzeugen()}>
            {httpsArt === "eigene-ca" ? "Zertifikat erzeugen" : "Zertifikat prüfen"}
          </button>
          {https && (
            <div className={httpsPasst ? "meldung meldung-ok" : "meldung meldung-fehler"}>
              {httpsPasst ? (
                <>
                  <p>
                    {https.art === "eigene-ca" ? "Eigene Wurzel erzeugt" : "Zertifikat geprüft"} für {https.namen.join(", ")}, gültig bis{" "}
                    {new Date(https.gueltig_bis).toLocaleDateString("de-DE")}.
                  </p>
                  {https.ca_fingerabdruck && (
                    <>
                      <p className="klein">Fingerabdruck der Wurzel (SHA-256), nach der Installation auf PC und Handy vergleichen:</p>
                      <code className="schluessel abdruck">{https.ca_fingerabdruck}</code>
                    </>
                  )}
                </>
              ) : (
                <p>Die Adressen haben sich geändert. Bitte das Zertifikat neu erzeugen.</p>
              )}
            </div>
          )}
        </>
      );
      break;
    case 4:
      inhalt = (
        <>
          <p className="hinweis">Für Uhrzeiten in Mails, Wartungsfenstern und die Sicherung.</p>
          <label className="feld">
            <span>Zeitzone</span>
            <input list="zonen" value={zone} onChange={(e) => setZone(e.target.value)} />
            <datalist id="zonen">
              {zonen.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
          </label>
        </>
      );
      break;
    case 5:
      inhalt = (
        <>
          <p className="hinweis">
            Nur diese Netze dürfen die Sensoren der Zentrale (Ping, Ports, Webseiten) und SNMP-Abfragen erreichen. Vorgeschlagen ist das
            Netz dieses Rechners. Leer = keine. Eine pro Zeile, z. B. 10.10.0.0/16.
          </p>
          <label className="feld">
            <span>Freigegebene Netze</span>
            <textarea rows={4} value={netze} onChange={(e) => setNetze(e.target.value)} placeholder="10.10.0.0/16" />
          </label>
        </>
      );
      break;
    case 6:
      inhalt = (
        <>
          <label className="feld-check">
            <input type="checkbox" checked={mailAn} onChange={(e) => setMailAn(e.target.checked)} />
            <span>Alarm-Mails über ein SMTP-Relay verschicken (geht auch später unter Einstellungen → Mail)</span>
          </label>
          {mailAn && (
            <>
              <label className="feld">
                <span>Server</span>
                <input value={mServer} onChange={(e) => setMServer(e.target.value)} placeholder="smtp.example.com" />
              </label>
              <label className="feld">
                <span>Verschlüsselung</span>
                <select
                  value={mTls}
                  onChange={(e) => {
                    const t = e.target.value as Tls;
                    setMTls(t);
                    if (t === "tls") setMPort("465");
                    if (t === "starttls") setMPort("587");
                  }}
                >
                  <option value="starttls">STARTTLS (meist Port 587)</option>
                  <option value="tls">TLS von Anfang an (meist Port 465)</option>
                  <option value="keine">keine (nur Loopback)</option>
                </select>
              </label>
              <label className="feld">
                <span>Port</span>
                <input inputMode="numeric" value={mPort} onChange={(e) => setMPort(e.target.value.replace(/\D/g, ""))} />
              </label>
              <label className="feld">
                <span>Absender</span>
                <input value={mAbs} onChange={(e) => setMAbs(e.target.value)} placeholder="openwacht@example.com" />
              </label>
              <label className="feld">
                <span>Benutzer (leer = ohne Anmeldung)</span>
                <input value={mBen} onChange={(e) => setMBen(e.target.value)} autoComplete="off" />
              </label>
              {mBen.trim() && (
                <label className="feld">
                  <span>Passwort</span>
                  <input type="password" value={mPw} onChange={(e) => setMPw(e.target.value)} autoComplete="new-password" />
                </label>
              )}
              <button
                type="button"
                className="knopf"
                disabled={arbeitet || !mServer.trim() || !mAbs.trim()}
                onClick={() => void testmail()}
              >
                Testmail an {email || "den Admin"}
              </button>
              {mTest && <p className="meldung meldung-ok">{mTest}</p>}
            </>
          )}
        </>
      );
      break;
    case 7:
      inhalt = (
        <>
          <p className="hinweis">
            Die Zentrale sichert die Datenbank täglich nach /var/backups/openwacht. Den Hauptschlüssel (/etc/openwacht/schluessel) bitte
            getrennt aufbewahren, zum Beispiel im Passwortmanager.
          </p>
          <label className="feld">
            <span>Uhrzeit ({zone})</span>
            <select value={uhr} onChange={(e) => setUhr(Number(e.target.value))}>
              {Array.from({ length: 24 }, (_, h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, "0")}:05
                </option>
              ))}
            </select>
          </label>
          <label className="feld">
            <span>Aufbewahren (Tage)</span>
            <input
              inputMode="numeric"
              value={tage}
              onChange={(e) => setTage(Math.min(365, Number(e.target.value.replace(/\D/g, "")) || 0))}
            />
          </label>
        </>
      );
      break;
    case 8:
      inhalt = (
        <dl className="zusammenfassung">
          <dt>Hauptmandant</dt>
          <dd>{mandant}</dd>
          <dt>Admin</dt>
          <dd>
            {name} ({emailNorm}), Zwei-Faktor eingerichtet
          </dd>
          <dt>Oberfläche</dt>
          <dd>https://{adressListe[0]}</dd>
          <dt>Weitere Adressen</dt>
          <dd>{adressListe.slice(1).join(", ") || "–"}</dd>
          <dt>HTTPS</dt>
          <dd>{https?.art === "eigene-ca" ? "eigene OpenWacht-Wurzel" : "hochgeladenes Zertifikat"}</dd>
          <dt>Zeitzone</dt>
          <dd>{zone}</dd>
          <dt>Netzfreigabe</dt>
          <dd>{liste(netze).join(", ") || "keine"}</dd>
          <dt>Mail</dt>
          <dd>{mailAn ? `${mServer} (${mTls}, Port ${mPort})` : "später"}</dd>
          <dt>Sicherung</dt>
          <dd>
            täglich {String(uhr).padStart(2, "0")}:05, {tage} Tage
          </dd>
        </dl>
      );
      break;
  }

  return (
    <main className="seite-mittig">
      <form className="tafel tafel-breit assistent" onSubmit={weiter}>
        <Wortmarke />
        <h1 className="titel">Einrichtung</h1>
        <ol className="schritte" aria-label="Schritte">
          {SCHRITTE.map((s, i) => (
            <li
              key={s}
              className={i === schritt ? "aktiv" : i < schritt ? "erledigt" : undefined}
              aria-current={i === schritt ? "step" : undefined}
            >
              <span className="nr">{i + 1}</span>
              <span className="text">{s}</span>
            </li>
          ))}
        </ol>
        <h2 className="untertitel">
          {schritt + 1}. {SCHRITTE[schritt]}
        </h2>
        {inhalt}
        <Fehler text={fehler} />
        <div className="knopf-reihe">
          {schritt > 0 && (
            <button type="button" className="knopf" onClick={() => (setFehler(""), setSchritt(schritt - 1))}>
              Zurück
            </button>
          )}
          <button type="submit" className="knopf knopf-haupt" disabled={weiterGesperrt || arbeitet}>
            {schritt === SCHRITTE.length - 1 ? "Fertig" : schritt === 6 && !mailAn ? "Überspringen" : "Weiter"}
          </button>
        </div>
        {v && <p className="klein">Der Einrichtungslink gilt {v.token_gueltig_min} Minuten ab dem Erzeugen.</p>}
      </form>
    </main>
  );
}
