// SPDX-License-Identifier: AGPL-3.0-only

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { encode } from "uqr";
import { api, ApiError, setCsrf, type Ich } from "./api";
import { passkeyErzeugen, passkeyFehler, passkeyMoeglich, type RegOptionen } from "./passkey";
import { Dialog } from "./Startseite";
import { Wortmarke } from "./Wortmarke";

interface Props {
  ich: Ich;
  onFertig: () => void;
  onAbmelden: () => void;
}

// QR-Code als SVG aus der Modulmatrix. Kein innerHTML: Die URI enthält die
// E-Mail-Adresse, also Nutzerdaten.
export function QRCode({ text, label = "QR-Code für die Authenticator-App" }: { text: string; label?: string }) {
  const matrix = useMemo(() => encode(text, { ecc: "M", border: 2 }).data, [text]);
  const n = matrix.length;
  const pfad = useMemo(() => {
    let d = "";
    matrix.forEach((zeile, y) =>
      zeile.forEach((an, x) => {
        if (an) d += `M${x} ${y}h1v1h-1z`;
      }),
    );
    return d;
  }, [matrix]);
  return (
    <svg className="qr" viewBox={`0 0 ${n} ${n}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#fff" />
      <path d={pfad} fill="#1d2733" />
    </svg>
  );
}

// Wiederherstellungscodes anzeigen (Etappe 30): nur dieses eine Mal, die
// Zentrale speichert sie nicht im Klartext.
export function CodeListe({ codes }: { codes: string[] }) {
  return (
    <>
      <ol className="codes" aria-label="Wiederherstellungscodes">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ol>
      <p className="klein">
        Bewahre die Codes getrennt vom Handy auf, z. B. ausgedruckt oder im Passwort-Manager. Jeder Code gilt einmal, falls das Gerät mit
        der App verloren geht. Sie werden nur jetzt angezeigt.
      </p>
      <div className="knopf-reihe">
        <button type="button" className="knopf" onClick={() => void navigator.clipboard?.writeText(codes.join("\n"))}>
          Kopieren
        </button>
      </div>
    </>
  );
}

// Neue Wiederherstellungscodes erzeugen (die alten verfallen), mit Code aus der App.
export function WiederherstellungsDialog(props: { offen: number; onZu: () => void }) {
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const erzeugen = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setArbeitet(true);
    try {
      const r = await api<{ wiederherstellungscodes: string[] }>("POST", "/api/v1/zwei-faktor/codes", { code });
      setCodes(r.wiederherstellungscodes);
    } catch (err) {
      setCode("");
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <Dialog titel="Wiederherstellungscodes" onZu={props.onZu}>
      {codes ? (
        <CodeListe codes={codes} />
      ) : (
        <form onSubmit={erzeugen}>
          <p className="klein">
            {props.offen > 0 ? `Noch ${props.offen} von 10 Codes offen.` : "Keine Codes offen."} Neue Codes ersetzen alle bisherigen. Ohne
            App und ohne Code hilft nur der Betreiber auf der Zentrale (Befehl zweifaktor-zuruecksetzen).
          </p>
          <label className="feld">
            <span>Code aus der Authenticator-App</span>
            <input
              className="code-eingabe"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
          </label>
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}
            </p>
          )}
          <div className="knopf-reihe">
            <button className="knopf knopf-haupt" disabled={arbeitet || code.length !== 6}>
              Neue Codes erzeugen
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

export function ZweiFaktorEinrichten({ ich, onFertig, onAbmelden }: Props) {
  const [daten, setDaten] = useState<{ geheimnis: string; uri: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  useEffect(() => {
    let aktiv = true;
    api<{ geheimnis: string; uri: string }>("POST", "/api/v1/zwei-faktor/einrichten")
      .then((d) => aktiv && setDaten(d))
      .catch((e: Error) => aktiv && setFehler(e.message));
    return () => {
      aktiv = false;
    };
  }, []);

  const bestaetigen = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setArbeitet(true);
    try {
      const r = await api<{ csrf: string; wiederherstellungscodes?: string[] }>("POST", "/api/v1/zwei-faktor/bestaetigen", { code });
      setCsrf(r.csrf);
      if (r.wiederherstellungscodes?.length) {
        setCodes(r.wiederherstellungscodes);
      } else {
        onFertig();
      }
    } catch (err) {
      setCode("");
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  const gruppiert = daten?.geheimnis.match(/.{1,4}/g)?.join(" ") ?? "";

  if (codes) {
    return (
      <main className="seite-mittig">
        <div className="tafel tafel-breit">
          <Wortmarke />
          <h1 className="titel">Wiederherstellungscodes notieren</h1>
          <p className="hinweis">Die Zwei-Faktor-Anmeldung ist eingerichtet. Mit diesen Codes meldest du dich an, wenn das Handy fehlt.</p>
          <CodeListe codes={codes} />
          <button className="knopf knopf-haupt" type="button" onClick={onFertig}>
            Codes notiert, weiter
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="seite-mittig">
      <form className="tafel tafel-breit" onSubmit={bestaetigen}>
        <Wortmarke />
        <h1 className="titel">Zwei-Faktor-Anmeldung einrichten</h1>
        <p className="hinweis">
          Für dein Konto ist die Zwei-Faktor-Anmeldung Pflicht: Du meldest dich mit Passwort und einem Code aus einer Authenticator-App an,
          zum Beispiel Microsoft Authenticator, Google Authenticator oder 2FAS.
        </p>
        <div className="zweifa-reihe">
          <div className="qr-rahmen">{daten ? <QRCode text={daten.uri} /> : <div className="qr qr-leer" aria-busy="true" />}</div>
          <div className="zweifa-text">
            <p>Scanne den Code mit der App. Ohne Kamera gibst du den Schlüssel von Hand ein:</p>
            <code className="schluessel">{gruppiert}</code>
            <p className="klein">Konto: {ich.email}</p>
          </div>
        </div>
        <label className="feld">
          <span>Code aus der App</span>
          <input
            className="code-eingabe"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          />
        </label>
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
        <button className="knopf knopf-haupt" type="submit" disabled={arbeitet || !daten || code.length !== 6}>
          Einrichtung abschließen
        </button>
        <button type="button" className="knopf-text" onClick={onAbmelden}>
          Abmelden
        </button>
      </form>
    </main>
  );
}

// --- Passkeys (Etappe 36) ------------------------------------------------------

interface PasskeyEintrag {
  id: string;
  name: string;
  verfahren: string;
  angelegt: string;
  zuletzt: string | null;
}

const datum = (s: string | null) => (s ? new Date(s).toLocaleDateString("de-DE") : "noch nie");

export function PasskeyDialog(props: { onZu: () => void }) {
  const [liste, setListe] = useState<PasskeyEintrag[] | null>(null);
  const [moeglich, setMoeglich] = useState(true);
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [fehler, setFehler] = useState("");
  const [meldung, setMeldung] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const laden = async () => {
    try {
      const r = await api<{ passkeys: PasskeyEintrag[]; moeglich: boolean }>("GET", "/api/v1/passkeys");
      setListe(r.passkeys);
      setMoeglich(r.moeglich && passkeyMoeglich());
    } catch (e) {
      setFehler(e instanceof Error ? e.message : String(e));
    }
  };
  useEffect(() => {
    void laden();
  }, []);

  const hinzufuegen = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setMeldung("");
    setArbeitet(true);
    try {
      const o = await api<RegOptionen>("POST", "/api/v1/passkeys/optionen");
      const antwort = await passkeyErzeugen(o);
      await api("POST", "/api/v1/passkeys", { name, code, ...antwort });
      setMeldung(`Passkey „${name}“ hinzugefügt.`);
      setName("");
      await laden();
    } catch (err) {
      setFehler(err instanceof ApiError ? err.message : passkeyFehler(err));
    } finally {
      setCode("");
      setArbeitet(false);
    }
  };

  const entfernen = async (p: PasskeyEintrag) => {
    setFehler("");
    setMeldung("");
    try {
      await api("DELETE", `/api/v1/passkeys/${p.id}`);
      setMeldung(`Passkey „${p.name}“ entfernt.`);
      await laden();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <Dialog titel="Passkeys" onZu={props.onZu}>
      <p className="klein">
        Ein Passkey (Sicherheitsschlüssel, Windows Hello, Touch ID, Handy) ersetzt bei der Anmeldung den Code aus der App. Die App bleibt
        eingerichtet: Sie bestätigt heikle Änderungen und hilft, wenn der Passkey fehlt.
      </p>
      {liste === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : liste.length === 0 ? (
        <p className="leer">Noch kein Passkey.</p>
      ) : (
        <table className="tabelle">
          <caption className="sr-only">Deine Passkeys</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Verfahren</th>
              <th scope="col">Angelegt</th>
              <th scope="col">Zuletzt benutzt</th>
              <th scope="col">
                <span className="sr-only">Aktion</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {liste.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>{p.verfahren}</td>
                <td>{datum(p.angelegt)}</td>
                <td>{datum(p.zuletzt)}</td>
                <td>
                  <button className="knopf knopf-gefahr" onClick={() => void entfernen(p)} aria-label={`Passkey ${p.name} entfernen`}>
                    Entfernen
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {moeglich ? (
        <form onSubmit={hinzufuegen}>
          <label className="feld">
            <span>Name des neuen Passkeys</span>
            <input
              value={name}
              maxLength={60}
              required
              placeholder="z. B. Laptop oder Sicherheitsschlüssel"
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label className="feld">
            <span>Code aus der Authenticator-App</span>
            <input
              className="code-eingabe"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
          </label>
          <div className="knopf-reihe">
            <button className="knopf knopf-haupt" disabled={arbeitet || code.length !== 6 || !name.trim()}>
              Passkey hinzufügen
            </button>
          </div>
        </form>
      ) : (
        <p className="meldung">
          Passkeys gehen nur, wenn die Oberfläche über einen DNS-Namen mit HTTPS erreichbar ist (keine IP-Adresse) und der Browser sie
          unterstützt.
        </p>
      )}
      <div aria-live="polite">
        {meldung && <p className="meldung meldung-ok">{meldung}</p>}
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
      </div>
    </Dialog>
  );
}
