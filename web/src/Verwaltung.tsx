// SPDX-License-Identifier: AGPL-3.0-only

import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { api, rollenName, type AgentToken, type Anzeige, type TonEinstellung, type Benutzer, type Ich, type Mandant, type Rolle } from "./api";
import { darfPflegen, kinderVon, rolleIn, wurzeln, type Bereich } from "./bereich";
import { QRCode } from "./ZweiFaktor";
import { Verzeichnisse } from "./Verzeichnisse";
import { ApiTokens } from "./ApiTokens";
import { AgentUpdates } from "./AgentUpdates";
import { vor } from "./zeit";
import { AntraegeListe, AntragFormular } from "./Antraege";
import { verwaltungsListe, type Ort, type VerwaltungsReiter } from "./navigation";
import { Dialog } from "./Startseite";
import { TonFelder } from "./Ton";

interface Props {
  ich: Ich;
  mandanten: Mandant[];
  bereich: Bereich;
  unter: VerwaltungsReiter;
  gehe: (o: Partial<Ort>) => void;
  onGeaendert: () => Promise<void>;
  melden: (e: unknown) => void;
}

export function Verwaltung({ ich, mandanten, bereich, unter, gehe, onGeaendert, melden }: Props) {
  const mandant = bereich.mandant;
  const eltern = mandant.uebergeordnet_id ? bereich.nachId.get(mandant.uebergeordnet_id) : undefined;
  const hauptAdmin = mandanten.some((m) => m.uebergeordnet_id === null && m.rolle === "admin");
  return (
    <section className="ansicht" aria-labelledby="verwaltung-titel">
      <h1 id="verwaltung-titel" className="sr-only">
        Verwaltung
      </h1>
      <div className="umschalter unterreiter" role="group" aria-label="Verwaltung">
        {verwaltungsListe.map((v) => (
          <button key={v.id} type="button" className="umschalter-knopf" aria-pressed={unter === v.id} onClick={() => gehe({ unter: v.id })}>
            {v.text}
          </button>
        ))}
      </div>
      {unter === "mandanten" ? (
        <div className="mandanten-raster">
          <nav className="baum-spalte" aria-label="Mandanten">
            <Baum mandanten={mandanten} auswahl={mandant.id} onAuswahl={(id) => gehe({ mandant: id })} />
          </nav>
          <MandantAnsicht
            key={mandant.id}
            mandant={mandant}
            eltern={eltern}
            hauptAdmin={hauptAdmin}
            onGeaendert={onGeaendert}
            onGeloescht={() => {
              gehe({ mandant: mandant.uebergeordnet_id ?? "" });
              onGeaendert();
            }}
            onNeu={async (id) => {
              // Erst die Liste neu laden: Ein Mandant, den sie noch nicht
              // kennt, würde sonst auf die Wurzel zurückgesetzt.
              await onGeaendert();
              gehe({ mandant: id });
            }}
            melden={melden}
          />
        </div>
      ) : unter === "benutzer" ? (
        <BenutzerListe key={mandant.id} ich={ich} mandant={mandant} melden={melden} />
      ) : unter === "updates" ? (
        <AgentUpdates key={mandant.id} ich={ich} mandant={mandant} bereich={bereich} melden={melden} />
      ) : unter === "api" ? (
        <ApiTokens key={mandant.id} mandant={mandant} melden={melden} />
      ) : unter === "anmeldung" ? (
        <Verzeichnisse key={mandant.id} mandant={mandant} mandanten={mandanten} melden={melden} />
      ) : (
        <TokenListe key={mandant.id} bereich={bereich} melden={melden} />
      )}
    </section>
  );
}

// Wandanzeigen haben seit Etappe 17 eine eigene Seite unter „Einrichten“.
export function Wandanzeigen({ bereich, melden }: { mandant?: Mandant; bereich: Bereich; melden: (e: unknown) => void }) {
  return (
    <section className="ansicht" aria-label="Wandanzeigen">
      <AnzeigenListe bereich={bereich} melden={melden} />
    </section>
  );
}

// --- Mandantenbaum ------------------------------------------------------------

function Baum({ mandanten, auswahl, onAuswahl }: { mandanten: Mandant[]; auswahl: string; onAuswahl: (id: string) => void }) {
  const kinder = useMemo(() => kinderVon(mandanten), [mandanten]);
  const nachId = useMemo(() => new Map(mandanten.map((m) => [m.id, m])), [mandanten]);

  const knoten = (m: Mandant, tiefe: number): ReactNode => {
    const unter = kinder.get(m.id) ?? [];
    // Rolle nur dort zeigen, wo sie beginnt; darunter ist sie vererbt.
    const eltern = m.uebergeordnet_id ? nachId.get(m.uebergeordnet_id) : undefined;
    const zeigeRolle = m.rolle && eltern?.rolle !== m.rolle;
    return (
      <li key={m.id} role="treeitem" aria-selected={m.id === auswahl} aria-expanded={unter.length ? true : undefined} aria-level={tiefe}>
        <button className={m.id === auswahl ? "knoten knoten-aktiv" : "knoten"} onClick={() => onAuswahl(m.id)}>
          <span className="knoten-name">{m.name}</span>
          {zeigeRolle && m.rolle && <span className={`rolle rolle-${m.rolle}`}>{rollenName[m.rolle]}</span>}
        </button>
        {unter.length > 0 && <ul role="group">{unter.map((u) => knoten(u, tiefe + 1))}</ul>}
      </li>
    );
  };

  return (
    <ul className="baum" role="tree" aria-label="Mandantenbaum">
      {wurzeln(mandanten).map((w) => knoten(w, 1))}
    </ul>
  );
}

// --- Ansicht eines Mandanten ------------------------------------------------

interface AnsichtProps {
  mandant: Mandant;
  eltern?: Mandant;
  hauptAdmin: boolean;
  onGeaendert: () => void;
  onGeloescht: () => void;
  onNeu: (id: string) => Promise<void>;
  melden: (e: unknown) => void;
}

function MandantAnsicht({ mandant, eltern, hauptAdmin, onGeaendert, onGeloescht, onNeu, melden }: AnsichtProps) {
  const admin = mandant.rolle === "admin";
  const [modus, setModus] = useState<"" | "umbenennen" | "unter" | "loeschen" | "antrag">("");
  const [stand, setStand] = useState(0);
  const [hinweis, setHinweis] = useState("");

  return (
    <div className="ansicht-kopf">
      {eltern && <p className="pfad">Unter {eltern.name}</p>}
      {modus === "umbenennen" ? (
        <NameFormular
          start={mandant.name}
          knopf="Umbenennen"
          onAbbrechen={() => setModus("")}
          onSenden={async (name) => {
            await api("PATCH", `/api/v1/mandanten/${mandant.id}`, { name });
            setModus("");
            onGeaendert();
          }}
          melden={melden}
        />
      ) : (
        <h2 className="titel-gross">{mandant.name}</h2>
      )}
      <p className="klein">Deine Rolle hier: {mandant.rolle ? rollenName[mandant.rolle] : "keine"}</p>
      {modus === "" && (
        <div className="aktionen">
          {hauptAdmin && admin && (
            <button className="knopf" onClick={() => setModus("unter")}>
              Untermandant anlegen
            </button>
          )}
          {!hauptAdmin && admin && (
            <button className="knopf" onClick={() => setModus("antrag")}>
              Untermandant beantragen
            </button>
          )}
          {admin && (
            <button className="knopf" onClick={() => setModus("umbenennen")}>
              Umbenennen
            </button>
          )}
          {admin && (
            <>
              <a className="knopf" href={`/api/v1/mandanten/${mandant.id}/rezertifizierung?format=pdf`} download>
                Rezertifizierung (PDF)
              </a>
              <a className="knopf" href={`/api/v1/mandanten/${mandant.id}/rezertifizierung?format=csv`} download>
                Rezertifizierung (CSV)
              </a>
            </>
          )}
          {eltern?.rolle === "admin" && (
            <button className="knopf knopf-gefahr" onClick={() => setModus("loeschen")}>
              Löschen
            </button>
          )}
        </div>
      )}
      {modus === "loeschen" && (
        <div className="bestaetigung" role="alertdialog" aria-label="Mandant löschen">
          <p>
            „{mandant.name}“ löschen? Das geht nur, solange der Mandant keine Untermandanten, Benutzer oder Einträge im Audit-Log hat.
          </p>
          <div className="aktionen">
            <button
              className="knopf knopf-gefahr"
              onClick={async () => {
                try {
                  await api("DELETE", `/api/v1/mandanten/${mandant.id}`);
                  onGeloescht();
                } catch (e) {
                  setModus("");
                  melden(e);
                }
              }}
            >
              Endgültig löschen
            </button>
            <button className="knopf" onClick={() => setModus("")}>
              Abbrechen
            </button>
          </div>
        </div>
      )}
      {modus === "antrag" && (
        <AntragFormular
          mandant={mandant}
          onAbbrechen={() => setModus("")}
          onFertig={() => {
            setModus("");
            setStand(stand + 1);
            setHinweis("Antrag gestellt. Ein Admin des Hauptmandanten entscheidet; der Antrag steht unten.");
          }}
          melden={melden}
        />
      )}
      <div aria-live="polite">{hinweis && <p className="meldung meldung-ok">{hinweis}</p>}</div>
      <AntraegeListe stand={stand} onGeaendert={async () => onGeaendert()} melden={melden} />
      {modus === "unter" && (
        <NameFormular
          start=""
          beschriftung={`Name des neuen Mandanten unter ${mandant.name}`}
          knopf="Anlegen"
          onAbbrechen={() => setModus("")}
          onSenden={async (name) => {
            const neu = await api<Mandant>("POST", "/api/v1/mandanten", { uebergeordnet_id: mandant.id, name });
            setModus("");
            await onNeu(neu.id);
          }}
          melden={melden}
        />
      )}
    </div>
  );
}

// --- Benutzer eines Mandanten -------------------------------------------------

function BenutzerListe({ ich, mandant, melden }: { ich: Ich; mandant: Mandant; melden: (e: unknown) => void }) {
  const admin = mandant.rolle === "admin";
  const [benutzer, setBenutzer] = useState<Benutzer[] | null>(null);
  const [neu, setNeu] = useState(false);

  const ladeBenutzer = useCallback(async () => {
    try {
      const r = await api<{ benutzer: Benutzer[] }>("GET", `/api/v1/benutzer?mandant=${mandant.id}`);
      setBenutzer(r.benutzer);
    } catch (e) {
      melden(e);
    }
  }, [mandant.id, melden]);

  useEffect(() => {
    void ladeBenutzer();
  }, [ladeBenutzer]);

  return (
    <>
      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Benutzer in {mandant.name}</h2>
        {admin && !neu && (
          <button className="knopf" onClick={() => setNeu(true)}>
            Benutzer anlegen
          </button>
        )}
      </div>
      {neu && (
        <BenutzerFormular
          mandant={mandant}
          onAbbrechen={() => setNeu(false)}
          onAngelegt={() => {
            setNeu(false);
            void ladeBenutzer();
          }}
          melden={melden}
        />
      )}
      {benutzer === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : benutzer.length === 0 ? (
        <p className="leer">{admin ? "Noch keine Benutzer. Lege den ersten über „Benutzer anlegen“ an." : "Keine Benutzer in diesem Mandanten."}</p>
      ) : (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Rolle hier</th>
              <th scope="col">Anmeldung</th>
              {admin && <th scope="col">Aktionen</th>}
            </tr>
          </thead>
          <tbody>
            {benutzer.map((b) => (
              <BenutzerZeile key={b.id} b={b} ich={ich} mandant={mandant} admin={admin} onGeaendert={ladeBenutzer} melden={melden} />
            ))}
          </tbody>
        </table>
      )}
      <p className="klein">Benutzer gehören einem Mandanten; ihre Rolle gilt dort und in allen Mandanten darunter.</p>
    </>
  );
}

// --- Offene Agent-Tokens im Bereich ---------------------------------------------

function TokenListe({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const [tokens, setTokens] = useState<(AgentToken & { mandant: string })[] | null>(null);
  // Tokens sehen nur Admins und Operatoren; Leser bekommen 403.
  const ids = useMemo(() => [...bereich.ids].filter((id) => darfPflegen(bereich, id)), [bereich]);

  const laden = useCallback(async () => {
    try {
      const listen = await Promise.all(
        ids.map(async (id) => {
          const r = await api<{ tokens: AgentToken[] }>("GET", `/api/v1/mandanten/${id}/agent-tokens`);
          return r.tokens.map((t) => ({ ...t, mandant: bereich.nachId.get(id)?.name ?? "" }));
        }),
      );
      setTokens(listen.flat().sort((a, b) => b.erstellt.localeCompare(a.erstellt)));
    } catch (e) {
      melden(e);
    }
  }, [ids, bereich, melden]);

  useEffect(() => {
    void laden();
  }, [laden]);

  return (
    <>
      <h2 className="abschnitt">Offene Agent-Tokens</h2>
      <p className="klein">Neue Tokens erzeugst du unter Hosts → „Host hinzufügen“ oder beim Gerät mit „Agent hinzufügen“. Hier siehst du alle, die noch gelten, und kannst sie widerrufen.</p>
      {ids.length === 0 ? (
        <p className="leer">Tokens sehen nur Admins und Operatoren.</p>
      ) : tokens === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : tokens.length === 0 ? (
        <p className="leer">Keine offenen Tokens.</p>
      ) : (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Notiz</th>
              {bereich.mehrere && <th scope="col">Mandant</th>}
              <th scope="col">Noch</th>
              <th scope="col">Gilt bis</th>
              <th scope="col">Aktion</th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td>{t.notiz || "ohne Notiz"}</td>
                {bereich.mehrere && <td>{t.mandant}</td>}
                <td>{t.restanzahl}×</td>
                <td>{new Date(t.laeuft_ab).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}</td>
                <td>
                  <button
                    className="knopf"
                    onClick={async () => {
                      try {
                        await api("DELETE", `/api/v1/agent-tokens/${t.id}`);
                        void laden();
                      } catch (e) {
                        melden(e);
                      }
                    }}
                  >
                    Widerrufen
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function NameFormular(props: {
  start: string;
  beschriftung?: string;
  knopf: string;
  onSenden: (name: string) => Promise<void>;
  onAbbrechen: () => void;
  melden: (e: unknown) => void;
}) {
  const [name, setName] = useState(props.start);
  const [arbeitet, setArbeitet] = useState(false);
  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      await props.onSenden(name.trim());
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <form className="formular-zeile" onSubmit={senden}>
      <label className="feld feld-breit">
        <span>{props.beschriftung ?? "Name"}</span>
        <input autoFocus maxLength={100} required value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim()}>
        {props.knopf}
      </button>
      <button type="button" className="knopf" onClick={props.onAbbrechen}>
        Abbrechen
      </button>
    </form>
  );
}

// Zufälliges Startpasswort aus dem Kryptografie-Zufall des Browsers.
function startPasswort() {
  const zeichen = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const z = crypto.getRandomValues(new Uint32Array(16));
  let s = "";
  z.forEach((n, i) => (s += (i > 0 && i % 4 === 0 ? "-" : "") + zeichen[n % zeichen.length]));
  return s;
}

function BenutzerFormular(props: { mandant: Mandant; onAngelegt: () => void; onAbbrechen: () => void; melden: (e: unknown) => void }) {
  const [anzeigename, setAnzeigename] = useState("");
  const [email, setEmail] = useState("");
  const [passwort, setPasswort] = useState(startPasswort);
  const [rolle, setRolle] = useState<Rolle>("leser");
  const [arbeitet, setArbeitet] = useState(false);

  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      const neu = await api<Benutzer>("POST", "/api/v1/benutzer", { mandant_id: props.mandant.id, email, anzeigename, passwort });
      await api("PUT", `/api/v1/benutzer/${neu.id}/rollen/${props.mandant.id}`, { rolle });
      props.onAngelegt();
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <form className="formular" onSubmit={senden}>
      <label className="feld">
        <span>Name</span>
        <input autoFocus required maxLength={100} value={anzeigename} onChange={(e) => setAnzeigename(e.target.value)} />
      </label>
      <label className="feld">
        <span>E-Mail-Adresse</span>
        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label className="feld">
        <span>Startpasswort (bitte sicher übergeben)</span>
        <input className="mono" required minLength={12} value={passwort} onChange={(e) => setPasswort(e.target.value)} />
      </label>
      <label className="feld">
        <span>Rolle in {props.mandant.name}</span>
        <select value={rolle} onChange={(e) => setRolle(e.target.value as Rolle)}>
          <option value="leser">Leser – sieht alles in diesem Bereich</option>
          <option value="operator">Operator – pflegt Sensoren und Agents</option>
          <option value="admin">Admin – verwaltet Benutzer und Rechte</option>
        </select>
      </label>
      <div className="aktionen">
        <button className="knopf knopf-haupt" disabled={arbeitet}>
          Benutzer anlegen
        </button>
        <button type="button" className="knopf" onClick={props.onAbbrechen}>
          Abbrechen
        </button>
      </div>
    </form>
  );
}

function BenutzerZeile(props: { b: Benutzer; ich: Ich; mandant: Mandant; admin: boolean; onGeaendert: () => void; melden: (e: unknown) => void }) {
  const { b, ich, mandant, admin, onGeaendert, melden } = props;
  const rolleHier = b.rollen.find((r) => r.mandant_id === mandant.id)?.rolle;
  const selbst = b.id === ich.id;
  const [pwModus, setPwModus] = useState(false);
  const [neuesPw, setNeuesPw] = useState("");

  const aendern = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      onGeaendert();
    } catch (e) {
      melden(e);
    }
  };

  return (
    <tr className={b.deaktiviert ? "zeile-aus" : undefined}>
      <td>
        <div className="name">{b.anzeigename}</div>
        <div className="klein">{b.email}</div>
      </td>
      <td>
        {admin && !selbst && !b.verzeichnis ? (
          <select
            aria-label={`Rolle von ${b.anzeigename}`}
            value={rolleHier ?? ""}
            onChange={(e) => {
              const v = e.target.value;
              void aendern(() =>
                v
                  ? api("PUT", `/api/v1/benutzer/${b.id}/rollen/${mandant.id}`, { rolle: v })
                  : api("DELETE", `/api/v1/benutzer/${b.id}/rollen/${mandant.id}`),
              );
            }}
          >
            <option value="">keine</option>
            <option value="leser">Leser</option>
            <option value="operator">Operator</option>
            <option value="admin">Admin</option>
          </select>
        ) : rolleHier ? (
          rollenName[rolleHier]
        ) : (
          "keine"
        )}
      </td>
      <td>
        {b.deaktiviert ? "deaktiviert" : b.verzeichnis ? (b.zwei_faktor_aktiv ? "AD und App" : "AD") : b.zwei_faktor_aktiv ? "Passwort und App" : "nur Passwort"}
      </td>
      {admin && (
        <td>
          {selbst ? (
            <span className="klein">du selbst</span>
          ) : pwModus ? (
            <form
              className="formular-zeile"
              onSubmit={(e) => {
                e.preventDefault();
                void aendern(async () => {
                  await api("PUT", `/api/v1/benutzer/${b.id}/passwort`, { passwort: neuesPw });
                  setPwModus(false);
                });
              }}
            >
              <input aria-label="Neues Passwort" className="mono" minLength={12} required value={neuesPw} onChange={(e) => setNeuesPw(e.target.value)} />
              <button className="knopf knopf-haupt">Setzen</button>
              <button type="button" className="knopf" onClick={() => setPwModus(false)}>
                Abbrechen
              </button>
            </form>
          ) : (
            <div className="aktionen">
              {b.verzeichnis ? (
                <span className="klein">Rechte aus AD-Gruppen</span>
              ) : (
              <button
                className="knopf"
                onClick={() => {
                  setNeuesPw(startPasswort());
                  setPwModus(true);
                }}
              >
                Passwort neu setzen
              </button>
              )}
              <button className="knopf" onClick={() => void aendern(() => api("PATCH", `/api/v1/benutzer/${b.id}`, { deaktiviert: !b.deaktiviert }))}>
                {b.deaktiviert ? "Aktivieren" : "Deaktivieren"}
              </button>
            </div>
          )}
        </td>
      )}
    </tr>
  );
}

// --- Wandanzeigen ---------------------------------------------------------------

function AnzeigenListe({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const mandant = bereich.mandant;
  const admin = rolleIn(bereich, mandant.id) === "admin";
  const [liste, setListe] = useState<Anzeige[] | null>(null);
  const [neu, setNeu] = useState(false);
  const [link, setLink] = useState<{ name: string; link: string } | null>(null);
  const [loeschen, setLoeschen] = useState("");
  // „Neuer Link“ (0.99.2): ID der Anzeige, deren Link ersetzt werden soll
  const [erneuern, setErneuern] = useState("");

  const laden = useCallback(async () => {
    try {
      const r = await api<{ anzeigen: Anzeige[] }>("GET", "/api/v1/anzeigen");
      setListe(r.anzeigen.filter((a) => bereich.ids.has(a.mandant_id)));
    } catch (e) {
      melden(e);
    }
  }, [bereich, melden]);

  useEffect(() => {
    void laden();
  }, [laden]);

  const jetzt = Date.now();
  return (
    <>
      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Wandanzeigen</h2>
        {admin && !neu && !link && (
          <button className="knopf" onClick={() => setNeu(true)}>
            Wandanzeige anlegen
          </button>
        )}
      </div>
      <p className="klein">
        Eine Wandanzeige zeigt den Zustand eines Mandanten als Sonnendiagramm auf einem Bildschirm, ohne Benutzerkonto. Sie sieht nur Namen und
        Farben und kann nichts ändern. Wer den Link hat, sieht die Anzeige; Löschen sperrt sie sofort. Ein Klick auf den Namen öffnet
        eine Vorschau in deiner Sitzung; „Neuer Link“ ersetzt den Link, der alte und alle damit angemeldeten Bildschirme gelten sofort
        nicht mehr.
      </p>
      {neu && (
        <AnzeigeFormular
          mandant={mandant}
          onFertig={(e) => {
            setNeu(false);
            if (e) setLink(e);
            void laden();
          }}
          melden={melden}
        />
      )}
      {link && (
        <div className="einschub">
          <h3 className="einschub-titel">Link für „{link.name}“</h3>
          <p className="hinweis">
            Den Link gibt es nur jetzt. Im Browser des Bildschirms öffnen (am besten im Vollbild- oder Kiosk-Modus); danach steht er dort nicht mehr in
            der Adresszeile. Geht er verloren, mit „Neuer Link“ einen neuen erzeugen.
          </p>
          <p className="mono umbruch">{link.link}</p>
          <div className="qr-rahmen">
            <QRCode text={link.link} label="QR-Code des Anzeige-Links" />
          </div>
          <div className="aktionen">
            <button
              className="knopf"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(link.link);
                } catch {
                  melden(new Error("Kopieren nicht möglich. Bitte den Link markieren und von Hand kopieren."));
                }
              }}
            >
              Link kopieren
            </button>
            <button className="knopf knopf-haupt" onClick={() => setLink(null)}>
              Fertig
            </button>
          </div>
        </div>
      )}
      {liste === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : liste.length === 0 ? (
        <p className="leer">{admin ? "Noch keine Wandanzeige." : "Wandanzeigen sehen und anlegen nur Admins."}</p>
      ) : (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Name</th>
              {bereich.mehrere && <th scope="col">Mandant</th>}
              <th scope="col">Zeigt</th>
              <th scope="col">Nur aus Netz</th>
              <th scope="col">Zuletzt da</th>
              <th scope="col">Aktion</th>
            </tr>
          </thead>
          <tbody>
            {liste.map((a) => (
              <tr key={a.id}>
                <td>
                  <a href={`/anzeige/vorschau?id=${a.id}`} target="_blank" rel="noopener noreferrer" title="Vorschau in einem neuen Tab">
                    {a.name}
                  </a>
                </td>
                {bereich.mehrere && <td>{bereich.nachId.get(a.mandant_id)?.name ?? ""}</td>}
                <td>{a.mit_untermandanten ? "mit Untermandanten" : "nur diesen Mandanten"}</td>
                <td className="mono">{a.netz ?? "überall"}</td>
                <td>{a.zuletzt_da ? vor(a.zuletzt_da, jetzt) : "noch nie"}</td>
                <td>
                  {loeschen === a.id ? (
                    <div className="aktionen">
                      <button
                        className="knopf knopf-gefahr"
                        onClick={async () => {
                          try {
                            await api("DELETE", `/api/v1/anzeigen/${a.id}`);
                            setLoeschen("");
                            void laden();
                          } catch (e) {
                            melden(e);
                          }
                        }}
                      >
                        Ja, löschen
                      </button>
                      <button className="knopf" onClick={() => setLoeschen("")}>
                        Abbrechen
                      </button>
                    </div>
                  ) : erneuern === a.id ? (
                    <div className="aktionen">
                      <button
                        className="knopf knopf-gefahr"
                        onClick={async () => {
                          try {
                            const r = await api<{ name: string; link: string }>("POST", `/api/v1/anzeigen/${a.id}/neuer-link`);
                            setErneuern("");
                            setNeu(false);
                            setLink({ name: r.name, link: r.link });
                            void laden();
                          } catch (e) {
                            melden(e);
                          }
                        }}
                      >
                        Ja, alter Link ungültig
                      </button>
                      <button className="knopf" onClick={() => setErneuern("")}>
                        Abbrechen
                      </button>
                    </div>
                  ) : (
                    <div className="aktionen">
                      <AnzeigeTon a={a} onGeaendert={laden} melden={melden} />
                      <button className="knopf" onClick={() => setErneuern(a.id)}>
                        Neuer Link
                      </button>
                      <button className="knopf" onClick={() => setLoeschen(a.id)}>
                        Löschen
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function AnzeigeFormular(props: { mandant: Mandant; onFertig: (e?: { name: string; link: string }) => void; melden: (e: unknown) => void }) {
  const [name, setName] = useState("");
  const [mitUnter, setMitUnter] = useState(true);
  const [netz, setNetz] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    try {
      const r = await api<{ id: string; link: string }>("POST", `/api/v1/mandanten/${props.mandant.id}/anzeigen`, {
        name: name.trim(),
        mit_untermandanten: mitUnter,
        netz: netz.trim(),
      });
      props.onFertig({ name: name.trim(), link: r.link });
    } catch (err) {
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={senden}>
        <h3 className="einschub-titel">Wandanzeige für „{props.mandant.name}“</h3>
        <label className="feld">
          <span>Name</span>
          <input autoFocus required maxLength={100} value={name} placeholder="z. B. Büro Flur" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="feld">
          <span>Nur aus diesem Netz (optional)</span>
          <input maxLength={50} value={netz} placeholder="z. B. 10.10.0.0/23" onChange={(e) => setNetz(e.target.value)} />
        </label>
        <label className="haken formular-voll">
          <input type="checkbox" checked={mitUnter} onChange={(e) => setMitUnter(e.target.checked)} />
          <span>Untermandanten mit anzeigen</span>
        </label>
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim()}>
            Anlegen und Link erzeugen
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig()}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}

// Ton der Wandanzeige (1.0.2): ab Werk nur bei Kritisch. Am Bildschirm muss
// einmal „Ton einschalten“ angeklickt werden, sonst spielt der Browser nichts.
function AnzeigeTon({ a, onGeaendert, melden }: { a: Anzeige; onGeaendert: () => void; melden: (e: unknown) => void }) {
  const [offen, setOffen] = useState(false);
  const [w, setW] = useState<TonEinstellung>(a.ton ?? { ton: "krit", klang: "bling", lautstaerke: 70, entwarnung: false });
  return (
    <>
      <button className="knopf" onClick={() => setOffen(true)}>
        Ton
      </button>
      {offen && (
        <Dialog titel={`Ton: ${a.name}`} onZu={() => setOffen(false)}>
          <form
            className="formular"
            onSubmit={async (ev) => {
              ev.preventDefault();
              try {
                await api("PUT", `/api/v1/anzeigen/${a.id}/ton`, w);
                setOffen(false);
                onGeaendert();
              } catch (err) {
                melden(err);
              }
            }}
          >
            <p className="klein">Am Bildschirm einmal „Ton einschalten“ anklicken; Browser spielen sonst keinen Ton ab.</p>
            <TonFelder wert={w} setWert={setW} name={"anzeige-" + a.id} />
            <div className="aktionen">
              <button className="knopf knopf-haupt" type="submit">
                Speichern
              </button>
              <button className="knopf" type="button" onClick={() => setOffen(false)}>
                Abbrechen
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  );
}
