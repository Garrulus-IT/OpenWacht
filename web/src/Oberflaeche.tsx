// SPDX-License-Identifier: AGPL-3.0-only

// Rahmen nach der Anmeldung (Etappe 17): Seitenleiste links mit den Gruppen
// Überwachen, Einrichten und Verwaltung und der Mandantenwahl (Entwurf B),
// Kopf mit Brotkrumen und Platz für Knöpfe der Seite. Auf schmalen
// Bildschirmen ist die Leiste ein Menü hinter dem Hamburger-Knopf.

import { LizenzHinweis } from "./Lizenz";
import { Zeichen } from "./Zeichen";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, ApiError, type Ich, type Mandant } from "./api";
import { Hosts } from "./Hosts";
import { AlarmeSeite } from "./AlarmeSeite";
import { Startseite } from "./Startseite";
import { Verwaltung, Wandanzeigen } from "./Verwaltung";
import { SensorVorlagen } from "./SensorVorlagen";
import { SnmpProfile } from "./SnmpProfile";
import { Berichte } from "./Berichte";
import { Einstellungen } from "./Einstellungen";
import { WartungSeite } from "./WartungSeite";
import { PasskeyDialog, WiederherstellungsDialog } from "./ZweiFaktor";
import { Schnellsuche } from "./Schnellsuche";
import { RandHinweise, TON_VORGABE, TonDialog } from "./Ton";
import { Topologie } from "./Topologie";
import { Zertifikate } from "./Zertifikate";
import type { HinweiseTon } from "./api";
import { quellenLeeren } from "./quelle";
import { baumReihe, bereichFuer, wurzeln } from "./bereich";
import { adresse, navGruppen, seitenTitel, useOrt, type NavPunkt, type Ort } from "./navigation";
import type { Thema } from "./thema";

interface Props {
  ich: Ich;
  onAbmelden: () => void;
  onAbgelaufen: () => void;
  thema: Thema;
  onThema: (t: Thema) => void;
}

// Fehler anzeigen; bei abgelaufener Sitzung zurück zur Anmeldung.
function useFehler(onAbgelaufen: () => void) {
  const [fehler, setFehler] = useState("");
  const melden = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) {
        onAbgelaufen();
        return;
      }
      setFehler(e instanceof Error ? e.message : String(e));
    },
    [onAbgelaufen],
  );
  return { fehler, setFehler, melden };
}

// Symbole der Seitenleiste (eigene Linien, keine Bibliothek).
// Piktogramme im Stil von Otl Aicher (Corporate Design, Abschnitt 6):
// Raster 24, Strich 2 px, eckige Enden, nur 0°, 45° und 90°, dazu Kreise.
const symbolPfad: Record<NavPunkt["id"], string> = {
  dashboard: "M3 3h7v8H3zM13 3h8v5h-8zM13 11h8v10h-8zM3 14h7v7H3z",
  hosts: "M3 4h18v6H3zM3 14h18v6H3zM6 7h3M6 17h3",
  // Baum: oben ein Gerät, darunter zwei
  topologie: "M9 3h6v5H9zM3 16h6v5H3zM15 16h6v5h-6zM12 8v4M6 12h12M6 12v4M18 12v4",
  zertifikate: "M4 4h16v11H4zM8 8h8M8 11h5M15 15v6l2-1.5 2 1.5v-6",
  // Glocke: Kreisbogen, senkrechte Flanken, 45°-Krempe
  alarme: "M6 17v-6a6 6 0 0 1 12 0v6l2 2H4zM10 21h4",
  berichte: "M5 3h10l4 4v14H5zM15 3v4h4M8 12h8M8 16h8",
  vorlagen: "M4 4h16v4H4zM4 10h10v4H4zM4 16h16v4H4z",
  // Schlüssel
  snmpprofile: "M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 12h9M17 12v4M20 12v3",
  anzeigen: "M3 4h18v12H3zM8 20h8M12 16v4",
  // Uhr, Zeiger in 90° und 45°
  wartung: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l4 4",
  verwaltung: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3a4 4 0 0 1 0 8M17 14a7 7 0 0 1 5 7",
  // Rad mit acht Speichen statt Zahnrad: nur 0°, 45° und 90°
  einstellungen: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9 7 7M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1",
};

export function Symbol({ pfad }: { pfad: string }) {
  return (
    <svg viewBox="0 0 24 24" className="symbol" aria-hidden="true">
      <path d={pfad} />
    </svg>
  );
}

function Marke() {
  return (
    <div className="leiste-marke">
      <Zeichen className="zeichen" />
      <span>
        Open<span className="wortmarke-rest">Wacht</span>
      </span>
    </div>
  );
}

// Ein Klick mit Zusatztaste öffnet wie bei jedem Link einen neuen Tab.
function linkKlick(e: React.MouseEvent, fn: () => void) {
  if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  fn();
}

export function Oberflaeche({ ich, onAbmelden, onAbgelaufen, thema, onThema }: Props) {
  const { ort, gehe } = useOrt();
  const [mandanten, setMandanten] = useState<Mandant[] | null>(null);
  const { fehler, setFehler, melden } = useFehler(onAbgelaufen);
  const [menue, setMenue] = useState(false);
  const [codesDialog, setCodesDialog] = useState(false);
  const [passkeyDialog, setPasskeyDialog] = useState(false);
  const [tonDialog, setTonDialog] = useState(false);
  const [suche, setSuche] = useState(false);
  const [hinweiseTon, setHinweiseTon] = useState<HinweiseTon>(ich.hinweise_ton ?? TON_VORGABE);
  // Zusatz in den Brotkrumen (z. B. das gewählte Gerät) und Platz für Knöpfe der Seite im Kopf
  const [krume, setKrume] = useState<ReactNode>(null);
  const [kopfZiel, setKopfZiel] = useState<HTMLElement | null>(null);
  const burger = useRef<HTMLButtonElement>(null);
  const leiste = useRef<HTMLElement>(null);

  const ladeMandanten = useCallback(async () => {
    try {
      const r = await api<{ mandanten: Mandant[] }>("GET", "/api/v1/mandanten");
      setMandanten(r.mandanten);
    } catch (e) {
      melden(e);
    }
  }, [melden]);

  useEffect(() => {
    void ladeMandanten();
  }, [ladeMandanten]);

  // Zwischengespeicherte Daten der Widgets gehören zur Sitzung: beim Abmelden
  // oder Ablauf verwerfen, damit ein anderer Benutzer im selben Fenster nichts sieht.
  useEffect(() => () => quellenLeeren(), []);

  // Unbekannter oder fehlender Mandant in der Adresse: auf die erste Wurzel
  // korrigieren, ohne neuen Eintrag im Verlauf.
  useEffect(() => {
    if (!mandanten || mandanten.length === 0) return;
    if (!mandanten.some((m) => m.id === ort.mandant)) gehe({ mandant: wurzeln(mandanten)[0]!.id }, true);
  }, [mandanten, ort.mandant, gehe]);

  // Menü am Handy: Escape schließt und gibt den Fokus an den Knopf zurück.
  useEffect(() => {
    if (!menue) return;
    // erst nach dem Umschalten der Sichtbarkeit fokussierbar
    const f = window.requestAnimationFrame(() => leiste.current?.querySelector<HTMLElement>("select, a")?.focus());
    const taste = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMenue(false);
        burger.current?.focus();
      }
    };
    window.addEventListener("keydown", taste);
    return () => {
      window.cancelAnimationFrame(f);
      window.removeEventListener("keydown", taste);
    };
  }, [menue]);

  useEffect(() => setKrume(null), [ort.reiter]);

  // Schnellsuche (1.0.6): Strg+K bzw. ⌘K, auch aus Eingabefeldern heraus.
  useEffect(() => {
    const taste = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSuche(true);
      }
    };
    window.addEventListener("keydown", taste);
    return () => window.removeEventListener("keydown", taste);
  }, []);

  const bereich = useMemo(
    () => (mandanten ? bereichFuer(mandanten, ort.mandant, ort.mitUnter) : null),
    [mandanten, ort.mandant, ort.mitUnter],
  );
  const reihe = useMemo(() => baumReihe(mandanten ?? []), [mandanten]);
  // Der Schalter wirkt nur dort, wo Listen über den Bereich gehen.
  const zeigeSchalter =
    !!mandanten?.some((m) => m.uebergeordnet_id === ort.mandant) &&
    (ort.reiter !== "verwaltung" || ort.unter === "tokens" || ort.unter === "updates") &&
    ort.reiter !== "vorlagen";

  const wechseln = useCallback(
    (o: Partial<Ort>) => {
      setFehler("");
      setMenue(false);
      gehe(o);
    },
    [gehe, setFehler],
  );

  const titel = seitenTitel[ort.reiter];
  useEffect(() => {
    document.title = `${titel} – OpenWacht`;
  }, [titel]);

  return (
    <div className={`app${menue ? " menue-offen" : ""}`}>
      <aside className="leiste" id="leiste" ref={leiste} aria-label="Navigation">
        <Marke />
        {mandanten && mandanten.length > 0 && (
          <div className="leiste-mandant">
            <label className="leiste-feld">
              <span className="leiste-feld-text">Mandant</span>
              <select value={ort.mandant} onChange={(e) => wechseln({ mandant: e.target.value })}>
                {reihe.map(({ m, tiefe }) => (
                  <option key={m.id} value={m.id}>
                    {" ".repeat(tiefe) + m.name}
                  </option>
                ))}
              </select>
            </label>
            {zeigeSchalter && (
              <label className="schalter-feld leiste-schalter">
                <input type="checkbox" checked={ort.mitUnter} onChange={(e) => wechseln({ mitUnter: e.target.checked })} />
                <span>mit Untermandanten</span>
              </label>
            )}
          </div>
        )}
        <nav className="nav" aria-label="Hauptbereiche">
          {navGruppen.map((g) => (
            <div key={g.titel} className="nav-gruppe">
              <h2 className="nav-titel">{g.titel}</h2>
              <ul>
                {g.punkte
                  .filter((p) => !p.betreiber || ich.betreiber)
                  .map((p) => (
                    <li key={p.id}>
                      <a
                        className="nav-punkt"
                        href={adresse({ ...ort, reiter: p.id, unter: "mandanten", alarm: "aktiv", geraet: "" })}
                        aria-current={ort.reiter === p.id ? "page" : undefined}
                        onClick={(e) => linkKlick(e, () => wechseln({ reiter: p.id as Ort["reiter"], unter: "mandanten", alarm: "aktiv" }))}
                      >
                        <Symbol pfad={symbolPfad[p.id]} />
                        <span className="nav-text">{p.text}</span>
                        {p.bald && <span className="bald">{p.bald}</span>}
                      </a>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </nav>
        <div className="leiste-fuss">
          <div className="leiste-person" title={ich.email}>
            <Symbol pfad="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0" />
            <span className="nav-text">{ich.anzeigename}</span>
          </div>
          <label className="leiste-feld leiste-thema">
            <span className="leiste-feld-text">Darstellung</span>
            <select value={thema} onChange={(e) => onThema(e.target.value as Thema)}>
              <option value="system">wie System</option>
              <option value="hell">Hell</option>
              <option value="dunkel">Dunkel</option>
            </select>
          </label>
          {ich.zwei_faktor_aktiv && (
            <button
              className={ich.wiederherstellungscodes_offen <= 2 ? "knopf-text leiste-codes warnung-text" : "knopf-text leiste-codes"}
              onClick={() => setCodesDialog(true)}
            >
              Wiederherstellungscodes ({ich.wiederherstellungscodes_offen} offen)
            </button>
          )}
          {ich.zwei_faktor_aktiv && (
            <button className="knopf-text leiste-codes" onClick={() => setPasskeyDialog(true)}>
              Passkeys
            </button>
          )}
          <button className="knopf-text leiste-codes" onClick={() => setTonDialog(true)}>
            Hinweise und Ton
          </button>
          {tonDialog && <TonDialog wert={hinweiseTon} onGespeichert={setHinweiseTon} onZu={() => setTonDialog(false)} />}
          {passkeyDialog && <PasskeyDialog onZu={() => setPasskeyDialog(false)} />}
          {codesDialog && (
            <WiederherstellungsDialog
              offen={ich.wiederherstellungscodes_offen}
              onZu={() => {
                setCodesDialog(false);
                onAbgelaufen();
              }}
            />
          )}
          <button className="knopf leiste-abmelden" onClick={onAbmelden}>
            Abmelden
          </button>
          <p className="leiste-version">
            OpenWacht {ich.version}
            {ich.commit && ich.commit !== "unknown" ? ` · Commit ${ich.commit.replace(/^([0-9a-f]{7})[0-9a-f]*/, "$1")}` : ""}
          </p>
          <LizenzHinweis version={ich.version} />
        </div>
      </aside>
      {menue && <div className="schleier" aria-hidden="true" onClick={() => setMenue(false)} />}
      <RandHinweise e={hinweiseTon} onAlarme={() => wechseln({ reiter: "alarme", alarm: "aktiv" })} />

      <div className="haupt">
        <header className="kopf">
          <button
            ref={burger}
            className="burger"
            aria-label={menue ? "Menü schließen" : "Menü öffnen"}
            aria-expanded={menue}
            aria-controls="leiste"
            onClick={() => setMenue(!menue)}
          >
            <Symbol pfad="M3 6h18M3 12h18M3 18h18" />
          </button>
          <nav className="krumen" aria-label="Brotkrumen">
            {krume ? (
              <>
                <a href={adresse({ ...ort, geraet: "" })} onClick={(e) => linkKlick(e, () => wechseln({ geraet: "" }))}>
                  {titel}
                </a>
                <span aria-hidden="true"> › </span>
                <span className="krume-aktuell" aria-current="page">
                  {krume}
                </span>
              </>
            ) : (
              <span className="krume-aktuell" aria-current="page">
                {titel}
              </span>
            )}
          </nav>
          <button className="kopf-suche" onClick={() => setSuche(true)} aria-keyshortcuts="Control+K Meta+K" title="Schnellsuche (Strg+K)">
            <Symbol pfad="M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-4.35-4.35" />
            <span className="kopf-suche-text">Suchen</span>
            <kbd className="kopf-suche-taste">Strg K</kbd>
          </button>
          <div className="kopf-rechts" ref={setKopfZiel} />
        </header>
        {suche && mandanten && (
          <Schnellsuche mandanten={mandanten} betreiber={ich.betreiber} onZu={() => setSuche(false)} gehe={wechseln} />
        )}

        <main className="inhalt" id="inhalt">
          {fehler && (
            <p className="meldung meldung-fehler" role="alert">
              {fehler}{" "}
              <button className="knopf-text" onClick={() => setFehler("")}>
                Ausblenden
              </button>
            </p>
          )}
          {mandanten === null ? (
            <p className="klein" aria-busy="true">
              Lädt …
            </p>
          ) : mandanten.length === 0 ? (
            <p className="leer">Dir ist noch kein Mandant zugeordnet. Wende dich an deine IT.</p>
          ) : !bereich ? null : ort.reiter === "dashboard" ? (
            <Startseite bereich={bereich} mandanten={mandanten} kopfZiel={kopfZiel} melden={melden} gehe={wechseln} />
          ) : ort.reiter === "hosts" ? (
            <Hosts
              key={bereich.mandant.id}
              bereich={bereich}
              geraet={ort.geraet}
              ansicht={ort.geraetReiter}
              onOeffnen={(geraet) => gehe({ geraet })}
              onAnsicht={(geraetReiter) => gehe({ geraetReiter }, true)}
              onKrume={setKrume}
              melden={melden}
            />
          ) : ort.reiter === "alarme" ? (
            <AlarmeSeite key={bereich.mandant.id} bereich={bereich} unter={ort.alarm} gehe={wechseln} melden={melden} />
          ) : ort.reiter === "vorlagen" ? (
            <SensorVorlagen key={bereich.mandant.id} bereich={bereich} melden={melden} />
          ) : ort.reiter === "snmpprofile" ? (
            <SnmpProfile key={bereich.mandant.id} bereich={bereich} melden={melden} />
          ) : ort.reiter === "einstellungen" ? (
            <Einstellungen ich={ich} melden={melden} />
          ) : ort.reiter === "zertifikate" ? (
            <Zertifikate bereich={bereich} onOeffnen={(geraet) => wechseln({ reiter: "hosts", geraet })} />
          ) : ort.reiter === "topologie" ? (
            <Topologie bereich={bereich} onOeffnen={(geraet) => wechseln({ reiter: "hosts", geraet })} />
          ) : ort.reiter === "berichte" ? (
            <Berichte key={bereich.mandant.id + String(ort.mitUnter)} bereich={bereich} mitUnter={ort.mitUnter} melden={melden} />
          ) : ort.reiter === "wartung" ? (
            <WartungSeite key={bereich.mandant.id} bereich={bereich} melden={melden} />
          ) : ort.reiter === "anzeigen" ? (
            <Wandanzeigen key={bereich.mandant.id} mandant={bereich.mandant} bereich={bereich} melden={melden} />
          ) : (
            <Verwaltung
              ich={ich}
              mandanten={mandanten}
              bereich={bereich}
              unter={ort.unter}
              gehe={wechseln}
              onGeaendert={ladeMandanten}
              melden={melden}
            />
          )}
        </main>
      </div>
    </div>
  );
}
