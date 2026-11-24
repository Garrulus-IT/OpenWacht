// SPDX-License-Identifier: AGPL-3.0-only

// Gruppenbaum (Etappe 13): Gruppen je Mandant, bis zu 4 Ebenen, Reihenfolge
// von Hand. Hier stehen die Hilfen für den Baum, die Auswahl im
// Geräteformular und die Ansicht „Gruppen ordnen“ im Reiter Hosts.
//
// Ordnen geht dreifach: Pfeile und Auswahlfelder (auch per Tastatur und am
// Handy) sowie Ziehen mit der Maus. Die Zentrale prüft alles noch einmal
// (Zyklen, Tiefe, Mandant); die Prüfungen hier sparen nur Fehlversuche.

import { useRef, useState, type DragEvent, type FormEvent, type ReactNode } from "react";
import { api, type Gruppe } from "./api";
import { darfPflegen, mandantName, type Bereich } from "./bereich";

export const maxEbenen = 4;

// Kinder einer Gruppe (oder die oberste Ebene eines Mandanten) in ihrer Reihenfolge.
export function kinder(gruppen: Gruppe[], mandant: string, eltern: string | null): Gruppe[] {
  return gruppen
    .filter((g) => g.mandant_id === mandant && g.eltern_id === eltern)
    .sort((a, b) => a.position - b.position || a.name.localeCompare(b.name, "de"));
}

export function nachId(gruppen: Gruppe[]) {
  return new Map(gruppen.map((g) => [g.id, g]));
}

// Pfad einer Gruppe, z. B. „Netzwerk / Switche“.
export function pfad(idx: Map<string, Gruppe>, id: string | null): string {
  const teile: string[] = [];
  for (let g = id ? idx.get(id) : undefined, n = 0; g && n < 10; g = g.eltern_id ? idx.get(g.eltern_id) : undefined, n++) {
    teile.unshift(g.name);
  }
  return teile.join(" / ");
}

function ebene(idx: Map<string, Gruppe>, id: string | null): number {
  let n = 0;
  for (let g = id ? idx.get(id) : undefined; g && n < 10; g = g.eltern_id ? idx.get(g.eltern_id) : undefined) n++;
  return n;
}

// Höhe des Teilbaums unter einer Gruppe (0 = keine Untergruppen).
function hoehe(gruppen: Gruppe[], id: string, n = 0): number {
  if (n > 10) return n;
  let h = 0;
  for (const c of gruppen) if (c.eltern_id === id) h = Math.max(h, 1 + hoehe(gruppen, c.id, n + 1));
  return h;
}

// Liegt „ziel“ in „gruppe“ oder ist es die Gruppe selbst?
function innerhalb(idx: Map<string, Gruppe>, ziel: string | null, gruppe: string): boolean {
  for (let g = ziel ? idx.get(ziel) : undefined, n = 0; g && n < 10; g = g.eltern_id ? idx.get(g.eltern_id) : undefined, n++) {
    if (g.id === gruppe) return true;
  }
  return false;
}

// Alle Gruppen eines Mandanten in Baumreihenfolge, als Optionen mit Pfad.
export function optionen(gruppen: Gruppe[], mandant: string): { id: string; text: string }[] {
  const idx = nachId(gruppen);
  const out: { id: string; text: string }[] = [];
  const lauf = (eltern: string | null, tiefe: number) => {
    if (tiefe > maxEbenen) return;
    for (const g of kinder(gruppen, mandant, eltern)) {
      out.push({ id: g.id, text: pfad(idx, g.id) });
      lauf(g.id, tiefe + 1);
    }
  };
  lauf(null, 1);
  return out;
}

// Auswahl der Gruppe im Geräteformular.
export function GruppeAuswahl(props: { gruppen: Gruppe[]; mandant: string; wert: string; setWert: (s: string) => void }) {
  const opt = optionen(props.gruppen, props.mandant);
  return (
    <label className="feld">
      <span>Gruppe (optional)</span>
      <select value={props.wert} onChange={(e) => props.setWert(e.target.value)}>
        <option value="">– ohne Gruppe –</option>
        {opt.map((o) => (
          <option key={o.id} value={o.id}>
            {o.text}
          </option>
        ))}
      </select>
    </label>
  );
}

// --- Gruppen ordnen -------------------------------------------------------------

export interface OrdnenGeraet {
  id: string;
  name: string;
  mandant_id: string;
  gruppe_id: string | null;
  // CSS-Klasse des Signals (Zustand)
  signal: string;
}

type Zug = { art: "geraete"; ids: string[]; mandant: string } | { art: "gruppe"; id: string; mandant: string };
type Ziel = { mandant: string; gruppe: string | null; davor: boolean };

export function GruppenOrdnen(props: {
  bereich: Bereich;
  gruppen: Gruppe[];
  geraete: OrdnenGeraet[];
  onGeaendert: () => void;
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const { bereich, gruppen, geraete } = props;
  const idx = nachId(gruppen);
  const [auswahl, setAuswahl] = useState<Set<string>>(new Set());
  const [nach, setNach] = useState("");
  const [bearbeite, setBearbeite] = useState<{ art: "neu" | "aendern" | "loeschen"; mandant: string; id: string | null } | null>(null);
  const [beschaeftigt, setBeschaeftigt] = useState(false);
  const [ziel, setZiel] = useState<string>("");
  const zug = useRef<Zug | null>(null);

  // Mandanten im Bereich mit Geräten oder Gruppen; der gewählte Mandant immer.
  const mandanten = [...bereich.ids].filter(
    (m) => m === bereich.mandant.id || gruppen.some((g) => g.mandant_id === m) || geraete.some((d) => d.mandant_id === m),
  );
  mandanten.sort((a, b) =>
    a === bereich.mandant.id ? -1 : b === bereich.mandant.id ? 1 : mandantName(bereich, a).localeCompare(mandantName(bereich, b), "de"),
  );

  const ausfuehren = async (fn: () => Promise<unknown>) => {
    setBeschaeftigt(true);
    try {
      await fn();
    } catch (e) {
      props.melden(e);
    } finally {
      setBeschaeftigt(false);
      props.onGeaendert();
    }
  };

  const zuordnen = (ids: string[], gruppe: string | null) =>
    ausfuehren(async () => {
      await api("POST", "/api/v1/geraete/gruppe", { geraete: ids, gruppe_id: gruppe ?? "" });
      setAuswahl(new Set());
    });

  const verschieben = (g: Gruppe, eltern: string | null, vor: string | null) =>
    ausfuehren(async () => {
      if (g.eltern_id !== eltern) await api("PUT", `/api/v1/gruppen/${g.id}`, { name: g.name, eltern_id: eltern ?? "" });
      if (vor !== null || g.eltern_id === eltern) await api("POST", `/api/v1/gruppen/${g.id}/position`, { vor_id: vor ?? "" });
    });

  // Gruppe eine Stelle hoch oder runter.
  const schieben = (g: Gruppe, richtung: -1 | 1) => {
    const sib = kinder(gruppen, g.mandant_id, g.eltern_id);
    const i = sib.findIndex((x) => x.id === g.id);
    if (richtung === -1 && i > 0) void verschieben(g, g.eltern_id, sib[i - 1]!.id);
    if (richtung === 1 && i < sib.length - 1) void verschieben(g, g.eltern_id, sib[i + 2]?.id ?? null);
  };

  // Ist ein Ziel für den laufenden Zug erlaubt? Grund für die Ablehnung oder "".
  const pruefen = (z: Zug, t: Ziel): string => {
    if (z.mandant !== t.mandant) return "Nur innerhalb eines Mandanten.";
    if (z.art === "geraete") return "";
    const eltern = t.davor ? (t.gruppe ? (idx.get(t.gruppe)?.eltern_id ?? null) : null) : t.gruppe;
    if (eltern && innerhalb(idx, eltern, z.id)) return "Nicht in sich selbst oder eine Untergruppe.";
    if (ebene(idx, eltern) + 1 + hoehe(gruppen, z.id) > maxEbenen) return `Höchstens ${maxEbenen} Ebenen.`;
    return "";
  };

  const zielVon = (e: DragEvent, mandant: string, gruppe: string | null): Ziel => {
    if (!gruppe || zug.current?.art !== "gruppe") return { mandant, gruppe, davor: false };
    const r = e.currentTarget.getBoundingClientRect();
    return { mandant, gruppe, davor: e.clientY - r.top < r.height / 3 };
  };

  const zielProps = (mandant: string, gruppe: string | null) => ({
    onDragOver: (e: DragEvent) => {
      const z = zug.current;
      if (!z) return;
      const t = zielVon(e, mandant, gruppe);
      if (pruefen(z, t)) {
        setZiel("");
        return;
      }
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      setZiel(`${gruppe ?? "m:" + mandant}${t.davor ? ":davor" : ""}`);
    },
    onDragLeave: () => setZiel(""),
    onDrop: (e: DragEvent) => {
      e.preventDefault();
      const z = zug.current;
      if (!z) return;
      const t = zielVon(e, mandant, gruppe); // braucht den laufenden Zug
      zug.current = null;
      setZiel("");
      const grund = pruefen(z, t);
      if (grund) {
        props.melden(new Error(grund));
        return;
      }
      if (z.art === "geraete") {
        void zuordnen(z.ids, t.gruppe);
        return;
      }
      const g = idx.get(z.id);
      if (!g || g.id === t.gruppe) return;
      if (t.davor && t.gruppe) void verschieben(g, idx.get(t.gruppe)?.eltern_id ?? null, t.gruppe);
      else if (g.eltern_id !== t.gruppe) void verschieben(g, t.gruppe, null);
    },
  });

  const zieheGeraet = (d: OrdnenGeraet) => (e: DragEvent) => {
    // Ist das Gerät markiert, ziehen alle markierten Geräte seines Mandanten mit.
    const ids = auswahl.has(d.id) ? geraete.filter((x) => auswahl.has(x.id) && x.mandant_id === d.mandant_id).map((x) => x.id) : [d.id];
    zug.current = { art: "geraete", ids, mandant: d.mandant_id };
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", d.name);
  };
  const zieheGruppe = (g: Gruppe) => (e: DragEvent) => {
    e.stopPropagation();
    zug.current = { art: "gruppe", id: g.id, mandant: g.mandant_id };
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", g.name);
  };
  const zugEnde = () => {
    zug.current = null;
    setZiel("");
  };

  const umschalten = (id: string) => {
    const s = new Set(auswahl);
    if (s.has(id)) s.delete(id);
    else s.add(id);
    setAuswahl(s);
    setNach("");
  };

  const markiert = geraete.filter((d) => auswahl.has(d.id));
  const markiertMandanten = new Set(markiert.map((d) => d.mandant_id));
  const einMandant = markiertMandanten.size === 1 ? [...markiertMandanten][0]! : "";

  const geraetZeilen = (mandant: string, gruppe: string | null, darf: boolean): ReactNode[] =>
    geraete
      .filter((d) => d.mandant_id === mandant && (d.gruppe_id ?? null) === gruppe)
      .sort((a, b) => a.name.localeCompare(b.name, "de"))
      .map((d) => (
        <li
          key={d.id}
          className={`ordnen-geraet${auswahl.has(d.id) ? " markiert" : ""}`}
          draggable={darf}
          onDragStart={zieheGeraet(d)}
          onDragEnd={zugEnde}
        >
          <label>
            <input type="checkbox" disabled={!darf} checked={auswahl.has(d.id)} onChange={() => umschalten(d.id)} />
            <span className={`signal ${d.signal}`} aria-hidden="true" />
            <span className="name">{d.name}</span>
          </label>
        </li>
      ));

  const gruppeKnoten = (g: Gruppe, darf: boolean, tiefe: number): ReactNode => {
    const sib = kinder(gruppen, g.mandant_id, g.eltern_id);
    const i = sib.findIndex((x) => x.id === g.id);
    // Geräte im ganzen Teilbaum, wie in der Hosts-Liste
    const teilbaum = new Set([g.id, ...gruppen.filter((c) => innerhalb(idx, c.id, g.id)).map((c) => c.id)]);
    const anzahl = geraete.filter((d) => d.gruppe_id && teilbaum.has(d.gruppe_id)).length;
    const zp = darf ? zielProps(g.mandant_id, g.id) : {};
    return (
      <li key={g.id} className="ordnen-gruppe">
        <div
          className={`ordnen-kopf${ziel === g.id ? " ziel-hinein" : ""}${ziel === g.id + ":davor" ? " ziel-davor" : ""}`}
          draggable={darf}
          onDragStart={zieheGruppe(g)}
          onDragEnd={zugEnde}
          {...zp}
        >
          <span className="ordnen-griff" aria-hidden="true">
            ⠿
          </span>
          <span className="name">{g.name}</span>
          <span className="klein">
            {anzahl} {anzahl === 1 ? "Gerät" : "Geräte"}
          </span>
          {darf && (
            <span className="ordnen-knoepfe">
              <button
                className="knopf knopf-klein"
                disabled={beschaeftigt || i <= 0}
                aria-label={`„${g.name}“ nach oben`}
                onClick={() => schieben(g, -1)}
              >
                ↑
              </button>
              <button
                className="knopf knopf-klein"
                disabled={beschaeftigt || i >= sib.length - 1}
                aria-label={`„${g.name}“ nach unten`}
                onClick={() => schieben(g, 1)}
              >
                ↓
              </button>
              <button className="knopf knopf-klein" onClick={() => setBearbeite({ art: "aendern", mandant: g.mandant_id, id: g.id })}>
                Bearbeiten
              </button>
              {tiefe < maxEbenen && (
                <button className="knopf knopf-klein" onClick={() => setBearbeite({ art: "neu", mandant: g.mandant_id, id: g.id })}>
                  Untergruppe
                </button>
              )}
              <button className="knopf knopf-klein" onClick={() => setBearbeite({ art: "loeschen", mandant: g.mandant_id, id: g.id })}>
                Löschen
              </button>
            </span>
          )}
        </div>
        {bearbeite?.id === g.id && (
          <GruppeFormular
            key={bearbeite.art}
            art={bearbeite.art}
            gruppe={g}
            gruppen={gruppen}
            onFertig={() => {
              setBearbeite(null);
              props.onGeaendert();
            }}
            melden={props.melden}
          />
        )}
        <ul className="ordnen-liste">
          {kinder(gruppen, g.mandant_id, g.id).map((c) => gruppeKnoten(c, darf, tiefe + 1))}
          {geraetZeilen(g.mandant_id, g.id, darf)}
        </ul>
      </li>
    );
  };

  return (
    <div className="ordnen" aria-busy={beschaeftigt}>
      <p className="hinweis klein">
        Geräte markieren und unten verschieben oder mit der Maus auf eine Gruppe ziehen. Eine Gruppe auf das obere Drittel einer anderen
        ziehen setzt sie davor, sonst hinein. Gruppen dienen nur der Übersicht und der Wandanzeige; Rechte hängen am Mandanten.
      </p>
      {mandanten.map((m) => {
        const darf = darfPflegen(bereich, m);
        const zp = darf ? zielProps(m, null) : {};
        return (
          <section key={m} className="ordnen-mandant" aria-label={`Gruppen in ${mandantName(bereich, m)}`}>
            <div className={`ordnen-kopf ordnen-oben${ziel === "m:" + m ? " ziel-hinein" : ""}`} {...zp}>
              <span className="name">{bereich.mehrere ? mandantName(bereich, m) : "Oberste Ebene"}</span>
              <span className="klein">Hierher ziehen: ohne Gruppe bzw. oberste Ebene</span>
              {darf && (
                <span className="ordnen-knoepfe">
                  <button className="knopf knopf-klein" onClick={() => setBearbeite({ art: "neu", mandant: m, id: null })}>
                    Neue Gruppe
                  </button>
                </span>
              )}
            </div>
            {bearbeite?.mandant === m && bearbeite.id === null && (
              <GruppeFormular
                art="neu"
                mandant={m}
                gruppen={gruppen}
                onFertig={() => {
                  setBearbeite(null);
                  props.onGeaendert();
                }}
                melden={props.melden}
              />
            )}
            <ul className="ordnen-liste">
              {kinder(gruppen, m, null).map((g) => gruppeKnoten(g, darf, 1))}
              {geraetZeilen(m, null, darf)}
            </ul>
          </section>
        );
      })}

      {markiert.length > 0 && (
        <div className="ordnen-leiste" role="region" aria-label="Markierte Geräte">
          <span>
            {markiert.length} {markiert.length === 1 ? "Gerät" : "Geräte"} markiert
          </span>
          <label className="feld feld-inline">
            <span>Verschieben nach</span>
            <select value={nach} onChange={(e) => setNach(e.target.value)}>
              <option value="">– ohne Gruppe –</option>
              {einMandant &&
                optionen(gruppen, einMandant).map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.text}
                  </option>
                ))}
            </select>
          </label>
          {!einMandant && <span className="klein">Geräte aus mehreren Mandanten lassen sich nur aus ihren Gruppen nehmen.</span>}
          <button className="knopf knopf-haupt" disabled={beschaeftigt} onClick={() => void zuordnen([...auswahl], nach || null)}>
            Verschieben
          </button>
          <button className="knopf" onClick={() => setAuswahl(new Set())}>
            Auswahl aufheben
          </button>
        </div>
      )}
      <div className="aktionen">
        <button className="knopf knopf-haupt" onClick={props.onFertig}>
          Fertig
        </button>
      </div>
    </div>
  );
}

// Anlegen (oben oder als Untergruppe), Umbenennen/Verschieben, Löschen.
function GruppeFormular(props: {
  art: "neu" | "aendern" | "loeschen";
  gruppe?: Gruppe; // bei „neu“: Eltern-Gruppe
  mandant?: string;
  gruppen: Gruppe[];
  onFertig: () => void;
  melden: (e: unknown) => void;
}) {
  const g = props.gruppe;
  const mandant = g?.mandant_id ?? props.mandant ?? "";
  const idx = nachId(props.gruppen);
  const [name, setName] = useState(props.art === "aendern" && g ? g.name : "");
  const [eltern, setEltern] = useState(props.art === "aendern" && g ? (g.eltern_id ?? "") : "");
  const [fehler, setFehler] = useState("");

  const absenden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    try {
      if (props.art === "neu") await api("POST", `/api/v1/mandanten/${mandant}/gruppen`, { name, eltern_id: g?.id ?? "" });
      else if (props.art === "aendern" && g) await api("PUT", `/api/v1/gruppen/${g.id}`, { name, eltern_id: eltern });
      else if (g) await api("DELETE", `/api/v1/gruppen/${g.id}`);
      props.onFertig();
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    }
  };

  if (props.art === "loeschen" && g) {
    const oben = g.eltern_id ? `nach „${pfad(idx, g.eltern_id)}“` : "auf die oberste Ebene bzw. ohne Gruppe";
    return (
      <form className="bestaetigung" role="alertdialog" aria-label="Gruppe löschen" onSubmit={absenden}>
        <p>
          „{g.name}“ löschen? Geräte und Untergruppen darin wandern {oben}.
        </p>
        {fehler && (
          <p className="meldung meldung-fehler" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-gefahr">Löschen</button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    );
  }

  // Mögliche neue Eltern: nicht die Gruppe selbst, keine ihrer Untergruppen, Tiefe passt.
  const h = g ? hoehe(props.gruppen, g.id) : 0;
  const elternOpt =
    props.art === "aendern" && g
      ? optionen(props.gruppen, mandant).filter((o) => !innerhalb(idx, o.id, g.id) && ebene(idx, o.id) + 1 + h <= maxEbenen)
      : [];
  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={absenden}>
        <h3 className="einschub-titel">
          {props.art === "neu" ? (g ? `Untergruppe in „${g.name}“` : "Neue Gruppe") : `„${g?.name}“ bearbeiten`}
        </h3>
        <label className="feld">
          <span>Name</span>
          <input required maxLength={50} value={name} placeholder="z. B. Switche" onChange={(e) => setName(e.target.value)} />
        </label>
        {props.art === "aendern" && (
          <label className="feld">
            <span>Liegt in</span>
            <select value={eltern} onChange={(e) => setEltern(e.target.value)}>
              <option value="">– oberste Ebene –</option>
              {elternOpt.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.text}
                </option>
              ))}
            </select>
          </label>
        )}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt">{props.art === "neu" ? "Anlegen" : "Speichern"}</button>
          <button type="button" className="knopf" onClick={props.onFertig}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
