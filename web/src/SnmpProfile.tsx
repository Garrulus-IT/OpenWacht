// SPDX-License-Identifier: AGPL-3.0-only

// Seite „SNMP-Profile“ (Etappe 27): Community oder v3-Zugang je Mandant, an
// beliebig vielen Geräten wiederverwendbar. Die Zugangsdaten zeigt die
// Oberfläche nie wieder an; wer sie ändert, gibt sie vollständig neu ein.
// Ändern verschlüsselt alle Geräte mit dem Profil neu. Pflegen und sehen
// dürfen nur Admins; Profile der Eltern sehen Admins eines Untermandanten nicht.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type SnmpProfil } from "./api";
import { mandantName, rolleIn, type Bereich } from "./bereich";
import { profilVersion, V3Felder, type SnmpWerte } from "./Snmp";
import { vor } from "./zeit";

export function SnmpProfile({ bereich, melden }: { bereich: Bereich; melden: (e: unknown) => void }) {
  const admin = rolleIn(bereich, bereich.mandant.id) === "admin";
  const [liste, setListe] = useState<SnmpProfil[] | null>(null);
  // "neu" oder ID des Profils, das bearbeitet wird
  const [form, setForm] = useState("");
  const [loeschen, setLoeschen] = useState<SnmpProfil | null>(null);
  const [hinweis, setHinweis] = useState("");

  const laden = useCallback(async () => {
    try {
      const r = await api<{ profile: SnmpProfil[] }>("GET", "/api/v1/snmp-profile");
      setListe(r.profile.filter((p) => bereich.ids.has(p.mandant_id)));
    } catch (e) {
      melden(e);
    }
  }, [bereich, melden]);
  useEffect(() => {
    void laden();
  }, [laden]);

  const bearbeitet = liste?.find((p) => p.id === form) ?? null;
  return (
    <section className="ansicht" aria-labelledby="profile-titel">
      <div className="abschnitt-kopf">
        <h2 id="profile-titel" className="abschnitt">
          SNMP-Profile
        </h2>
        {admin && !form && (
          <button className="knopf" onClick={() => setForm("neu")}>
            Profil anlegen
          </button>
        )}
      </div>
      <p className="klein">
        Ein Profil hält Version und Zugangsdaten (Community oder SNMPv3-Benutzer) für viele Geräte. Am Gerät unter SNMP „Profil“ wählen;
        ändert sich das Profil, übernehmen alle Geräte die neuen Zugangsdaten. Profile gelten für den Mandanten und alle darunter.
      </p>
      {!admin && <p className="leer">SNMP-Profile sehen und pflegen nur Admins des Mandanten.</p>}
      {hinweis && (
        <p className="meldung meldung-ok" role="status">
          {hinweis}
        </p>
      )}
      {form && (
        <ProfilFormular
          key={form}
          bereich={bereich}
          profil={bearbeitet}
          onFertig={(text) => {
            setForm("");
            setHinweis(text ?? "");
            void laden();
          }}
          melden={melden}
        />
      )}
      {loeschen && (
        <div className="einschub" role="alertdialog" aria-labelledby="profil-loeschen-titel">
          <h3 id="profil-loeschen-titel" className="einschub-titel">
            Profil „{loeschen.name}“ löschen?
          </h3>
          <p>
            {loeschen.geraete > 0
              ? `${loeschen.geraete} ${loeschen.geraete === 1 ? "Gerät behält" : "Geräte behalten"} ihre Zugangsdaten und fragen weiter ab, nur ohne Bezug zum Profil.`
              : "Kein Gerät nutzt dieses Profil."}
          </p>
          <div className="aktionen">
            <button
              className="knopf knopf-gefahr"
              onClick={async () => {
                try {
                  await api("DELETE", `/api/v1/snmp-profile/${loeschen.id}`);
                  setLoeschen(null);
                  setHinweis("");
                  void laden();
                } catch (e) {
                  melden(e);
                }
              }}
            >
              Löschen
            </button>
            <button className="knopf" onClick={() => setLoeschen(null)}>
              Abbrechen
            </button>
          </div>
        </div>
      )}
      {liste === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : liste.length === 0 ? (
        admin && <p className="leer">Noch keine SNMP-Profile.</p>
      ) : (
        <table className="tabelle">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Version</th>
              <th scope="col">Geräte</th>
              <th scope="col">Geändert</th>
              <th scope="col">Aktionen</th>
            </tr>
          </thead>
          <tbody>
            {liste.map((p) => (
              <tr key={p.id}>
                <td className="name">
                  {p.name}
                  {bereich.mehrere && <span className="mandant-marke">{mandantName(bereich, p.mandant_id)}</span>}
                </td>
                <td>
                  {profilVersion(p)} {p.version !== "3" && <span className="marke marke-warn">Klartext</span>}
                </td>
                <td>{p.geraete}</td>
                <td>{vor(p.geaendert, Date.now())}</td>
                <td className="aktionen-zelle">
                  {rolleIn(bereich, p.mandant_id) === "admin" && (
                    <>
                      <button className="knopf knopf-klein" onClick={() => setForm(p.id)}>
                        Bearbeiten
                      </button>
                      <button className="knopf knopf-klein knopf-gefahr" onClick={() => setLoeschen(p)}>
                        Löschen
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ProfilFormular(props: {
  bereich: Bereich;
  profil: SnmpProfil | null;
  onFertig: (hinweis?: string) => void;
  melden: (e: unknown) => void;
}) {
  const p = props.profil;
  const [name, setName] = useState(p?.name ?? "");
  const [w, setW] = useState<SnmpWerte>({
    version: p?.version ?? "3",
    adresse: "",
    port: "161",
    community: "",
    benutzer: "",
    auth: p?.v3_auth ?? "sha256",
    authPasswort: "",
    priv: p?.v3_priv ?? "aes",
    privPasswort: "",
    intervall: "60",
    aktiv: true,
    traps: false,
    sammler: "",
    profil: "",
  });
  const [fehler, setFehler] = useState("");
  const [arbeitet, setArbeitet] = useState(false);
  // Neue Zugangsdaten sind Pflicht beim Anlegen und beim Wechsel der Version.
  const neu = !p || p.version !== w.version;

  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setFehler("");
    setArbeitet(true);
    const v3 = w.version === "3";
    const body = {
      name: name.trim(),
      version: w.version,
      community: v3 ? "" : w.community,
      v3:
        v3 && (w.authPasswort || w.privPasswort)
          ? { benutzer: w.benutzer.trim(), auth: w.auth, auth_passwort: w.authPasswort, priv: w.priv, priv_passwort: w.privPasswort }
          : null,
    };
    try {
      if (p) {
        const r = await api<{ neu_verschluesselt: number }>("PUT", `/api/v1/snmp-profile/${p.id}`, body);
        props.onFertig(
          r.neu_verschluesselt > 0
            ? `Profil gespeichert; ${r.neu_verschluesselt} ${r.neu_verschluesselt === 1 ? "Gerät nutzt" : "Geräte nutzen"} jetzt die neuen Zugangsdaten.`
            : "Profil gespeichert.",
        );
      } else {
        await api("POST", `/api/v1/mandanten/${props.bereich.mandant.id}/snmp-profile`, body);
        props.onFertig(`Profil „${body.name}“ angelegt.`);
      }
    } catch (err) {
      setFehler(err instanceof Error ? err.message : String(err));
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <div className="einschub">
      <form className="formular formular-flach" onSubmit={senden} aria-label={p ? "SNMP-Profil bearbeiten" : "SNMP-Profil anlegen"}>
        <h3 className="einschub-titel">{p ? `Profil „${p.name}“ bearbeiten` : `Neues Profil in „${props.bereich.mandant.name}“`}</h3>
        <label className="feld formular-voll">
          <span>Name</span>
          <input required maxLength={60} value={name} placeholder="Switches Hauptsitz" onChange={(e) => setName(e.target.value)} />
        </label>
        <fieldset className="feld formular-voll auswahl auswahl-reihe">
          <legend>SNMP-Version</legend>
          <label>
            <input type="radio" name="profil-version" checked={w.version === "3"} onChange={() => setW({ ...w, version: "3" })} />
            <span>v3 (verschlüsselt, empfohlen)</span>
          </label>
          <label>
            <input type="radio" name="profil-version" checked={w.version === "2c"} onChange={() => setW({ ...w, version: "2c" })} />
            <span>v2c</span>
          </label>
          <label>
            <input type="radio" name="profil-version" checked={w.version === "1"} onChange={() => setW({ ...w, version: "1" })} />
            <span>v1 (nur für alte Geräte)</span>
          </label>
        </fieldset>
        {w.version === "3" ? (
          <V3Felder w={w} setW={setW} neu={neu} />
        ) : (
          <label className="feld">
            <span>Community{neu ? "" : " (leer = unverändert)"}</span>
            <input
              type="password"
              autoComplete="off"
              required={neu}
              maxLength={64}
              value={w.community}
              placeholder={neu ? "wie an den Geräten eingestellt" : "••••••••"}
              onChange={(e) => setW({ ...w, community: e.target.value })}
            />
          </label>
        )}
        {p && p.geraete > 0 && (
          <p className="hinweis klein formular-voll">
            Neue Zugangsdaten gehen sofort an {p.geraete} {p.geraete === 1 ? "Gerät" : "Geräte"}; die Geräte selbst müssen sie schon kennen.
          </p>
        )}
        {fehler && (
          <p className="meldung meldung-fehler formular-voll" role="alert">
            {fehler}
          </p>
        )}
        <div className="aktionen">
          <button className="knopf knopf-haupt" disabled={arbeitet || !name.trim()}>
            Speichern
          </button>
          <button type="button" className="knopf" onClick={() => props.onFertig()}>
            Abbrechen
          </button>
        </div>
      </form>
    </div>
  );
}
