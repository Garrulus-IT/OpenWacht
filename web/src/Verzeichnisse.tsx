// SPDX-License-Identifier: AGPL-3.0-only

// Verwaltung › Anmeldung über AD (Etappe 22a): Anbindungen an ein Active
// Directory per LDAPS. AD-Gruppen ergeben Mandant und Rolle; das Passwort des
// Dienstkontos geht nur hin, nie zurück. Speichern und Löschen verlangen die
// Bestätigung (Code aus der App bzw. eigenes Passwort).

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { api, rollenName, type Mandant, type Rolle } from "./api";
import { baumReihe } from "./bereich";
import { bestaetigungFertig, CodeFeld } from "./Bestaetigung";

interface Gruppe {
  gruppe: string;
  mandant: string;
  rolle: Rolle;
}

interface Anbindung {
  id: string;
  art: "ldap" | "oidc";
  mandant: string;
  mandant_name: string;
  name: string;
  url: string;
  eigene_ca: boolean;
  bind_dn: string;
  base_dn: string;
  netbios: string | null;
  verschachtelt: boolean;
  zwei_faktor: boolean;
  aktiv: boolean;
  domaenen: string[];
  gruppen: Gruppe[];
  konten: number;
  adress_claim: AdressClaim;
  // Etappe 30: Untermandanten brauchen die Freigabe des Betreibers
  domaenen_status: Record<string, Freigabe>;
  netbios_status: Freigabe;
  sitzung_stunden: number;
}

type Freigabe = "beantragt" | "freigegeben" | "abgelehnt";

function Anmeldename(props: { text: string; status: Freigabe | undefined }) {
  if (props.status === "beantragt") {
    return (
      <span className="status-beantragt" title="Wartet auf die Freigabe durch den Betreiber">
        {props.text} (beantragt)
      </span>
    );
  }
  if (props.status === "abgelehnt") {
    return (
      <span className="status-abgelehnt" title="Vom Betreiber abgelehnt">
        {props.text} (abgelehnt)
      </span>
    );
  }
  return <span>{props.text}</span>;
}

type AdressClaim = "email" | "upn" | "preferred_username";

export function Verzeichnisse(props: { mandant: Mandant; mandanten: Mandant[]; melden: (e: unknown) => void }) {
  const { mandant, mandanten, melden } = props;
  const admin = mandant.rolle === "admin";
  const [liste, setListe] = useState<Anbindung[] | null>(null);
  const [rueckkehr, setRueckkehr] = useState("");
  const [form, setForm] = useState<Anbindung | "neu" | "neu-oidc" | null>(null);
  const [testErgebnis, setTestErgebnis] = useState<Record<string, string>>({});

  const laden = useCallback(async () => {
    try {
      const r = await api<{ verzeichnisse: Anbindung[]; sso_rueckkehr: string }>("GET", "/api/v1/verzeichnisse");
      setListe(r.verzeichnisse);
      setRueckkehr(r.sso_rueckkehr);
    } catch (e) {
      melden(e);
    }
  }, [melden]);
  useEffect(() => {
    void laden();
  }, [laden]);

  const testen = async (a: Anbindung) => {
    setTestErgebnis((t) => ({ ...t, [a.id]: "prüft …" }));
    try {
      const r = await api<{ ok: boolean; fehler?: string }>("POST", `/api/v1/verzeichnisse/${a.id}/test`);
      setTestErgebnis((t) => ({ ...t, [a.id]: r.ok ? "Verbindung und Dienstkonto in Ordnung" : (r.fehler ?? "fehlgeschlagen") }));
    } catch (e) {
      setTestErgebnis((t) => ({ ...t, [a.id]: e instanceof Error ? e.message : String(e) }));
    }
  };

  const hier = (liste ?? []).filter((a) => a.mandant === mandant.id);
  const darunter = (liste ?? []).filter((a) => a.mandant !== mandant.id);

  return (
    <>
      <div className="abschnitt-kopf">
        <h2 className="abschnitt">Anmeldung über AD und SSO für {mandant.name}</h2>
        {admin && form === null && (
          <div className="aktionen">
            <button className="knopf" onClick={() => setForm("neu")}>
              AD anbinden
            </button>
            <button className="knopf" onClick={() => setForm("neu-oidc")}>
              SSO (OIDC) anbinden
            </button>
          </div>
        )}
      </div>
      <p className="klein">
        Benutzer melden sich mit ihrem AD-Konto an (name@domäne oder DOMÄNE\name) oder per Firmen-Login (OIDC: Keycloak, ADFS, Entra ID)
        über „Mit Firmen-Login anmelden“. Mitglieder der zugeordneten AD-Gruppen bekommen das Konto beim ersten Anmelden; Rechte, Sperre und
        Name gleicht OpenWacht stündlich mit dem AD ab. Der Verzeichnisdienst muss in der Netzfreigabe liegen. Lokale Konten mit gleicher
        Adresse gehen vor.
      </p>
      {!admin && <p className="leer">Nur Admins des Mandanten richten die Anmeldung über AD ein.</p>}
      {form !== null && (
        <AnbindungFormular
          mandant={mandant}
          mandanten={mandanten}
          vorher={form === "neu" || form === "neu-oidc" ? null : form}
          art={form === "neu-oidc" ? "oidc" : form === "neu" ? "ldap" : form.art}
          rueckkehr={rueckkehr}
          onFertig={() => {
            setForm(null);
            void laden();
          }}
          onAbbrechen={() => setForm(null)}
          melden={melden}
        />
      )}
      {liste === null ? (
        <p className="klein" aria-busy="true">
          Lädt …
        </p>
      ) : (
        admin &&
        form === null &&
        (hier.length === 0 && darunter.length === 0 ? (
          <p className="leer">Noch keine Anbindung.</p>
        ) : (
          [...hier, ...darunter].map((a) => (
            <AnbindungKarte
              key={a.id}
              a={a}
              mandanten={mandanten}
              test={testErgebnis[a.id]}
              onTest={() => void testen(a)}
              onBearbeiten={() => setForm(a)}
              onGeloescht={() => void laden()}
              melden={melden}
            />
          ))
        ))
      )}
    </>
  );
}

function AnbindungKarte(props: {
  a: Anbindung;
  mandanten: Mandant[];
  test?: string;
  onTest: () => void;
  onBearbeiten: () => void;
  onGeloescht: () => void;
  melden: (e: unknown) => void;
}) {
  const { a, mandanten } = props;
  const [loeschen, setLoeschen] = useState(false);
  const [code, setCode] = useState("");
  const name = (id: string) => mandanten.find((m) => m.id === id)?.name ?? "unbekannt";
  return (
    <section className="panel" aria-label={`Anbindung ${a.name}`}>
      <div className="panel-kopf">
        <h3 className="panel-titel">
          {a.name} {!a.aktiv && <span className="marke">aus</span>}
        </h3>
        <span className="klein">
          {a.mandant_name} · {a.konten} {a.konten === 1 ? "Konto" : "Konten"}
        </span>
      </div>
      <div className="panel-inhalt">
        <dl className="eigenschaften">
          <dt>{a.art === "oidc" ? "Issuer (OIDC)" : "Server (LDAP)"}</dt>
          <dd className="mono">{a.url}</dd>
          <dt>Anmeldung mit</dt>
          <dd className="mono anmeldenamen">
            {a.domaenen.map((d) => (
              <Anmeldename key={d} text={"name@" + d} status={a.domaenen_status[d]} />
            ))}
            {a.netbios && <Anmeldename text={a.netbios + "\\name"} status={a.netbios_status} />}
          </dd>
          <dt>{a.art === "oidc" ? "Client-ID" : "Dienstkonto"}</dt>
          <dd className="mono">{a.bind_dn}</dd>
          <dt>{a.art === "oidc" ? "Gruppen-Claim" : "Suchbasis"}</dt>
          <dd className="mono">{a.base_dn}</dd>
          {a.art === "oidc" && (
            <>
              <dt>Adresse aus Claim</dt>
              <dd className="mono">{a.adress_claim}</dd>
            </>
          )}
          <dt>Zwei-Faktor</dt>
          <dd>{a.zwei_faktor ? "Pflicht (Code aus der App zusätzlich zum AD-Passwort)" : "nicht verlangt"}</dd>
          <dt>Sitzung höchstens</dt>
          <dd>{a.sitzung_stunden ? `${a.sitzung_stunden} Std.` : "12 Std. (Standard)"}</dd>
        </dl>
        {(Object.values(a.domaenen_status).includes("beantragt") || a.netbios_status === "beantragt") && (
          <p className="hinweis klein">
            Anmeldungen mit beantragten Domänen bzw. NetBIOS-Namen gehen erst, wenn der Betreiber sie unter Einstellungen › Anmelde-Domänen
            freigibt. So kann kein Mandant Anmeldungen fremder Domänen auf seinen Server umleiten.
          </p>
        )}
        {a.gruppen.length === 0 ? (
          <p className="leer">Keine Gruppen zugeordnet: Niemand kann sich anmelden.</p>
        ) : (
          <table className="tabelle verzeichnis-gruppen">
            <thead>
              <tr>
                <th scope="col">{a.art === "oidc" ? "Gruppe" : "AD-Gruppe"}</th>
                <th scope="col">Mandant</th>
                <th scope="col">Rolle</th>
              </tr>
            </thead>
            <tbody>
              {a.gruppen.map((g) => (
                <tr key={g.gruppe + g.mandant}>
                  <td className="mono">{g.gruppe}</td>
                  <td>{name(g.mandant)}</td>
                  <td>{rollenName[g.rolle]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {props.test && (
          <p className="klein" role="status">
            {props.test}
          </p>
        )}
        {loeschen ? (
          <form
            className="bestaetigung"
            aria-label="Anbindung löschen"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                await api("DELETE", `/api/v1/verzeichnisse/${a.id}`, { code });
                props.onGeloescht();
              } catch (err) {
                props.melden(err);
              }
            }}
          >
            <p>
              „{a.name}“ löschen? Alle {a.konten} Konten aus diesem AD werden gesperrt und abgemeldet.
            </p>
            <CodeFeld wert={code} setWert={setCode} id={`vz-loeschen-${a.id}`} />
            <div className="aktionen">
              <button className="knopf knopf-gefahr" disabled={!bestaetigungFertig(code)}>
                Endgültig löschen
              </button>
              <button type="button" className="knopf" onClick={() => setLoeschen(false)}>
                Abbrechen
              </button>
            </div>
          </form>
        ) : (
          <div className="aktionen">
            <button className="knopf" onClick={props.onTest}>
              Verbindung testen
            </button>
            <button className="knopf" onClick={props.onBearbeiten}>
              Bearbeiten
            </button>
            <button className="knopf knopf-gefahr" onClick={() => setLoeschen(true)}>
              Löschen
            </button>
          </div>
        )}
      </div>
    </section>
  );
}

function AnbindungFormular(props: {
  art: "ldap" | "oidc";
  rueckkehr: string;
  mandant: Mandant;
  mandanten: Mandant[];
  vorher: Anbindung | null;
  onFertig: () => void;
  onAbbrechen: () => void;
  melden: (e: unknown) => void;
}) {
  const v = props.vorher;
  const oidc = props.art === "oidc";
  const heim = v ? v.mandant : props.mandant.id;
  // Ziele der Gruppen: der Mandant der Anbindung und alles darunter, soweit Admin.
  const ziele = useMemo(() => {
    const reihe = baumReihe(props.mandanten);
    const i = reihe.findIndex((x) => x.m.id === heim);
    const start = reihe[i];
    if (!start) return [];
    const out = [start];
    for (const x of reihe.slice(i + 1)) {
      if (x.tiefe <= start.tiefe) break;
      out.push(x);
    }
    return out.filter((x) => x.m.rolle === "admin");
  }, [props.mandanten, heim]);

  const [name, setName] = useState(v?.name ?? (oidc ? "Firmen-Login" : "Active Directory"));
  const [url, setUrl] = useState(v?.url ?? (oidc ? "https://" : "ldaps://"));
  const [ca, setCa] = useState("");
  const [bindDN, setBindDN] = useState(v?.bind_dn ?? "");
  const [passwort, setPasswort] = useState("");
  const [baseDN, setBaseDN] = useState(v?.base_dn ?? "");
  const [adressClaim, setAdressClaim] = useState<AdressClaim>(v?.adress_claim ?? "email");
  const [netbios, setNetbios] = useState(v?.netbios ?? "");
  const [domaenen, setDomaenen] = useState((v?.domaenen ?? []).join(", "));
  const [verschachtelt, setVerschachtelt] = useState(v?.verschachtelt ?? !oidc);
  const [zweiFaktor, setZweiFaktor] = useState(v?.zwei_faktor ?? false);
  const [aktiv, setAktiv] = useState(v?.aktiv ?? true);
  const [stunden, setStunden] = useState(v?.sitzung_stunden ? String(v.sitzung_stunden) : "");
  const [gruppen, setGruppen] = useState<Gruppe[]>(v?.gruppen ?? []);
  const [code, setCode] = useState("");
  const [arbeitet, setArbeitet] = useState(false);

  const senden = async (e: FormEvent) => {
    e.preventDefault();
    setArbeitet(true);
    const body = {
      art: props.art,
      client_id: bindDN.trim(),
      gruppen_claim: baseDN.trim(),
      adress_claim: oidc ? adressClaim : "email",
      mandant: heim,
      name: name.trim(),
      url: url.trim(),
      ca: ca.trim(),
      bind_dn: bindDN.trim(),
      passwort,
      base_dn: baseDN.trim(),
      netbios: netbios.trim(),
      domaenen: domaenen
        .split(/[\s,;]+/)
        .map((x) => x.trim())
        .filter(Boolean),
      verschachtelt,
      zwei_faktor: zweiFaktor,
      aktiv,
      sitzung_stunden: stunden ? Number(stunden) : 0,
      gruppen: gruppen.filter((g) => g.gruppe.trim()),
      code,
    };
    try {
      if (v) await api("PUT", `/api/v1/verzeichnisse/${v.id}`, body);
      else await api("POST", "/api/v1/verzeichnisse", body);
      props.onFertig();
    } catch (err) {
      setCode("");
      props.melden(err);
    } finally {
      setArbeitet(false);
    }
  };

  const setG = (i: number, g: Partial<Gruppe>) => setGruppen((l) => l.map((x, j) => (j === i ? { ...x, ...g } : x)));

  return (
    <form className="panel formular" onSubmit={senden} aria-label={v ? "Anbindung bearbeiten" : oidc ? "SSO anbinden" : "AD anbinden"}>
      <div className="panel-inhalt">
        <label className="feld">
          <span>Name</span>
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        {oidc && (
          <p className="klein">
            Beim Identity Provider einen vertraulichen Client anlegen (Authorization Code mit PKCE) und als Weiterleitungsadresse{" "}
            <code>{props.rueckkehr}</code> eintragen. Die Anmeldung per SSO geht nur über diese Adresse. Der Gruppen-Claim muss im ID-Token
            stehen.
          </p>
        )}
        <label className="feld">
          <span>
            {oidc ? "Issuer (https://sso.firma.de/realms/firma)" : "Server (ldaps://dc1.firma.de oder ldap://…:389 mit StartTLS)"}
          </span>
          <input className="mono" required value={url} onChange={(e) => setUrl(e.target.value)} />
        </label>
        <label className="feld">
          <span>CA-Zertifikat des Servers (PEM){v?.eigene_ca ? ", bei Änderung neu einfügen" : ", leer = Zertifikate des Systems"}</span>
          <textarea className="mono" rows={3} value={ca} onChange={(e) => setCa(e.target.value)} />
        </label>
        <label className="feld">
          <span>{oidc ? "Client-ID" : "Dienstkonto (DN, nur Leserechte)"}</span>
          <input
            className="mono"
            required
            placeholder={oidc ? "openwacht" : "CN=svc-openwacht,OU=Dienste,DC=firma,DC=de"}
            value={bindDN}
            onChange={(e) => setBindDN(e.target.value)}
          />
        </label>
        <label className="feld">
          <span>
            {oidc ? "Client-Secret" : "Passwort des Dienstkontos"}
            {v ? " (leer = unverändert; bei neuem Server, Client/Dienstkonto oder CA Pflicht)" : ""}
          </span>
          <input type="password" autoComplete="new-password" required={!v} value={passwort} onChange={(e) => setPasswort(e.target.value)} />
        </label>
        <label className="feld">
          <span>{oidc ? "Gruppen-Claim (leer = groups)" : "Suchbasis (DN)"}</span>
          <input
            className="mono"
            required={!oidc}
            placeholder={oidc ? "groups" : "DC=firma,DC=de"}
            value={baseDN}
            onChange={(e) => setBaseDN(e.target.value)}
          />
        </label>
        {oidc && (
          <label className="feld">
            <span>Adresse des Kontos aus dem Claim</span>
            <select value={adressClaim} onChange={(e) => setAdressClaim(e.target.value as AdressClaim)}>
              <option value="email">email (Standard; email_verified=false wird abgelehnt)</option>
              <option value="upn">upn (z. B. Entra ID)</option>
              <option value="preferred_username">preferred_username (nur wenn der IdP ihn festlegt)</option>
            </select>
          </label>
        )}
        <label className="feld">
          <span>Domänen für name@domäne (UPN-Suffixe, durch Komma getrennt)</span>
          <input className="mono" placeholder="firma.de" value={domaenen} onChange={(e) => setDomaenen(e.target.value)} />
        </label>
        {!oidc && (
          <>
            <label className="feld">
              <span>NetBIOS-Name für DOMÄNE\name (optional)</span>
              <input className="mono" maxLength={15} placeholder="FIRMA" value={netbios} onChange={(e) => setNetbios(e.target.value)} />
            </label>
            <label className="feld-check">
              <input type="checkbox" checked={verschachtelt} onChange={(e) => setVerschachtelt(e.target.checked)} />
              <span>Verschachtelte Gruppen auflösen (AD)</span>
            </label>
          </>
        )}
        <label className="feld-check">
          <input type="checkbox" checked={zweiFaktor} onChange={(e) => setZweiFaktor(e.target.checked)} />
          <span>Zwei-Faktor-Anmeldung (Code aus der App) zusätzlich verlangen</span>
        </label>
        <label className="feld">
          <span>Sitzung höchstens</span>
          <select value={stunden} onChange={(e) => setStunden(e.target.value)}>
            <option value="">12 Stunden (Standard)</option>
            {[1, 2, 4, 8].map((h) => (
              <option key={h} value={String(h)}>
                {h} {h === 1 ? "Stunde" : "Stunden"}
              </option>
            ))}
          </select>
          <span className="klein">
            {oidc
              ? "Wer im Identity Provider gesperrt wird, bleibt bis zum Ende der Sitzung angemeldet: Eine kürzere Dauer verkürzt diese Zeit."
              : "Der Abgleich mit dem AD sperrt entzogene Konten stündlich; eine kürzere Sitzung erzwingt zusätzlich eine neue Anmeldung."}
          </span>
        </label>
        {v && (
          <label className="feld-check">
            <input type="checkbox" checked={aktiv} onChange={(e) => setAktiv(e.target.checked)} />
            <span>Anmeldung über diese Anbindung erlauben</span>
          </label>
        )}
        <fieldset className="feld-gruppe">
          <legend>{oidc ? "Gruppen aus dem Claim" : "AD-Gruppen"} → Mandant und Rolle</legend>
          {gruppen.map((g, i) => (
            <div className="formular-zeile" key={i}>
              <input
                className="mono"
                aria-label={oidc ? "Gruppe" : "AD-Gruppe (DN)"}
                placeholder={oidc ? "openwacht-admins" : "CN=GG-OpenWacht-Admins,OU=Gruppen,DC=firma,DC=de"}
                value={g.gruppe}
                onChange={(e) => setG(i, { gruppe: e.target.value })}
              />
              <select aria-label="Mandant" value={g.mandant} onChange={(e) => setG(i, { mandant: e.target.value })}>
                {ziele.map((z) => (
                  <option key={z.m.id} value={z.m.id}>
                    {"  ".repeat(z.tiefe) + z.m.name}
                  </option>
                ))}
              </select>
              <select aria-label="Rolle" value={g.rolle} onChange={(e) => setG(i, { rolle: e.target.value as Rolle })}>
                <option value="leser">Leser</option>
                <option value="operator">Operator</option>
                <option value="admin">Admin</option>
              </select>
              <button type="button" className="knopf" onClick={() => setGruppen((l) => l.filter((_, j) => j !== i))}>
                Entfernen
              </button>
            </div>
          ))}
          <button
            type="button"
            className="knopf"
            disabled={ziele.length === 0}
            onClick={() => setGruppen((l) => [...l, { gruppe: "", mandant: ziele[0]?.m.id ?? heim, rolle: "leser" }])}
          >
            Gruppe hinzufügen
          </button>
        </fieldset>
        <p className="klein">
          {oidc
            ? "Vor dem Speichern lädt OpenWacht die Konfiguration des Identity Providers. Wer in keiner Gruppe ist, kommt nicht hinein; Rechte gleicht jede Anmeldung ab."
            : "Vor dem Speichern prüft OpenWacht die Verbindung mit dem Dienstkonto. Wer in keiner Gruppe ist, kommt nicht hinein; wer aus allen Gruppen fällt, wird beim nächsten Abgleich gesperrt."}
        </p>
        <CodeFeld wert={code} setWert={setCode} id="vz-code" />
        <div className="knopf-reihe">
          <button type="button" className="knopf" onClick={props.onAbbrechen}>
            Abbrechen
          </button>
          <button className="knopf knopf-haupt" disabled={arbeitet || !bestaetigungFertig(code)}>
            {v ? "Speichern" : "Anbinden"}
          </button>
        </div>
      </div>
    </form>
  );
}
