// SPDX-License-Identifier: AGPL-3.0-only

// Bestätigung sicherheitsrelevanter Änderungen (Etappe 22a): mit
// eingerichteter Zwei-Faktor-Anmeldung ein frischer Code aus der App, sonst
// (wenn die Einstellung 2FA nicht verlangt) das eigene Passwort.

let mitApp = true;

// Von App.tsx nach dem Laden von /api/v1/ich gesetzt.
export function setzeBestaetigung(zweiFaktorAktiv: boolean) {
  mitApp = zweiFaktorAktiv;
}

export function bestaetigungFertig(wert: string): boolean {
  return mitApp ? wert.length === 6 : wert.length > 0;
}

export function CodeFeld(props: { wert: string; setWert: (s: string) => void; id: string }) {
  if (!mitApp) {
    return (
      <label className="feld code-feld" htmlFor={props.id}>
        <span>Eigenes Passwort zur Bestätigung</span>
        <input
          id={props.id}
          type="password"
          autoComplete="current-password"
          maxLength={1000}
          required
          value={props.wert}
          onChange={(e) => props.setWert(e.target.value)}
        />
      </label>
    );
  }
  return (
    <label className="feld code-feld" htmlFor={props.id}>
      <span>Code aus der Authenticator-App</span>
      <input
        id={props.id}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        value={props.wert}
        onChange={(e) => props.setWert(e.target.value.replace(/\D/g, ""))}
      />
    </label>
  );
}
