// SPDX-License-Identifier: AGPL-3.0-only

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, setCsrf, type Ich } from "./api";
import { Anmeldung } from "./Anmeldung";
import { setzeBestaetigung } from "./Bestaetigung";
import { ZweiFaktorEinrichten } from "./ZweiFaktor";
import { Oberflaeche } from "./Oberflaeche";
import { useThema } from "./thema";

type Zustand = { art: "laden" } | { art: "abgemeldet" } | { art: "angemeldet"; ich: Ich } | { art: "fehler"; text: string };

export function App() {
  const [zustand, setZustand] = useState<Zustand>({ art: "laden" });
  // Auf oberster Ebene, damit die Seite auch vor der Anmeldung einem
  // Wechsel der Systemeinstellung folgt.
  const [thema, setThema] = useThema();

  const laden = useCallback(async () => {
    try {
      const ich = await api<Ich>("GET", "/api/v1/ich");
      setCsrf(ich.csrf);
      setzeBestaetigung(ich.zwei_faktor_aktiv);
      setZustand({ art: "angemeldet", ich });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setCsrf("");
        setZustand({ art: "abgemeldet" });
      } else {
        setZustand({ art: "fehler", text: e instanceof Error ? e.message : String(e) });
      }
    }
  }, []);

  useEffect(() => {
    void laden();
  }, [laden]);

  const abmelden = async () => {
    try {
      await api("DELETE", "/api/v1/sitzung");
    } finally {
      setCsrf("");
      setZustand({ art: "abgemeldet" });
    }
  };

  switch (zustand.art) {
    case "laden":
      return <div className="seite-mittig" aria-busy="true" />;
    case "fehler":
      return (
        <div className="seite-mittig">
          <div className="tafel">
            <p className="meldung meldung-fehler" role="alert">
              {zustand.text}
            </p>
            <button className="knopf" onClick={() => void laden()}>
              Erneut versuchen
            </button>
          </div>
        </div>
      );
    case "abgemeldet":
      return <Anmeldung onAngemeldet={laden} />;
    case "angemeldet":
      if (zustand.ich.zwei_faktor_einrichten) {
        return <ZweiFaktorEinrichten ich={zustand.ich} onFertig={laden} onAbmelden={abmelden} />;
      }
      return <Oberflaeche ich={zustand.ich} onAbmelden={abmelden} onAbgelaufen={laden} thema={thema} onThema={setThema} />;
  }
}
