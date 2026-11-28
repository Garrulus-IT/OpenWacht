// SPDX-License-Identifier: AGPL-3.0-only

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { Wandanzeige } from "./Wandanzeige";
import { Einrichtung } from "./Einrichtung";
import { fuehrungEinschalten } from "./fuehrung";
import "./tokens.css";
import "./styles.css";
import { ohneBasis } from "./basis";

const root = document.getElementById("app");
// Führung nach Aktionen (1.0.12), nicht auf der Wandanzeige
if (root && !ohneBasis().startsWith("/anzeige")) fuehrungEinschalten();
if (root) {
  createRoot(root).render(
    <StrictMode>
      {/* Die Wandanzeige hat keine Benutzersitzung und eine eigene Seite. */}
      {ohneBasis() === "/anzeige" ? (
        <Wandanzeige />
      ) : ohneBasis() === "/anzeige/vorschau" ? (
        // Vorschau in der Admin-Sitzung (0.99.2), ohne Anzeige-Schlüssel
        <Wandanzeige vorschau={new URLSearchParams(window.location.search).get("id") ?? ""} />
      ) : ohneBasis() === "/einrichtung" ? (
        <Einrichtung />
      ) : (
        <App />
      )}
    </StrictMode>,
  );
}
