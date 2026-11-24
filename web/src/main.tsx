// SPDX-License-Identifier: AGPL-3.0-only

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { Wandanzeige } from "./Wandanzeige";
import { Einrichtung } from "./Einrichtung";
import "./tokens.css";
import "./styles.css";

const root = document.getElementById("app");
if (root) {
  createRoot(root).render(
    <StrictMode>
      {/* Die Wandanzeige hat keine Benutzersitzung und eine eigene Seite. */}
      {window.location.pathname === "/anzeige" ? (
        <Wandanzeige />
      ) : window.location.pathname === "/anzeige/vorschau" ? (
        // Vorschau in der Admin-Sitzung (0.99.2), ohne Anzeige-Schlüssel
        <Wandanzeige vorschau={new URLSearchParams(window.location.search).get("id") ?? ""} />
      ) : window.location.pathname === "/einrichtung" ? (
        <Einrichtung />
      ) : (
        <App />
      )}
    </StrictMode>,
  );
}
