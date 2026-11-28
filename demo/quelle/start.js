// SPDX-License-Identifier: AGPL-3.0-only

// Lädt die Demo: Service Worker anmelden, warten, bis Server und Datenbank im
// Browser laufen, dann die gewünschte Seite öffnen.
// Englisch, wenn der Browser nicht Deutsch bevorzugt.
const EN = {
  titel: "Click demo",
  text: "This is the real program: the same server, the same interface, the same database (PostgreSQL), just running entirely in this browser. The first visit downloads about %GROESSE% MB.",
  hinweis: "Whatever you type stays in this browser. Nothing is sent anywhere.",
  ueber: "About OpenWacht",
  impressum: "Legal notice",
  datenschutz: "Privacy",
  "Starte …": "Starting …",
  "Lade die Beschreibung der Demo …": "Loading the demo …",
  "Lade die Datenbank (PostgreSQL) …": "Loading the database (PostgreSQL) …",
  "Lade die Beispieldaten …": "Loading the sample data …",
  "Starte die Zentrale von OpenWacht …": "Starting the OpenWacht server …",
  "Dieser Browser kann die Demo nicht ausführen (Service Worker fehlen, etwa in manchen privaten Fenstern).":
    "This browser cannot run the demo (no service workers, for example in some private windows).",
  "Die Demo konnte nicht starten: ": "The demo could not start: ",
  "Fehler: ": "Error: ",
};
const englisch = !(navigator.language ?? "de").toLowerCase().startsWith("de");
const tr = (t) => {
  if (!englisch) return t;
  for (const [de, en] of Object.entries(EN)) if (de.endsWith(": ") && t.startsWith(de)) return en + t.slice(de.length);
  return EN[t] ?? t;
};
if (englisch) {
  document.documentElement.lang = "en";
  for (const el of document.querySelectorAll("[data-t]")) el.textContent = EN[el.dataset.t].replace("%GROESSE%", document.documentElement.dataset.groesse ?? "");
}

(async () => {
  const stand = document.getElementById("stand");
  const zeige = (t) => (stand.textContent = tr(t));
  zeige("Starte …");
  if (!("serviceWorker" in navigator)) {
    zeige("Dieser Browser kann die Demo nicht ausführen (Service Worker fehlen, etwa in manchen privaten Fenstern).");
    return;
  }
  // Basis-Pfad der Demo, beim Bauen eingesetzt (z. B. /openwacht/demo).
  const basis = document.documentElement.dataset.basis ?? "";
  const demo = basis + "/_demo/";
  const hier = location.pathname;
  const ziel = hier.startsWith(demo) || !hier.startsWith(basis + "/") ? basis + "/" : hier + location.search + location.hash;
  try {
    await navigator.serviceWorker.register(basis + "/demo-sw.js", { scope: basis + "/" });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((ok) => navigator.serviceWorker.addEventListener("controllerchange", ok, { once: true }));
    }
    navigator.serviceWorker.addEventListener("message", (e) => {
      if (e.data?.demo !== "fortschritt") return;
      if (e.data.text === "bereit") location.replace(ziel);
      else zeige(e.data.text);
    });
    navigator.serviceWorker.controller.postMessage({ demo: "starte" });
    // Falls der Server schon lief, kommt keine Meldung mehr.
    const z = await (await fetch(demo + "api/zustand", { cache: "no-store" })).json();
    if (z.fortschritt === "bereit") location.replace(ziel);
  } catch (e) {
    zeige("Die Demo konnte nicht starten: " + e.message);
  }
})();
