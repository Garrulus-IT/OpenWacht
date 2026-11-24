// SPDX-License-Identifier: AGPL-3.0-only

// Darstellung vor dem ersten Zeichnen setzen, damit die Seite im dunklen
// Modus nicht erst hell aufblitzt. Eigene Datei statt Inline-Skript, weil die
// CSP nur 'self' erlaubt. Die Logik danach übernimmt src/thema.ts; beide
// müssen denselben Schlüssel und dieselben Werte verwenden.
(function () {
  var wahl = "system";
  try {
    var w = window.localStorage.getItem("openwacht.thema");
    if (w === "hell" || w === "dunkel") wahl = w;
  } catch (e) {
    /* Speicher gesperrt: dem System folgen */
  }
  var dunkel = wahl === "dunkel" || (wahl === "system" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-thema", dunkel ? "dunkel" : "hell");
})();
