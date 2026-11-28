// SPDX-License-Identifier: AGPL-3.0-only

// Leiste der Klick-Demo über jeder Seite: Zugänge zum Ausprobieren,
// Zurücksetzen, Hinweis, dass alles im Browser läuft. Gehört nicht zu
// OpenWacht; der Service Worker fügt sie in jede Seite ein.
(() => {
  if (document.getElementById("oc-demo")) return;
  // Basis-Pfad der Demo: OpenWacht nennt ihn in <meta name="basis">.
  const basis = document.querySelector('meta[name="basis"]')?.content ?? "";
  const demo = basis + "/_demo/";
  const api = (pfad) => fetch(demo + "api/" + pfad, { cache: "no-store" }).then((r) => r.json());
  // Sprache der Leiste: die des Browsers (Deutsch oder Englisch).
  const de = (navigator.language ?? "de").toLowerCase().startsWith("de");
  const T = de
    ? {
        demo: "Klick-Demo",
        lokal: "Läuft nur in diesem Browser. Nichts wird gesendet.",
        zugaenge: "Zugänge zum Ausprobieren",
        zurueck: "Zurücksetzen",
        frage: "Demo zurücksetzen? Alle Änderungen in diesem Browser gehen verloren.",
        ueber: "Über OpenWacht",
        impressum: "Impressum",
        datenschutz: "Datenschutz",
        passwort: "Passwort für alle: ",
        erfunden: ". Personen und Inhalte sind erfunden.",
        als: "Anmelden als ",
        laeuft: "Melde an …",
        code: "Code aus der App: ",
        fehler: "Anmelden ging nicht.",
        download: "Herunterladen ging nicht",
      }
    : {
        demo: "Click demo",
        lokal: "Runs only in this browser. Nothing is sent.",
        zugaenge: "Accounts to try",
        zurueck: "Reset",
        frage: "Reset the demo? All changes in this browser will be lost.",
        ueber: "About OpenWacht",
        impressum: "Legal notice",
        datenschutz: "Privacy",
        passwort: "Password for everyone: ",
        erfunden: ". People and content are made up.",
        als: "Sign in as ",
        laeuft: "Signing in …",
        code: "Code from the app: ",
        fehler: "Sign-in failed.",
        download: "Download failed",
      };
  const el = (tag, attr = {}, ...kinder) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attr)) {
      if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    e.append(...kinder);
    return e;
  };

  const leiste = el("aside", { id: "oc-demo", "aria-label": T.demo });
  const zugaenge = el("div", { id: "oc-demo-zugaenge", hidden: "" });
  const knopf = el("button", { type: "button", class: "oc-demo-voll", "aria-expanded": "false", "aria-controls": "oc-demo-zugaenge" }, T.zugaenge);
  knopf.addEventListener("click", () => {
    const auf = zugaenge.hidden;
    zugaenge.hidden = !auf;
    knopf.setAttribute("aria-expanded", String(auf));
  });
  const version = el("span", { class: "oc-demo-leise" }, "");
  leiste.append(
    el(
      "div",
      { class: "oc-demo-zeile" },
      el("span", { class: "oc-demo-marke" }, el("span", { class: "oc-demo-zeichen", "aria-hidden": "true" }), el("strong", {}, T.demo)),
      version,
      el("span", { class: "oc-demo-leise" }, T.lokal),
      knopf,
      el(
        "button",
        {
          type: "button",
          onclick: async () => {
            if (!confirm(T.frage)) return;
            await api("zuruecksetzen");
            const reg = await navigator.serviceWorker.getRegistration();
            await reg?.unregister();
            location.assign(demo + "start.html");
          },
        },
        T.zurueck,
      ),
      el("a", { href: "https://garrulus.de/openwacht" }, T.ueber),
      el("a", { href: "https://garrulus.de/impressum" }, T.impressum),
      el("a", { href: "https://garrulus.de/datenschutz" }, T.datenschutz),
    ),
    zugaenge,
  );

  async function zeigeZugaenge() {
    const d = await api("personen");
    version.textContent = "OpenWacht " + d.version;
    zugaenge.replaceChildren(
      el("p", {}, T.passwort, el("code", {}, d.passwort), T.erfunden),
      el(
        "ul",
        {},
        ...d.personen.map((p) =>
          el(
            "li",
            {},
            el(
              "button",
              {
                type: "button",
                onclick: async (ev) => {
                  ev.target.disabled = true;
                  ev.target.textContent = T.laeuft;
                  const r = await api("anmelden?email=" + encodeURIComponent(p.email));
                  if (r.weiter) location.assign(r.weiter);
                  else {
                    ev.target.disabled = false;
                    ev.target.textContent = T.als + p.name;
                    alert(r.fehler ?? T.fehler);
                  }
                },
              },
              T.als + p.name,
            ),
            el("span", {}, de ? p.rolle : p.role ?? p.rolle),
            el("code", {}, p.email),
            p.code ? el("span", { class: "oc-demo-leise" }, T.code, el("code", { "data-code": p.email }, p.code)) : "",
          ),
        ),
      ),
    );
  }
  zeigeZugaenge();
  // Codes für den zweiten Faktor alle 30 Sekunden neu, wie in der App.
  setInterval(async () => {
    if (zugaenge.hidden) return;
    const d = await api("personen");
    for (const p of d.personen) {
      const c = zugaenge.querySelector(`[data-code="${CSS.escape(p.email)}"]`);
      if (c && p.code) c.textContent = p.code;
    }
  }, 5000);
  // Hält den Service Worker wach, solange die Seite offen ist.
  setInterval(() => fetch(demo + "api/lebt").catch(() => {}), 20000);

  // Links mit download-Attribut lädt Chrome am Service Worker vorbei aus dem
  // Netz. Deshalb hier selbst über den Service Worker holen und speichern.
  document.addEventListener(
    "click",
    async (ev) => {
      const a = ev.target.closest?.("a[download]");
      if (!a || a.origin !== location.origin || a.href.startsWith("blob:")) return;
      ev.preventDefault();
      const r = await fetch(a.href, { credentials: "same-origin" });
      if (!r.ok) {
        alert(T.download + " (" + r.status + ").");
        return;
      }
      const cd = r.headers.get("Content-Disposition") ?? "";
      const m = cd.match(/filename\*=UTF-8''([^;]+)/i) ?? cd.match(/filename="?([^";]+)"?/i);
      const name = m ? decodeURIComponent(m[1]) : a.getAttribute("download") || "download";
      const url = URL.createObjectURL(await r.blob());
      const tmp = el("a", { href: url, download: name, hidden: "" });
      document.body.append(tmp);
      tmp.click();
      tmp.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    },
    true,
  );

  const ein = () => document.body.prepend(leiste);
  if (document.body) ein();
  else document.addEventListener("DOMContentLoaded", ein);
})();
