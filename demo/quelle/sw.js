// SPDX-License-Identifier: AGPL-3.0-only

// Service Worker der Klick-Demo. Er fängt alle Anfragen der Seite ab und
// beantwortet sie mit der echten Zentrale von OpenWacht (WebAssembly) und
// einer PostgreSQL-Datenbank im Browser (PGlite). Nichts verlässt den Browser:
// Außer den Dateien der Demo selbst (<Basis>/_demo/…) geht keine Anfrage ins
// Netz. Die Demo kann unter einem Unterpfad liegen (Scope des Workers), der
// Server bekommt ihn als Basis-Pfad.
//
// Der Stand (Datenbank, Anmeldung) bleibt in IndexedDB dieses
// Browsers, bis jemand „Demo zurücksetzen“ wählt.

import { speicher, melder, BASIS } from "./fs-setzen.js";
import "wasm_exec";
import { PGlite } from "@electric-sql/pglite";
import { starteServer } from "./kern.js";
import { Kekse } from "./kekse.js";
import { Ablage } from "./ablage.js";
import { totp } from "./totp.js";

const DEMO = BASIS + "/_demo/";
const ablage = new Ablage("openwacht-demo");
const kekse = new Kekse(ablage);

let start = null; // Promise auf { fetchFn, demo }
let fortschritt = "";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

function melde(text) {
  fortschritt = text;
  self.clients.matchAll({ includeUncontrolled: true }).then((cs) => cs.forEach((c) => c.postMessage({ demo: "fortschritt", text })));
}

// entpackt: gzip-Datei der Demo als Antwort mit dem richtigen Typ.
async function entpackt(pfad, typ) {
  const r = await fetch(DEMO + pfad, { cache: "no-cache" });
  if (!r.ok || !r.body) throw new Error(`${pfad}: ${r.status}`);
  return new Response(r.body.pipeThrough(new DecompressionStream("gzip")), { headers: { "Content-Type": typ } });
}

async function holeBytes(pfad) {
  const r = await fetch(DEMO + pfad, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${pfad}: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function hochfahren() {
  melde("Lade die Beschreibung der Demo …");
  const demo = await (await fetch(DEMO + "demo.json", { cache: "no-cache" })).json();
  const stand = await ablage.hole("meta", "stand");
  const frisch = !stand || stand.version !== demo.version || stand.commit !== demo.commit;
  if (frisch) {
    await ablage.leere("dateien");
    await ablage.leere("kekse");
    await new Promise((ok) => {
      const r = indexedDB.deleteDatabase("/pglite/openwacht-demo");
      r.onsuccess = r.onerror = r.onblocked = () => ok();
    });
  }
  kekse.laden(await ablage.alle("kekse"));

  // Anhänge zurück ins Dateisystem des Servers.
  speicher.laden(await ablage.alleMitSchluessel("dateien"));

  melde("Lade die Datenbank (PostgreSQL) …");
  const [wasmPg, dataPg] = await Promise.all([
    WebAssembly.compileStreaming(entpackt("pglite/pglite.wasm.gz", "application/wasm")),
    entpackt("pglite/pglite.data.gz", "application/octet-stream").then((r) => r.blob()),
  ]);
  const opt = { dataDir: "idb://openwacht-demo", relaxedDurability: false, pgliteWasmModule: wasmPg, fsBundle: dataPg };
  if (frisch) {
    melde("Lade die Beispieldaten …");
    opt.loadDataDir = new Blob([await holeBytes("daten.tar.gz")]);
  }
  const db = await PGlite.create(opt);
  if (frisch) await ablage.setze("meta", "stand", { version: demo.version, commit: demo.commit });

  melde("Starte die Zentrale von OpenWacht …");
  const wasm = await WebAssembly.compileStreaming(entpackt("openwacht.wasm.gz", "application/wasm"));
  const schluessel = Uint8Array.from(atob(demo.schluessel), (c) => c.charCodeAt(0));
  const fetchFn = await starteServer({ db, wasm, schluessel, basis: self.location.origin + BASIS, rolle: demo.rolle, agents: JSON.stringify(demo.agents ?? []), debug: !!demo.debug });
  melde("bereit");
  return { fetchFn, demo, db };
}

melder.aenderung = (pfad, daten) => {
  if (daten) ablage.setze("dateien", pfad, daten.slice());
  else ablage.loesche("dateien", pfad);
};

function bereit() {
  if (!start) {
    start = hochfahren().catch((e) => {
      start = null;
      melde("Fehler: " + e.message);
      throw e;
    });
  }
  return start;
}

// ---------------------------------------------------------------- Anfragen

async function anServer(request) {
  const { fetchFn } = await bereit();
  const url = new URL(request.url);
  const headers = [];
  request.headers.forEach((wert, name) => {
    if (name.toLowerCase() !== "cookie") headers.push([name, wert]);
  });
  // Der Browser schickt Origin nicht immer mit (etwa bei GET); der Server
  // prüft ihn nur bei Änderungen, dann ist er gesetzt.
  // Cookies: die des Servers aus dem eigenen Speicher, dazu die, die die
  // Oberfläche selbst setzt (Darstellung hell/dunkel), aus dem Browser.
  let browser = [];
  try {
    browser = (await self.cookieStore?.getAll()) ?? [];
  } catch {
    // ohne Cookie Store API nur die eigenen
  }
  const keks = [kekse.kopf(url.pathname), ...browser.filter((c) => !kekse.hat(c.name)).map((c) => `${c.name}=${c.value}`)].filter(Boolean).join("; ");
  if (keks) headers.push(["Cookie", keks]);
  const body = request.method === "GET" || request.method === "HEAD" ? null : new Uint8Array(await request.arrayBuffer());
  const r = await fetchFn(request.method, url.href, headers, body);
  const aus = new Headers();
  for (const [name, wert] of r.headers) {
    if (name.toLowerCase() === "set-cookie") kekse.setze(wert);
    else aus.append(name, wert);
  }
  const istHtml = (aus.get("Content-Type") ?? "").startsWith("text/html");
  let inhalt = r.body;
  if (istHtml && r.status !== 204) {
    const text = new TextDecoder().decode(r.body);
    const tag = `<link rel="stylesheet" href="${DEMO}hilfe.css"><script src="${DEMO}hilfe.js" defer></script>`;
    inhalt = new TextEncoder().encode(text.includes("</head>") ? text.replace("</head>", tag + "</head>") : tag + text);
    aus.delete("Content-Length");
  }
  if (r.status >= 300 && r.status < 400) return new Response(null, { status: r.status, headers: aus });
  return new Response(r.status === 204 || r.status === 304 || request.method === "HEAD" ? null : inhalt, { status: r.status, headers: aus });
}

async function zuruecksetzen(json) {
  // Danach meldet hilfe.js den Service Worker ab und lädt neu: frischer
  // Server, frische Datenbank.
  const alt = start;
  start = null;
  try {
    await (await alt)?.db.close();
  } catch {
    // schon zu
  }
  await new Promise((ok) => {
    const r = indexedDB.deleteDatabase("/pglite/openwacht-demo");
    r.onsuccess = r.onerror = r.onblocked = () => ok();
  });
  await ablage.leere("meta");
  await ablage.leere("dateien");
  await ablage.leere("kekse");
  kekse.leeren();
  return json({ ok: true });
}

// Kleine Schnittstelle für die Leiste der Demo (hilfe.js).
async function demoApi(url) {
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  const was = url.pathname.slice((DEMO + "api/").length);
  if (was === "lebt") return new Response(null, { status: 204 });
  if (was === "zustand") return json({ fortschritt, laeuft: !!start });
  if (was === "zuruecksetzen") return zuruecksetzen(json);
  const { demo, fetchFn } = await bereit();
  if (was === "personen") {
    return json({
      version: demo.version,
      passwort: demo.passwort,
      personen: await Promise.all(demo.personen.map(async (p) => ({ email: p.email, name: p.name, rolle: p.rolle, role: p.role, code: p.geheimnis ? await totp(p.geheimnis) : "" }))),
    });
  }
  if (was === "anmelden") {
    const p = demo.personen.find((x) => x.email === url.searchParams.get("email"));
    if (!p) return json({ fehler: "unbekannt" }, 404);
    kekse.leeren();
    const rufe = async (method, pfad, body) => {
      const h = [["Origin", self.location.origin], ["Content-Type", "application/json"]];
      const k = kekse.kopf(BASIS + pfad);
      if (k) h.push(["Cookie", k]);
      const r = await fetchFn(method, self.location.origin + BASIS + pfad, h, new TextEncoder().encode(JSON.stringify(body)));
      for (const [n, v] of r.headers) if (n.toLowerCase() === "set-cookie") kekse.setze(v);
      const text = new TextDecoder().decode(r.body);
      if (r.status !== 200) throw new Error(text);
      return JSON.parse(text);
    };
    try {
      const r = await rufe("POST", "/api/v1/sitzung", { email: p.email, passwort: demo.passwort });
      if (r.zweiter_faktor) {
        // Jeden Code nimmt der Server nur einmal: notfalls auf den nächsten warten.
        try {
          await rufe("POST", "/api/v1/sitzung/zweiter-faktor", { code: await totp(p.geheimnis) });
        } catch {
          await new Promise((ok) => setTimeout(ok, 30000 - (Date.now() % 30000) + 300));
          await rufe("POST", "/api/v1/sitzung/zweiter-faktor", { code: await totp(p.geheimnis) });
        }
      }
    } catch (e) {
      return json({ fehler: String(e.message ?? e) }, 400);
    }
    return json({ weiter: BASIS + "/" });
  }
  return json({ fehler: "unbekannt" }, 404);
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return; // nichts Fremdes
  if (url.pathname.startsWith(DEMO + "api/")) {
    e.respondWith(demoApi(url));
    return;
  }
  if (url.pathname.startsWith(DEMO) || url.pathname === BASIS + "/demo-sw.js") return; // Dateien der Demo aus dem Netz
  if (!url.pathname.startsWith(BASIS + "/")) return; // nicht Teil der Demo
  e.respondWith(
    anServer(e.request).catch(
      (err) =>
        new Response(`<!doctype html><meta charset="utf-8"><title>Demo</title><p>Die Demo konnte nicht starten: ${String(err.message ?? err).replace(/[<&]/g, "")}</p><p><a href="${DEMO}start.html">Neu laden</a></p>`, {
          status: 503,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    ),
  );
});

self.addEventListener("message", (e) => {
  if (e.data?.demo === "starte") bereit().catch(() => {});
});
