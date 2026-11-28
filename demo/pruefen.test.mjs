// SPDX-License-Identifier: AGPL-3.0-only

// Prüft die gebaute Klick-Demo (demo/ausgabe) im echten Chrome:
//   - Startseite, Leiste, Anmelden über die Leiste
//   - Rechte wie im Betrieb (RLS in der Datenbank im Browser)
//   - Stand bleibt nach einem Neustart des Service Workers (Datenbank,
//     Anmeldung)
//   - Zurücksetzen
//   - Außer den Dateien der Demo geht keine Anfrage an den Webserver.
//
// Aufruf aus demo/ nach node bauen.mjs: npm run pruefen
// OPENWACHT_E2E_CHROME: Chrome oder Chromium (Voreinstellung /usr/bin/google-chrome)

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { chromium } from "playwright-core";
import { BASIS, starte } from "./zeigen.mjs";

const PORT = 18099;
const BASE = `http://localhost:${PORT}${BASIS}`;
const demo = JSON.parse(readFileSync(new URL("./ausgabe/_demo/demo.json", import.meta.url), "utf8"));
const person = (name) => demo.personen.find((p) => p.name === name);

let server, b, ctx, p, cdp;
const anfragen = [];
const fehler = [];

before(async () => {
  server = await starte(PORT, (pfad) => anfragen.push(pfad));
  const pfad = process.env.OPENWACHT_E2E_CHROME ?? ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"].find(existsSync);
  b = await chromium.launch({ executablePath: pfad, args: ["--no-sandbox", "--no-proxy-server"] });
  ctx = await b.newContext({ locale: "de-DE", viewport: { width: 1300, height: 900 } });
  p = await ctx.newPage();
  p.on("pageerror", (e) => fehler.push(String(e)));
  cdp = await ctx.newCDPSession(p);
  await cdp.send("ServiceWorker.enable");
});
after(async () => {
  await b?.close();
  server?.close();
});

async function alsPerson(name) {
  await p.goto(BASE + "/");
  await p.waitForSelector("#oc-demo", { timeout: 90000 });
  const zug = p.locator("#oc-demo button", { hasText: "Zugänge" });
  if ((await zug.getAttribute("aria-expanded")) !== "true") await zug.click();
  const geladen = p.waitForEvent("load", { timeout: 90000 });
  await p.locator("#oc-demo button", { hasText: "Anmelden als " + name }).click();
  await geladen;
  assert.ok(!new URL(p.url()).pathname.startsWith(BASIS + "/anmelden"), p.url());
  await p.waitForSelector(".app", { timeout: 30000 });
}

// api: Aufruf aus der Seite heraus, wie die Oberfläche (über den Service Worker).
function api(method, pfad, body, typ = "application/json") {
  return p.evaluate(
    async ([method, pfad, body, typ, basis]) => {
      const ich = await (await fetch(basis + "/api/v1/ich")).json();
      const init = { method, headers: { "X-CSRF-Token": ich.csrf ?? "" } };
      if (body !== null) {
        init.headers["Content-Type"] = typ;
        init.body = typ === "application/json" ? JSON.stringify(body) : Uint8Array.from(body);
      }
      const r = await fetch(basis + pfad, init);
      const text = await r.text();
      return { status: r.status, text };
    },
    [method, pfad, body ?? null, typ, BASIS],
  );
}

async function neustartServiceWorker() {
  await p.waitForTimeout(800); // die Datenbank sichert kurz nach der letzten Anfrage
  await cdp.send("ServiceWorker.stopAllWorkers");
  await p.waitForTimeout(300);
}

test("Startseite lädt die Demo, Leiste nach Corporate Design", async () => {
  await p.goto(BASE + "/");
  await p.waitForSelector("#oc-demo", { timeout: 90000 });
  assert.match(await p.locator("#oc-demo").innerText(), /Klick-Demo/);
  assert.match(await p.locator("#oc-demo").innerText(), new RegExp("OpenWacht " + demo.version.replace(/\./g, "\\.")));
  // Ohne Anmeldung die echte Anmeldeseite von OpenWacht.
  await p.waitForSelector('input[autocomplete="username"]', { timeout: 30000 });
  const schrift = await p.locator("#oc-demo").evaluate((e) => getComputedStyle(e).fontFamily);
  assert.match(schrift, /D-DIN/);
});

const json = async (pfad) => {
  const r = await api("GET", pfad);
  assert.equal(r.status, 200, pfad + ": " + r.text.slice(0, 300));
  return JSON.parse(r.text);
};
const geraeteNamen = async () => (await json("/api/v1/geraete")).geraete.map((g) => g.name).sort();

test("Paula Praxis sieht nur die Geräte ihrer Praxis", async () => {
  await alsPerson("Paula Praxis");
  assert.deepEqual(await geraeteNamen(), ["fritzbox-praxis", "praxis-server", "www-praxis"]);
});

test("Ben Bonn sieht nur den Standort Bonn", async () => {
  await alsPerson("Ben Bonn");
  assert.deepEqual(await geraeteNamen(), ["drucker-bonn", "fw-bonn", "pc-lager", "srv-bonn01", "sw-bonn01"]);
});

test("Alex Admin: zweiter Faktor, Agents melden, Alarme entstehen, Verlauf von Tagen", async () => {
  await alsPerson("Alex Admin");
  const ich = await json("/api/v1/ich");
  assert.ok(ich.betreiber, JSON.stringify(ich).slice(0, 300));
  assert.ok((await geraeteNamen()).length >= 20);
  // Die Simulation meldet gleich nach dem Start; Alarme folgen nach der ersten Prüfrunde.
  let alarme = [];
  for (let i = 0; i < 90 && alarme.length < 3; i++) {
    await p.waitForTimeout(2000);
    alarme = (await json("/api/v1/alarme")).alarme ?? [];
  }
  assert.ok(alarme.length >= 3, "zu wenige Alarme: " + JSON.stringify(alarme).slice(0, 500));
  // Verlauf: die Demo füllt rückwirkend Tage auf.
  const dc = demo.agents.find((a) => a.host === "srv-dc01");
  let punkte = [];
  for (let i = 0; i < 30; i++) {
    const v = await json(`/api/v1/agents/${dc.id}/verlauf?zeitraum=7t`);
    punkte = v.reihen.find((r) => r.name === "cpu")?.punkte ?? [];
    if (punkte.length > 0 && Date.now() / 1000 - punkte[0][0] > 3 * 86400) break;
    await p.waitForTimeout(2000);
  }
  assert.ok(punkte.length > 0 && Date.now() / 1000 - punkte[0][0] > 3 * 86400, "kein Verlauf über Tage: " + punkte.length);
  const haupt = (await json("/api/v1/mandanten")).mandanten.find((m) => m.uebergeordnet_id === null);
  const r = await api("POST", `/api/v1/mandanten/${haupt.id}/geraete`, { name: "demo-test", adresse: "10.20.0.99", gruppe_id: "" });
  assert.equal(r.status, 201, r.text);
});

test("Die Oberfläche zeigt Dashboard, Hosts und Topologie", async () => {
  for (const seite of ["/", "/hosts", "/alarme", "/topologie"]) {
    await p.goto(BASE + seite);
    await p.waitForSelector(".app", { timeout: 30000 });
    await p.waitForTimeout(500);
  }
});

test("Nach Neustart des Service Workers: angemeldet, Daten da", async () => {
  await neustartServiceWorker();
  await p.reload();
  await p.waitForSelector(".app", { timeout: 60000 });
  const ich = await json("/api/v1/ich");
  assert.equal(ich.email, person("Alex Admin").email);
  assert.ok((await geraeteNamen()).includes("demo-test"), "Gerät fehlt nach Neustart");
});

test("Zurücksetzen: frischer Stand", async () => {
  p.once("dialog", (d) => d.accept());
  await p.locator("#oc-demo button", { hasText: "Zurücksetzen" }).click();
  await p.waitForSelector('input[autocomplete="username"]', { timeout: 90000 });
  await alsPerson("Alex Admin");
  assert.ok(!(await geraeteNamen()).includes("demo-test"), "Gerät noch da");
});

test("Leiste und Startseite auf Englisch, wenn der Browser es will", async () => {
  const c2 = await b.newContext({ locale: "en-US" });
  const p2 = await c2.newPage();
  await p2.goto(BASE + "/_demo/start.html");
  assert.equal(await p2.locator("h1").textContent(), "Click demo");
  await p2.waitForSelector("#oc-demo", { timeout: 90000 });
  assert.match(await p2.locator("#oc-demo").innerText(), /Click demo[\s\S]*Accounts to try/);
  await c2.close();
});

test("Nur Dateien der Demo vom Webserver, keine Skriptfehler", async () => {
  console.log("Anfragen an den Webserver:", [...new Set(anfragen)].join(" "));
  const fremd = anfragen.filter((a) => !a.startsWith(BASIS + "/_demo/") && a !== BASIS + "/demo-sw.js" && a !== BASIS + "/");
  // Erlaubt: die erste Seite, bevor der Service Worker läuft (Startseite).
  assert.ok(fremd.length <= 2, "an den Webserver: " + fremd.join(", "));
  assert.deepEqual(fehler, []);
});
