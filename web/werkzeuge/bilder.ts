// SPDX-License-Identifier: AGPL-3.0-only

// Bildschirmfotos für Handbuch und README auf Knopfdruck.
//
//   cd web && npm ci && npm run bilder
//
// Das Skript baut Zentrale und simagent, legt in einer PostgreSQL eine frische
// Datenbank an, klickt den Einrichtungsassistenten durch, füllt die Zentrale
// mit neutralen Demodaten („Beispiel GmbH“) und fotografiert jede Seite hell
// und dunkel, am Desktop und am Handy. Ergebnis:
//
//   docs/handbuch/bilder/*.webp   (Handbuch, 1000 px breit)
//   docs/bilder/*.png             (README und Übersicht)
//
// Nur für Entwicklung, läuft nicht in der CI. Voraussetzungen:
//   - Go (Version aus go.mod) und Node wie für den Build
//   - PostgreSQL 16 mit einem Superuser-Zugang, z. B. die Test-Datenbank der Sandbox:
//       BILDER_PG="host=127.0.0.1 port=54329 user=postgres"   (Standard)
//   - Chrome oder Chromium: BILDER_CHROME (Standard /usr/bin/google-chrome).
//     playwright-core lädt keinen eigenen Browser herunter.
//   - snmpd (Net-SNMP) für die SNMP-Bilder: BILDER_SNMPD (Standard /usr/sbin/snmpd)
//
// Das Skript legt die Rollen bilder_owner und bilder_app sowie die
// Datenbank bilder an und überschreibt sie bei jedem Lauf. Es fasst keine
// anderen Datenbanken an. Alle Namen, Adressen und Personen sind erfunden
// (Beispieldomain .example, Adressen aus 10.20.0.0/24 bzw. Loopback).

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, openSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type BrowserContext, type Locator, type Page } from "playwright-core";

// --- Konfiguration ---------------------------------------------------------------

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const PG = process.env.BILDER_PG ?? "host=127.0.0.1 port=54329 user=postgres";
const CHROME = process.env.BILDER_CHROME ?? "/usr/bin/google-chrome";
const SNMPD = process.env.BILDER_SNMPD ?? "/usr/sbin/snmpd";
const ARBEIT = process.env.BILDER_ARBEIT ?? mkdtempSync(join(tmpdir(), "bilder-"));
const NUR = (process.env.BILDER_NUR ?? "").split(",").filter(Boolean); // nur diese Bilder (Fehlersuche)

// Technische Namen der Zentrale an einer Stelle.
const PROG = "openwacht";
const ENV = "OPENWACHT";
const SCHEMA = "openwacht";

const PORT_WEB = 18443;
const PORT_AGENT = 18444;
const PORT_NTFY = 18586;
const PORT_SNMP = 16161;
const PORT_ONTAP = 18447; // ONTAP-Attrappe auf 127.0.20.30 (im Bild 10.20.0.30:443)
const PORT_BREVIS = 18449; // SMS-Gateway-Attrappe (brevis.one) auf 127.0.20.70 (im Bild https://10.20.0.70)
const PORT_XAPI = 18448; // XAPI-Attrappe: Pool-Master 127.0.20.50, zweiter Host 127.0.20.51 (im Bild 10.20.0.50:443)
const BASIS = `http://localhost:${PORT_WEB}`;
const AUS_HANDBUCH = join(REPO, "docs/handbuch/bilder");
const AUS_README = join(REPO, "docs/bilder");

// Demodaten: erfunden, ohne Bezug zu echten Personen, Orten oder Netzen.
const ADMIN = { name: "Erika Mustermann", email: "erika.mustermann@beispiel.example", pw: "Demo-Passwort-" + randomBytes(6).toString("hex") };
const NORD_ADMIN = { name: "Max Beispiel", email: "max.beispiel@beispiel.example", pw: ADMIN.pw };
const HAUPT = "Beispiel GmbH";
const ADRESSEN = ["openwacht.beispiel.example", "10.20.0.5"];
// Im Assistenten nur das Beispielnetz; die Demo-Gegenstellen liegen auf
// Loopback (127.0.20.0/24) und werden danach freigegeben.
const NETZE = ["10.20.0.0/24"];
const NETZE_DEMO = [...NETZE, "127.0.20.0/24"];
const COMMUNITY = "demo-" + randomBytes(4).toString("hex");

// --- Hilfen ------------------------------------------------------------------------

function schritt(text: string) {
  console.log(`\n== ${text}`);
}

function lauf(cmd: string, args: string[], opt: { cwd?: string; env?: Record<string, string>; eingabe?: string } = {}): string {
  const r = spawnSync(cmd, args, {
    cwd: opt.cwd ?? REPO,
    env: { ...process.env, ...opt.env },
    input: opt.eingabe,
    encoding: "utf8",
    maxBuffer: 64 << 20,
  });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} endete mit ${r.status}:\n${r.stderr}\n${r.stdout}`);
  }
  return r.stdout;
}

function psql(sql: string, db = "postgres"): string {
  return lauf("psql", [`${PG} dbname=${db}`, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql]).trim();
}

function dsn(rolle: string, pw: string): string {
  // Verbindung der Zentrale: Host und Port aus BILDER_PG, eigene Rolle.
  const teile = Object.fromEntries(PG.split(/\s+/).map((t) => t.split("=") as [string, string]));
  return `host=${teile.host ?? "127.0.0.1"} port=${teile.port ?? "5432"} user=${rolle} password=${pw} dbname=bilder sslmode=disable`;
}

const warte = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function bisErreichbar(url: string, sekunden = 60) {
  for (let i = 0; i < sekunden * 4; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // noch nicht da
    }
    await warte(250);
  }
  throw new Error(`${url} nicht erreichbar`);
}

// TOTP nach RFC 6238 (SHA-1, 6 Stellen, 30 s), wie jede Authenticator-App.
function totp(geheimnis: string, versatz = 0): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of geheimnis.replace(/[\s=]/g, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const zaehler = Buffer.alloc(8);
  zaehler.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + versatz));
  const h = createHmac("sha1", key).update(zaehler).digest();
  const o = h[h.length - 1]! & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

// Jeder Code gilt nur einmal: vor dem nächsten auf den nächsten 30-s-Schritt warten.
let letzterSchritt = 0;
async function frischerCode(geheimnis: string): Promise<string> {
  while (Math.floor(Date.now() / 30000) <= letzterSchritt) await warte(1000);
  letzterSchritt = Math.floor(Date.now() / 30000);
  return totp(geheimnis);
}

// --- Prozesse ----------------------------------------------------------------------

const prozesse: ChildProcess[] = [];
function hintergrund(name: string, cmd: string, args: string[], env: Record<string, string> = {}): ChildProcess {
  const log = openSync(join(ARBEIT, `${name}.log`), "a");
  const p = spawn(cmd, args, { cwd: ARBEIT, env: { ...process.env, ...env }, stdio: ["ignore", log, log] });
  prozesse.push(p);
  return p;
}
function aufraeumen() {
  for (const p of prozesse) if (p.exitCode === null) p.kill("SIGTERM");
}
process.on("exit", aufraeumen);
process.on("SIGINT", () => process.exit(130));

// --- Bilder ------------------------------------------------------------------------

let browser: Browser;
const geschrieben: string[] = [];

function gewollt(name: string): boolean {
  return NUR.length === 0 || NUR.includes(name);
}

// WebP-Kodierung im Browser selbst (Chrome kann WebP), damit das Skript keine
// Bildbibliothek braucht. Breite höchstens `breite`, Qualität wie bisher 0,62.
async function alsWebp(png: Buffer, breite: number): Promise<Buffer> {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  const daten = await p.evaluate(
    async ({ b64, breite }) => {
      const blob = await (await fetch(`data:image/png;base64,${b64}`)).blob();
      const bild = await createImageBitmap(blob);
      const f = Math.min(1, breite / bild.width);
      const c = document.createElement("canvas");
      c.width = Math.round(bild.width * f);
      c.height = Math.round(bild.height * f);
      const g = c.getContext("2d")!;
      g.imageSmoothingQuality = "high";
      g.drawImage(bild, 0, 0, c.width, c.height);
      return c.toDataURL("image/webp", 0.62).split(",")[1]!;
    },
    { b64: png.toString("base64"), breite },
  );
  await ctx.close();
  return Buffer.from(daten, "base64");
}

interface FotoOpt {
  element?: Locator;
  ganz?: boolean;
  breite?: number;
}

async function foto(page: Page, name: string, opt: FotoOpt = {}) {
  if (!gewollt(name)) return;
  await ruhe(page);
  await wieInstalliert(page);
  const png = opt.element
    ? await opt.element.screenshot({ animations: "disabled" })
    : await page.screenshot({ fullPage: opt.ganz ?? false, animations: "disabled" });
  let ziel: string;
  if (name.endsWith(".png")) {
    ziel = join(AUS_README, name);
    writeFileSync(ziel, png);
  } else {
    ziel = join(AUS_HANDBUCH, `${name}.webp`);
    writeFileSync(ziel, await alsWebp(png, opt.breite ?? 1000));
  }
  geschrieben.push(ziel);
  console.log(`   ${ziel.slice(REPO.length + 1)}`);
}

// Warten, bis die Seite fertig geladen hat (keine offenen Anfragen, Schriften da).
async function ruhe(page: Page) {
  await page.waitForLoadState("networkidle").catch(() => undefined);
  await page.evaluate(() => document.fonts.ready);
  await warte(400);
}

// Die Demo läuft ohne TLS auf Loopback; die Gegenstellen liegen in
// 127.0.20.0/24. In den Bildern soll stehen, was eine echte Installation
// zeigt: die eingerichtete Adresse und das Beispielnetz 10.20.0.0/24. Nur
// sichtbarer Text wird ersetzt, nach dem Laden und unmittelbar vor dem Foto.
const ANZEIGE: [RegExp, string][] = [
  [new RegExp(`https?://localhost:${PORT_WEB}`, "g"), `https://${ADRESSEN[0]}`],
  [new RegExp(`localhost:${PORT_WEB}`, "g"), ADRESSEN[0]!],
  [new RegExp(`127\\.0\\.0\\.1:${PORT_AGENT}`, "g"), `${ADRESSEN[0]}:8444`],
  [new RegExp(`127\\.0\\.20\\.30:${PORT_ONTAP}`, "g"), "10.20.0.30:443"],
  [new RegExp(`:${PORT_ONTAP}\\b`, "g"), ":443"],
  [new RegExp(`^${PORT_ONTAP}$`, "g"), "443"],
  [new RegExp(`127\\.0\\.20\\.50:${PORT_XAPI}`, "g"), "10.20.0.50:443"],
  [new RegExp(`127\\.0\\.20\\.70:${PORT_BREVIS}`, "g"), "10.20.0.70"],
  [new RegExp(`:${PORT_XAPI}\\b`, "g"), ":443"],
  [new RegExp(`^${PORT_XAPI}$`, "g"), "443"],
  [/127\.0\.20\.0\/24/g, "10.20.1.0/24"],
  [/127\.0\.20\.(\d+)/g, "10.20.0.$1"],
];

async function wieInstalliert(page: Page) {
  await page.evaluate((regeln) => {
    const liste = regeln.map(([q, f, n]) => [new RegExp(q, f), n] as const);
    const ersetzen = (t: string) => liste.reduce((a, [r, n]) => a.replace(r, n), t);
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const neu = ersetzen(n.nodeValue ?? "");
      if (neu !== n.nodeValue) n.nodeValue = neu;
    }
    for (const e of document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")) {
      const neu = ersetzen(e.value);
      if (neu !== e.value) e.value = neu;
    }
  }, ANZEIGE.map(([r, n]) => [r.source, r.flags, n] as [string, string, string]));
}

// Geheimnisse (QR-Code, Schlüssel, Codes) vor dem Foto verwischen. Die CSP
// verbietet eigene Stylesheets, element.style geht.
async function verwischen(l: Locator) {
  for (const e of await l.all()) await e.evaluate((el: HTMLElement) => (el.style.filter = "blur(7px)"));
}

async function neuerKontext(opt: { handy?: boolean; dunkel?: boolean; hoehe?: number } = {}): Promise<BrowserContext> {
  return browser.newContext({
    viewport: opt.handy ? { width: 390, height: opt.hoehe ?? 844 } : { width: 1280, height: opt.hoehe ?? 800 },
    deviceScaleFactor: 1,
    colorScheme: opt.dunkel ? "dark" : "light",
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    isMobile: opt.handy ?? false,
    hasTouch: opt.handy ?? false,
  });
}

// --- API über die Sitzung im Browser ---------------------------------------------------
//
// Die Sitzung steckt in __Host--Cookies, die nur der Browser selbst mitschickt;
// deshalb laufen die Aufrufe per fetch in der Seite.

class Api {
  private page: Page;
  constructor(page: Page) {
    this.page = page;
  }
  async rufe<T = any>(methode: string, pfad: string, body?: unknown): Promise<T> {
    const r = await this.page.evaluate(
      async ({ methode, pfad, body }) => {
        const ich = await fetch("/api/v1/ich", { cache: "no-store" });
        const csrf = ich.ok ? ((await ich.json()) as { csrf: string }).csrf : "";
        const res = await fetch(pfad, {
          method: methode,
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await res.text();
        return { status: res.status, text };
      },
      { methode, pfad, body },
    );
    if (r.status >= 300) throw new Error(`${methode} ${pfad}: ${r.status} ${r.text}`);
    return (r.text ? JSON.parse(r.text) : undefined) as T;
  }
}

// --- Anmeldung ---------------------------------------------------------------------

async function anmelden(page: Page, konto: { email: string; pw: string }, geheimnis: string) {
  await page.goto(BASIS + "/");
  await page.locator("input[type=email], input[autocomplete=username]").first().waitFor();
  await page.locator("input[type=email], input[autocomplete=username]").first().fill(konto.email);
  await page.locator("input[type=password]").first().fill(konto.pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  const feld = page.locator("input[autocomplete=one-time-code]");
  await feld.waitFor();
  await feld.fill(await frischerCode(geheimnis));
  await feld.press("Enter");
  await page.locator(".app").waitFor();
}

// ======================================================================================

async function main() {
  mkdirSync(AUS_HANDBUCH, { recursive: true });
  mkdirSync(AUS_README, { recursive: true });
  console.log(`Arbeitsverzeichnis: ${ARBEIT}`);

  schritt("Bauen");
  const bin = join(ARBEIT, "bin");
  lauf("go", ["run", "./tools/build", "-ziele", "linux/amd64", "-out", bin]);
  lauf("go", ["build", "-o", join(bin, "simagent"), "./tools/simagent"]);
  lauf("go", ["build", "-o", join(bin, "ontapattrappe"), "./tools/ontapattrappe"]);
  lauf("go", ["build", "-o", join(bin, "xapiattrappe"), "./tools/xapiattrappe"]);
  lauf("go", ["build", "-o", join(bin, "brevisattrappe"), "./tools/brevisattrappe"]);
  const zentrale = join(bin, `${PROG}-zentrale_linux_amd64`);
  const simagent = join(bin, "simagent");

  schritt("Datenbank");
  const pwOwner = randomBytes(12).toString("hex");
  const pwApp = randomBytes(12).toString("hex");
  psql(`DROP DATABASE IF EXISTS bilder WITH (FORCE)`);
  psql(`DROP ROLE IF EXISTS bilder_app`);
  psql(`DROP ROLE IF EXISTS bilder_owner`);
  psql(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${SCHEMA}_app') THEN CREATE ROLE ${SCHEMA}_app NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${SCHEMA}_traps') THEN CREATE ROLE ${SCHEMA}_traps NOLOGIN; END IF;
  END $$`);
  psql(`CREATE ROLE bilder_owner LOGIN PASSWORD '${pwOwner}'`);
  psql(`CREATE ROLE bilder_app LOGIN PASSWORD '${pwApp}' IN ROLE ${SCHEMA}_app`);
  psql(`CREATE DATABASE bilder OWNER bilder_owner ENCODING 'UTF8' TEMPLATE template0`);
  psql(`GRANT CONNECT ON DATABASE bilder TO bilder_app`);
  const envOwner = { [`${ENV}_DB_EIGENTUEMER`]: dsn("bilder_owner", pwOwner) };
  lauf(zentrale, ["migrieren"], { env: envOwner });

  const schluessel = join(ARBEIT, "schluessel");
  writeFileSync(schluessel, lauf(zentrale, ["schluessel"]));
  chmodSync(schluessel, 0o600);
  const link = lauf(zentrale, ["einrichtungslink"], { env: envOwner });
  const token = /#([A-Za-z0-9_-]+)/.exec(link)?.[1];
  if (!token) throw new Error("kein Einrichtungslink:\n" + link);

  schritt("Gegenstellen");
  // ntfy-Attrappe: nimmt Alarme an und verwirft sie.
  const http = await import("node:http");
  const ntfy = http.createServer((req, res) => {
    req.on("error", () => undefined);
    req.resume();
    req.on("end", () => res.end("{}"));
  });
  ntfy.listen(PORT_NTFY, "127.0.0.1");
  // Ein offener Port für „OK“-Sensoren der Zentrale.
  const net = await import("node:net");
  const offen = net.createServer((s) => {
    s.on("error", () => undefined); // Sensoren trennen hart
    s.end("220 demo ESMTP\r\n");
  });
  offen.listen(2525, "127.0.20.25");
  let snmp = false;
  if (existsSync(SNMPD)) {
    const conf = join(ARBEIT, "snmpd.conf");
    writeFileSync(
      conf,
      [
        `agentAddress udp:127.0.20.2:${PORT_SNMP}`,
        `rocommunity ${COMMUNITY} 127.0.0.0/8`,
        `sysName sw-core`,
        `sysLocation Rechenzentrum, Schrank 2`,
        `sysContact it@beispiel.example`,
        `sysDescr Demo-Switch (Net-SNMP)`,
      ].join("\n") + "\n",
    );
    // Ohne Platten- und Prozesstabellen: Ein Switch meldet keine Dateisysteme,
    // und so tauchen keine Einhängepunkte des Rechners in den Bildern auf.
    hintergrund("snmpd", SNMPD, ["-f", "-C", "-c", conf, "-I", "-hrh_storage,-hrh_filesys,-hr_storage,-hr_filesys,-hr_disk,-hr_swrun",  "-Lf", join(ARBEIT, "snmpd.log"), "-p", join(ARBEIT, "snmpd.pid"), "-u", "root"]);
    snmp = true;
  } else {
    console.log("   snmpd fehlt: SNMP-Bilder zeigen ein nicht erreichbares Gerät");
  }

  // ONTAP-Attrappe (NetApp-Cluster mit eigenem, selbstsigniertem Zertifikat)
  hintergrund("ontap", join(bin, "ontapattrappe"), ["-adresse", `127.0.20.30:${PORT_ONTAP}`]);
  // XAPI-Attrappe (XenServer-Pool mit zwei Hosts, je eigenes Zertifikat)
  hintergrund("xapi", join(bin, "xapiattrappe"), ["-master", "127.0.20.50", "-host2", "127.0.20.51", "-port", String(PORT_XAPI)]);
  // SMS-Gateway-Attrappe (brevis.one, eigenes Zertifikat, Testzugang openwacht-api)
  hintergrund("brevis", join(bin, "brevisattrappe"), ["-adresse", `127.0.20.70:${PORT_BREVIS}`]);

  schritt("Zentrale starten");
  hintergrund(
    "zentrale",
    zentrale,
    [
      "starten",
      "-adresse",
      `127.0.0.1:${PORT_WEB}`,
      "-basis-url",
      BASIS,
      "-schluessel",
      schluessel,
      "-agent-adresse",
      `127.0.0.1:${PORT_AGENT}`,
      "-agent-namen",
      "127.0.0.1",
      "-alarm-ziele",
      `http://127.0.0.1:${PORT_NTFY},https://127.0.20.70:${PORT_BREVIS}`,
    ],
    { [`${ENV}_DB`]: dsn("bilder_app", pwApp) },
  );
  await bisErreichbar(`${BASIS}/api/v1/gesund`);

  browser = await chromium.launch({ executablePath: CHROME, args: ["--no-sandbox", "--no-proxy-server"] });

  // --- Einrichtung -----------------------------------------------------------------
  schritt("Einrichtungsassistent");
  const geheimnis = await einrichtung(token);

  // --- Demodaten ---------------------------------------------------------------------
  schritt("Demodaten");
  const ctx = await neuerKontext();
  const page = await ctx.newPage();
  await anmelden(page, ADMIN, geheimnis);
  const api = new Api(page);
  const demo = await demodaten(api, geheimnis, simagent, snmp);
  await kennfarbenDemo(api, demo);

  schritt("Seiten fotografieren");
  await seiten(page, api, demo, geheimnis);
  await wandanzeige(page, api, demo);
  await ctx.close();
  await abgemeldet();
  await handy(geheimnis);
  await dunkel(geheimnis);
  await untermandant();

  await browser.close();
  ntfy.close();
  offen.close();
  console.log(`\nFertig: ${geschrieben.length} Bilder.`);
  aufraeumen();
  process.exit(0);
}

// --- Einrichtungsassistent ----------------------------------------------------------

async function einrichtung(token: string): Promise<string> {
  const ctx = await neuerKontext({ hoehe: 900 });
  const page = await ctx.newPage();
  await page.goto(`${BASIS}/einrichtung#${token}`);
  const weiter = page.getByRole("button", { name: "Weiter", exact: true });

  await page.getByLabel("Name des Hauptmandanten").fill(HAUPT);
  await foto(page, "einrichtung-1-mandant");
  await weiter.click();

  await page.getByLabel("Name", { exact: true }).fill(ADMIN.name);
  await page.getByLabel("E-Mail").fill(ADMIN.email);
  await page.getByLabel("Passwort", { exact: true }).fill(ADMIN.pw);
  await page.getByLabel("Passwort wiederholen").fill(ADMIN.pw);
  await page.getByRole("button", { name: "Zwei-Faktor-Anmeldung einrichten" }).click();
  const schl = page.locator("code.schluessel");
  await schl.waitFor();
  const geheimnis = (await schl.textContent())!.replace(/\s/g, "");
  await verwischen(page.locator(".qr-rahmen, code.schluessel"));
  await foto(page, "einrichtung-2-admin");
  await page.getByLabel("Code aus der App").fill(await frischerCode(geheimnis));
  await page.getByRole("button", { name: "Code prüfen" }).click();
  await page.getByText(`Eingerichtet für ${ADMIN.email}`).waitFor();
  await weiter.click();

  await page.getByLabel("Adressen").fill(ADRESSEN.join("\n"));
  await foto(page, "einrichtung-3-adresse");
  await weiter.click();

  await page.getByRole("button", { name: "Zertifikat erzeugen" }).click();
  await page.getByText("Eigene Wurzel erzeugt").waitFor();
  await foto(page, "einrichtung-4-https");
  await weiter.click();

  await page.getByLabel("Zeitzone").fill("Europe/Berlin");
  await weiter.click();

  await page.getByLabel("Freigegebene Netze").fill(NETZE.join("\n"));
  await foto(page, "einrichtung-6-netze");
  await weiter.click();

  await page.getByRole("button", { name: "Überspringen", exact: true }).click(); // Mail: später unter Einstellungen
  await weiter.click(); // Sicherung: Vorschlag übernehmen

  await foto(page, "einrichtung-9-zusammenfassung");
  await page.getByRole("button", { name: "Fertig", exact: true }).click();
  await page.getByText("OpenWacht ist eingerichtet").waitFor();
  await foto(page, "einrichtung-fertig");
  await ctx.close();
  return geheimnis;
}

// --- Demodaten ----------------------------------------------------------------------

interface Demo {
  haupt: string;
  nord: string;
  sued: string;
  geraete: Record<string, string>;
  checks: Record<string, string>;
}

async function demodaten(api: Api, geheimnis: string, simagent: string, snmp: boolean): Promise<Demo> {
  await api.rufe("PUT", "/api/v1/einstellungen", { netze: NETZE_DEMO, code: await frischerCode(geheimnis) });
  const mandanten = (await api.rufe<{ mandanten: { id: string; name: string; uebergeordnet_id: string | null }[] }>("GET", "/api/v1/mandanten"))
    .mandanten;
  const haupt = mandanten.find((m) => m.uebergeordnet_id === null)!.id;
  const neuMandant = async (name: string, eltern: string) =>
    (await api.rufe<{ id: string }>("POST", "/api/v1/mandanten", { uebergeordnet_id: eltern, name })).id;
  const nord = await neuMandant("Standort Nord", haupt);
  const sued = await neuMandant("Standort Süd", haupt);
  await neuMandant("Labor", haupt);

  // Gruppen im Hauptmandanten
  const gruppe = async (m: string, name: string, eltern = "") =>
    (await api.rufe<{ id: string }>("POST", `/api/v1/mandanten/${m}/gruppen`, { name, eltern_id: eltern })).id;
  const rz = await gruppe(haupt, "Rechenzentrum");
  const netz = await gruppe(haupt, "Netzwerk", rz);
  const buero = await gruppe(haupt, "Büro");

  // Alarmkanäle
  await api.rufe("POST", `/api/v1/mandanten/${haupt}/alarm-kanaele`, {
    art: "ntfy",
    name: "Bereitschaft IT",
    auch_untermandanten: true,
    aktiv: true,
    server: `http://127.0.0.1:${PORT_NTFY}`,
    topic: "it-bereitschaft",
  });
  await api.rufe("POST", `/api/v1/mandanten/${haupt}/alarm-kanaele`, {
    art: "mail",
    name: "Team Betrieb",
    auch_untermandanten: false,
    aktiv: true,
    alle_benutzer: true,
    empfaenger: [],
  });

  // Agents (simagent): melden echte Messwerte über das Agent-Protokoll.
  const agentToken = async (m: string, anzahl: number) =>
    (await api.rufe<{ token: string }>("POST", `/api/v1/mandanten/${m}/agent-tokens`, { notiz: "Demo", anzahl, gueltig_stunden: 24 })).token;
  const sim = (name: string, token: string, hosts: string[], still: string[] = []) =>
    hintergrund(`simagent-${name}`, simagent, [
      "-zentrale",
      `https://127.0.0.1:${PORT_AGENT}`,
      "-token",
      token,
      "-hosts",
      hosts.join(","),
      "-runden",
      "0",
      "-takt",
      "20s",
      ...(still.length ? ["-ohne-meldung", still.join(",")] : []),
    ], { HTTPS_PROXY: "", https_proxy: "", NO_PROXY: "*" });
  sim("haupt", await agentToken(haupt, 3), ["srv-file01", "srv-db01", "srv-app01"]);
  // Telefonanlage (0.44.0, Vorlagensatz Swyx); eigener simagent, damit die
  // übrigen Hosts gleich bleiben.
  sim("telefonie", await agentToken(haupt, 1), ["srv-tel01"]);
  sim("nord", await agentToken(nord, 1), ["srv-nord01"]);
  sim("sued", await agentToken(sued, 2), ["srv-sued01", "nas-sued"], ["nas-sued"]);
  // Offenes Token für die Liste „Agent-Tokens“
  await api.rufe("POST", `/api/v1/mandanten/${sued}/agent-tokens`, { notiz: "Neue Kassenrechner", anzahl: 5, gueltig_stunden: 72 });

  const geraeteLesen = async () =>
    Object.fromEntries(
      (await api.rufe<{ geraete: { id: string; name: string }[] }>("GET", "/api/v1/geraete")).geraete.map((g) => [g.name, g.id]),
    ) as Record<string, string>;
  let geraete: Record<string, string> = {};
  for (let i = 0; i < 120 && Object.keys(geraete).length < 7; i++) {
    await warte(1000);
    geraete = await geraeteLesen();
  }

  // Geräte ohne Agent
  const neuGeraet = async (m: string, name: string, adresse: string, gruppe_id = "") =>
    (await api.rufe<{ id: string }>("POST", `/api/v1/mandanten/${m}/geraete`, { name, adresse, gruppe_id })).id;
  const swCore = await neuGeraet(haupt, "sw-core", "10.20.0.2", netz);
  const apOg = await neuGeraet(haupt, "ap-og", "10.20.0.31", netz);
  const drucker = await neuGeraet(haupt, "drucker-eg", "10.20.0.40", buero);
  const mail = await neuGeraet(haupt, "mail-gw", "10.20.0.25", rz);
  const fwNord = await neuGeraet(nord, "fw-nord", "10.20.1.1");
  await neuGeraet(haupt, "aff-c250", "10.20.0.30", rz);
  await neuGeraet(haupt, "pool-rz", "10.20.0.50", rz);

  // Abhängigkeiten für die Topologie (1.0.3): alles im Haus hängt am Core-Switch,
  // der Drucker zusätzlich am Access Point.
  const alle = (await api.rufe<{ geraete: { id: string; name: string; adresse: string | null }[] }>("GET", "/api/v1/geraete")).geraete;
  const haengtAn = async (id: string | undefined, eltern: string) => {
    const g = alle.find((x) => x.id === id);
    if (g) await api.rufe("PUT", `/api/v1/geraete/${g.id}`, { name: g.name, adresse: g.adresse ?? "", abhaengig_von: eltern });
  };
  for (const id of [apOg, mail, geraete["srv-file01"], geraete["srv-db01"], geraete["srv-app01"], geraete["srv-tel01"]]) await haengtAn(id, swCore);
  await haengtAn(drucker, apOg);

  // Agent-Geräte in Gruppen
  await api.rufe("POST", "/api/v1/geraete/gruppe", { geraete: [geraete["srv-file01"], geraete["srv-db01"], geraete["srv-app01"]].filter(Boolean), gruppe_id: rz });

  // Sensoren der Zentrale. Erreichbar ist nur der Demo-Port auf 127.0.20.25; alles
  // andere in 127.0.20.0/24 ist zu und ergibt echte Alarme.
  const sensor = async (g: string, name: string, typ: string, ziel: unknown, intervall = 60) =>
    (await api.rufe<{ id: string }>("POST", `/api/v1/geraete/${g}/checks`, { name, typ, ziel, intervall_sekunden: intervall, aktiv: true })).id;
  const checks: Record<string, string> = {};
  checks.drucker = await sensor(drucker, "Druckdienst (Port 9100)", "tcp", { host: "127.0.20.40", port: 9100 });
  checks.ap = await sensor(apOg, "Admin-Oberfläche (HTTPS)", "tcp", { host: "127.0.20.31", port: 443 });
  checks.mail = await sensor(mail, "SMTP-Banner", "tcp_banner", { host: "127.0.20.25", port: 2525, erwartet: "ESMTP" }, 60).catch(
    async () => await sensor(mail, "SMTP-Port", "tcp", { host: "127.0.20.25", port: 2525 }),
  );
  checks.fw = await sensor(fwNord, "VPN-Gateway", "tcp", { host: "127.0.20.1", port: 443 });
  checks.pausiert = await sensor(drucker, "Scan-Ablage (SMB)", "tcp", { host: "127.0.20.40", port: 445 });
  await api.rufe("PUT", `/api/v1/checks/${checks.pausiert}`, {
    name: "Scan-Ablage (SMB)",
    typ: "tcp",
    ziel: { host: "127.0.20.40", port: 445 },
    intervall_sekunden: 60,
    aktiv: false,
  });

  // SNMP am Core-Switch
  if (snmp) {
    await api.rufe("PUT", `/api/v1/geraete/${swCore}/snmp`, {
      version: "2c",
      adresse: "127.0.20.2",
      port: PORT_SNMP,
      profil: "",
      community: COMMUNITY,
      v3: null,
      intervall_sekunden: 60,
      aktiv: true,
      traps: false,
      sammler: "",
      ueberwacht: [],
    });
  }
  await api.rufe("POST", `/api/v1/mandanten/${haupt}/snmp-profile`, {
    name: "Switches Rechenzentrum",
    version: "3",
    community: "",
    v3: { benutzer: "monitor", auth: "SHA-256", auth_passwort: "demo-" + randomBytes(8).toString("hex"), priv: "AES", priv_passwort: "demo-" + randomBytes(8).toString("hex") },
  });

  // Schwellen: srv-sued01 meldet Warnung beim RAM
  if (geraete["srv-sued01"]) {
    await api.rufe("PUT", `/api/v1/geraete/${geraete["srv-sued01"]}/schwellen`, { schwellen: { speicher_warn: 30, speicher_krit: 99 } });
  }
  // Warnungen: Platte von srv-db01 und RAM des Switches über niedrigen Schwellen
  if (geraete["srv-db01"]) {
    await api.rufe("PUT", `/api/v1/geraete/${geraete["srv-db01"]}/schwellen`, { schwellen: { platte_warn: 40, platte_krit: 99 } });
  }
  await api.rufe("PUT", `/api/v1/geraete/${swCore}/schwellen`, { schwellen: { speicher_warn: 5, speicher_krit: 99 } });
  // Wartung: srv-app01 für ein Update
  if (geraete["srv-app01"]) await api.rufe("PUT", `/api/v1/geraete/${geraete["srv-app01"]}/wartung`, { minuten: 120, grund: "Update auf neue Version" });
  // Wartungsfenster
  await api.rufe("POST", "/api/v1/wartungsfenster", {
    name: "Patchtag Server",
    grund: "Monatliche Updates",
    ziel_art: "gruppe",
    ziel_id: rz,
    untergruppen: true,
    wiederholung: "monatlich",
    zeitzone: "Europe/Berlin",
    aktiv: true,
    uhrzeit: "22:00",
    dauer_min: 180,
    nter: 2,
    wochentag: 2,
    versatz: 0,
  }).catch((e) => console.log("   Wartungsfenster:", String(e).slice(0, 200)));

  // Benutzer
  const benutzer = async (m: string, email: string, anzeigename: string, rolle: string, passwort = randomBytes(12).toString("hex") + "Aa1!") => {
    const b = await api.rufe<{ id: string }>("POST", "/api/v1/benutzer", { mandant_id: m, email, anzeigename, passwort });
    await api.rufe("PUT", `/api/v1/benutzer/${b.id}/rollen/${m}`, { rolle });
  };
  await benutzer(haupt, "jonas.weber@beispiel.example", "Jonas Weber", "operator");
  await benutzer(haupt, "lea.schmidt@beispiel.example", "Lea Schmidt", "leser");
  await benutzer(nord, NORD_ADMIN.email, NORD_ADMIN.name, "admin", NORD_ADMIN.pw);

  // Wiederherstellungscodes, damit die Seitenleiste nicht daran erinnert
  await api.rufe("POST", "/api/v1/zwei-faktor/codes", { code: await frischerCode(geheimnis) });
  console.log("   Wiederherstellungscodes offen:", (await api.rufe<{ wiederherstellungscodes_offen: number }>("GET", "/api/v1/ich")).wiederherstellungscodes_offen);
  // API-Token (braucht einen frischen Zwei-Faktor-Code)
  await api.rufe("POST", "/api/v1/api-tokens", { mandant: haupt, name: "Inventar-Skript", rolle: "leser", tage: 90, code: await frischerCode(geheimnis) });

  // Warten, bis Sensoren gelaufen sind und Alarme stehen
  for (let i = 0; i < 180; i++) {
    const a = await api.rufe<{ alarme: { id: string; status: string; check_id?: string }[] }>("GET", "/api/v1/alarme").catch(() => ({ alarme: [] }));
    if ((a.alarme ?? []).length >= 3) break;
    await warte(1000);
  }
  // Einen Alarm bestätigen (Druckdienst)
  const alarme = await api.rufe<{ alarme: { id: string; titel?: string; check?: string; name?: string }[] }>("GET", "/api/v1/alarme");
  const zuBestaetigen = alarme.alarme.find((a) => JSON.stringify(a).includes("Druckdienst"));
  if (zuBestaetigen) await api.rufe("POST", `/api/v1/alarme/${zuBestaetigen.id}/bestaetigen`, { kommentar: "Toner getauscht, Gerät startet neu" });

  return { haupt, nord, sued, geraete: { ...(await geraeteLesen()) }, checks };
}

// --- Seiten -----------------------------------------------------------------------

async function gehe(page: Page, pfad: string) {
  await page.goto(BASIS + pfad);
  await page.locator(".app").waitFor();
  await ruhe(page);
}

// Seiten am Desktop (hell), angemeldet als Admin des Hauptmandanten.
async function seiten(page: Page, api: Api, demo: Demo, geheimnis: string) {
  await gehe(page, "/");
  await foto(page, "dashboard");

  await gehe(page, "/hosts");
  await foto(page, "hosts");
  await foto(page, "hosts.png");

  await page.getByRole("button", { name: "Host hinzufügen" }).click();
  await page.getByLabel("Name", { exact: true }).first().fill("srv-print01");
  await page.getByLabel("IP-Adresse oder Hostname (optional)").fill("10.20.0.41");
  await foto(page, "host-hinzufuegen");
  await page.keyboard.press("Escape");

  await gehe(page, "/hosts");
  await page.getByRole("button", { name: "Gruppen ordnen" }).click();
  await foto(page, "gruppen");

  await gehe(page, "/hosts");
  await page.getByRole("button", { name: "Importieren" }).click();
  await page.locator("textarea").first().fill(
    [
      "name;adresse;gruppe;sensor;port",
      "sw-etage1;10.20.0.11;Netzwerk;ping;",
      "sw-etage2;10.20.0.12;Netzwerk;ping;",
      "kamera-hof;10.20.0.60;Büro;tcp;554",
      "srv-alt;;Rechenzentrum;tcp;99999",
    ].join("\n"),
  );
  await page.getByRole("button", { name: "Prüfen" }).click();
  await page.locator(".import-vorschau, table").first().waitFor().catch(() => undefined);
  await foto(page, "import-vorschau", { ganz: true });

  const srv = demo.geraete["srv-file01"]!;
  const sw = demo.geraete["sw-core"]!;
  await gehe(page, `/hosts?geraet=${srv}`);
  await foto(page, "host-agent");
  await foto(page, "host-detail.png", { ganz: true });
  await gehe(page, `/hosts?geraet=${sw}`);
  await foto(page, "host-snmp");
  await gehe(page, `/hosts?geraet=${sw}&ansicht=sensoren`);
  await foto(page, "host-sensoren");

  if (gewollt("topologie")) {
    await gehe(page, "/topologie");
    await foto(page, "topologie");
  }
  if (gewollt("hinweise-ton")) {
    await gehe(page, "/alarme");
    await page.getByRole("button", { name: "Hinweise und Ton" }).click();
    await foto(page, "hinweise-ton", { element: page.locator("dialog.dialog") });
    await page.keyboard.press("Escape");
  }
  await netapp(page, demo);
  await xenserver(page, demo);

  await gehe(page, "/alarme");
  await foto(page, "alarme");
  await gehe(page, "/alarme/protokoll");
  await foto(page, "alarme-protokoll");
  await gehe(page, "/alarme/kanaele");
  await foto(page, "alarme-kanaele");
  await sms(page);
  await vorlagensaetze(page, demo);
  await gehe(page, "/wartung");
  await foto(page, "wartung");
  await gehe(page, "/berichte");
  await page.locator('select:has(option[value^="20"])').first().selectOption({ index: 0 }); // laufender Monat
  await foto(page, "berichte");
  await gehe(page, "/sensor-vorlagen");
  await foto(page, "sensor-vorlagen");
  await page.locator("#kennfarben").scrollIntoViewIfNeeded();
  await page.getByRole("button", { name: "+ Kennfarbe" }).click();
  await page.getByPlaceholder("z. B. Neustart verpasst").fill("Zertifikat läuft ab");
  await page.getByRole("button", { name: "Vorschlag #00838a" }).click();
  await foto(page, "kennfarben", { element: page.locator("#kennfarben") });
  await page.getByRole("button", { name: "Abbrechen" }).last().click();
  await gehe(page, "/snmp-profile");
  await foto(page, "snmp-profile");

  await gehe(page, "/verwaltung");
  await foto(page, "mandanten");
  await foto(page, "verwaltung-haupt-admin.png");
  await gehe(page, "/verwaltung/benutzer");
  await foto(page, "benutzer");
  await gehe(page, "/verwaltung/tokens");
  await foto(page, "agent-tokens");
  await gehe(page, "/verwaltung/updates");
  await foto(page, "agent-updates");
  await gehe(page, "/verwaltung/api");
  await foto(page, "api-tokens");

  await page.setViewportSize({ width: 1280, height: 1200 });
  await gehe(page, "/verwaltung/anmeldung");
  await page.getByRole("button", { name: "AD anbinden" }).click();
  const form = page.getByRole("form", { name: "AD anbinden" });
  await form.getByLabel("Name", { exact: true }).fill("Active Directory");
  await form.locator("input.mono").nth(0).fill("ldaps://dc1.beispiel.example");
  await form.getByPlaceholder("CN=svc-openwacht,OU=Dienste,DC=firma,DC=de").fill("CN=svc-openwacht,OU=Dienste,DC=beispiel,DC=example");
  await form.getByPlaceholder("DC=firma,DC=de", { exact: true }).fill("DC=beispiel,DC=example");
  await form.getByPlaceholder("firma.de", { exact: true }).fill("beispiel.example");
  await foto(page, "ad-anbinden", { element: form });
  await page.setViewportSize({ width: 1280, height: 800 });

  // Mail-Relay für die Seite Einstellungen
  await api
    .rufe("PUT", "/api/v1/einstellungen/mail", {
      server: "mail.beispiel.example",
      port: 587,
      tls: "starttls",
      absender: "openwacht@beispiel.example",
      benutzer: "",
      ca: "",
      code: await frischerCode(geheimnis),
    })
    .catch((e) => console.log("   Mail-Relay:", String(e).slice(0, 200)));
  await gehe(page, "/einstellungen");
  await foto(page, "einstellungen");
  await foto(page, "einstellungen-installation", { element: panel(page, "Installation"), breite: 2000 });
  await foto(page, "einstellungen-mail", { element: panel(page, "Mail (SMTP)"), breite: 2000 });
}

// NetApp über das Aktionsmenü einrichten: Verbindung prüfen, Fingerabdruck
// übernehmen, erneut prüfen, speichern; danach die Werte am Gerät.
async function netapp(page: Page, demo: Demo) {
  const id = demo.geraete["aff-c250"];
  if (!id) return;
  await gehe(page, `/hosts?geraet=${id}`);
  await page.getByRole("button", { name: /Aktionen/ }).first().click();
  await page.getByRole("menuitem", { name: "NetApp einrichten" }).click();
  const form = page.locator("form").filter({ hasText: "NetApp für" });
  await form.getByLabel("Adresse des Clusters").fill("127.0.20.30");
  await form.getByRole("textbox", { name: "Port", exact: true }).fill(String(PORT_ONTAP));
  await form.getByLabel("Benutzer").fill("svc-openwacht");
  await form.getByLabel(/^Passwort/).fill("lese-pass-123"); // Testwert der Attrappe
  await form.getByRole("button", { name: "Verbindung prüfen" }).click();
  await form.getByRole("button", { name: "Fingerabdruck übernehmen" }).waitFor();
  await foto(page, "netapp-fingerabdruck", { element: form });
  await form.getByRole("button", { name: "Fingerabdruck übernehmen" }).click();
  await warte(3100); // „Verbindung prüfen“ höchstens alle 3 Sekunden
  await form.getByRole("button", { name: "Verbindung prüfen" }).click();
  await form.getByText("Das Konto hat nur Leserecht").waitFor();
  await foto(page, "netapp-einrichten", { element: form });
  await form.getByRole("button", { name: "Speichern" }).click();
  await form.waitFor({ state: "detached" });
  for (let i = 0; i < 60; i++) {
    await gehe(page, `/hosts?geraet=${id}`);
    if ((await page.locator(".geraet-netapp table").count()) > 0) break;
    await warte(1000);
  }
  await foto(page, "host-netapp", { ganz: true });

  // Ausnahme (0.99.2): die SnapMirror-Beziehung mit großer Verzögerung ausnehmen
  if (gewollt("sensor-ausnehmen")) {
    await page.setViewportSize({ width: 1280, height: 1400 });
    await gehe(page, `/hosts?geraet=${id}&ansicht=sensoren`);
    await page.getByRole("button", { name: /^SnapMirror .* ausnehmen$/ }).first().click();
    await page.getByPlaceholder("z. B. alte Vault-Beziehung, wird nicht mehr gepflegt").fill("Altlast aus der Migration, wird nicht mehr gepflegt");
    await page.getByRole("button", { name: "Ausnehmen", exact: true }).click();
    await page.getByRole("button", { name: /^SnapMirror .* wieder überwachen$/ }).first().waitFor();
    await foto(page, "sensor-ausnehmen", { element: page.locator(".sensoren-reiter") });
    await page.setViewportSize({ width: 1280, height: 800 });
  }
}

// XenServer über das Aktionsmenü einrichten: root wird abgewiesen, dann
// Verbindung prüfen, Fingerabdruck übernehmen, erneut prüfen, speichern;
// danach die Werte am Gerät.
async function xenserver(page: Page, demo: Demo) {
  const id = demo.geraete["pool-rz"];
  if (!id) return;
  await gehe(page, `/hosts?geraet=${id}`);
  await page.getByRole("button", { name: /Aktionen/ }).first().click();
  await page.getByRole("menuitem", { name: "XenServer einrichten" }).click();
  const form = page.locator("form").filter({ hasText: "XenServer für" });
  await form.getByLabel("Adresse des Pool-Masters").fill("127.0.20.50");
  await form.getByRole("textbox", { name: "Port", exact: true }).fill(String(PORT_XAPI));
  await form.getByLabel(/^Benutzer/).fill("root");
  await form.getByText("root wird abgelehnt").waitFor();
  await foto(page, "xenserver-root", { element: form });
  await form.getByLabel(/^Benutzer/).fill("svc-openwacht@beispiel.example");
  await form.getByLabel(/^Passwort/).fill("lese-pass-123"); // Testwert der Attrappe
  await form.getByRole("button", { name: "Verbindung prüfen" }).click();
  await form.getByRole("button", { name: "Fingerabdruck übernehmen" }).waitFor();
  await foto(page, "xenserver-fingerabdruck", { element: form });
  await form.getByRole("button", { name: "Fingerabdruck übernehmen" }).click();
  await warte(3100); // „Verbindung prüfen“ höchstens alle 3 Sekunden
  await form.getByRole("button", { name: "Verbindung prüfen" }).click();
  await form.getByText("Das Konto hat nur Leserecht").waitFor();
  await foto(page, "xenserver-einrichten", { element: form });
  await form.getByRole("button", { name: "Speichern" }).click();
  await form.waitFor({ state: "detached" });
  for (let i = 0; i < 60; i++) {
    await gehe(page, `/hosts?geraet=${id}`);
    if ((await page.locator(".geraet-xenserver table").count()) > 0) break;
    await warte(1000);
  }
  await foto(page, "host-xenserver", { ganz: true });
}

// SMS-Kanal (brevis.one) anlegen: eigene Mobilnummer, Gateway aus den
// Alarmzielen, Fingerabdruck holen, Empfänger, Test-SMS an die Attrappe.
async function sms(page: Page) {
  await gehe(page, "/alarme/kanaele");
  const mobil = page.locator("form.meine-mobilnummer");
  await mobil.getByRole("textbox").fill("+49 170 1234567"); // erfundene Nummer
  await mobil.getByRole("button", { name: "Speichern" }).click();
  await mobil.getByText("Gespeichert.").waitFor();
  await foto(page, "alarm-mobilnummer", { element: mobil });
  await page.getByRole("button", { name: "Kanal anlegen" }).click();
  const form = page.locator("form").filter({ hasText: "Alarmkanal anlegen" });
  await form.getByLabel("SMS (brevis.one)").check();
  await form.getByLabel("Name", { exact: true }).fill("SMS Bereitschaft");
  await form.getByLabel("API-Benutzer").fill("openwacht-api");
  await form.getByLabel("Passwort", { exact: true }).fill("test-passwort-123"); // Testwert der Attrappe
  await form.getByRole("button", { name: "Fingerabdruck holen" }).click();
  await form.getByText("Übernommen.").waitFor();
  await form.getByText("Erika Mustermann").click();
  await form.getByLabel(/zusätzlich anrufen/).check();
  // Hohes Fenster, damit die feste Kopfleiste das Formular nicht überdeckt.
  await page.setViewportSize({ width: 1280, height: 1800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await foto(page, "alarmkanal-sms", { element: form });
  await page.setViewportSize({ width: 1280, height: 800 });
  await form.getByRole("button", { name: "Anlegen" }).click();
  await form.waitFor({ state: "detached" });
  const zeile = page.locator("li").filter({ hasText: "SMS Bereitschaft" }).first();
  await zeile.getByRole("button", { name: "Test senden" }).click();
  await zeile.getByText("Test-SMS gesendet").waitFor();
  await foto(page, "alarmkanal-sms-test", { element: zeile });
}

// Vorlagensatz Swyx (0.44.0): anwenden, dann Sensoren am Gerät. Der simagent
// misst keine Sensoren; die Zustände setzt das Skript wie ein Windows-Agent
// sie melden würde (Werte erfunden).
async function vorlagensaetze(page: Page, demo: Demo) {
  const tel = demo.geraete["srv-tel01"];
  if (!tel) throw new Error("srv-tel01 fehlt");
  await gehe(page, "/sensor-vorlagen");
  const saetze = page.locator("table").filter({ hasText: "Ferrari OfficeMaster" });
  await saetze.waitFor();
  await page.setViewportSize({ width: 1280, height: 1800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await foto(page, "sensor-vorlagensaetze", { element: saetze });
  // Eigener Satz (0.46.0): eingebauten Satz „SQL Server“ kopieren, einen Eintrag entfernen, speichern
  await saetze.locator("tr").filter({ hasText: "Standardinstanz" }).getByRole("button", { name: "Als eigenen" }).click();
  const satzForm = page.getByRole("form", { name: "Vorlagensatz" });
  await satzForm.getByLabel("Name", { exact: true }).fill("SQL Server Verwaltung");
  await satzForm.getByRole("button", { name: "SQL: Port 1433 entfernen" }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await foto(page, "vorlagensatz-eigen", { element: satzForm });
  await satzForm.getByRole("button", { name: "Speichern" }).click();
  await satzForm.waitFor({ state: "detached" });
  await page.setViewportSize({ width: 1280, height: 800 });
  await saetze.locator("tr").filter({ hasText: "SwyxWare" }).getByRole("button", { name: "Anwenden" }).click();
  const form = page.locator("form").filter({ hasText: "„Swyx“ anwenden" });
  await form.getByLabel(/srv-tel01/).check();
  await form.getByRole("button", { name: "Anlegen" }).click();
  await form.getByRole("status").waitFor();
  await page.setViewportSize({ width: 1280, height: 1800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await foto(page, "vorlagensatz-anwenden", { element: form });
  await page.setViewportSize({ width: 1280, height: 800 });
  const zustand: [string, string, string, string][] = [
    ["Swyx: Dienst SwyxServer", "ok", "Dienst läuft", ""],
    ["Swyx: Dienst ConfigDataStore", "ok", "Dienst läuft", ""],
    ["Swyx: Dienst LinkManager", "ok", "Dienst läuft", ""],
    ["Swyx: Server aktiv", "ok", "Wert im Rahmen", "1"],
    ["Swyx: Leitungen angemeldet", "ok", "Wert im Rahmen", "2"],
    ["Swyx: Leitung abgemeldet", "crit", "Wert unter 1 (kritisch)", "minimum 0 (2 Instanzen)"],
    ["Swyx: Kanalauslastung", "ok", "Wert im Rahmen", "maximum 37,5 (2 Instanzen)"],
    ["Swyx: Gespräche", "ok", "Wert gelesen", "12"],
    ["Swyx: Lizenzen Benutzer", "ok", "Wert im Rahmen", "78 %"],
    ["Swyx: SIP-Geräte", "ok", "Wert gelesen", "64"],
  ];
  for (const [name, status, meldung, messwert] of zustand) {
    psql(
      `UPDATE ${SCHEMA}.checks SET status = '${status}', message = '${meldung}', metric = ${messwert ? `'${messwert}'` : "NULL"},
         since = now() - interval '25 minutes', last_run = now(), next_run = now() + interval '1 day'
       WHERE device_id = '${tel}' AND name = '${name}'`,
      "bilder",
    );
  }
  await page.setViewportSize({ width: 1280, height: 1800 });
  await gehe(page, `/hosts?geraet=${tel}&ansicht=sensoren`);
  const tabelle = page.locator("table").filter({ hasText: "Swyx: Server aktiv" });
  await tabelle.waitFor();
  await page.evaluate(() => window.scrollTo(0, 0));
  await foto(page, "host-sensoren-swyx", { element: tabelle });
  // Löschen im Reiter (0.99.2): ganzen Satz vom Gerät entfernen, Bestätigung offen
  await page.getByRole("button", { name: "Von diesem Gerät entfernen" }).first().click();
  await foto(page, "host-sensoren-loeschen", { element: page.locator(".sensoren-reiter"), breite: 1000 });
  await page.getByRole("button", { name: "Abbrechen" }).first().click();
  await page.setViewportSize({ width: 1280, height: 800 });
}

// Panel der Seite Einstellungen über seine Überschrift (innerste section).
function panel(page: Page, titel: string): Locator {
  return page.getByRole("heading", { name: titel, exact: true }).first().locator("xpath=ancestor::section[1]");
}

async function abgemeldet() {
  const ctx = await neuerKontext();
  const page = await ctx.newPage();
  await page.goto(BASIS + "/");
  await page.locator("input[type=email], input[autocomplete=username]").first().waitFor();
  await foto(page, "anmeldung");
  await foto(page, "anmeldung.png");
  await ctx.close();
}

async function handy(geheimnis: string) {
  const ctx = await neuerKontext({ handy: true });
  const page = await ctx.newPage();
  await anmelden(page, ADMIN, geheimnis);
  await gehe(page, "/");
  await page.setViewportSize({ width: 390, height: 800 });
  await foto(page, "dashboard-handy", { breite: 390 });
  await page.setViewportSize({ width: 390, height: 844 });
  await foto(page, "handy.png");
  await gehe(page, "/hosts");
  await foto(page, "hosts-handy.png", { ganz: true });
  await ctx.close();
}

async function dunkel(geheimnis: string) {
  const ctx = await neuerKontext({ dunkel: true });
  const page = await ctx.newPage();
  await anmelden(page, ADMIN, geheimnis);
  await gehe(page, "/hosts");
  await foto(page, "hosts-dunkel");
  await ctx.close();
}

// Kennfarben für die Bilder (0.99.2): zwei verwendet, eine ohne Gerät.
async function kennfarbenDemo(api: Api, demo: Demo) {
  const kf = async (name: string, farbe: string) =>
    (await api.rufe<{ id: string }>("POST", `/api/v1/mandanten/${demo.haupt}/kennfarben`, { name, farbe })).id;
  const pink = await kf("Neustart verpasst", "#d6457f");
  const orange = await kf("Backup überfällig", "#e07a1f");
  await kf("Lizenz läuft ab", "#1fa2b0");
  type S = { schluessel: string; geraet_id: string; status: string };
  let sensoren: S[] = [];
  // Die Zentrale prüft nach dem Anlegen erst nach und nach: auf Warnung und Kritisch warten.
  for (let i = 0; i < 30; i++) {
    sensoren = (await api.rufe<{ sensoren: S[] }>("GET", "/api/v1/sensoren")).sensoren;
    if (sensoren.some((x) => x.status === "crit")) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  const schlimmste = (id: string) => sensoren.filter((x) => x.geraet_id === id && x.status !== "ok");
  // je ein Gerät, dessen einziges Problem die Kennfarbe bekommt (sonst gewinnt Rot)
  const einzeln = sensoren.filter((x) => (x.status === "warn" || x.status === "crit") && schlimmste(x.geraet_id).length === 1);
  const crit = einzeln.find((x) => x.status === "crit");
  const warn = sensoren.find((x) => x.status === "warn" && !schlimmste(x.geraet_id).some((y) => y.status === "crit" || y.status === "unknown"));
  if (warn) await api.rufe("PUT", "/api/v1/sensoren/kennfarbe", { schluessel: warn.schluessel, kennfarbe_id: orange });
  if (crit) await api.rufe("PUT", "/api/v1/sensoren/kennfarbe", { schluessel: crit.schluessel, kennfarbe_id: pink });
  console.log(`   Kennfarben an ${warn ? 1 : 0} Warnung, ${crit ? 1 : 0} Kritisch`);
}

// Wandanzeige im Querformat eines Leitstellen-Bildschirms (immer dunkel).
async function wandanzeige(admin: Page, api: Api, demo: Demo) {
  if (!gewollt("wandanzeige") && !gewollt("wandanzeige-verwaltung")) return;
  const a = await api.rufe<{ link: string }>("POST", `/api/v1/mandanten/${demo.haupt}/anzeigen`, { name: "Leitstand", netz: "", mit_untermandanten: true });
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, colorScheme: "dark", locale: "de-DE", timezoneId: "Europe/Berlin" });
  const page = await ctx.newPage();
  await page.goto(a.link);
  await page.locator(".wand-flaeche .sonne").waitFor();
  await foto(page, "wandanzeige", { breite: 1600 });
  await ctx.close();
  // Verwaltung (0.99.2): Name öffnet die Vorschau, „Neuer Link“ mit Bestätigung
  await gehe(admin, "/wandanzeigen");
  await admin.getByRole("button", { name: "Neuer Link" }).first().click();
  await foto(admin, "wandanzeige-verwaltung");
  await admin.getByRole("button", { name: "Abbrechen" }).first().click();
  const id = (await admin.getByRole("link", { name: "Leitstand" }).getAttribute("href"))!.split("id=")[1]!;
  const vctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, colorScheme: "dark", locale: "de-DE", timezoneId: "Europe/Berlin", storageState: await admin.context().storageState() });
  const vp = await vctx.newPage();
  await vp.goto(`${BASIS}/anzeige/vorschau?id=${id}`);
  await vp.locator(".wand-flaeche .sonne").waitFor();
  await foto(vp, "wandanzeige-vorschau", { breite: 1600 });
  await vctx.close();
}

// Erste Anmeldung des Admins von „Standort Nord“: Zwei-Faktor einrichten,
// danach seine Sicht auf die Verwaltung. Dazu ein Agent-Einzeiler.
async function untermandant() {
  const ctx = await neuerKontext();
  const page = await ctx.newPage();
  await page.goto(BASIS + "/");
  await page.locator("input[type=email], input[autocomplete=username]").first().fill(NORD_ADMIN.email);
  await page.locator("input[type=password]").first().fill(NORD_ADMIN.pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  const schl = page.locator("code.schluessel").first();
  await schl.waitFor();
  const geheimnis = (await schl.textContent())!.replace(/\s/g, "");
  await verwischen(page.locator(".qr-rahmen, code.schluessel"));
  await foto(page, "zwei-faktor-einrichten.png");
  const feld = page.locator("input[autocomplete=one-time-code]");
  await feld.fill(await frischerCode(geheimnis));
  await feld.press("Enter");
  // Wiederherstellungscodes bestätigen, falls angezeigt
  const weiter = page.getByRole("button", { name: /Weiter|Codes gesichert|Fertig/ });
  await weiter.first().click({ timeout: 10000 }).catch(() => undefined);
  await gehe(page, "/verwaltung");
  await foto(page, "verwaltung-untermandant-admin.png");

  await gehe(page, "/hosts");
  await page.getByRole("button", { name: "Host hinzufügen" }).click();
  await page.getByLabel("Name", { exact: true }).first().fill("srv-nord02");
  await page.getByRole("button", { name: /Anlegen/ }).first().click();
  await page.locator("pre").first().waitFor();
  await verwischen(page.locator("pre"));
  await foto(page, "agent-hinzufuegen.png");
  await ctx.close();
}

main().catch((e) => {
  console.error(e);
  console.error(`Protokolle: ${ARBEIT}`);
  process.exit(1);
});
