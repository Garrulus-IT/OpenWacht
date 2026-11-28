// SPDX-License-Identifier: AGPL-3.0-only

// Baut die Klick-Demo nach demo/ausgabe/.
//
// Der Ablauf benutzt nur das echte Programm:
//   1. PostgreSQL als PGlite (dieselbe Datenbank, die später im Browser
//      läuft), erreichbar über einen lokalen Socket.
//   2. Die Zentrale (für diesen Rechner gebaut) migriert und richtet ein.
//   3. Die Demo-Zentrale (cmd/openwacht-demo) startet; über die HTTP-API (wie
//      die Oberfläche) entstehen Mandanten, Geräte, Sensoren und Personen.
//      Die Agents der Demo registrieren sich über den echten Agent-Handler.
//   4. Der Stand der Datenbank wird gespeichert; dazu kommen die Zentrale als
//      WebAssembly, PGlite und der Service Worker.
//
// Messwerte und Alarme entstehen erst im Browser (Simulation in
// cmd/openwacht-demo/sim.go), damit ihre Zeiten stimmen.
//
// Aufruf aus demo/: npm ci && node bauen.mjs [--basis=/openwacht/demo]
// Braucht Go (wie für das Programm) und Node.

import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { build } from "esbuild";
import { execFileSync, spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync, mkdtempSync, chmodSync } from "node:fs";
import { createServer } from "node:net";
import { gzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const hier = dirname(fileURLToPath(import.meta.url));
const repo = resolve(hier, "..");
const aus = join(hier, "ausgabe");
const tmp = mkdtempSync(join(tmpdir(), "openwacht-demo-"));
const version = readFileSync(join(repo, "VERSION"), "utf8").trim();
const commit = (() => {
  try {
    return execFileSync("git", ["-C", repo, "rev-parse", "--short=12", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "unbekannt";
  }
})();
const ldflags = `-s -w -X github.com/garrulus-it/openwacht/internal/version.Version=${version} -X github.com/garrulus-it/openwacht/internal/version.Commit=${commit}`;

// Demo-Zugänge: alles erfunden, nur für die Demo. Das Passwort steht in der
// Demo selbst, es schützt nichts.
export const PASSWORT = "demo-passwort-2026";
const ROLLE_SERVER = "demo_server";

function log(...a) {
  console.log("•", ...a);
}

async function freierPort() {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => ok(p));
    });
  });
}

export function totp(secret, t = Date.now()) {
  const alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").replace(/\s/g, "").toUpperCase()) bits += alph.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = createHmac("sha1", key).update(ctr).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}

const warte = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- HTTP-Client

class Sitzung {
  constructor(basis) {
    this.basis = basis;
    this.kekse = new Map();
    this.csrf = "";
    this.geheimnis = "";
    this.letzterTakt = -1;
  }
  async rufe(method, pfad, body) {
    const headers = { Origin: this.basis };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && this.csrf) headers["X-CSRF-Token"] = this.csrf;
    if (this.kekse.size) headers.Cookie = [...this.kekse].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await fetch(this.basis + pfad, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      const name = kv.slice(0, i);
      const wert = kv.slice(i + 1);
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(c) || wert === "") this.kekse.delete(name);
      else this.kekse.set(name, wert);
    }
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { text };
    }
    if (!res.ok) throw new Error(`${method} ${pfad}: ${res.status} ${text.slice(0, 300)}`);
    return data;
  }
  // code: ein Zwei-Faktor-Code, den der Server noch nicht gesehen hat (jeden
  // nimmt er nur einmal), notfalls nach dem Warten auf den nächsten Takt.
  async code() {
    let takt = Math.floor(Date.now() / 30000);
    if (takt <= this.letzterTakt) {
      await warte(30000 - (Date.now() % 30000) + 300);
      takt = Math.floor(Date.now() / 30000);
    }
    this.letzterTakt = takt;
    return totp(this.geheimnis);
  }
  async anmelden(email, geheimnis) {
    this.geheimnis = geheimnis ?? "";
    const r = await this.rufe("POST", "/api/v1/sitzung", { email, passwort: PASSWORT });
    let fertig = r;
    if (r.zweiter_faktor) {
      fertig = await this.rufe("POST", "/api/v1/sitzung/zweiter-faktor", { code: await this.code() });
    }
    this.csrf = fertig.csrf;
    if (fertig.zwei_faktor_einrichten) {
      const e = await this.rufe("POST", "/api/v1/zwei-faktor/einrichten", {});
      this.geheimnis = e.geheimnis.replace(/\s/g, "");
      await this.rufe("POST", "/api/v1/zwei-faktor/bestaetigen", { code: await this.code() });
    }
    const ich = await this.rufe("GET", "/api/v1/ich");
    if (ich.csrf) this.csrf = ich.csrf;
    return this.geheimnis;
  }
}

// ---------------------------------------------------------------- Datenbank

async function datenbank() {
  const db = await PGlite.create();
  const port = await freierPort();
  const sock = new PGLiteSocketServer({ db, port, host: "127.0.0.1", maxConnections: 8 });
  await sock.start();
  await db.exec(`
    CREATE ROLE openwacht_app NOLOGIN;
    CREATE ROLE openwacht_traps NOLOGIN;
    CREATE ROLE demo_owner NOLOGIN;
    CREATE ROLE ${ROLLE_SERVER} NOLOGIN IN ROLE openwacht_app;
    GRANT CREATE ON DATABASE postgres TO demo_owner;
    GRANT demo_owner, ${ROLLE_SERVER} TO postgres;
  `);
  return { db, sock, dsn: `host=127.0.0.1 port=${port} user=postgres dbname=postgres sslmode=disable` };
}

// Asynchron: PGlite läuft in diesem Prozess und muss weiter antworten können.
function programm(args, env, eingabe) {
  return new Promise((ok, fehler) => {
    const p = spawn(join(tmp, "zentrale"), args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stdin.end(eingabe ?? "");
    p.on("exit", (code) => (code === 0 ? ok(out) : fehler(new Error(`zentrale ${args[0]}: Exit ${code}`))));
  });
}

async function bisErreichbar(url) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).status < 500) return;
    } catch {
      // läuft noch nicht
    }
    await warte(100);
  }
  throw new Error("Server startet nicht");
}

// ---------------------------------------------------------------- Personen

// Die Personen der Demo. Der Hauptmandant heißt „Beispiel GmbH“ (Köln), dazu
// ein Standort und ein betreuter Kunde als Untermandanten.
const HAUPT = "Beispiel GmbH";
const BONN = "Standort Bonn";
const PRAXIS = "Praxis am Markt";
const PERSONEN = [
  { email: "alex.admin@beispiel.example", name: "Alex Admin", rolle: "Admin und Betreiber, sieht alles", role: "admin and operator, sees everything" },
  { email: "jonas.weber@beispiel.example", name: "Jonas Weber", mandant: HAUPT, mandantRolle: "operator", rolle: "Operator, bestätigt Alarme", role: "operator, acknowledges alerts" },
  { email: "lea.schmidt@beispiel.example", name: "Lea Schmidt", mandant: HAUPT, mandantRolle: "leser", rolle: "nur lesen", role: "read only" },
  { email: "ben.bonn@beispiel.example", name: "Ben Bonn", mandant: BONN, mandantRolle: "admin", rolle: "Admin, sieht nur den Standort Bonn", role: "admin, sees only the Bonn site" },
  { email: "paula.praxis@beispiel.example", name: "Paula Praxis", mandant: PRAXIS, mandantRolle: "leser", rolle: "Kundin, sieht nur ihre Praxis", role: "customer, sees only her practice" },
];

// ---------------------------------------------------------------- Beispieldaten

async function beispieldaten(basis) {
  const api = new Sitzung(basis);
  const geheimnisse = {};
  geheimnisse[PERSONEN[0].email] = await api.anmelden(PERSONEN[0].email);
  await api.rufe("POST", "/api/v1/zwei-faktor/codes", { code: await api.code() });
  await api.rufe("PUT", "/api/v1/einstellungen", { netze: ["10.20.0.0/16", "192.168.178.0/24"], code: await api.code() });

  const haupt = (await api.rufe("GET", "/api/v1/mandanten")).mandanten.find((m) => m.uebergeordnet_id === null).id;
  const mandant = async (name) => (await api.rufe("POST", "/api/v1/mandanten", { uebergeordnet_id: haupt, name })).id;
  const bonn = await mandant(BONN);
  const praxis = await mandant(PRAXIS);
  const mandanten = { [HAUPT]: haupt, [BONN]: bonn, [PRAXIS]: praxis };

  const gruppe = async (m, name, eltern = "") => (await api.rufe("POST", `/api/v1/mandanten/${m}/gruppen`, { name, eltern_id: eltern })).id;
  const rz = await gruppe(haupt, "Serverraum");
  const netz = await gruppe(haupt, "Netzwerk", rz);
  const buero = await gruppe(haupt, "Büro");

  await api.rufe("POST", `/api/v1/mandanten/${haupt}/alarm-kanaele`, {
    art: "mail",
    name: "Team Betrieb",
    auch_untermandanten: true,
    aktiv: true,
    alle_benutzer: true,
    empfaenger: [],
  });

  // Agents: registrieren sich über den echten Agent-Handler; melden sich ab
  // dann im Browser (Simulation).
  const agents = [];
  const agentsFuer = async (m, hosts, still = []) => {
    const { token } = await api.rufe("POST", `/api/v1/mandanten/${m}/agent-tokens`, { notiz: "Demo", anzahl: hosts.length + still.length, gueltig_stunden: 1 });
    const res = await fetch(basis + "/_demo/agents", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token, hosts, still }) });
    if (!res.ok) throw new Error(`Agents: ${res.status} ${await res.text()}`);
    agents.push(...(await res.json()));
  };
  await agentsFuer(haupt, ["srv-dc01", "srv-file01", "srv-app01", "srv-db01", "pc-empfang"]);
  await agentsFuer(bonn, ["srv-bonn01"], ["pc-lager"]);
  await agentsFuer(praxis, ["praxis-server"]);
  // Offenes Token für die Liste „Agent-Tokens“
  await api.rufe("POST", `/api/v1/mandanten/${bonn}/agent-tokens`, { notiz: "Neue Kassenrechner", anzahl: 3, gueltig_stunden: 160 });

  const alle = async () => (await api.rufe("GET", "/api/v1/geraete")).geraete;
  const id = Object.fromEntries((await alle()).map((g) => [g.name, g.id]));
  for (const a of agents) if (!id[a.host]) throw new Error(`Gerät zu Agent ${a.host} fehlt`);

  // Geräte ohne Agent
  const geraet = async (m, name, adresse, gruppe_id = "") => (id[name] = (await api.rufe("POST", `/api/v1/mandanten/${m}/geraete`, { name, adresse, gruppe_id })).id);
  await geraet(haupt, "fw-koeln", "10.20.0.1", netz);
  await geraet(haupt, "sw-core01", "10.20.0.2", netz);
  await geraet(haupt, "usv-serverraum", "10.20.0.3", rz);
  await geraet(haupt, "pve01", "10.20.0.20", rz);
  await geraet(haupt, "nas-backup", "10.20.0.30", rz);
  await geraet(haupt, "intranet", "10.20.0.80", rz);
  await geraet(haupt, "drucker-eg", "10.20.0.40", buero);
  await geraet(bonn, "fw-bonn", "10.20.1.1");
  await geraet(bonn, "sw-bonn01", "10.20.1.2");
  await geraet(bonn, "drucker-bonn", "10.20.1.40");
  await geraet(praxis, "fritzbox-praxis", "192.168.178.1");
  await geraet(praxis, "www-praxis", "10.20.2.10");

  await api.rufe("POST", "/api/v1/geraete/gruppe", { geraete: ["srv-dc01", "srv-file01", "srv-app01", "srv-db01"].map((n) => id[n]), gruppe_id: rz });
  await api.rufe("POST", "/api/v1/geraete/gruppe", { geraete: [id["pc-empfang"]], gruppe_id: buero });

  // Abhängigkeiten (Topologie): alles in Köln hängt am Core-Switch, der an der Firewall.
  const liste = await alle();
  const haengtAn = async (name, eltern) => {
    const g = liste.find((x) => x.id === id[name]);
    await api.rufe("PUT", `/api/v1/geraete/${g.id}`, { name: g.name, adresse: g.adresse ?? "", abhaengig_von: id[eltern] });
  };
  await haengtAn("sw-core01", "fw-koeln");
  for (const n of ["srv-dc01", "srv-file01", "pve01", "nas-backup", "usv-serverraum", "drucker-eg", "pc-empfang", "intranet"]) await haengtAn(n, "sw-core01");
  for (const n of ["srv-app01", "srv-db01"]) await haengtAn(n, "pve01");
  await haengtAn("sw-bonn01", "fw-bonn");
  for (const n of ["srv-bonn01", "drucker-bonn"]) await haengtAn(n, "sw-bonn01");

  // Sensoren der Zentrale (in der Demo von der Simulation beantwortet)
  const sensor = async (g, name, typ, ziel, intervall = 60) =>
    (await api.rufe("POST", `/api/v1/geraete/${id[g]}/checks`, { name, typ, ziel, intervall_sekunden: intervall, aktiv: true })).id;
  await sensor("fw-koeln", "Erreichbar", "ping", { host: "10.20.0.1" });
  await sensor("fw-koeln", "VPN-Portal (HTTPS)", "tcp", { host: "10.20.0.1", port: 443 });
  await sensor("fw-bonn", "Erreichbar", "ping", { host: "10.20.1.1" });
  await sensor("srv-dc01", "DNS", "dns", { name: "beispiel.example", server: "10.20.0.10" });
  await sensor("srv-dc01", "Zeitserver", "ntp", { host: "10.20.0.10" });
  await sensor("intranet", "Startseite", "http", { url: "https://10.20.0.80/" });
  await sensor("intranet", "Zertifikat", "tls", { host: "10.20.0.80", port: 443 });
  await sensor("www-praxis", "Website", "http", { url: "https://10.20.2.10/" });
  await sensor("www-praxis", "Zertifikat", "tls", { host: "10.20.2.10", port: 443, verbinde: "www.praxis-am-markt.example" }, 300).catch(() =>
    sensor("www-praxis", "Zertifikat", "tls", { host: "10.20.2.10", port: 443 }, 300),
  );
  await sensor("drucker-eg", "Druckdienst (Port 9100)", "tcp", { host: "10.20.0.40", port: 9100 });

  // Sensoren auf Agents
  await sensor("srv-db01", "PostgreSQL", "dienst", { name: "postgresql" });
  await sensor("srv-bonn01", "PostgreSQL", "dienst", { name: "postgresql" });
  await sensor("srv-app01", "nginx", "prozess", { name: "nginx", mindestens: 1 });
  await sensor("srv-dc01", "Automatische Dienste", "autodienste", { ausnahmen: [] }).catch((e) => log("autodienste:", String(e).slice(0, 200)));
  await sensor("srv-file01", "Sicherung", "datei", { pfad: "D:\\Backup", ordner: true, warnung_stunden: 26, kritisch_stunden: 50 }, 300).catch((e) =>
    log("datei:", String(e).slice(0, 200)),
  );
  await sensor("praxis-server", "Sicherung", "datei", { pfad: "D:\\Backup", ordner: true, warnung_stunden: 26, kritisch_stunden: 50 }, 300).catch((e) =>
    log("datei:", String(e).slice(0, 200)),
  );

  // SNMP (die Werte liefert in der Demo die Simulation)
  const snmp = (g, adresse) =>
    api.rufe("PUT", `/api/v1/geraete/${id[g]}/snmp`, {
      version: "2c",
      adresse,
      port: 161,
      profil: "",
      community: "demo-" + randomBytes(4).toString("hex"),
      v3: null,
      intervall_sekunden: 60,
      aktiv: true,
      traps: false,
      sammler: "",
      ueberwacht: [],
    });
  await snmp("sw-core01", "10.20.0.2");
  await snmp("sw-bonn01", "10.20.1.2");
  await snmp("nas-backup", "10.20.0.30");
  await snmp("usv-serverraum", "10.20.0.3");
  await snmp("drucker-bonn", "10.20.1.40");
  await api.rufe("PUT", `/api/v1/geraete/${id["pve01"]}/proxmox`, {
    adresse: "10.20.0.20",
    port: 8006,
    token: "monitor@pve!openwacht=" + crypto.randomUUID(),
    ca: "",
    intervall_sekunden: 60,
    aktiv: true,
  });
  await api.rufe("PUT", `/api/v1/geraete/${id["fritzbox-praxis"]}/fritzbox`, {
    adresse: "192.168.178.1",
    port: 49000,
    https: false,
    benutzer: "openwacht",
    passwort: "demo-" + randomBytes(8).toString("hex"),
    fingerabdruck: "",
    intervall_sekunden: 60,
    aktiv: true,
  });

  // Schwellen: Platte D: von srv-file01 warnt ab 90 % (die Platte wächst).
  await api.rufe("PUT", `/api/v1/geraete/${id["srv-file01"]}/schwellen`, { schwellen: { platte_warn: 90, platte_krit: 97 } });

  // Wartungsfenster: monatlicher Patchtag, immer in der Zukunft
  await api
    .rufe("POST", "/api/v1/wartungsfenster", {
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
    })
    .catch((e) => log("Wartungsfenster:", String(e).slice(0, 200)));

  // API-Token
  await api.rufe("POST", "/api/v1/api-tokens", { mandant: haupt, name: "Inventar-Skript", rolle: "leser", tage: 365, code: await api.code() });

  // Personen
  for (const p of PERSONEN.slice(1)) {
    const m = mandanten[p.mandant];
    const neu = await api.rufe("POST", "/api/v1/benutzer", { mandant_id: m, email: p.email, anzeigename: p.name, passwort: PASSWORT });
    await api.rufe("PUT", `/api/v1/benutzer/${neu.id}/rollen/${m}`, { rolle: p.mandantRolle });
    const s = new Sitzung(basis);
    const g = await s.anmelden(p.email);
    if (g) geheimnisse[p.email] = g;
  }
  return {
    agents,
    personen: PERSONEN.map((p) => ({ email: p.email, name: p.name, rolle: p.rolle, role: p.role, geheimnis: geheimnisse[p.email] ?? "" })),
  };
}

// ---------------------------------------------------------------- Ablauf

// --nur-dateien: Datenbank und Personen vom letzten Lauf behalten, nur Server,
// Service Worker und Dateien neu (schneller beim Entwickeln).
const nurDateien = process.argv.includes("--nur-dateien");
// --basis=/openwacht/demo: Unterpfad, unter dem die Demo ausgeliefert wird
// (Voreinstellung: Wurzel). Die Zentrale bekommt ihn als Basis-Pfad.
const basisArg = process.argv.find((a) => a.startsWith("--basis="))?.slice("--basis=".length) ?? "";
const BASIS = basisArg.replace(/\/$/, "");
if (!/^(\/[A-Za-z0-9_-]+)*$/.test(BASIS)) {
  console.error("--basis: Pfad wie /openwacht/demo (Buchstaben, Ziffern, - und _)");
  process.exit(1);
}

// --ohne-oberflaeche: die schon gebaute Oberfläche (internal/webui/dist)
// nehmen, etwa eine unminifizierte zum Fehlersuchen.
const ohneOberflaeche = process.argv.includes("--ohne-oberflaeche");

async function main() {
  const d = join(aus, "_demo");
  if (!ohneOberflaeche) {
    log("Oberfläche bauen");
    execFileSync("npm", ["ci", "--no-audit", "--no-fund"], { cwd: join(repo, "web"), stdio: "inherit" });
    execFileSync("npm", ["run", "build"], { cwd: join(repo, "web"), stdio: "inherit" });
  }

  if (!nurDateien) {
    rmSync(aus, { recursive: true, force: true });
    await datenTeil(d);
  }
  await dateienTeil(d);
}

async function datenTeil(d) {
  mkdirSync(d, { recursive: true });

  log("Zentrale bauen", version, commit);
  execFileSync("go", ["build", "-trimpath", "-ldflags", ldflags, "-o", join(tmp, "zentrale"), "./cmd/zentrale"], { cwd: repo, stdio: "inherit" });
  execFileSync("go", ["build", "-trimpath", "-ldflags", ldflags, "-o", join(tmp, "openwacht-demo"), "./cmd/openwacht-demo"], { cwd: repo, stdio: "inherit" });

  log("Datenbank (PGlite) einrichten");
  const { db, sock, dsn } = await datenbank();
  const env = { OPENWACHT_DB_EIGENTUEMER: dsn, OPENWACHT_DB: dsn };
  // Eine Sitzung für alle Verbindungen: Die Rolle gilt für alle.
  await db.exec("SET ROLE demo_owner");
  await programm(["migrieren"], env);
  await programm(["einrichten", "-mandant", HAUPT, "-email", PERSONEN[0].email, "-name", PERSONEN[0].name], env, PASSWORT + "\n");
  await programm(["betreiber", "-email", PERSONEN[0].email], env);
  await db.exec(`SET ROLE ${ROLLE_SERVER}`);

  log("Demo-Zentrale starten und Beispieldaten anlegen");
  const schluessel = (await programm(["schluessel"], env)).trim();
  writeFileSync(join(tmp, "schluessel"), schluessel + "\n");
  chmodSync(join(tmp, "schluessel"), 0o600);
  const port = await freierPort();
  const basis = `http://localhost:${port}`;
  const srv = spawn(join(tmp, "openwacht-demo"), ["-adresse", `127.0.0.1:${port}`, "-basis-url", basis, "-schluessel", join(tmp, "schluessel"), "-rolle", ROLLE_SERVER], {
    env: { ...process.env, OPENWACHT_DB: dsn },
    stdio: ["ignore", "inherit", "inherit"],
  });
  let daten;
  try {
    await bisErreichbar(basis + "/api/v1/ich");
    daten = await beispieldaten(basis);
  } finally {
    srv.kill();
  }
  await new Promise((r) => (srv.exitCode !== null ? r() : srv.once("exit", r)));

  log("Stand der Datenbank speichern");
  await sock.stop();
  await db.exec("RESET ROLE");
  // Kleiner machen: Die Vorlagen-Datenbanken braucht nur CREATE DATABASE,
  // das die Demo nie aufruft; VACUUM FULL packt die Tabellen dicht.
  await db.exec(`UPDATE pg_database SET datistemplate = false WHERE datname IN ('template0', 'template1')`);
  await db.exec("DROP DATABASE template0");
  await db.exec("DROP DATABASE template1");
  await db.exec("VACUUM FULL");
  await db.exec("SET wal_recycle = off");
  for (let i = 0; i < 2; i++) {
    await db.query("SELECT pg_switch_wal()");
    await db.exec("CHECKPOINT");
  }
  const dump = await db.dumpDataDir("none");
  mkdirSync(join(d, "pglite"), { recursive: true });
  writeFileSync(join(d, "daten.tar.gz"), gzipSync(Buffer.from(await dump.arrayBuffer()), { level: 9 }));
  await db.close();

  writeFileSync(
    join(d, "demo.json"),
    JSON.stringify(
      { version, commit, debug: !!process.env.DEMO_DEBUG, rolle: ROLLE_SERVER, eigentuemer: "demo_owner", schluessel, passwort: PASSWORT, personen: daten.personen, agents: daten.agents },
      null,
      2,
    ) + "\n",
  );
}

async function dateienTeil(d) {
  log("Zentrale als WebAssembly bauen");
  execFileSync("go", ["build", "-trimpath", "-ldflags", ldflags, "-o", join(tmp, "openwacht.wasm"), "./cmd/openwacht-demo"], {
    cwd: repo,
    stdio: "inherit",
    env: { ...process.env, GOOS: "js", GOARCH: "wasm" },
  });
  writeFileSync(join(d, "openwacht.wasm.gz"), gzipSync(readFileSync(join(tmp, "openwacht.wasm")), { level: 9 }));
  const goroot = execFileSync("go", ["env", "GOROOT"], { encoding: "utf8" }).trim();

  log("Service Worker bündeln");
  const pgl = join(hier, "node_modules/@electric-sql/pglite/dist");
  // Große Dateien schon gepackt ausliefern (der Service Worker entpackt sie):
  // klein über die Leitung, egal wie der Webserver komprimiert.
  for (const f of ["pglite.wasm", "pglite.data"]) writeFileSync(join(d, "pglite", f + ".gz"), gzipSync(readFileSync(join(pgl, f)), { level: 9 }));
  for (const f of ["initdb.wasm"]) copyFileSync(join(pgl, f), join(d, "pglite", f));
  await build({
    entryPoints: [join(hier, "quelle/sw.js")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    minify: true,
    legalComments: "linked",
    outfile: join(aus, "demo-sw.js"),
    alias: { wasm_exec: join(goroot, "lib/wasm/wasm_exec.js") },
    define: { "import.meta.url": "globalThis.__demoPglite" },
    logLevel: "warning",
    plugins: [
      {
        // PGlite lädt in Node eigene Module; im Browser nie erreicht.
        name: "ohne-node",
        setup(b) {
          b.onResolve({ filter: /^(node:)?(module|fs|fs\/promises|path|url|zlib|crypto|stream|util|os|child_process|worker_threads)$/ }, (a) => ({ path: a.path, namespace: "ohne-node" }));
          b.onLoad({ filter: /.*/, namespace: "ohne-node" }, () => ({
            contents: "export default {}; export const createRequire = () => () => { throw new Error('nur in Node'); };",
          }));
        },
      },
    ],
  });
  for (const f of ["hilfe.js", "hilfe.css", "start.js", "start.css"]) copyFileSync(join(hier, "quelle", f), join(d, f));
  // Was der erste Besuch lädt, gerundet auf ganze MB.
  const gross = ["demo-sw.js", "_demo/openwacht.wasm.gz", "_demo/daten.tar.gz", "_demo/pglite/pglite.wasm.gz", "_demo/pglite/pglite.data.gz"]
    .map((f) => statSync(join(aus, f)).size)
    .reduce((a, b) => a + b, 0);
  const mb = String(Math.ceil(gross / 1e6));
  log("Erster Besuch lädt", mb, "MB");
  // Startseite mit Basis-Pfad; auch als index.html für den Ordner selbst.
  const start = readFileSync(join(hier, "quelle/start.html"), "utf8").replaceAll("%BASIS%", BASIS).replaceAll("%GROESSE%", mb);
  writeFileSync(join(d, "start.html"), start);
  writeFileSync(join(aus, "index.html"), start);
  const dj = JSON.parse(readFileSync(join(d, "demo.json"), "utf8"));
  dj.basis = BASIS;
  writeFileSync(join(d, "demo.json"), JSON.stringify(dj, null, 2) + "\n");
  mkdirSync(join(d, "schriften"), { recursive: true });
  for (const f of ["D-DIN.woff2", "D-DIN-Bold.woff2"]) copyFileSync(join(repo, "web/src/schriften", f), join(d, "schriften", f));
  copyFileSync(join(repo, "web/public/lizenzen/OFL-D-DIN.txt"), join(d, "schriften", "OFL-D-DIN.txt"));
  copyFileSync(join(repo, "web/public/favicon.svg"), join(d, "favicon.svg"));
  copyFileSync(join(repo, "LICENSE"), join(d, "LICENSE-OpenWacht.txt"));
  copyFileSync(join(hier, "node_modules/@electric-sql/pglite/LICENSE"), join(d, "LICENSE-PGlite.txt"));
  copyFileSync(join(goroot, "LICENSE"), join(d, "LICENSE-Go.txt"));
  log("fertig:", aus);
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => {
    rmSync(tmp, { recursive: true, force: true });
    // PGlite und sein Socket halten Node sonst offen.
    process.exit(process.exitCode ?? 0);
  });
