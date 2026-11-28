// SPDX-License-Identifier: AGPL-3.0-only

// Zeigt die gebaute Demo lokal: node zeigen.mjs [Port], dann
// http://localhost:8099/ öffnen. Verhält sich wie der Webserver der Demo
// (deploy/Caddyfile auf der Website): unbekannte Pfade liefern die Startseite,
// die den Service Worker anmeldet, dazu dieselben Sicherheits-Header.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const wurzel = fileURLToPath(new URL("./ausgabe/", import.meta.url));
const typen = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".gz": "application/gzip",
  ".data": "application/octet-stream",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};
export const KOPF = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
};

// Basis-Pfad aus dem Bau (node bauen.mjs --basis=…): Die Demo liegt dann
// unter diesem Pfad, wie auf der Website.
export const BASIS = JSON.parse(await readFile(join(wurzel, "_demo/demo.json"), "utf8")).basis ?? "";

// starte: Server auf port; protokoll(pfad) erfährt jede Anfrage (für Tests).
export function starte(port, protokoll = () => {}) {
  const s = createServer(async (req, res) => {
    const roh = new URL(req.url, "http://x").pathname;
    protokoll(roh);
    if (roh !== BASIS + "/" && !roh.startsWith(BASIS + "/")) {
      res.writeHead(roh === BASIS || roh === "/" ? 302 : 404, { Location: BASIS + "/" });
      res.end();
      return;
    }
    const pfad = normalize(decodeURIComponent(roh.slice(BASIS.length))).replace(/^(\.\.[/\\])+/, "");
    let datei = join(wurzel, pfad);
    try {
      if (!(await stat(datei)).isFile()) throw new Error("kein File");
    } catch {
      datei = join(wurzel, "_demo/start.html");
    }
    const inhalt = await readFile(datei);
    res.writeHead(200, { ...KOPF, "Content-Type": typen[extname(datei)] ?? "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(inhalt);
  });
  return new Promise((ok) => s.listen(port, "127.0.0.1", () => ok(s)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.argv[2] ?? 8099);
  await starte(port);
  console.log(`Demo: http://localhost:${port}${BASIS}/`);
}
