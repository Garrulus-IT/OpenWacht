// SPDX-License-Identifier: AGPL-3.0-only

// Startet den Server (WebAssembly) gegen eine PGlite-Datenbank und liefert die
// Funktion, die Anfragen beantwortet:
//   antwort = await fetchFn(method, url, [[name, wert], …], body | null)
//   → { status, headers: [[name, wert], …], body: Uint8Array }
// Vorher müssen globalThis.fs (speicher.js) gesetzt und wasm_exec.js geladen
// sein (in dieser Reihenfolge, wasm_exec.js liest fs beim Laden).

export async function starteServer({ db, wasm, schluessel, basis, rolle, agents = "[]", debug = false, sichernNach = 300 }) {
  const go = new globalThis.Go();
  // Die Datenbank liegt im Speicher und wird gebündelt in den Browser
  // (IndexedDB) geschrieben: kurz nachdem nichts mehr läuft, nicht nach jeder
  // Nachricht. Das hält die Demo schnell; verloren gehen könnte nur, was in
  // den letzten Millisekunden vor einem Absturz geschah.
  // Bei ständiger Arbeit im Hintergrund (Agents, Sensoren) gäbe es nie eine
  // Pause: Dann spätestens alle zwei Sekunden sichern.
  let uhr = null;
  let erste = 0;
  const sichern = () => {
    const jetzt = Date.now();
    if (!uhr) erste = jetzt;
    clearTimeout(uhr);
    const warte = Math.max(0, Math.min(sichernNach, erste + 2000 - jetzt));
    uhr = setTimeout(() => {
      uhr = null;
      db.syncToFs().catch((e) => console.warn("Sichern:", e));
    }, warte);
  };
  return new Promise((ok, fehler) => {
    globalThis.ocDemo = {
      pg: (bytes) =>
        db
          .execProtocolRaw(bytes, { syncToFs: false })
          .finally(sichern)
          .catch((e) => {
            let text = e?.message;
            if (!text) {
              try {
                text = JSON.stringify(e);
              } catch {
                text = String(e);
              }
            }
            throw new Error(text);
          }),
      schluessel,
      basis,
      rolle,
      agents,
      debug,
      bereit: (fn) => ok(fn),
      fehler: (m) => fehler(new Error(m)),
    };
    const inst = wasm instanceof WebAssembly.Module ? WebAssembly.instantiate(wasm, go.importObject) : WebAssembly.instantiate(wasm, go.importObject).then((r) => r.instance);
    inst.then((i) => go.run(i)).catch(fehler);
  });
}
