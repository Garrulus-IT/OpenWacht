// SPDX-License-Identifier: AGPL-3.0-only

// Muss vor wasm_exec.js laufen: wasm_exec.js liest globalThis.fs beim Laden.
import { erzeugeSpeicher } from "./speicher.js";

export const melder = { aenderung: () => {} };
export const speicher = erzeugeSpeicher({ aenderung: (p, d) => melder.aenderung(p, d) });
globalThis.fs = speicher.fs;

// Basis-Pfad der Demo aus dem Scope des Service Workers (z. B.
// /openwacht/demo), "" an der Wurzel.
export const BASIS = new URL(self.registration.scope).pathname.replace(/\/$/, "");

// Basis für die Dateien von PGlite (im Bündel steht import.meta.url dafür).
globalThis.__demoPglite = self.location.origin + BASIS + "/_demo/pglite/pglite.js";
