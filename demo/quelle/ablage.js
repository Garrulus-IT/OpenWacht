// SPDX-License-Identifier: AGPL-3.0-only

// IndexedDB für den Stand der Demo: meta (Version), dateien (Anhänge des
// Servers), kekse (Anmeldung). Die Datenbank selbst legt PGlite getrennt ab.
const SPEICHER = ["meta", "dateien", "kekse"];

export class Ablage {
  constructor(name) {
    this.name = name;
    this.db = null;
  }
  offen() {
    if (!this.db) {
      this.db = new Promise((ok, fehler) => {
        const r = indexedDB.open(this.name, 1);
        r.onupgradeneeded = () => SPEICHER.forEach((s) => r.result.createObjectStore(s));
        r.onsuccess = () => ok(r.result);
        r.onerror = () => fehler(r.error);
      });
    }
    return this.db;
  }
  async auftrag(speicher, modus, fn) {
    const db = await this.offen();
    return new Promise((ok, fehler) => {
      const tx = db.transaction(speicher, modus);
      const r = fn(tx.objectStore(speicher));
      tx.oncomplete = () => ok(r?.result);
      tx.onerror = () => fehler(tx.error);
    });
  }
  hole(s, k) {
    return this.auftrag(s, "readonly", (st) => st.get(k));
  }
  setze(s, k, v) {
    return this.auftrag(s, "readwrite", (st) => st.put(v, k));
  }
  loesche(s, k) {
    return this.auftrag(s, "readwrite", (st) => st.delete(k));
  }
  leere(s) {
    return this.auftrag(s, "readwrite", (st) => st.clear());
  }
  alle(s) {
    return this.auftrag(s, "readonly", (st) => st.getAll());
  }
  async alleMitSchluessel(s) {
    const [k, v] = await Promise.all([this.auftrag(s, "readonly", (st) => st.getAllKeys()), this.alle(s)]);
    return k.map((x, i) => [x, v[i]]);
  }
}
