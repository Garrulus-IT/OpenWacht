// SPDX-License-Identifier: AGPL-3.0-only

// Cookies der Demo. Ein Service Worker kann dem Browser keine Cookies setzen
// (Set-Cookie ist in selbst gebauten Antworten verboten). Deshalb hält er sie
// selbst und gibt sie dem Server bei jeder Anfrage mit, wie ein Browser:
// Name, Wert, Pfad, Ablauf. Die Seite selbst sieht sie nie (wie HttpOnly).
export class Kekse {
  constructor(ablage) {
    this.ablage = ablage;
    this.liste = new Map(); // name → { wert, pfad, bis }
  }
  laden(eintraege) {
    for (const e of eintraege) this.liste.set(e.name, e);
  }
  setze(kopf) {
    const [kv, ...attr] = kopf.split(";").map((s) => s.trim());
    const i = kv.indexOf("=");
    const name = kv.slice(0, i);
    const wert = kv.slice(i + 1);
    let pfad = "/";
    let bis = 0;
    for (const a of attr) {
      const [k, v = ""] = a.split("=");
      const kl = k.toLowerCase();
      if (kl === "path") pfad = v;
      if (kl === "max-age") bis = Number(v) <= 0 ? -1 : Date.now() + Number(v) * 1000;
      if (kl === "expires" && !bis) bis = Date.parse(v) || 0;
    }
    if (bis === -1 || (bis && bis < Date.now()) || wert === "") {
      this.liste.delete(name);
      this.ablage.loesche("kekse", name);
      return;
    }
    const e = { name, wert, pfad, bis };
    this.liste.set(name, e);
    this.ablage.setze("kekse", name, e);
  }
  kopf(pfad) {
    const jetzt = Date.now();
    const teile = [];
    for (const [name, e] of this.liste) {
      if (e.bis && e.bis < jetzt) {
        this.liste.delete(name);
        continue;
      }
      if (pfad.startsWith(e.pfad)) teile.push(`${name}=${e.wert}`);
    }
    return teile.join("; ");
  }
  hat(name) {
    return this.liste.has(name);
  }
  leeren() {
    this.liste.clear();
    this.ablage.leere("kekse");
  }
}
