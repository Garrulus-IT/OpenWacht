// SPDX-License-Identifier: AGPL-3.0-only

// TOTP nach RFC 6238 (30 Sekunden, 6 Ziffern, SHA-1), wie eine
// Authenticator-App. Nur für die erfundenen Konten der Demo.
export async function totp(geheimnis, zeit = Date.now()) {
  const alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of geheimnis.replace(/[=\s]/g, "").toUpperCase()) bits += alph.indexOf(c).toString(2).padStart(5, "0");
  const roh = Uint8Array.from(bits.match(/.{8}/g), (b) => parseInt(b, 2));
  const zaehler = new DataView(new ArrayBuffer(8));
  zaehler.setBigUint64(0, BigInt(Math.floor(zeit / 30000)));
  const key = await crypto.subtle.importKey("raw", roh, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, zaehler.buffer));
  const o = h[19] & 15;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return String(n).padStart(6, "0");
}
