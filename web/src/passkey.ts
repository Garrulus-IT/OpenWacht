// SPDX-License-Identifier: AGPL-3.0-only

// Passkeys (WebAuthn) im Browser, Etappe 36. Die Zentrale schickt Binärwerte
// als Base64url; der Browser braucht ArrayBuffer.

function vonB64(s: string): ArrayBuffer {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function zuB64(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const passkeyMoeglich = () => typeof window !== "undefined" && !!window.PublicKeyCredential && window.isSecureContext;

interface Cred {
  type: "public-key";
  id: string;
}

export interface RegOptionen {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  excludeCredentials: Cred[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
}

export interface AnmeldeOptionen {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  allowCredentials: Cred[];
}

const creds = (l: Cred[]) => l.map((c) => ({ type: c.type, id: vonB64(c.id) }));

// Meldung für Abbruch und Fehler des Browsers (keine technischen Namen).
export function passkeyFehler(e: unknown): string {
  const n = e instanceof DOMException ? e.name : "";
  if (n === "NotAllowedError" || n === "AbortError") return "Abgebrochen oder Zeit abgelaufen. Bitte erneut versuchen.";
  if (n === "InvalidStateError") return "Dieser Passkey ist für dein Konto schon registriert.";
  if (n === "SecurityError") return "Der Browser erlaubt Passkeys für diese Adresse nicht (HTTPS und DNS-Name nötig).";
  return e instanceof Error ? e.message : String(e);
}

export async function passkeyErzeugen(o: RegOptionen): Promise<{ client_data: string; attestation: string }> {
  const c = (await navigator.credentials.create({
    publicKey: {
      challenge: vonB64(o.challenge),
      rp: o.rp,
      user: { id: vonB64(o.user.id), name: o.user.name, displayName: o.user.displayName },
      pubKeyCredParams: o.pubKeyCredParams,
      timeout: o.timeout,
      attestation: o.attestation,
      excludeCredentials: creds(o.excludeCredentials),
      authenticatorSelection: o.authenticatorSelection,
    },
  })) as PublicKeyCredential | null;
  if (!c) throw new Error("Kein Passkey erzeugt.");
  const r = c.response as AuthenticatorAttestationResponse;
  return { client_data: zuB64(r.clientDataJSON), attestation: zuB64(r.attestationObject) };
}

export async function passkeyNutzen(o: AnmeldeOptionen) {
  const c = (await navigator.credentials.get({
    publicKey: {
      challenge: vonB64(o.challenge),
      rpId: o.rpId,
      timeout: o.timeout,
      userVerification: o.userVerification,
      allowCredentials: creds(o.allowCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!c) throw new Error("Kein Passkey gewählt.");
  const r = c.response as AuthenticatorAssertionResponse;
  return {
    id: zuB64(c.rawId),
    client_data: zuB64(r.clientDataJSON),
    authenticator_data: zuB64(r.authenticatorData),
    signature: zuB64(r.signature),
  };
}
