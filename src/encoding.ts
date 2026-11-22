// Web Crypto only: this runs on Workers, with no Node APIs.

const encoder = new TextEncoder();

export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** `byteLength` bytes from the platform CSPRNG, base64url without padding. Never fewer than 32. */
export function randomToken(byteLength = 32): string {
  if (!Number.isInteger(byteLength) || byteLength < 32) throw new RangeError("randomToken: at least 32 bytes");
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

/** SHA-256 of the UTF-8 text, base64url without padding (43 characters). */
export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return base64Url(new Uint8Array(digest));
}

/** The PKCE S256 challenge for a verifier (RFC 7636 §4.2). */
export function codeChallengeS256(verifier: string): Promise<string> {
  return sha256(verifier);
}

/**
 * Equality whose time does not depend on where the strings first differ. Both sides are short
 * hashes here, so their lengths are public; a length mismatch answers false at once.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** A 32-byte random value in base64url: 43 characters of [A-Za-z0-9_-]. */
export const RAW_TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** HTTP Basic credentials as RFC 6749 §2.3.1 asks: each half form-url-encoded, then base64. */
export function basicAuth(clientId: string, clientSecret: string): string {
  const form = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
  return `Basic ${btoa(`${form(clientId)}:${form(clientSecret)}`)}`;
}
