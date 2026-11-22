// A stand-in for account.forspring.ai: an EdDSA key from jose, a JWKS, an authorize step that
// hands back a code, and a token endpoint that checks Basic auth, the redirect URI and PKCE S256
// before minting an id_token. Passed to the package as its injectable fetch.
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK, type JWTPayload } from "jose";

import { sha256 } from "../src/encoding.js";

export const ISSUER = "https://account.forspring.ai/api/auth";
export const CLIENT_ID = "sitespring";
export const CLIENT_SECRET = "test-client-secret-5b1d9e";
export const APP = "https://app.example.test";
export const REDIRECT_URI = `${APP}/api/auth/callback/forspring`;
export const POST_LOGOUT = `${APP}/`;

export interface Clock {
  t: number;
}

export function clockAt(iso = "2026-11-22T12:00:00Z"): Clock {
  return { t: Date.parse(iso) };
}

interface PendingCode {
  clientId: string;
  redirectUri: string;
  challenge: string;
  nonce: string;
  scope: string;
}

export interface FakeAccount {
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  /** The browser at the account: answers the callback URL the account would redirect to. */
  authorize(location: string): Promise<string>;
  /** Claims merged into (or, with undefined, removed from) the next id_tokens. */
  claims: Record<string, unknown>;
  /** Header overrides for the next id_tokens. */
  idTokenHeader: { alg?: string; kid?: string };
  /** When set, the token endpoint answers this status with no id_token. */
  tokenStatus: number | null;
  /** Every id_token minted. */
  issued: string[];
  tokenRequests: { authorization: string | null; body: URLSearchParams }[];
  jwksFetches: number;
  person: { sub: string; email: string; name: string; sid: string };
  signLogoutToken(claims?: Record<string, unknown>, header?: { typ?: string; alg?: string; kid?: string }): Promise<string>;
  sign(payload: JWTPayload, header?: { alg?: string; kid?: string; typ?: string }): Promise<string>;
}

export async function fakeAccount(clock: Clock): Promise<FakeAccount> {
  const ed = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const es = await generateKeyPair("ES256");
  const edJwk: JWK = { ...(await exportJWK(ed.publicKey)), kid: "ed-1", alg: "EdDSA", use: "sig" };
  const esJwk: JWK = { ...(await exportJWK(es.publicKey)), kid: "es-1", alg: "ES256", use: "sig" };
  // A key the account never published: tokens signed with it must not verify.
  const rogue = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const codes = new Map<string, PendingCode>();
  let n = 0;

  const keyFor = (alg: string, kid: string): CryptoKey => (kid === "rogue" ? rogue.privateKey : alg === "ES256" ? es.privateKey : ed.privateKey);

  const account: FakeAccount = {
    claims: {},
    idTokenHeader: {},
    tokenStatus: null,
    issued: [],
    tokenRequests: [],
    jwksFetches: 0,
    person: { sub: "acct_user_1", email: "Ada@Example.test", name: "Ada", sid: "acct_sess_1" },

    async sign(payload, header = {}) {
      const alg = header.alg ?? "EdDSA";
      const kid = header.kid ?? (alg === "ES256" ? "es-1" : "ed-1");
      const jwt = new SignJWT(payload).setProtectedHeader({ alg, kid, ...(header.typ ? { typ: header.typ } : {}) });
      return jwt.sign(keyFor(alg, kid));
    },

    async signLogoutToken(claims = {}, header = {}) {
      const iat = Math.floor(clock.t / 1000);
      n += 1;
      const payload: Record<string, unknown> = {
        iss: ISSUER,
        aud: CLIENT_ID,
        sub: account.person.sub,
        sid: account.person.sid,
        iat,
        exp: iat + 120,
        jti: `jti-${n}`,
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
        ...claims,
      };
      for (const [k, v] of Object.entries(payload)) if (v === undefined) delete payload[k];
      return account.sign(payload as JWTPayload, { typ: header.typ ?? "logout+jwt", ...(header.alg ? { alg: header.alg } : {}), ...(header.kid ? { kid: header.kid } : {}) });
    },

    async authorize(location) {
      const url = new URL(location);
      if (url.origin + url.pathname !== `${ISSUER}/oauth2/authorize`) throw new Error("not the authorize endpoint");
      const p = url.searchParams;
      if (p.get("response_type") !== "code") throw new Error("response_type");
      if (p.get("code_challenge_method") !== "S256") throw new Error("PKCE must be S256");
      const challenge = p.get("code_challenge");
      const nonce = p.get("nonce");
      const state = p.get("state");
      if (!challenge || !nonce || !state) throw new Error("missing PKCE, nonce or state");
      n += 1;
      const code = `code-${n}-${crypto.randomUUID()}`;
      codes.set(code, { clientId: p.get("client_id") ?? "", redirectUri: p.get("redirect_uri") ?? "", challenge, nonce, scope: p.get("scope") ?? "" });
      const back = new URL(p.get("redirect_uri") ?? "");
      back.searchParams.set("code", code);
      back.searchParams.set("state", state);
      back.searchParams.set("iss", ISSUER);
      return back.toString();
    },

    async fetch(input, init) {
      const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (href === `${ISSUER}/jwks`) {
        account.jwksFetches += 1;
        return Response.json({ keys: [edJwk, esJwk] });
      }
      if (href !== `${ISSUER}/oauth2/token` || init?.method !== "POST") return new Response("not found", { status: 404 });

      const headers = new Headers(init.headers);
      const body = new URLSearchParams(String(init.body));
      account.tokenRequests.push({ authorization: headers.get("authorization"), body });
      if (account.tokenStatus !== null) return Response.json({ error: "server_error" }, { status: account.tokenStatus });

      const basic = /^Basic (.+)$/.exec(headers.get("authorization") ?? "");
      const [id, secret] = basic ? atob(basic[1] ?? "").split(":") : [];
      if (id !== CLIENT_ID || secret !== CLIENT_SECRET) return Response.json({ error: "invalid_client" }, { status: 401 });
      const pending = codes.get(body.get("code") ?? "");
      codes.delete(body.get("code") ?? "");
      if (!pending || body.get("grant_type") !== "authorization_code") return Response.json({ error: "invalid_grant" }, { status: 400 });
      if (pending.redirectUri !== body.get("redirect_uri") || pending.clientId !== CLIENT_ID) return Response.json({ error: "invalid_grant" }, { status: 400 });
      if ((await sha256(body.get("code_verifier") ?? "")) !== pending.challenge) return Response.json({ error: "invalid_grant" }, { status: 400 });

      const iat = Math.floor(clock.t / 1000);
      const payload: Record<string, unknown> = {
        iss: ISSUER,
        aud: CLIENT_ID,
        sub: account.person.sub,
        sid: account.person.sid,
        email: account.person.email,
        email_verified: true,
        name: account.person.name,
        nonce: pending.nonce,
        auth_time: iat - 60,
        iat,
        exp: iat + 36_000,
        ...account.claims,
      };
      for (const [k, v] of Object.entries(payload)) if (v === undefined) delete payload[k];
      const idToken = await account.sign(payload as JWTPayload, account.idTokenHeader);
      account.issued.push(idToken);
      return Response.json({ access_token: "at-opaque", token_type: "Bearer", expires_in: 3600, id_token: idToken });
    },
  };
  return account;
}

/** The `name=value` pair of a Set-Cookie line, as a browser sends it back. */
export function cookiePair(setCookie: string | undefined): string {
  if (!setCookie) throw new Error("no Set-Cookie");
  return setCookie.split(";")[0] ?? "";
}

export function cookieValue(setCookie: string | undefined): string {
  const pair = cookiePair(setCookie);
  return pair.slice(pair.indexOf("=") + 1);
}
