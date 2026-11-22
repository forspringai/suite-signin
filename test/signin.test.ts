import { describe, expect, it, vi } from "vitest";

import { sha256 } from "../src/encoding.js";
import * as main from "../src/index.js";
import { redirect, sessionIdHash, suiteSignIn } from "../src/index.js";
import { issueSessionForTests } from "../src/testing.js";
import type { CallbackResult, SuiteSignInConfig } from "../src/types.js";
import { APP, CLIENT_ID, CLIENT_SECRET, cookiePair, cookieValue, ISSUER, POST_LOGOUT, REDIRECT_URI } from "./fake-account.js";
import { baseConfig, harness, LOGIN_COOKIE, SESSION_COOKIE } from "./harness.js";
import { memoryStore } from "./memory-store.js";

const DAY = 86_400;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;

function refusedOf(result: CallbackResult): string | null {
  return result.ok ? null : result.refused;
}

/** Signs in and answers the cookie header a browser would now send. */
async function signedInCookie(h: Awaited<ReturnType<typeof harness>>): Promise<string> {
  const result = await h.signIn();
  if (!result.ok) throw new Error(`refused: ${result.refused}`);
  return cookiePair(result.setCookie[0]);
}

describe("configuration", () => {
  const valid = async (): Promise<SuiteSignInConfig> => {
    const h = await harness();
    return baseConfig(h.store, h.account, h.clock, []);
  };

  it("derives the fixed endpoints from the issuer, with no discovery", async () => {
    const h = await harness();
    expect(h.signin.endpoints).toEqual({
      issuer: "https://account.forspring.ai/api/auth",
      authorize: "https://account.forspring.ai/api/auth/oauth2/authorize",
      token: "https://account.forspring.ai/api/auth/oauth2/token",
      jwks: "https://account.forspring.ai/api/auth/jwks",
      endSession: "https://account.forspring.ai/api/auth/oauth2/end-session",
    });
  });

  it("refuses a session or login cookie name not starting with __Host-", async () => {
    const config = await valid();
    expect(() => suiteSignIn({ ...config, cookie: { name: "ss_session" } })).toThrow(/cookie.name must start with "__Host-"/);
    expect(() => suiteSignIn({ ...config, cookie: { name: "__Secure-ss" } })).toThrow(/__Host-/);
    expect(() => suiteSignIn({ ...config, cookie: { name: SESSION_COOKIE, loginName: "ss_login" } })).toThrow(/cookie.loginName/);
    expect(() => suiteSignIn({ ...config, cookie: { name: "__Host-a;b" } })).toThrow(/cookie.name/);
    expect(() => suiteSignIn({ ...config, cookie: { name: SESSION_COOKIE, loginName: SESSION_COOKIE } })).toThrow(/differ/);
  });

  it("refuses x-forwarded-for as the rate-limit header", async () => {
    const config = await valid();
    expect(() => suiteSignIn({ ...config, ipHeader: "X-Forwarded-For" })).toThrow(/x-forwarded-for is never used/);
    expect(() => suiteSignIn({ ...config, ipHeader: "true-client-ip" })).not.toThrow();
  });

  it("takes scopes from config, requiring openid and email and refusing offline_access", async () => {
    const config = await valid();
    expect(() => suiteSignIn({ ...config, scopes: ["email"] })).toThrow(/openid/);
    expect(() => suiteSignIn({ ...config, scopes: ["openid"] })).toThrow(/email/);
    expect(() => suiteSignIn({ ...config, scopes: ["openid", "email", "offline_access"] })).toThrow(/offline_access/);
    expect(() => suiteSignIn({ ...config, scopes: undefined as unknown as string[] })).toThrow(/scopes is required/);
  });

  it("allows only asymmetric algorithms, EdDSA by default", async () => {
    const config = await valid();
    expect(() => suiteSignIn({ ...config, algorithms: ["none"] })).toThrow(/algorithms/);
    expect(() => suiteSignIn({ ...config, algorithms: ["HS256"] })).toThrow(/algorithms/);
    expect(() => suiteSignIn({ ...config, algorithms: [] })).toThrow(/algorithms/);
    expect(() => suiteSignIn({ ...config, algorithms: ["EdDSA", "ES256"] })).not.toThrow();
  });

  it("refuses non-https URIs and bad lifetimes, and never echoes the client secret", async () => {
    const config = await valid();
    expect(() => suiteSignIn({ ...config, redirectUri: "http://app.example.test/cb" })).toThrow(/redirectUri/);
    expect(() => suiteSignIn({ ...config, account: { ...config.account, issuer: "http://account.test" } })).toThrow(/issuer/);
    expect(() => suiteSignIn({ ...config, lifetimes: { idleS: 40 * DAY } })).toThrow(/idleS/);
    expect(() => suiteSignIn({ ...config, lifetimes: { loginS: 3600 } })).toThrow(/loginS/);
    expect(() => suiteSignIn({ ...config, product: "Site Spring" })).toThrow(/product/);
    const messages: string[] = [];
    for (const bad of [{ cookie: { name: "x" } }, { scopes: [] }, { redirectUri: "nope" }, { account: { ...config.account, clientId: "" } }]) {
      try {
        suiteSignIn({ ...config, ...bad } as SuiteSignInConfig);
      } catch (error) {
        messages.push(String(error));
      }
    }
    expect(messages).toHaveLength(4);
    for (const m of messages) expect(m).not.toContain(CLIENT_SECRET);
  });
});

describe("start", () => {
  it("makes state, nonce and verifier from 32 random bytes, base64url, stored as hashes", async () => {
    const h = await harness();
    const states = new Set<string>();
    for (let i = 0; i < 5; i += 1) {
      const started = await h.signin.start(h.get("/sign-in"));
      if (!started.ok) throw new Error("refused");
      const url = new URL(started.location);
      const state = url.searchParams.get("state") ?? "";
      const nonce = url.searchParams.get("nonce") ?? "";
      expect(state).toMatch(B64URL_32);
      expect(nonce).toMatch(B64URL_32);
      expect(state).not.toBe(nonce);
      states.add(state);

      const row = h.store.logins.get(await sha256(state));
      expect(row).toBeDefined();
      expect(row?.nonceHash).toBe(await sha256(nonce));
      expect(row?.verifier).toMatch(B64URL_32);
      // The store never holds the state or nonce themselves.
      expect(JSON.stringify(row)).not.toContain(state);
      expect(JSON.stringify(row)).not.toContain(nonce);
    }
    expect(states.size).toBe(5);
  });

  it("uses PKCE S256: the challenge is the SHA-256 of the stored verifier", async () => {
    const h = await harness();
    const started = await h.signin.start(h.get("/sign-in"));
    if (!started.ok) throw new Error("refused");
    const url = new URL(started.location);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const row = h.store.logins.get(await sha256(url.searchParams.get("state") ?? ""));
    expect(url.searchParams.get("code_challenge")).toBe(await sha256(row?.verifier ?? ""));
    expect(url.searchParams.get("code_challenge")).not.toBe(row?.verifier);
  });

  it("sends the configured client id, redirect URI and scopes", async () => {
    const h = await harness({ scopes: ["openid", "email", "profile"] });
    const started = await h.signin.start(h.get("/sign-in"));
    if (!started.ok) throw new Error("refused");
    const url = new URL(started.location);
    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/oauth2/authorize`);
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("response_type")).toBe("code");
  });

  it("binds the attempt to the browser with a __Host- login cookie whose hash is stored, for 10 minutes", async () => {
    const h = await harness();
    const started = await h.signin.start(h.get("/sign-in"));
    if (!started.ok) throw new Error("refused");
    const cookie = started.setCookie[0] ?? "";
    const state = new URL(started.location).searchParams.get("state") ?? "";
    expect(cookie.startsWith(`${LOGIN_COOKIE}_${(await sha256(state)).slice(0, 8)}=`)).toBe(true);
    for (const attr of ["Path=/", "Max-Age=600", "HttpOnly", "Secure", "SameSite=Lax"]) expect(cookie).toContain(attr);
    expect(cookie.toLowerCase()).not.toContain("domain");
    const value = cookieValue(cookie);
    expect(value).toMatch(B64URL_32);
    const row = h.store.logins.get(await sha256(new URL(started.location).searchParams.get("state") ?? ""));
    expect(row?.bindingHash).toBe(await sha256(value));
    expect(row?.expiresAt).toBe(Math.floor(h.clock.t / 1000) + 600);
  });

  it("keeps a same-origin returnTo with its query, and sends anything else home", async () => {
    const h = await harness();
    const back = async (returnTo: string) => {
      const r = await h.signIn({ returnTo });
      if (!r.ok) throw new Error(r.refused);
      return r.returnTo;
    };
    expect(await back("/device?user_code=ABCD-EFGH")).toBe("/device?user_code=ABCD-EFGH");
    expect(await back("/oauth/authorize?client_id=x&state=y")).toBe("/oauth/authorize?client_id=x&state=y");
    expect(await back("/o/acme/approve/site-1/dep-2")).toBe("/o/acme/approve/site-1/dep-2");
    expect(await back("//evil.example/x")).toBe("/");
    expect(await back("/\\evil.example")).toBe("/");
    expect(await back("https://evil.example/")).toBe("/");
  });
});

describe("callback", () => {
  it("verifies the account's id_token and answers the person, the returnTo and the cookies", async () => {
    const h = await harness();
    const result = await h.signIn({ returnTo: "/o/acme/" });
    if (!result.ok) throw new Error(result.refused);
    expect(result.person).toEqual({
      sub: "acct_user_1",
      email: "ada@example.test",
      name: "Ada",
      sid: "acct_sess_1",
      authTime: new Date(h.clock.t - 60_000),
    });
    expect(result.returnTo).toBe("/o/acme/");
    expect(result.setCookie).toHaveLength(2);
    expect(result.setCookie[1]).toMatch(/^__Host-sitespring_login_[A-Za-z0-9_-]{8}=; Path=\/; Max-Age=0; HttpOnly; Secure; SameSite=Lax$/);
  });

  it("exchanges the code with client_secret_basic and the PKCE verifier", async () => {
    const h = await harness();
    await h.signIn();
    const request = h.account.tokenRequests[0];
    expect(request?.authorization).toBe(`Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`);
    expect(request?.body.get("grant_type")).toBe("authorization_code");
    expect(request?.body.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(request?.body.get("code_verifier")).toMatch(B64URL_32);
    expect(request?.body.has("client_secret")).toBe(false);
  });

  it("sets a __Host- session cookie of 32 random bytes and stores only its SHA-256", async () => {
    const h = await harness();
    const result = await h.signIn();
    if (!result.ok) throw new Error(result.refused);
    const cookie = result.setCookie[0] ?? "";
    expect(cookie.startsWith(`${SESSION_COOKIE}=`)).toBe(true);
    for (const attr of ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", `Max-Age=${30 * DAY - 60}`]) expect(cookie).toContain(attr);
    expect(cookie.toLowerCase()).not.toContain("domain=");
    const raw = cookieValue(cookie);
    expect(raw).toMatch(B64URL_32);
    expect(h.store.sessions.size).toBe(1);
    const [key, row] = [...h.store.sessions.entries()][0] ?? [];
    expect(key).toBe(await sha256(raw));
    expect(row?.idHash).toBe(await sessionIdHash(raw));
    expect(JSON.stringify(row)).not.toContain(raw);
  });

  it("takes the login row once: the same callback a second time is refused", async () => {
    const h = await harness();
    const { callbackUrl, loginCookie } = await h.begin();
    expect((await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie))).ok).toBe(true);
    expect(refusedOf(await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie)))).toBe("no_login");
    expect(h.store.sessions.size).toBe(1);
  });

  it("refuses a login row older than 10 minutes, and deletes it", async () => {
    const h = await harness();
    const { callbackUrl, loginCookie } = await h.begin();
    h.advance(600);
    expect(refusedOf(await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie)))).toBe("expired");
    expect(h.store.logins.size).toBe(0);
  });

  it("refuses a callback in another browser, or with no login cookie", async () => {
    const h = await harness();
    const victim = await h.begin();
    const attacker = await h.begin();
    expect(refusedOf(await h.signin.callback(h.callbackRequest(victim.callbackUrl, attacker.loginCookie)))).toBe("binding_mismatch");
    const again = await h.begin();
    expect(refusedOf(await h.signin.callback(h.callbackRequest(again.callbackUrl, null)))).toBe("binding_mismatch");
    expect(h.store.sessions.size).toBe(0);
  });

  it("answers error= from authorize as account_error and burns the login row", async () => {
    const h = await harness();
    const { callbackUrl, loginCookie } = await h.begin();
    const url = new URL(callbackUrl);
    const state = url.searchParams.get("state") ?? "";
    const failed = `${REDIRECT_URI}?error=access_denied&state=${state}&iss=${encodeURIComponent(ISSUER)}`;
    expect(refusedOf(await h.signin.callback(h.callbackRequest(failed, loginCookie)))).toBe("account_error");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie)))).toBe("no_login");
  });

  it("refuses a callback with no state, no code, or an unknown state", async () => {
    const h = await harness();
    const iss = `iss=${encodeURIComponent(ISSUER)}`;
    expect(refusedOf(await h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?code=x&${iss}`, null)))).toBe("bad_request");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?code=x&state=${"a".repeat(43)}&${iss}`, null)))).toBe("no_login");
    const one = await h.begin();
    const noCode = new URL(one.callbackUrl);
    noCode.searchParams.delete("code");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(noCode.toString(), one.loginCookie)))).toBe("bad_request");
  });

  it("requires iss (RFC 9207) to be the issuer, on success and error redirects alike, before error= is read", async () => {
    const h = await harness();
    const wrong = await h.begin();
    const mixUp = new URL(wrong.callbackUrl);
    mixUp.searchParams.set("iss", "https://evil.example/api/auth");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(mixUp.toString(), wrong.loginCookie)))).toBe("iss_mismatch");

    const missing = await h.begin();
    const noIss = new URL(missing.callbackUrl);
    noIss.searchParams.delete("iss");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(noIss.toString(), missing.loginCookie)))).toBe("iss_mismatch");

    expect(refusedOf(await h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?error=access_denied`, null)))).toBe("iss_mismatch");
    expect(refusedOf(await h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?error=access_denied&iss=https%3A%2F%2Fevil.example`, null)))).toBe("iss_mismatch");
    // Each refused callback still burned its login row.
    expect(refusedOf(await h.signin.callback(h.callbackRequest(missing.callbackUrl, missing.loginCookie)))).toBe("no_login");
    expect(h.store.sessions.size).toBe(0);
  });

  it("answers a refused or unreachable token endpoint as token_exchange_failed", async () => {
    const h = await harness();
    h.account.tokenStatus = 400;
    expect(refusedOf(await h.signIn())).toBe("token_exchange_failed");
    const down = await harness({ fetch: async () => Promise.reject(new TypeError("network down")) });
    expect(refusedOf(await down.signIn())).toBe("token_exchange_failed");
  });

  it.each([
    ["another issuer", { iss: "https://evil.example/api/auth" }],
    ["another audience", { aud: "pulsespring" }],
    ["several audiences with no azp", { aud: [CLIENT_ID, "pulsespring"] }],
    ["an azp naming another client", { azp: "pulsespring" }],
    ["an expired exp", { exp: 1_000_000 }],
    ["no exp", { exp: undefined }],
    ["an iat in the future", { iat: Math.floor(Date.parse("2026-11-22T12:10:00Z") / 1000) }],
    ["an iat too old", { iat: Math.floor(Date.parse("2026-11-22T11:00:00Z") / 1000) }],
    ["no iat", { iat: undefined }],
    ["another nonce", { nonce: "b".repeat(43) }],
    ["no nonce", { nonce: undefined }],
    ["no sub", { sub: undefined }],
  ])("refuses an id_token with %s", async (_label, claims) => {
    const h = await harness();
    h.account.claims = claims;
    expect(refusedOf(await h.signIn())).toBe("invalid_id_token");
    expect(h.store.sessions.size).toBe(0);
  });

  it("refuses an id_token signed with an algorithm outside the allow-list, or an unpublished key", async () => {
    const h = await harness();
    h.account.idTokenHeader = { alg: "ES256" };
    expect(refusedOf(await h.signIn())).toBe("invalid_id_token");
    h.account.idTokenHeader = { alg: "EdDSA", kid: "rogue" };
    expect(refusedOf(await h.signIn())).toBe("invalid_id_token");

    const both = await harness({ algorithms: ["EdDSA", "ES256"] });
    both.account.idTokenHeader = { alg: "ES256" };
    expect((await both.signIn()).ok).toBe(true);
  });

  it.each([
    ["the string true", { email_verified: "true" }],
    ["the number 1", { email_verified: 1 }],
    ["false", { email_verified: false }],
    ["no email_verified", { email_verified: undefined }],
    ["no email", { email: undefined }],
  ])("requires email_verified === true: refuses %s", async (_label, claims) => {
    const h = await harness();
    h.account.claims = claims;
    expect(refusedOf(await h.signIn())).toBe("email_not_verified");
    expect(h.store.sessions.size).toBe(0);
  });

  it("refuses a sign-in whose auth_time is already past the absolute limit", async () => {
    const h = await harness();
    h.account.claims = { auth_time: Math.floor(h.clock.t / 1000) - 31 * DAY };
    expect(refusedOf(await h.signIn())).toBe("auth_too_old");
  });

  it("lets onSignIn refuse, creating no session", async () => {
    const seen: string[] = [];
    const h = await harness({
      onSignIn: async (person) => {
        seen.push(person.sub);
        return { refuse: "product_off" };
      },
    });
    const result = await h.signIn();
    expect(result).toMatchObject({ ok: false, refused: "product_refused", detail: "product_off" });
    expect(seen).toEqual(["acct_user_1"]);
    expect(h.store.sessions.size).toBe(0);
  });

  it("never draws HTML: a refusal is data plus the cleared login cookie", async () => {
    const h = await harness();
    const { callbackUrl, loginCookie } = await h.begin();
    const state = new URL(callbackUrl).searchParams.get("state") ?? "";
    const result = await h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?error=access_denied&state=${state}&iss=${encodeURIComponent(ISSUER)}`, loginCookie));
    expect(result).toEqual({ ok: false, refused: "account_error", setCookie: [`${cookiePair(loginCookie).split("=")[0]}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`] });
  });
});

describe("rate limit", () => {
  it("counts starts per cf-connecting-ip, 10 a minute, and ignores x-forwarded-for", async () => {
    const h = await harness();
    const start = (ip: string, xff?: string) =>
      h.signin.start(new Request(`${APP}/sign-in`, { headers: { "cf-connecting-ip": ip, ...(xff ? { "x-forwarded-for": xff } : {}) } }));
    for (let i = 0; i < 10; i += 1) expect((await start("198.51.100.1", `10.0.0.${i}`)).ok).toBe(true);
    expect(await start("198.51.100.1", "10.0.0.99")).toEqual({ ok: false, refused: "rate_limited", setCookie: [] });
    expect((await start("198.51.100.2")).ok).toBe(true);
    h.advance(60);
    expect((await start("198.51.100.1")).ok).toBe(true);
  });

  it("counts callbacks per IP separately from starts", async () => {
    const h = await harness();
    const cb = () => h.signin.callback(h.callbackRequest(`${REDIRECT_URI}?error=x&iss=${encodeURIComponent(ISSUER)}`, null, "198.51.100.9"));
    for (let i = 0; i < 10; i += 1) expect(refusedOf(await cb())).toBe("account_error");
    expect(refusedOf(await cb())).toBe("rate_limited");
    expect((await h.signin.start(new Request(`${APP}/sign-in`, { headers: { "cf-connecting-ip": "198.51.100.9" } }))).ok).toBe(true);
  });

  it("uses the configured header and a product's own limiter", async () => {
    const keys: string[] = [];
    const h = await harness({ ipHeader: "true-client-ip", rateLimit: async (key) => (keys.push(key), key !== "start:192.0.2.5") });
    const r1 = await h.signin.start(new Request(`${APP}/sign-in`, { headers: { "true-client-ip": "192.0.2.4", "cf-connecting-ip": "192.0.2.5" } }));
    const r2 = await h.signin.start(new Request(`${APP}/sign-in`, { headers: { "true-client-ip": "192.0.2.5" } }));
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
    expect(keys).toEqual(["start:192.0.2.4", "start:192.0.2.5"]);
  });
});

describe("session", () => {
  it("answers the signed-in person from the store, and null for no, unknown or malformed cookies", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const me = await h.signin.session(h.get("/", cookie));
    expect(me).toMatchObject({ sub: "acct_user_1", email: "ada@example.test", sid: "acct_sess_1" });
    expect(me?.sessionIdHash).toBe(await sha256(cookie.split("=")[1] ?? ""));
    expect(await h.signin.session(h.get("/"))).toBeNull();
    expect(await h.signin.session(h.get("/", `${SESSION_COOKIE}=${"x".repeat(43)}`))).toBeNull();
    expect(await h.signin.session(h.get("/", `${SESSION_COOKIE}=short`))).toBeNull();
  });

  it("reads the store every time: a deleted row ends the session at once", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
    h.store.sessions.clear();
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();
  });

  it("ends after 7 days idle, and deletes the row", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    h.advance(7 * DAY - 1);
    expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
    h.advance(7 * DAY);
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();
    expect(h.store.sessions.size).toBe(0);
  });

  it("renews the idle window at most once a day", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    for (let i = 0; i < 10; i += 1) {
      h.advance(3600);
      await h.signin.session(h.get("/", cookie));
    }
    expect(h.store.renewals).toBe(0);
    h.advance(DAY);
    const me = await h.signin.session(h.get("/", cookie));
    expect(h.store.renewals).toBe(1);
    expect(me?.expiresAt.getTime()).toBe(h.clock.t - (h.clock.t % 1000) + 7 * DAY * 1000);
    await h.signin.session(h.get("/", cookie));
    expect(h.store.renewals).toBe(1);
  });

  it("ends 30 days from auth_time, however often it is used", async () => {
    const h = await harness();
    h.account.claims = { auth_time: Math.floor(h.clock.t / 1000) - 10 * DAY };
    const cookie = await signedInCookie(h);
    for (let day = 1; day < 20; day += 1) {
      h.advance(DAY);
      expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
    }
    h.advance(DAY);
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();
  });

  it("ends 30 days from sign-in when the account omits auth_time, and never stretches for a future one", async () => {
    const h = await harness();
    h.account.claims = { auth_time: undefined };
    const cookie = await signedInCookie(h);
    for (let day = 1; day < 30; day += 1) {
      h.advance(DAY);
      expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
    }
    h.advance(DAY);
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();

    const future = await harness();
    future.account.claims = { auth_time: Math.floor(future.clock.t / 1000) + 5 * DAY };
    const result = await future.signIn();
    if (!result.ok) throw new Error(result.refused);
    const row = [...future.store.sessions.values()][0];
    expect(row?.absoluteExpiresAt).toBe(Math.floor(future.clock.t / 1000) + 30 * DAY);
  });
});

describe("signOut", () => {
  it("takes POST only", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const result = await h.signin.signOut(h.get("/sign-out", cookie));
    expect(result).toEqual({ ok: false, refused: "method_not_allowed", setCookie: [] });
    expect(h.store.sessions.size).toBe(1);
  });

  it("deletes the session, clears the cookie, and goes to end-session with id_token_hint", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const result = await h.signin.signOut(new Request(`${APP}/sign-out`, { method: "POST", headers: { cookie, origin: APP } }));
    if (!result.ok) throw new Error(result.refused);
    expect(result.ended).toBe(true);
    expect(h.store.sessions.size).toBe(0);
    expect(result.setCookie).toEqual([`${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`]);
    const url = new URL(result.location);
    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/oauth2/end-session`);
    expect(url.searchParams.get("id_token_hint")).toBe(h.account.issued[0]);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(POST_LOGOUT);
    expect(url.searchParams.has("client_id")).toBe(false);
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();
  });

  it("works with no session: client_id instead of id_token_hint, and still clears the cookie", async () => {
    const h = await harness();
    const result = await h.signin.signOut(new Request(`${APP}/sign-out`, { method: "POST" }));
    if (!result.ok) throw new Error(result.refused);
    expect(result.ended).toBe(false);
    expect(result.setCookie).toEqual([`${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`]);
    const url = new URL(result.location);
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.has("id_token_hint")).toBe(false);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(POST_LOGOUT);
  });

  it("refuses a sign-out posted from another origin", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const result = await h.signin.signOut(
      new Request(`${APP}/sign-out`, { method: "POST", headers: { cookie, origin: "https://customer.sites.example.test" } }),
    );
    expect(result).toEqual({ ok: false, refused: "cross_origin", setCookie: [] });
    expect(h.store.sessions.size).toBe(1);
  });
});

describe("backchannelLogout", () => {
  const post = (token: string | null, type = "application/x-www-form-urlencoded") =>
    new Request(`${APP}/forspring/logout`, {
      method: "POST",
      headers: { "content-type": type },
      body: token === null ? "" : new URLSearchParams({ logout_token: token }).toString(),
    });

  it("ends the sessions of the token's sid, answering 200 no-store", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    await issueSessionForTests(h.store, { sub: "acct_user_1", email: "ada@example.test", sid: "acct_sess_2" }, { now: new Date(h.clock.t) });
    const result = await h.signin.backchannelLogout(post(await h.account.signLogoutToken()));
    expect(result.ok).toBe(true);
    expect(result.ok && result.ended).toBe(1);
    expect(result.response.status).toBe(200);
    expect(result.response.headers.get("cache-control")).toBe("no-store");
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();
    expect(h.store.sessions.size).toBe(1);
  });

  it("ends every session of the sub when the token has no sid", async () => {
    const h = await harness();
    await signedInCookie(h);
    await issueSessionForTests(h.store, { sub: "acct_user_1", email: "ada@example.test", sid: "other" }, { now: new Date(h.clock.t) });
    await issueSessionForTests(h.store, { sub: "acct_user_2", email: "bo@example.test" }, { now: new Date(h.clock.t) });
    const result = await h.signin.backchannelLogout(post(await h.account.signLogoutToken({ sid: undefined })));
    expect(result.ok && result.ended).toBe(2);
    expect([...h.store.sessions.values()].map((s) => s.sub)).toEqual(["acct_user_2"]);
  });

  it("refuses a replayed jti", async () => {
    const h = await harness();
    const token = await h.account.signLogoutToken();
    expect((await h.signin.backchannelLogout(post(token))).ok).toBe(true);
    const again = await h.signin.backchannelLogout(post(token));
    expect(again).toMatchObject({ ok: false, refused: "replayed" });
    expect(again.response.status).toBe(400);
  });

  it.each([
    ["a nonce", { nonce: "n" }, {}, "nonce_present"],
    ["no events", { events: undefined }, {}, "invalid_logout_token"],
    ["another event", { events: { "http://schemas.openid.net/event/other": {} } }, {}, "not_a_logout_event"],
    ["a non-object event value", { events: { "http://schemas.openid.net/event/backchannel-logout": "yes" } }, {}, "not_a_logout_event"],
    ["no sid or sub", { sid: undefined, sub: undefined }, {}, "no_sid_or_sub"],
    ["no jti", { jti: undefined }, {}, "invalid_logout_token"],
    ["another issuer", { iss: "https://evil.example/api/auth" }, {}, "invalid_logout_token"],
    ["another audience", { aud: "pulsespring" }, {}, "invalid_logout_token"],
    ["an iat too old", { iat: Math.floor(Date.parse("2026-11-22T11:50:00Z") / 1000), exp: undefined }, {}, "invalid_logout_token"],
    ["an iat in the future", { iat: Math.floor(Date.parse("2026-11-22T12:05:00Z") / 1000), exp: undefined }, {}, "invalid_logout_token"],
    ["no iat", { iat: undefined }, {}, "invalid_logout_token"],
    ["the id_token typ", {}, { typ: "JWT" }, "invalid_logout_token"],
    ["an algorithm outside the allow-list", {}, { alg: "ES256" }, "invalid_logout_token"],
    ["an unpublished key", {}, { kid: "rogue" }, "invalid_logout_token"],
  ] as const)("refuses a logout_token with %s", async (_label, claims, header, reason) => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const result = await h.signin.backchannelLogout(post(await h.account.signLogoutToken(claims as Record<string, unknown>, header)));
    expect(result).toMatchObject({ ok: false, refused: reason });
    expect(result.response.status).toBe(400);
    expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
  });

  it("refuses a GET, a missing token and a JSON body", async () => {
    const h = await harness();
    const get = await h.signin.backchannelLogout(new Request(`${APP}/forspring/logout`));
    expect(get).toMatchObject({ ok: false, refused: "method_not_allowed" });
    expect(get.response.status).toBe(405);
    expect(await h.signin.backchannelLogout(post(null))).toMatchObject({ refused: "no_logout_token" });
    expect(await h.signin.backchannelLogout(post(await h.account.signLogoutToken(), "application/json"))).toMatchObject({ refused: "no_logout_token" });
  });
});

describe("endFor and prune", () => {
  it("endFor deletes every session row of the person", async () => {
    const h = await harness();
    await signedInCookie(h);
    await signedInCookie(h);
    await issueSessionForTests(h.store, { sub: "acct_user_2", email: "bo@example.test" }, { now: new Date(h.clock.t) });
    expect(await h.signin.endFor({ sub: "acct_user_1" })).toBe(2);
    expect([...h.store.sessions.values()].map((s) => s.sub)).toEqual(["acct_user_2"]);
    await expect(h.signin.endFor({ sub: "" })).rejects.toThrow(/sub/);
  });

  it("prune removes expired logins, sessions and jtis", async () => {
    const h = await harness();
    await h.begin();
    await signedInCookie(h);
    await h.signin.backchannelLogout(
      new Request(`${APP}/forspring/logout`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: await h.account.signLogoutToken({ sid: "none" }) }).toString(),
      }),
    );
    expect(await h.signin.prune()).toEqual({ logins: 0, sessions: 0, jtis: 0, hits: 0 });
    h.advance(8 * DAY);
    expect(await h.signin.prune()).toEqual({ logins: 1, sessions: 1, jtis: 1, hits: 2 });
  });
});

describe("test seam", () => {
  it("issueSessionForTests seeds a browser that session() accepts", async () => {
    const h = await harness();
    const { raw, idHash } = await issueSessionForTests(h.store, { sub: "acct_user_9", email: "cy@example.test", name: "Cy" }, { now: new Date(h.clock.t) });
    expect(raw).toMatch(B64URL_32);
    expect(idHash).toBe(await sessionIdHash(raw));
    expect(await h.signin.session(h.get("/", `${SESSION_COOKIE}=${raw}`))).toMatchObject({ sub: "acct_user_9", name: "Cy", sessionIdHash: idHash });
  });

  it("redirect() builds a 302 with every Set-Cookie", async () => {
    const response = redirect("/o/acme/", ["a=1; Path=/", "b=; Max-Age=0"]);
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/o/acme/");
    expect(response.headers.getSetCookie()).toEqual(["a=1; Path=/", "b=; Max-Age=0"]);
  });
});

describe("secrets never reach logs or errors", () => {
  it("logs only event names and reason codes, through every path", async () => {
    const consoleLines: string[] = [];
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) =>
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      }),
    );
    try {
      const store = memoryStore();
      const h = await harness({ log: undefined }, store);
      const secrets: string[] = [CLIENT_SECRET];
      const results: unknown[] = [];

      const { callbackUrl, loginCookie, location } = await h.begin();
      const authorize = new URL(location).searchParams;
      secrets.push(authorize.get("state") ?? "", authorize.get("nonce") ?? "", cookieValue(loginCookie));
      secrets.push(new URL(callbackUrl).searchParams.get("code") ?? "");
      const ok = await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie));
      results.push(ok);
      if (!ok.ok) throw new Error(ok.refused);
      const raw = cookieValue(ok.setCookie[0]);
      secrets.push(h.account.issued[0] ?? "", h.account.tokenRequests[0]?.body.get("code_verifier") ?? "");

      results.push(await h.signin.session(h.get("/", `${SESSION_COOKIE}=${raw}`)));
      results.push(await h.signin.callback(h.callbackRequest(callbackUrl, loginCookie)));
      h.account.claims = { aud: "other" };
      results.push(await h.signIn());
      h.account.tokenStatus = 500;
      results.push(await h.signIn());
      const logout = await h.account.signLogoutToken({ nonce: "x" });
      secrets.push(logout);
      const bc = await h.signin.backchannelLogout(
        new Request(`${APP}/forspring/logout`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ logout_token: logout }).toString(),
        }),
      );
      results.push({ ok: bc.ok, refused: bc.ok ? null : bc.refused });
      const out = await h.signin.signOut(new Request(`${APP}/sign-out`, { method: "POST", headers: { cookie: `${SESSION_COOKIE}=${raw}` } }));
      if (out.ok) results.push({ ...out, location: "(holds the id_token_hint by design)" });

      expect(consoleLines.length).toBeGreaterThan(5);
      const everything = [...consoleLines, ...results.map((r) => JSON.stringify(r))].join("\n");
      // The session's raw value appears only in the Set-Cookie of the successful callback.
      const withoutSetCookie = everything.replace(JSON.stringify(ok.setCookie[0]).slice(1, -1), "");
      for (const secret of [...secrets, raw]) {
        expect(secret.length).toBeGreaterThan(8);
        expect(withoutSetCookie).not.toContain(secret);
      }
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});

describe("security read fixes", () => {
  const ipStart = (h: Awaited<ReturnType<typeof harness>>, headers: Record<string, string>) =>
    h.signin.start(new Request(`${APP}/sign-in`, { headers }));

  it("keys an IPv6 address by its /64", async () => {
    const h = await harness();
    for (let i = 1; i <= 10; i += 1) expect((await ipStart(h, { "cf-connecting-ip": `2001:db8:1:2::${i.toString(16)}` })).ok).toBe(true);
    expect((await ipStart(h, { "cf-connecting-ip": "2001:0db8:0001:0002:ffff:ffff:ffff:ffff" })).ok).toBe(false);
    expect((await ipStart(h, { "cf-connecting-ip": "2001:db8:1:3::1" })).ok).toBe(true);
    expect([...h.store.hits.keys()].map((k) => k.split("@")[0])).toEqual(["start:2001:db8:1:2::/64", "start:2001:db8:1:3::/64"]);
  });

  it("takes rateLimit as { limit, windowS }", async () => {
    const h = await harness({ rateLimit: { limit: 2, windowS: 10 } });
    const ip = { "cf-connecting-ip": "198.51.100.20" };
    expect((await ipStart(h, ip)).ok).toBe(true);
    expect((await ipStart(h, ip)).ok).toBe(true);
    expect((await ipStart(h, ip)).ok).toBe(false);
    h.advance(10);
    expect((await ipStart(h, ip)).ok).toBe(true);
    const config = baseConfig(h.store, h.account, h.clock, []);
    expect(() => suiteSignIn({ ...config, rateLimit: { limit: 0 } })).toThrow(/rateLimit.limit/);
    expect(() => suiteSignIn({ ...config, rateLimit: { windowS: 1.5 } })).toThrow(/rateLimit.windowS/);
  });

  it("does not limit a request with no usable address, rather than sharing one bucket", async () => {
    const calls: string[] = [];
    const h = await harness();
    for (let i = 0; i < 15; i += 1) expect((await ipStart(h, {})).ok).toBe(true);
    for (let i = 0; i < 15; i += 1) expect((await ipStart(h, { "cf-connecting-ip": "not-an-address" })).ok).toBe(true);
    expect(h.store.hits.size).toBe(0);
    const custom = await harness({ rateLimit: async (key) => (calls.push(key), false) });
    expect((await ipStart(custom, {})).ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it("refuses a back-channel body over 16 KB, by Content-Length or as read", async () => {
    const h = await harness();
    const cookie = await signedInCookie(h);
    const token = await h.account.signLogoutToken();
    const post = (body: string, headers: Record<string, string> = {}) =>
      h.signin.backchannelLogout(
        new Request(`${APP}/forspring/logout`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body }),
      );
    const big = await post(`logout_token=${token}`, { "content-length": "16385" });
    expect(big).toMatchObject({ ok: false, refused: "too_large" });
    expect(big.response.status).toBe(400);
    expect(await post(`logout_token=${token}`, { "content-length": "12abc" })).toMatchObject({ refused: "too_large" });
    // No Content-Length on the request: the read itself stops at the cap.
    expect(await post(`logout_token=${token}&pad=${"a".repeat(16_384)}`)).toMatchObject({ refused: "too_large" });
    expect(await h.signin.session(h.get("/", cookie))).not.toBeNull();
    expect(await post(`logout_token=${token}`)).toMatchObject({ ok: true, ended: 1 });
  });

  it("keeps issueSessionForTests out of the main entry", () => {
    expect("issueSessionForTests" in main).toBe(false);
    expect(typeof main.sessionIdHash).toBe("function");
  });

  it("ends the session the browser already holds when it signs in again", async () => {
    const h = await harness();
    const first = await signedInCookie(h);
    const firstHash = await sha256(cookieValue(first));
    const { callbackUrl, loginCookie } = await h.begin();
    const result = await h.signin.callback(h.callbackRequest(callbackUrl, `${first}; ${loginCookie}`));
    if (!result.ok) throw new Error(result.refused);
    expect(h.store.sessions.has(firstHash)).toBe(false);
    expect(h.store.sessions.size).toBe(1);
    expect(await h.signin.session(h.get("/", first))).toBeNull();
    expect(await h.signin.session(h.get("/", cookiePair(result.setCookie[0])))).not.toBeNull();
  });

  it("lets two tabs sign in in parallel, each with its own login cookie", async () => {
    const h = await harness();
    const a = await h.begin({ returnTo: "/a" });
    const b = await h.begin({ returnTo: "/b" });
    expect(cookiePair(a.loginCookie).split("=")[0]).not.toBe(cookiePair(b.loginCookie).split("=")[0]);
    const both = `${a.loginCookie}; ${b.loginCookie}`;
    const rb = await h.signin.callback(h.callbackRequest(b.callbackUrl, both));
    const ra = await h.signin.callback(h.callbackRequest(a.callbackUrl, both));
    expect(rb).toMatchObject({ ok: true, returnTo: "/b" });
    expect(ra).toMatchObject({ ok: true, returnTo: "/a" });
    // Each callback clears only its own attempt's cookie.
    expect(rb.setCookie[1]?.split("=")[0]).toBe(cookiePair(b.loginCookie).split("=")[0]);
  });

  it("refuses another attempt's binding value under this attempt's cookie name", async () => {
    const h = await harness();
    const victim = await h.begin();
    const attacker = await h.begin();
    const forged = `${cookiePair(victim.loginCookie).split("=")[0]}=${cookieValue(attacker.loginCookie)}`;
    expect(refusedOf(await h.signin.callback(h.callbackRequest(victim.callbackUrl, forged)))).toBe("binding_mismatch");
  });

  it("refuses a login cookie name that leaves no room for the attempt suffix", async () => {
    const h = await harness();
    const config = baseConfig(h.store, h.account, h.clock, []);
    expect(() => suiteSignIn({ ...config, cookie: { name: SESSION_COOKIE, loginName: `__Host-${"l".repeat(60)}` } })).toThrow(/attempt suffix/);
  });
});
