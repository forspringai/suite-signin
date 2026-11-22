import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

import { assertHostCookieName, clearCookie, readCookie, setCookie } from "./cookies.js";
import { basicAuth, codeChallengeS256, constantTimeEqual, RAW_TOKEN, randomToken, sha256 } from "./encoding.js";
import { rateLimitAddress } from "./rate-key.js";
import { safeReturnTo } from "./return-to.js";
import { absoluteExpiry, fromSeconds, newSession, resolveLifetimes, toSeconds } from "./session.js";
import type {
  AccountEndpoints,
  BackchannelRefusal,
  BackchannelResult,
  CallbackRefusal,
  CallbackResult,
  FetchLike,
  Person,
  SessionRow,
  SignedIn,
  SignInLogEvent,
  SignOutResult,
  StartResult,
  SuiteSignIn,
  SuiteSignInConfig,
} from "./types.js";

const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
/** Asymmetric algorithms only: never "none", never an HMAC keyed by something the client knows. */
const ASYMMETRIC_ALGORITHMS = new Set(["EdDSA", "Ed25519", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
const HEADER_NAME = /^[a-z0-9-]{1,64}$/;
const PRODUCT = /^[a-z0-9-]{1,32}$/;
const RATE_WINDOW_S = 60;
const RATE_LIMIT = 10;
const TOKEN_TIMEOUT_MS = 10_000;
/** A back-channel logout body (logout_token=<JWT>) is at most 16 KB. */
const MAX_BODY_BYTES = 16_384;
const TOO_LARGE = Symbol("too large");

class EmailNotVerified extends Error {}

/**
 * The body as text, reading no more than `cap` bytes: a body that goes past it is cancelled and
 * answered TOO_LARGE, whatever its Content-Length said. An unreadable body reads as "".
 */
async function readCapped(request: Request, cap: number): Promise<string | typeof TOO_LARGE> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel().catch(() => {});
        return TOO_LARGE;
      }
      chunks.push(value);
    }
  } catch {
    return "";
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** JWKS resolvers, per transport and URL, so one isolate fetches the keys once and reuses them. */
const jwksCache = new WeakMap<FetchLike, Map<string, JWTVerifyGetKey>>();
const defaultFetch: FetchLike = (input, init) => fetch(input, init);

function jwksFor(fetchImpl: FetchLike, url: string, userAgent: string): JWTVerifyGetKey {
  let byUrl = jwksCache.get(fetchImpl);
  if (!byUrl) {
    byUrl = new Map();
    jwksCache.set(fetchImpl, byUrl);
  }
  let resolver = byUrl.get(url);
  if (!resolver) {
    resolver = createRemoteJWKSet(new URL(url), {
      headers: { "user-agent": userAgent },
      [customFetch]: (input: string, init: RequestInit) => fetchImpl(input, init),
    });
    byUrl.set(url, resolver);
  }
  return resolver;
}

function httpsUrl(value: unknown, field: string): URL {
  let url: URL;
  try {
    url = new URL(String(value));
  } catch {
    throw new TypeError(`suite-signin: ${field} must be an absolute https URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new TypeError(`suite-signin: ${field} must be an absolute https URL with no credentials or fragment`);
  }
  return url;
}

/** The account's fixed endpoints, derived from the issuer with no discovery fetch. */
export function accountEndpoints(issuer: string): AccountEndpoints {
  const url = httpsUrl(issuer, "account.issuer");
  if (url.search) throw new TypeError("suite-signin: account.issuer must have no query");
  const base = url.toString().replace(/\/+$/, "");
  return {
    issuer: base,
    authorize: `${base}/oauth2/authorize`,
    token: `${base}/oauth2/token`,
    jwks: `${base}/jwks`,
    endSession: `${base}/oauth2/end-session`,
  };
}

function nonEmpty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`suite-signin: ${field} is required`);
  return value;
}

/**
 * Sign-in for a suite product's console, as an OIDC client of the Forspring account: authorization
 * code with PKCE S256, the id_token verified against the account's keys, a server-side session in
 * the product's store, single sign-out and OIDC Back-Channel Logout 1.0. Everything is checked
 * here, once, when the product configures it; a mistake throws a TypeError naming the field
 * (never its value).
 */
export function suiteSignIn(config: SuiteSignInConfig): SuiteSignIn {
  if (config === null || typeof config !== "object") throw new TypeError("suite-signin: config is required");
  const product = nonEmpty(config.product, "product");
  if (!PRODUCT.test(product)) throw new TypeError("suite-signin: product must be 1 to 32 of [a-z0-9-]");

  const endpoints = accountEndpoints(nonEmpty(config.account?.issuer, "account.issuer"));
  const clientId = nonEmpty(config.account?.clientId, "account.clientId");
  const clientSecret = nonEmpty(config.account?.clientSecret, "account.clientSecret");
  const redirectUri = httpsUrl(nonEmpty(config.redirectUri, "redirectUri"), "redirectUri").toString();
  const appOrigin = new URL(redirectUri).origin;
  const postLogoutRedirectUri = httpsUrl(nonEmpty(config.postLogoutRedirectUri, "postLogoutRedirectUri"), "postLogoutRedirectUri").toString();

  if (!Array.isArray(config.scopes)) throw new TypeError("suite-signin: scopes is required");
  const scopes = [...new Set(config.scopes)];
  if (scopes.some((s) => typeof s !== "string" || !SCOPE_TOKEN.test(s))) throw new TypeError("suite-signin: scopes must be scope tokens");
  if (!scopes.includes("openid")) throw new TypeError("suite-signin: scopes must include openid");
  if (!scopes.includes("email")) throw new TypeError("suite-signin: scopes must include email: the id_token's verified email is required");
  if (scopes.includes("offline_access")) throw new TypeError("suite-signin: scopes must not include offline_access");

  const cookieName = nonEmpty(config.cookie?.name, "cookie.name");
  assertHostCookieName(cookieName, "cookie.name");
  const loginName = config.cookie.loginName ?? `__Host-${product}_login`;
  assertHostCookieName(loginName, "cookie.loginName");
  // The per-attempt suffix must still make a valid name.
  assertHostCookieName(`${loginName}_AAAAAAAA`, "cookie.loginName (with its 9-character attempt suffix)");
  if (loginName === cookieName || cookieName.startsWith(`${loginName}_`)) {
    throw new TypeError("suite-signin: cookie.loginName must differ from cookie.name");
  }
  const loginCookieName = (stateHash: string) => `${loginName}_${stateHash.slice(0, 8)}`;

  const store = config.store;
  if (!store || typeof store.takeLogin !== "function") throw new TypeError("suite-signin: store is required");

  const algorithms = [...(config.algorithms ?? ["EdDSA"])];
  if (algorithms.length === 0 || algorithms.some((a) => !ASYMMETRIC_ALGORITHMS.has(a))) {
    throw new TypeError("suite-signin: algorithms must be a non-empty list of asymmetric JWS algorithms");
  }

  const lifetimes = resolveLifetimes(config.lifetimes);
  const ipHeader = (config.ipHeader ?? "cf-connecting-ip").toLowerCase();
  if (!HEADER_NAME.test(ipHeader)) throw new TypeError("suite-signin: ipHeader must be a header name");
  if (ipHeader === "x-forwarded-for" || ipHeader === "forwarded") {
    throw new TypeError("suite-signin: ipHeader must be a header the client cannot set; x-forwarded-for is never used");
  }

  const clockTolerance = config.clockToleranceS ?? 60;
  const logoutTokenMaxAge = config.logoutTokenMaxAgeS ?? 300;
  const idTokenMaxAge = config.idTokenMaxAgeS ?? 600;
  for (const [field, value] of [["clockToleranceS", clockTolerance], ["logoutTokenMaxAgeS", logoutTokenMaxAge], ["idTokenMaxAgeS", idTokenMaxAge]] as const) {
    if (!Number.isInteger(value) || value < 0) throw new TypeError(`suite-signin: ${field} must be a non-negative integer`);
  }

  const fetchImpl: FetchLike = config.fetch ?? defaultFetch;
  const userAgent = config.userAgent ?? `Forspring-${product} suite-signin/0.1`;
  const clock = config.now ?? (() => new Date());
  const log: (event: Omit<SignInLogEvent, "product">) => void =
    config.log === false
      ? () => {}
      : config.log
        ? (e) => (config.log as (event: SignInLogEvent) => void)({ product, ...e })
        : (e) => console.log(JSON.stringify({ msg: "suite-signin", product, ...e }));
  const rateLimit = config.rateLimit ?? {};
  let rateWindowS = RATE_WINDOW_S;
  let rateLimitCount = RATE_LIMIT;
  if (rateLimit !== false && typeof rateLimit !== "function") {
    if (rateLimit === null || typeof rateLimit !== "object") throw new TypeError("suite-signin: rateLimit must be { limit, windowS }, a function or false");
    rateWindowS = rateLimit.windowS ?? RATE_WINDOW_S;
    rateLimitCount = rateLimit.limit ?? RATE_LIMIT;
    if (!Number.isInteger(rateWindowS) || rateWindowS <= 0) throw new TypeError("suite-signin: rateLimit.windowS must be a positive integer");
    if (!Number.isInteger(rateLimitCount) || rateLimitCount <= 0) throw new TypeError("suite-signin: rateLimit.limit must be a positive integer");
  }
  const onSignIn = config.onSignIn;

  // ---- helpers ----------------------------------------------------------------------------

  async function allowed(kind: "start" | "callback", request: Request): Promise<boolean> {
    if (rateLimit === false) return true;
    // No usable address: not limited, rather than one bucket shared by every such request.
    const address = rateLimitAddress(request.headers.get(ipHeader));
    if (address === null) return true;
    const key = `${kind}:${address}`;
    if (typeof rateLimit === "function") return await rateLimit(key);
    return await store.hit(key, rateWindowS, rateLimitCount, toSeconds(clock()));
  }

  async function exchangeCode(code: string, verifier: string): Promise<string> {
    const response = await fetchImpl(endpoints.token, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        authorization: basicAuth(clientId, clientSecret),
        "user-agent": userAgent,
      },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    });
    // Neither the status text nor the body is kept: an error body can echo what was sent.
    if (!response.ok) throw new Error("token endpoint refused");
    const body = (await response.json().catch(() => null)) as { id_token?: unknown } | null;
    if (!body || typeof body.id_token !== "string" || body.id_token.length === 0) throw new Error("no id_token");
    return body.id_token;
  }

  const jwks = () => jwksFor(fetchImpl, endpoints.jwks, userAgent);

  async function verifyIdToken(idToken: string, nonceHash: string, now: Date): Promise<Person> {
    const { payload } = await jwtVerify(idToken, jwks(), {
      issuer: endpoints.issuer,
      audience: clientId,
      algorithms,
      clockTolerance,
      maxTokenAge: idTokenMaxAge,
      currentDate: now,
      requiredClaims: ["exp", "iat", "sub", "nonce"],
    });
    if (typeof payload.nonce !== "string" || !constantTimeEqual(await sha256(payload.nonce), nonceHash)) throw new Error("nonce");
    // OIDC Core §3.1.3.7: with several audiences, azp must name this client; when present it must anyway.
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp === undefined) throw new Error("azp");
    if (payload.azp !== undefined && payload.azp !== clientId) throw new Error("azp");
    if (typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 255) throw new Error("sub");
    const authTime = payload.auth_time;
    if (authTime !== undefined && (typeof authTime !== "number" || !Number.isFinite(authTime))) throw new Error("auth_time");
    // Strictly the boolean true: "true", 1 or a missing claim are not a verified address.
    if (payload.email_verified !== true) throw new EmailNotVerified();
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    if (email === "") throw new EmailNotVerified();
    return {
      sub: payload.sub,
      email,
      name: typeof payload.name === "string" && payload.name !== "" ? payload.name : null,
      sid: typeof payload.sid === "string" && payload.sid !== "" ? payload.sid : null,
      authTime: typeof authTime === "number" ? fromSeconds(Math.floor(authTime)) : null,
    };
  }

  function signedIn(row: SessionRow, idleExpiresAt: number, absoluteExpiresAt: number): SignedIn {
    return {
      sub: row.sub,
      email: row.email,
      name: row.name,
      sid: row.sid,
      authTime: row.authTime === null ? null : fromSeconds(row.authTime),
      sessionIdHash: row.idHash,
      createdAt: fromSeconds(row.createdAt),
      expiresAt: fromSeconds(idleExpiresAt),
      absoluteExpiresAt: fromSeconds(absoluteExpiresAt),
    };
  }

  function backchannelResponse(status: number): Response {
    return new Response(null, { status, headers: { "cache-control": "no-store" } });
  }

  // ---- the calls ----------------------------------------------------------------------------

  return {
    endpoints,

    async start(request, options = {}): Promise<StartResult> {
      if (!(await allowed("start", request))) {
        log({ event: "start_refused", reason: "rate_limited" });
        return { ok: false, refused: "rate_limited", setCookie: [] };
      }
      const nowS = toSeconds(clock());
      const returnTo = safeReturnTo(options.returnTo, appOrigin) ?? "/";
      const state = randomToken(32);
      const nonce = randomToken(32);
      const verifier = randomToken(32);
      const binding = randomToken(32);
      await store.putLogin({
        stateHash: await sha256(state),
        nonceHash: await sha256(nonce),
        verifier,
        returnTo,
        bindingHash: await sha256(binding),
        expiresAt: nowS + lifetimes.loginS,
      });

      const url = new URL(endpoints.authorize);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("scope", scopes.join(" "));
      url.searchParams.set("state", state);
      url.searchParams.set("nonce", nonce);
      url.searchParams.set("code_challenge", await codeChallengeS256(verifier));
      url.searchParams.set("code_challenge_method", "S256");
      log({ event: "start" });
      // One cookie per attempt, named from the state's hash, so parallel tabs keep their own.
      const cookie = setCookie(loginCookieName(await sha256(state)), binding, lifetimes.loginS);
      return { ok: true, location: url.toString(), setCookie: [cookie] };
    },

    async callback(request): Promise<CallbackResult> {
      let clearLogin: string[] = [];
      const refuse = (refused: CallbackRefusal, detail?: string): CallbackResult => {
        log({ event: "callback_refused", reason: refused });
        return detail === undefined ? { ok: false, refused, setCookie: clearLogin } : { ok: false, refused, detail, setCookie: clearLogin };
      };

      if (!(await allowed("callback", request))) return refuse("rate_limited");
      if (request.method !== "GET") return refuse("bad_request");
      const now = clock();
      const nowS = toSeconds(now);
      const params = new URL(request.url).searchParams;

      // The login row is taken (deleted) first, so a state is never usable twice, even after an error.
      const state = params.get("state");
      const stateHash = state !== null && RAW_TOKEN.test(state) ? await sha256(state) : null;
      const thisLoginCookie = stateHash === null ? null : loginCookieName(stateHash);
      if (thisLoginCookie !== null) clearLogin = [clearCookie(thisLoginCookie)];
      const login = stateHash === null ? null : await store.takeLogin(stateHash);
      // RFC 9207: the account names itself on every redirect back, success or error. Checked first,
      // so an error= that claims to come from another issuer is not believed either.
      if (params.get("iss") !== endpoints.issuer) return refuse("iss_mismatch");
      if (params.has("error")) return refuse("account_error");
      if (state === null || state === "") return refuse("bad_request");
      if (!login || thisLoginCookie === null) return refuse("no_login");
      if (login.expiresAt <= nowS) return refuse("expired");

      const binding = readCookie(request, thisLoginCookie);
      if (binding === null || !RAW_TOKEN.test(binding) || !constantTimeEqual(await sha256(binding), login.bindingHash)) {
        return refuse("binding_mismatch");
      }
      const code = params.get("code");
      if (code === null || code === "") return refuse("bad_request");

      let idToken: string;
      try {
        idToken = await exchangeCode(code, login.verifier);
      } catch {
        return refuse("token_exchange_failed");
      }

      let person: Person;
      try {
        person = await verifyIdToken(idToken, login.nonceHash, now);
      } catch (error) {
        return refuse(error instanceof EmailNotVerified ? "email_not_verified" : "invalid_id_token");
      }

      const authTimeS = person.authTime === null ? null : toSeconds(person.authTime);
      if (absoluteExpiry(authTimeS, nowS, lifetimes.absoluteS) <= nowS) return refuse("auth_too_old");

      if (onSignIn) {
        const verdict = await onSignIn(person, request);
        if (verdict && typeof verdict === "object" && typeof verdict.refuse === "string") return refuse("product_refused", verdict.refuse);
      }

      // A session this browser already holds is ended, not left behind beside the new one.
      const previous = readCookie(request, cookieName);
      if (previous !== null && RAW_TOKEN.test(previous)) await store.deleteSession(await sha256(previous));

      const { raw, row } = await newSession(person, idToken, nowS, lifetimes);
      await store.createSession(row);
      log({ event: "callback_ok" });
      return {
        ok: true,
        person,
        returnTo: safeReturnTo(login.returnTo, appOrigin) ?? "/",
        setCookie: [setCookie(cookieName, raw, row.absoluteExpiresAt - nowS), ...clearLogin],
      };
    },

    async session(request): Promise<SignedIn | null> {
      const raw = readCookie(request, cookieName);
      if (raw === null || !RAW_TOKEN.test(raw)) return null;
      const idHash = await sha256(raw);
      // Every call reads the store: no cookie cache, so a signed-out session ends at once (D17).
      const row = await store.getSession(idHash);
      if (!row) return null;
      const nowS = toSeconds(clock());
      const absolute = Math.min(row.absoluteExpiresAt, absoluteExpiry(row.authTime, row.createdAt, lifetimes.absoluteS));
      if (nowS >= row.idleExpiresAt || nowS >= absolute) {
        await store.deleteSession(idHash);
        log({ event: "session_expired" });
        return null;
      }
      let idle = row.idleExpiresAt;
      if (nowS - row.renewedAt >= lifetimes.renewS) {
        idle = Math.min(nowS + lifetimes.idleS, absolute);
        await store.renewSession(idHash, nowS, idle);
      }
      return signedIn(row, idle, absolute);
    },

    async signOut(request): Promise<SignOutResult> {
      if (request.method !== "POST") return { ok: false, refused: "method_not_allowed", setCookie: [] };
      // A form on another origin (a customer's site under the same parent domain) must not sign anyone out.
      const origin = request.headers.get("origin");
      if (origin !== null && origin !== new URL(request.url).origin) return { ok: false, refused: "cross_origin", setCookie: [] };

      const raw = readCookie(request, cookieName);
      const row = raw !== null && RAW_TOKEN.test(raw) ? await store.deleteSession(await sha256(raw)) : null;
      const url = new URL(endpoints.endSession);
      if (row?.idToken) url.searchParams.set("id_token_hint", row.idToken);
      else url.searchParams.set("client_id", clientId);
      url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
      log({ event: "sign_out", count: row ? 1 : 0 });
      return { ok: true, location: url.toString(), setCookie: [clearCookie(cookieName)], ended: row !== null };
    },

    async backchannelLogout(request): Promise<BackchannelResult> {
      const refuse = (refused: BackchannelRefusal, status = 400): BackchannelResult => {
        log({ event: "backchannel_refused", reason: refused });
        return { ok: false, refused, response: backchannelResponse(status) };
      };
      if (request.method !== "POST") return refuse("method_not_allowed", 405);
      const type = request.headers.get("content-type") ?? "";
      if (!/^application\/x-www-form-urlencoded\b/i.test(type)) return refuse("no_logout_token");
      const length = request.headers.get("content-length");
      if (length !== null && !(/^\d{1,10}$/.test(length) && Number(length) <= MAX_BODY_BYTES)) return refuse("too_large");
      const body = await readCapped(request, MAX_BODY_BYTES);
      if (body === TOO_LARGE) return refuse("too_large");
      const token = new URLSearchParams(body).get("logout_token");
      if (!token) return refuse("no_logout_token");

      const now = clock();
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(token, jwks(), {
          issuer: endpoints.issuer,
          audience: clientId,
          algorithms,
          typ: "logout+jwt",
          clockTolerance,
          maxTokenAge: logoutTokenMaxAge,
          currentDate: now,
          requiredClaims: ["iat", "jti", "events"],
        }));
      } catch {
        return refuse("invalid_logout_token");
      }

      const events = payload.events as unknown;
      const event = events !== null && typeof events === "object" && !Array.isArray(events) ? (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT] : undefined;
      if (event === null || typeof event !== "object" || Array.isArray(event)) return refuse("not_a_logout_event");
      if ("nonce" in payload) return refuse("nonce_present");
      const sid = typeof payload.sid === "string" && payload.sid !== "" ? payload.sid : null;
      const sub = typeof payload.sub === "string" && payload.sub !== "" ? payload.sub : null;
      if (sid === null && sub === null) return refuse("no_sid_or_sub");
      if (typeof payload.jti !== "string" || payload.jti === "" || payload.jti.length > 255) return refuse("no_jti");

      // Remembered for as long as the token could still be accepted, then pruned.
      const iat = payload.iat as number;
      const keepUntil = Math.max(iat + logoutTokenMaxAge, typeof payload.exp === "number" ? payload.exp : 0) + clockTolerance;
      if (await store.seenJti(payload.jti, Math.ceil(keepUntil))) return refuse("replayed");

      const ended = await store.deleteBy(sid !== null ? (sub !== null ? { sid, sub } : { sid }) : { sub: sub as string });
      log({ event: "backchannel_ok", count: ended });
      return { ok: true, ended, response: backchannelResponse(200) };
    },

    async endFor(query): Promise<number> {
      const sub = nonEmpty(query?.sub, "endFor sub");
      const ended = await store.deleteBy({ sub });
      log({ event: "end_for", count: ended });
      return ended;
    },

    async prune(now): Promise<Record<string, number>> {
      return await store.prune(toSeconds(now ?? clock()));
    },
  };
}

/** A 302 to `location` carrying the Set-Cookie headers: what most products answer with. */
export function redirect(location: string, setCookies: readonly string[] = [], status: 302 | 303 = 302): Response {
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const cookie of setCookies) headers.append("set-cookie", cookie);
  return new Response(null, { status, headers });
}
