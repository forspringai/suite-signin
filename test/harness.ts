import { suiteSignIn } from "../src/index.js";
import type { SignInLogEvent, SignInStore, SuiteSignInConfig } from "../src/types.js";
import { APP, CLIENT_ID, CLIENT_SECRET, clockAt, cookiePair, fakeAccount, ISSUER, POST_LOGOUT, REDIRECT_URI, type Clock, type FakeAccount } from "./fake-account.js";
import { memoryStore, type MemoryStore } from "./memory-store.js";

export const SESSION_COOKIE = "__Host-sitespring_session";
export const LOGIN_COOKIE = "__Host-sitespring_login";

export function baseConfig(store: SignInStore, account: FakeAccount, clock: Clock, logs: SignInLogEvent[]): SuiteSignInConfig {
  return {
    product: "sitespring",
    account: { issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
    redirectUri: REDIRECT_URI,
    postLogoutRedirectUri: POST_LOGOUT,
    scopes: ["openid", "email"],
    cookie: { name: SESSION_COOKIE },
    store,
    fetch: account.fetch,
    log: (e) => logs.push(e),
    now: () => new Date(clock.t),
  };
}

export interface Harness<S extends SignInStore = MemoryStore> {
  signin: ReturnType<typeof suiteSignIn>;
  store: S;
  account: FakeAccount;
  clock: Clock;
  logs: SignInLogEvent[];
  advance(seconds: number): void;
  /** Start in one browser, go through the fake account, and come back to the callback. */
  signIn(options?: { returnTo?: string; ip?: string }): ReturnType<ReturnType<typeof suiteSignIn>["callback"]>;
  /** A start and the authorize step, stopping before the callback. */
  begin(options?: { returnTo?: string; ip?: string }): Promise<{ callbackUrl: string; loginCookie: string; location: string }>;
  callbackRequest(url: string, cookie: string | null, ip?: string): Request;
  get(path: string, cookie?: string | null): Request;
}

export async function harness<S extends SignInStore = MemoryStore>(
  overrides: Partial<SuiteSignInConfig> = {},
  storeArg?: S,
): Promise<Harness<S>> {
  const clock = clockAt();
  const account = await fakeAccount(clock);
  const store = (storeArg ?? memoryStore()) as S;
  const logs: SignInLogEvent[] = [];
  const signin = suiteSignIn({ ...baseConfig(store, account, clock, logs), ...overrides });

  const callbackRequest = (url: string, cookie: string | null, ip = "203.0.113.7") =>
    new Request(url, { headers: { ...(cookie ? { cookie } : {}), "cf-connecting-ip": ip } });

  const begin: Harness<S>["begin"] = async (options = {}) => {
    const started = await signin.start(new Request(`${APP}/sign-in`, { headers: { "cf-connecting-ip": options.ip ?? "203.0.113.7" } }), {
      returnTo: options.returnTo,
    });
    if (!started.ok) throw new Error(`start refused: ${started.refused}`);
    const callbackUrl = await account.authorize(started.location);
    return { callbackUrl, loginCookie: cookiePair(started.setCookie[0]), location: started.location };
  };

  return {
    signin,
    store,
    account,
    clock,
    logs,
    advance: (seconds) => {
      clock.t += seconds * 1000;
    },
    begin,
    async signIn(options = {}) {
      const { callbackUrl, loginCookie } = await begin(options);
      return signin.callback(callbackRequest(callbackUrl, loginCookie, options.ip));
    },
    callbackRequest,
    get: (path, cookie) => new Request(`${APP}${path}`, { headers: cookie ? { cookie } : {} }),
  };
}
