/** Times in the store are Unix seconds. */
export type UnixSeconds = number;
/** A fetch-like transport: the global fetch, or a service binding's `fetch`. */
export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
/**
 * One sign-in attempt between `start` and `callback`. The state and nonce are kept only as their
 * SHA-256; the PKCE verifier must be kept as it is, since it is sent to the token endpoint. The
 * row is single use and lives 10 minutes.
 */
export interface LoginRow {
    stateHash: string;
    nonceHash: string;
    verifier: string;
    returnTo: string;
    /** SHA-256 of the `__Host-<product>_login` cookie that binds the attempt to one browser. */
    bindingHash: string;
    expiresAt: UnixSeconds;
}
/** A signed-in browser. The cookie holds the raw id; the store holds only its SHA-256. */
export interface SessionRow {
    idHash: string;
    sub: string;
    email: string;
    name: string | null;
    /** The account session this sign-in came from, for back-channel logout. */
    sid: string | null;
    /** Kept for the end-session redirect's id_token_hint; deleted with the row. */
    idToken: string | null;
    authTime: UnixSeconds | null;
    createdAt: UnixSeconds;
    renewedAt: UnixSeconds;
    idleExpiresAt: UnixSeconds;
    absoluteExpiresAt: UnixSeconds;
}
/** Which sessions a back-channel logout or `endFor` ends. */
export type SessionQuery = {
    sid: string;
    sub?: string;
} | {
    sub: string;
};
/**
 * Where sign-in keeps its rows. `d1SignInStore` is one; a product may bring its own. Every method
 * must be atomic on its own: `takeLogin` and `deleteSession` delete and return in one step, and
 * `seenJti` records and answers in one step, so two concurrent calls cannot both succeed.
 */
export interface SignInStore {
    putLogin(login: LoginRow): Promise<void>;
    /** Deletes the row and returns it (single use), or null. Expired rows are returned too: the caller checks. */
    takeLogin(stateHash: string): Promise<LoginRow | null>;
    createSession(session: SessionRow): Promise<void>;
    getSession(idHash: string): Promise<SessionRow | null>;
    renewSession(idHash: string, renewedAt: UnixSeconds, idleExpiresAt: UnixSeconds): Promise<void>;
    /** Deletes the row and returns it, or null. */
    deleteSession(idHash: string): Promise<SessionRow | null>;
    /** Deletes every matching row (never marks them ended) and answers how many. */
    deleteBy(query: SessionQuery): Promise<number>;
    /** Records the jti until `expiresAt`; true when it was already recorded (a replay). */
    seenJti(jti: string, expiresAt: UnixSeconds): Promise<boolean>;
    /** Counts one hit for `key` in the fixed window holding `now`; true while the count is within `limit`. */
    hit(key: string, windowS: number, limit: number, now: UnixSeconds): Promise<boolean>;
    /** Removes expired logins, sessions, jtis and rate-limit windows; answers the counts per table. */
    prune(now: UnixSeconds): Promise<Record<string, number>>;
}
/** Who signed in: only ever from a verified id_token. */
export interface Person {
    sub: string;
    email: string;
    name: string | null;
    sid: string | null;
    authTime: Date | null;
}
/** A live session, as `session(req)` answers it. */
export interface SignedIn extends Person {
    /** SHA-256 of the session cookie: the store's key, safe to log or compare. Never the raw id. */
    sessionIdHash: string;
    createdAt: Date;
    /** When the session ends unless used again (idle), never after the absolute limit. */
    expiresAt: Date;
    /** The absolute limit: 30 days (by default) from auth_time, else from sign-in here. */
    absoluteExpiresAt: Date;
}
export interface Lifetimes {
    /** A session dies this long after its last renewal. Default 7 days. */
    idleS: number;
    /** A session in use is renewed at most this often. Default 1 day. */
    renewS: number;
    /** However often it is used, a session dies this long after auth_time (else sign-in). Default 30 days. */
    absoluteS: number;
    /** A login row (and its binding cookie) lives this long. Default 10 minutes. */
    loginS: number;
}
export type StartResult = {
    ok: true;
    location: string;
    setCookie: string[];
} | {
    ok: false;
    refused: "rate_limited";
    setCookie: string[];
};
/**
 * Why a callback made no session. The product draws its own page from this; the package never
 * draws HTML.
 */
export type CallbackRefusal = 
/** Too many starts or callbacks from this address. */
"rate_limited"
/** The account answered the authorize request with `error=`. */
 | "account_error"
/** The callback had no state or no code. */
 | "bad_request"
/** No login row for this state: never started, already used, or pruned. */
 | "no_login"
/** The login row was older than its lifetime. */
 | "expired"
/** The login was started in another browser (or its binding cookie is gone). */
 | "binding_mismatch"
/** The callback's `iss` (RFC 9207) is missing or names another issuer. Checked before `error=`. */
 | "iss_mismatch"
/** The token endpoint refused the code or could not be reached. */
 | "token_exchange_failed"
/** The id_token failed signature, iss, aud, exp, iat, alg, nonce or claim checks. */
 | "invalid_id_token"
/** The id_token's email_verified is not exactly true, or it has no email. */
 | "email_not_verified"
/** auth_time is so old that the absolute limit has already passed. */
 | "auth_too_old"
/** The product's onSignIn hook refused; its reason is in `detail`. */
 | "product_refused";
export type CallbackResult = {
    ok: true;
    person: Person;
    /** The same-origin path (with query) the sign-in was started for. */
    returnTo: string;
    /** The session cookie, and the login cookie cleared. Send both. */
    setCookie: string[];
} | {
    ok: false;
    refused: CallbackRefusal;
    /** The onSignIn hook's own reason, for `product_refused` only. */
    detail?: string;
    /** The login cookie cleared. */
    setCookie: string[];
};
export type SignOutResult = {
    ok: true;
    /** The account's end-session URL, to redirect the browser to. */
    location: string;
    /** The session cookie cleared. */
    setCookie: string[];
    /** Whether a session row was found and deleted. */
    ended: boolean;
} | {
    ok: false;
    /** `method_not_allowed`: not a POST. `cross_origin`: the Origin header names another origin. */
    refused: "method_not_allowed" | "cross_origin";
    setCookie: string[];
};
export type BackchannelRefusal = "method_not_allowed" | "no_logout_token" | "invalid_logout_token" | "not_a_logout_event" | "nonce_present" | "no_sid_or_sub" | "no_jti" | "replayed"
/** The body is over 16 KB (by Content-Length, or as read). */
 | "too_large";
export type BackchannelResult = {
    ok: true;
    ended: number;
    response: Response;
} | {
    ok: false;
    refused: BackchannelRefusal;
    response: Response;
};
/** What the package logs: fixed event names and reason codes, never a token, secret or claim value. */
export interface SignInLogEvent {
    product: string;
    event: "start" | "start_refused" | "callback_ok" | "callback_refused" | "session_expired" | "sign_out" | "backchannel_ok" | "backchannel_refused" | "end_for";
    reason?: string;
    count?: number;
}
export interface RateLimitOptions {
    /** Requests per key per window. Default 10. */
    limit?: number;
    /** The fixed window, in seconds. Default 60. */
    windowS?: number;
}
export interface SignInHookRefusal {
    refuse: string;
}
export interface SuiteSignInConfig {
    /** The product's key, `[a-z0-9-]{1,32}`: in logs and the default login cookie name. */
    product: string;
    account: {
        /** e.g. https://account.forspring.ai/api/auth. Endpoints are derived from it, with no discovery. */
        issuer: string;
        clientId: string;
        clientSecret: string;
    };
    /** The redirect URI registered for the client at the account (absolute https). */
    redirectUri: string;
    /** The post-logout redirect URI registered for the client at the account (absolute https). */
    postLogoutRedirectUri: string;
    /** Must include openid and email; never offline_access. No default. */
    scopes: readonly string[];
    cookie: {
        /** The session cookie: must start with `__Host-`. */
        name: string;
        /**
         * The login-binding cookie's base name. Default `__Host-<product>_login`; must start with
         * `__Host-`. Each sign-in attempt gets its own cookie, `<loginName>_<first 8 characters of the
         * state's SHA-256, base64url>`, so sign-ins in parallel tabs do not clash.
         */
        loginName?: string;
    };
    store: SignInStore;
    /** id_token and logout_token algorithms allowed. Default ['EdDSA']. Never 'none' or an HMAC. */
    algorithms?: readonly string[];
    lifetimes?: Partial<Lifetimes>;
    /**
     * Default `{ limit: 10, windowS: 60 }`: the store's fixed window per `start:<addr>` and
     * `callback:<addr>`, where <addr> is an IPv4 address or an IPv6 /64. A function answers true when
     * the request may go ahead and is called with the same keys. `false` turns limiting off. A request
     * with no usable address in `ipHeader` is not limited, rather than sharing one bucket with all
     * other such requests.
     */
    rateLimit?: RateLimitOptions | ((key: string) => Promise<boolean>) | false;
    /** The header holding the client's address. Default `cf-connecting-ip`; `x-forwarded-for` is refused. */
    ipHeader?: string;
    /** Product hook after the id_token is verified and before any session exists. */
    onSignIn?: (person: Person, request: Request) => Promise<void | SignInHookRefusal>;
    /** Transport for the token endpoint and the JWKS. Default the global fetch. */
    fetch?: FetchLike;
    /** Sent on every call to the account (Cloudflare's bot check answers some defaults with 1010). */
    userAgent?: string;
    /** Allowed clock skew either way, in seconds. Default 60. */
    clockToleranceS?: number;
    /** A logout_token older than this (by iat) is refused. Default 300. */
    logoutTokenMaxAgeS?: number;
    /** An id_token older than this (by iat) is refused. Default 600: it was minted at the token call. */
    idTokenMaxAgeS?: number;
    /** Default: one JSON line per event to console.log. `false` turns logging off. */
    log?: ((event: SignInLogEvent) => void) | false;
    /** The clock. Default `() => new Date()`. */
    now?: () => Date;
}
export interface SuiteSignIn {
    start(request: Request, options?: {
        returnTo?: string | null;
    }): Promise<StartResult>;
    callback(request: Request): Promise<CallbackResult>;
    session(request: Request): Promise<SignedIn | null>;
    signOut(request: Request): Promise<SignOutResult>;
    backchannelLogout(request: Request): Promise<BackchannelResult>;
    endFor(query: {
        sub: string;
    }): Promise<number>;
    prune(now?: Date): Promise<Record<string, number>>;
    /** The endpoints derived from the issuer. */
    readonly endpoints: AccountEndpoints;
}
export interface AccountEndpoints {
    issuer: string;
    authorize: string;
    token: string;
    jwks: string;
    endSession: string;
}
