# @forspring/suite-signin

Sign-in for a Forspring suite product's console: an OIDC client of the Forspring account
(`account.forspring.ai`), with server-side sessions, single sign-out and OIDC Back-Channel Logout
1.0. The account is the only source of people, orgs and roles; this package keeps sign-in sessions
and nothing else. It runs on Cloudflare Workers (Web Crypto, no Node APIs). Its only runtime
dependency is `jose`.

## Install

By git tag, as the suite takes cli-kit; `dist/` is checked in, so installing runs no build:

```
"@forspring/suite-signin": "github:forspringai/suite-signin#v0.1.0"
```

## Configure

Everything product-specific is config: nothing about a product's paths or client is hard-coded.

```ts
import { suiteSignIn, d1SignInStore, redirect } from "@forspring/suite-signin";

const signin = suiteSignIn({
  product: "sitespring",                                   // logs; default login cookie base __Host-sitespring_login
  account: {
    issuer: "https://account.forspring.ai/api/auth",       // endpoints derived from it, no discovery fetch
    clientId: "sitespring",
    clientSecret: env.FORSPRING_CLIENT_SECRET,
  },
  redirectUri: "https://app.sitespring.app/api/auth/callback/forspring",
  postLogoutRedirectUri: "https://app.sitespring.app/",
  scopes: ["openid", "email"],                             // required: openid and email; never offline_access
  cookie: { name: "__Host-sitespring_session" },           // must start with __Host-
  store: d1SignInStore(env.CONTROL_DB, { prefix: "signin_" }),
  // optional:
  algorithms: ["EdDSA"],                                   // default; asymmetric algorithms only
  lifetimes: { idleS: 7 * 86400, renewS: 86400, absoluteS: 30 * 86400, loginS: 600 }, // defaults
  rateLimit: { limit: 10, windowS: 60 },                   // default; or (key) => Promise<boolean>, or false
  ipHeader: "cf-connecting-ip",                            // default; x-forwarded-for is refused
  onSignIn: async (person, req) => undefined,              // or { refuse: "product_off" }: no session is made
  fetch: undefined,                                        // transport for /oauth2/token and /jwks
  userAgent: "SiteSpring/1 (+https://sitespring.app)",
});
```

`redirectUri` and `postLogoutRedirectUri` are normalised with `URL.toString()` (so
`https://App.Example/` and `https://app.example:443/` both become `https://app.example/`, and a
bare origin gains a trailing `/`). They are sent to the account in that form, and the account
compares them exactly: register each one at the account exactly as `new URL(uri).toString()`
prints it.

The account's endpoints, from the issuer: `{issuer}/oauth2/authorize`, `{issuer}/oauth2/token`
(`client_secret_basic`), `{issuer}/jwks` and `{issuer}/oauth2/end-session`.

## Per request

The package returns data and `Set-Cookie` lines; the product builds its own responses and pages.
`redirect(location, setCookie)` is a small helper for the common 302.

| Call | Returns |
|---|---|
| `start(req, { returnTo? })` | `{ ok: true, location, setCookie }` or `{ ok: false, refused: "rate_limited" }` |
| `callback(req)` | `{ ok: true, person, returnTo, setCookie }` or `{ ok: false, refused, detail?, setCookie }` |
| `session(req)` | `SignedIn \| null` (reads the store every call; renews idle at most once per `renewS`) |
| `signOut(req)` | POST only. `{ ok: true, location, setCookie, ended }` (end-session URL) or `{ ok: false, refused }` |
| `backchannelLogout(req)` | `{ ok, ended \| refused, response }`: `response` is the 200 / 400 to answer the account with |
| `endFor({ sub })` | how many session rows were deleted |
| `prune(now?)` | counts removed per table; call it from the product's cron |

```ts
// GET /sign-in?return=<path>
const s = await signin.start(req, { returnTo: url.searchParams.get("return") });
return s.ok ? redirect(s.location, s.setCookie) : tooMany();

// GET <redirectUri path>
const c = await signin.callback(req);
return c.ok
  ? redirect(c.returnTo, c.setCookie)
  : redirect(`/sign-in-failed?error=${c.refused}`, c.setCookie);

// POST /sign-out
const o = await signin.signOut(req);
return o.ok ? redirect(o.location, o.setCookie, 303) : new Response(null, { status: 405 });

// POST <back-channel logout URI>
return (await signin.backchannelLogout(req)).response;
```

Callback refusals: `rate_limited`, `account_error` (an `error=` from authorize), `bad_request`,
`no_login` (unknown or already used), `expired`, `binding_mismatch` (another browser),
`iss_mismatch` (RFC 9207: `iss` missing or not the issuer, checked before `error=`), `token_exchange_failed`, `invalid_id_token`,
`email_not_verified`, `auth_too_old`, `product_refused` (with `detail`).

`returnTo` is a same-origin path with its query string, against the `redirectUri`'s origin.
Anything else (`//host`, `/\host`, an absolute URL, control characters, a backslash) becomes `/`.
`safeReturnTo(raw, origin)` is exported for a product's own links.

## What it guarantees

- **state, nonce, PKCE verifier and the browser binding** are each 32 bytes from
  `crypto.getRandomValues`, base64url. PKCE is S256. The login row is stored with the state, nonce and
  binding as SHA-256 only (the verifier must be sent, so it is kept as it is); it is single use
  (delete-returning), lives 10 minutes, and is bound to the browser by its own cookie,
  `__Host-<product>_login_<first 8 characters of the state's SHA-256>`, which expires with it. The
  callback finds its cookie from the returned state, so sign-ins in parallel tabs do not clash.
- **The callback requires `iss`** (RFC 9207) on every redirect back, success or `error=`, and
  refuses before reading `error=` when it is missing or wrong. It also deletes the store row of any
  session cookie the browser already presents before creating the new session.
- **The id_token** is verified with the account's JWKS: signature, `iss`, `aud` = clientId (and
  `azp` when there are several audiences), `exp`, `iat` (not in the future, at most 10 minutes old),
  `nonce` (against the stored hash), `sub`, the `algorithms` allow-list, and `email_verified === true`
  as a boolean.
- **Sessions**: the id is 32 random bytes; the cookie holds it and the store holds only its
  SHA-256. Cookies are `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`; a
  name not starting with `__Host-` is refused when configuring. Idle 7 days, renewed at most daily;
  absolute 30 days from `auth_time` (else from sign-in; a future `auth_time` counts as now).
- **Sign-out** is POST only and refuses a cross-origin `Origin`. It works with no session
  (`client_id` instead of `id_token_hint`) and always clears the cookie.
- **Back-channel logout** refuses a body over 16 KB (by `Content-Length`, and by reading at most
  16 KB), then checks `iss`, `aud`, `typ: logout+jwt`, `iat` (at most 5 minutes old),
  the `http://schemas.openid.net/event/backchannel-logout` event, `sid` or `sub`, no `nonce`, and
  `jti` replay through the store. It ends sessions by `sid` (and `sub` when given), else by `sub`.
- **`endFor`** deletes rows (they hold email, name and id_token), never marks them.
- **The rate limit** counts `start:<addr>` and `callback:<addr>` from `ipHeader` only, where
  `<addr>` is an IPv4 address, or an IPv6 address by its /64 (an IPv4-mapped address counts as its
  IPv4). By default 10 per key per 60 seconds, set with `rateLimit: { limit, windowS }`.
  **A request whose `ipHeader` is missing or holds no address is not limited** (by the default
  limiter or a function), rather than putting every such request into one shared bucket. On
  Cloudflare `cf-connecting-ip` is always set; behind anything else, make sure the header is.
- **Nothing secret is logged or put in an error**: logs carry event names and reason codes only.

## Store

`SignInStore` is a small interface (see `src/types.ts`); `d1SignInStore(db, { prefix })` is the D1
one. Copy `migrations/0001_suite_signin.sql` into the product's migrations: it creates
`signin_logins`, `signin_sessions`, `signin_jtis` and `signin_hits`. For another prefix
(`[a-z_]{1,20}`, since it goes into SQL), `migrationSql(prefix)` from `@forspring/suite-signin/d1`
gives the same text.

## Directory (optional)

```ts
import { accountDirectory } from "@forspring/suite-signin/directory";
const dir = accountDirectory({ issuer, clientId, clientSecret, fetch: env.ACCOUNT?.fetch.bind(env.ACCOUNT) });
await dir.orgsOf(sub);       // [{ id, name, role, productOn, orgSuspended }]
await dir.roleIn(sub, org);  // role, or null unless the product is on and the org not suspended
```

It asks the account's `GET /api/products/access` with the client as Basic auth, over a fetch-like
transport (a service binding's `fetch`) or HTTPS. `cacheS` defaults to 0: no call inherits an
earlier call's answer. When the account cannot answer it throws `AccountUnavailableError`.

## Tests in a product

```ts
// A separate entry, kept out of the main one so a Worker cannot import it by accident.
import { issueSessionForTests } from "@forspring/suite-signin/testing";
const { raw } = await issueSessionForTests(store, { sub: "acct_1", email: "a@example.test" });
const req = new Request(url, { headers: { cookie: `__Host-sitespring_session=${raw}` } });
```

`sessionIdHash(raw)` (the SHA-256 the store keys a session by) stays in the main entry.
