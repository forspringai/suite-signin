const PREFIX = /^[a-z_]{1,20}$/;
/** The prefix goes into SQL, so it is held to [a-z_]{1,20}. */
export function assertPrefix(prefix) {
    if (typeof prefix !== "string" || !PREFIX.test(prefix))
        throw new TypeError("suite-signin: prefix must be 1 to 20 of [a-z_]");
}
/**
 * The migration for a prefix: what migrations/0001_suite_signin.sql holds for the default
 * `signin_`. A product copies that file into its own migrations (editing the prefix if it uses
 * another); this function is the same text, for tests and for products that generate theirs.
 */
export function migrationSql(prefix = "signin_") {
    assertPrefix(prefix);
    const p = prefix;
    return `-- @forspring/suite-signin: sign-in attempts, sessions, back-channel logout jtis and rate-limit
-- windows. Times are Unix seconds. Copy into the product's migrations; additive only.

-- One sign-in attempt, single use, 10 minutes. state and nonce are stored only as SHA-256.
CREATE TABLE IF NOT EXISTS ${p}logins (
  state_hash TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL,
  verifier TEXT NOT NULL,
  return_to TEXT NOT NULL,
  binding_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ${p}logins_expires_at ON ${p}logins (expires_at);

-- One signed-in browser. id_hash is SHA-256 of the cookie; the raw value is never stored.
CREATE TABLE IF NOT EXISTS ${p}sessions (
  id_hash TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  sid TEXT,
  id_token TEXT,
  auth_time INTEGER,
  created_at INTEGER NOT NULL,
  renewed_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ${p}sessions_sub ON ${p}sessions (sub);
CREATE INDEX IF NOT EXISTS ${p}sessions_sid ON ${p}sessions (sid);
CREATE INDEX IF NOT EXISTS ${p}sessions_idle_expires_at ON ${p}sessions (idle_expires_at);
CREATE INDEX IF NOT EXISTS ${p}sessions_absolute_expires_at ON ${p}sessions (absolute_expires_at);

-- Back-channel logout token ids already used, kept until the token could no longer be accepted.
CREATE TABLE IF NOT EXISTS ${p}jtis (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ${p}jtis_expires_at ON ${p}jtis (expires_at);

-- Fixed-window rate-limit counts, per key (start:<ip>, callback:<ip>) and window.
CREATE TABLE IF NOT EXISTS ${p}hits (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);
CREATE INDEX IF NOT EXISTS ${p}hits_expires_at ON ${p}hits (expires_at);
`;
}
const login = (r) => ({
    stateHash: r.state_hash,
    nonceHash: r.nonce_hash,
    verifier: r.verifier,
    returnTo: r.return_to,
    bindingHash: r.binding_hash,
    expiresAt: Number(r.expires_at),
});
const session = (r) => ({
    idHash: r.id_hash,
    sub: r.sub,
    email: r.email,
    name: r.name,
    sid: r.sid,
    idToken: r.id_token,
    authTime: r.auth_time === null ? null : Number(r.auth_time),
    createdAt: Number(r.created_at),
    renewedAt: Number(r.renewed_at),
    idleExpiresAt: Number(r.idle_expires_at),
    absoluteExpiresAt: Number(r.absolute_expires_at),
});
/**
 * The SignInStore on D1, over the tables of `migrationSql(prefix)`. Every value is bound, never
 * spliced; only the validated prefix is part of the SQL text. Single use and replay checks are one
 * statement each (DELETE ... RETURNING, INSERT ... ON CONFLICT DO NOTHING RETURNING), so two
 * concurrent requests cannot both win.
 */
export function d1SignInStore(db, options = {}) {
    const p = options.prefix ?? "signin_";
    assertPrefix(p);
    if (!db || typeof db.prepare !== "function")
        throw new TypeError("suite-signin: d1SignInStore needs a D1 database");
    return {
        async putLogin(l) {
            await db
                .prepare(`INSERT INTO ${p}logins (state_hash, nonce_hash, verifier, return_to, binding_hash, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`)
                .bind(l.stateHash, l.nonceHash, l.verifier, l.returnTo, l.bindingHash, l.expiresAt)
                .run();
        },
        async takeLogin(stateHash) {
            const row = await db.prepare(`DELETE FROM ${p}logins WHERE state_hash = ?1 RETURNING *`).bind(stateHash).first();
            return row ? login(row) : null;
        },
        async createSession(s) {
            await db
                .prepare(`INSERT INTO ${p}sessions (id_hash, sub, email, name, sid, id_token, auth_time, created_at, renewed_at, idle_expires_at, absolute_expires_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`)
                .bind(s.idHash, s.sub, s.email, s.name, s.sid, s.idToken, s.authTime, s.createdAt, s.renewedAt, s.idleExpiresAt, s.absoluteExpiresAt)
                .run();
        },
        async getSession(idHash) {
            const row = await db.prepare(`SELECT * FROM ${p}sessions WHERE id_hash = ?1`).bind(idHash).first();
            return row ? session(row) : null;
        },
        async renewSession(idHash, renewedAt, idleExpiresAt) {
            await db
                .prepare(`UPDATE ${p}sessions SET renewed_at = ?2, idle_expires_at = MIN(?3, absolute_expires_at) WHERE id_hash = ?1`)
                .bind(idHash, renewedAt, idleExpiresAt)
                .run();
        },
        async deleteSession(idHash) {
            const row = await db.prepare(`DELETE FROM ${p}sessions WHERE id_hash = ?1 RETURNING *`).bind(idHash).first();
            return row ? session(row) : null;
        },
        async deleteBy(q) {
            const statement = "sid" in q
                ? q.sub !== undefined
                    ? db.prepare(`DELETE FROM ${p}sessions WHERE sid = ?1 AND sub = ?2 RETURNING id_hash`).bind(q.sid, q.sub)
                    : db.prepare(`DELETE FROM ${p}sessions WHERE sid = ?1 RETURNING id_hash`).bind(q.sid)
                : db.prepare(`DELETE FROM ${p}sessions WHERE sub = ?1 RETURNING id_hash`).bind(q.sub);
            const { results } = await statement.all();
            return results.length;
        },
        async seenJti(jti, expiresAt) {
            const row = await db
                .prepare(`INSERT INTO ${p}jtis (jti, expires_at) VALUES (?1, ?2) ON CONFLICT (jti) DO NOTHING RETURNING jti`)
                .bind(jti, expiresAt)
                .first();
            return row === null;
        },
        async hit(key, windowS, limit, now) {
            const windowStart = now - (now % windowS);
            const row = await db
                .prepare(`INSERT INTO ${p}hits (key, window_start, count, expires_at) VALUES (?1, ?2, 1, ?3)
           ON CONFLICT (key, window_start) DO UPDATE SET count = count + 1 RETURNING count`)
                .bind(key, windowStart, windowStart + windowS)
                .first();
            return Number(row?.count ?? Number.POSITIVE_INFINITY) <= limit;
        },
        async prune(now) {
            const changes = async (sql) => (await db.prepare(sql).bind(now).run()).meta?.changes ?? 0;
            return {
                logins: await changes(`DELETE FROM ${p}logins WHERE expires_at <= ?1`),
                sessions: await changes(`DELETE FROM ${p}sessions WHERE idle_expires_at <= ?1 OR absolute_expires_at <= ?1`),
                jtis: await changes(`DELETE FROM ${p}jtis WHERE expires_at <= ?1`),
                hits: await changes(`DELETE FROM ${p}hits WHERE expires_at <= ?1`),
            };
        },
    };
}
