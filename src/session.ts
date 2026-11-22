import { randomToken, sha256 } from "./encoding.js";
import type { Lifetimes, Person, SessionRow, UnixSeconds } from "./types.js";

const DAY_S = 86_400;

/** The suite's lifetimes (hub D-96, account D-35). */
export const DEFAULT_LIFETIMES: Readonly<Lifetimes> = Object.freeze({
  idleS: 7 * DAY_S,
  renewS: DAY_S,
  absoluteS: 30 * DAY_S,
  loginS: 600,
});

export function resolveLifetimes(given: Partial<Lifetimes> | undefined): Lifetimes {
  const l: Lifetimes = { ...DEFAULT_LIFETIMES, ...(given ?? {}) };
  for (const key of ["idleS", "renewS", "absoluteS", "loginS"] as const) {
    const value = l[key];
    if (!Number.isInteger(value) || value <= 0) throw new TypeError(`suite-signin: lifetimes.${key} must be a positive integer`);
  }
  if (l.renewS > l.idleS) throw new TypeError("suite-signin: lifetimes.renewS must not exceed lifetimes.idleS");
  if (l.idleS > l.absoluteS) throw new TypeError("suite-signin: lifetimes.idleS must not exceed lifetimes.absoluteS");
  if (l.loginS > 600) throw new TypeError("suite-signin: lifetimes.loginS must be at most 600 (10 minutes)");
  return l;
}

export const toSeconds = (date: Date): UnixSeconds => Math.floor(date.getTime() / 1000);
export const fromSeconds = (s: UnixSeconds): Date => new Date(s * 1000);

/**
 * The absolute limit counts from auth_time (when the person last authenticated at the account),
 * else from this sign-in. An auth_time in the future is read as now, so it can never stretch it.
 */
export function absoluteExpiry(authTime: UnixSeconds | null, createdAt: UnixSeconds, absoluteS: number): UnixSeconds {
  const from = authTime === null ? createdAt : Math.min(authTime, createdAt);
  return from + absoluteS;
}

/** The SHA-256 of a raw session id: what the store keys a session by. */
export function sessionIdHash(raw: string): Promise<string> {
  return sha256(raw);
}

/** A fresh session: 32 random bytes for the cookie, and the row that stores only their hash. */
export async function newSession(
  person: Person,
  idToken: string | null,
  nowS: UnixSeconds,
  lifetimes: Lifetimes,
): Promise<{ raw: string; row: SessionRow }> {
  const raw = randomToken(32);
  const authTime = person.authTime === null ? null : toSeconds(person.authTime);
  const absoluteExpiresAt = absoluteExpiry(authTime, nowS, lifetimes.absoluteS);
  const row: SessionRow = {
    idHash: await sha256(raw),
    sub: person.sub,
    email: person.email,
    name: person.name,
    sid: person.sid,
    idToken,
    authTime: authTime === null ? null : Math.min(authTime, nowS),
    createdAt: nowS,
    renewedAt: nowS,
    idleExpiresAt: Math.min(nowS + lifetimes.idleS, absoluteExpiresAt),
    absoluteExpiresAt,
  };
  return { raw, row };
}
