import type { Lifetimes, Person, SessionRow, SignInStore, UnixSeconds } from "./types.js";
/** The suite's lifetimes (hub D-96, account D-35). */
export declare const DEFAULT_LIFETIMES: Readonly<Lifetimes>;
export declare function resolveLifetimes(given: Partial<Lifetimes> | undefined): Lifetimes;
export declare const toSeconds: (date: Date) => UnixSeconds;
export declare const fromSeconds: (s: UnixSeconds) => Date;
/**
 * The absolute limit counts from auth_time (when the person last authenticated at the account),
 * else from this sign-in. An auth_time in the future is read as now, so it can never stretch it.
 */
export declare function absoluteExpiry(authTime: UnixSeconds | null, createdAt: UnixSeconds, absoluteS: number): UnixSeconds;
/** The SHA-256 of a raw session id: what the store keys a session by. */
export declare function sessionIdHash(raw: string): Promise<string>;
/** A fresh session: 32 random bytes for the cookie, and the row that stores only their hash. */
export declare function newSession(person: Person, idToken: string | null, nowS: UnixSeconds, lifetimes: Lifetimes): Promise<{
    raw: string;
    row: SessionRow;
}>;
/**
 * Tests only: seeds a signed-in browser without an account round trip. Writes a session row the
 * way a real sign-in does and answers the raw cookie value (send it as `<cookie name>=<raw>`) and
 * the hash the store keys it by.
 */
export declare function issueSessionForTests(store: SignInStore, person: {
    sub: string;
    email: string;
    name?: string | null;
    sid?: string | null;
    authTime?: Date | null;
}, options?: {
    now?: Date;
    lifetimes?: Partial<Lifetimes>;
    idToken?: string | null;
}): Promise<{
    raw: string;
    idHash: string;
    row: SessionRow;
}>;
