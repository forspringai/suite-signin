import { sessionIdHash } from "./session.js";
import type { Lifetimes, SessionRow, SignInStore } from "./types.js";
export { sessionIdHash };
/**
 * Seeds a signed-in browser without an account round trip. Writes a session row the way a real
 * sign-in does and answers the raw cookie value (send it as `<cookie name>=<raw>`) and the hash the
 * store keys it by.
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
