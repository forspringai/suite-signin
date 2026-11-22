// @forspring/suite-signin/testing: for a product's tests only, never its Worker. Kept out of the
// main entry so production code cannot reach it by accident.
import { newSession, resolveLifetimes, sessionIdHash, toSeconds } from "./session.js";
export { sessionIdHash };
/**
 * Seeds a signed-in browser without an account round trip. Writes a session row the way a real
 * sign-in does and answers the raw cookie value (send it as `<cookie name>=<raw>`) and the hash the
 * store keys it by.
 */
export async function issueSessionForTests(store, person, options = {}) {
    const nowS = toSeconds(options.now ?? new Date());
    const { raw, row } = await newSession({ sub: person.sub, email: person.email, name: person.name ?? null, sid: person.sid ?? null, authTime: person.authTime ?? null }, options.idToken ?? null, nowS, resolveLifetimes(options.lifetimes));
    await store.createSession(row);
    return { raw, idHash: row.idHash, row };
}
