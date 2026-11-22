import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { d1SignInStore, migrationSql } from "../src/d1.js";
import type { SessionRow, SignInStore } from "../src/types.js";
import { cookiePair } from "./fake-account.js";
import { harness } from "./harness.js";
import { memoryStore } from "./memory-store.js";
import { sqliteD1 } from "./sqlite-d1.js";

const T = 1_795_000_000;

function d1Store(prefix = "signin_"): { store: SignInStore; db: ReturnType<typeof sqliteD1> } {
  const db = sqliteD1();
  db.exec(migrationSql(prefix));
  return { store: d1SignInStore(db, { prefix }), db };
}

const session = (over: Partial<SessionRow> = {}): SessionRow => ({
  idHash: "h1",
  sub: "s1",
  email: "a@example.test",
  name: "A",
  sid: "sid1",
  idToken: "header.payload.sig",
  authTime: T - 60,
  createdAt: T,
  renewedAt: T,
  idleExpiresAt: T + 100,
  absoluteExpiresAt: T + 1000,
  ...over,
});

describe("the migration file", () => {
  it("is migrationSql for the default prefix signin_", () => {
    const file = readFileSync(new URL("../migrations/0001_suite_signin.sql", import.meta.url), "utf8");
    expect(file).toBe(migrationSql("signin_"));
    for (const table of ["signin_logins", "signin_sessions", "signin_jtis", "signin_hits"]) expect(file).toContain(`CREATE TABLE IF NOT EXISTS ${table} (`);
  });

  it("applies twice without error (IF NOT EXISTS)", () => {
    const db = sqliteD1();
    db.exec(migrationSql());
    db.exec(migrationSql());
    const tables = db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[];
    expect(tables.map((t) => t.name)).toEqual(["signin_hits", "signin_jtis", "signin_logins", "signin_sessions"]);
  });
});

describe("the prefix", () => {
  it.each(["", "Signin_", "signin-", "a;b", "s1_", "x".repeat(21), "signin_ --"])("refuses %j", (prefix) => {
    expect(() => migrationSql(prefix)).toThrow(/prefix/);
    expect(() => d1SignInStore(sqliteD1(), { prefix })).toThrow(/prefix/);
  });

  it("puts every table under a custom prefix", async () => {
    const { store, db } = d1Store("ss_auth_");
    await store.createSession(session());
    const tables = db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[];
    expect(tables.map((t) => t.name)).toEqual(["ss_auth_hits", "ss_auth_jtis", "ss_auth_logins", "ss_auth_sessions"]);
    expect(await store.getSession("h1")).toEqual(session());
  });
});

// The same contract, against the D1 store's SQL on SQLite and against the in-memory store the
// other tests use, so the two cannot drift apart.
describe.each([
  ["d1 (SQLite)", () => d1Store().store],
  ["memory", () => memoryStore() as SignInStore],
])("SignInStore contract: %s", (_name, make) => {
  it("takeLogin is delete-returning: single use", async () => {
    const store = make();
    const login = { stateHash: "st", nonceHash: "nh", verifier: "v", returnTo: "/x?y=1", bindingHash: "bh", expiresAt: T + 600 };
    await store.putLogin(login);
    expect(await store.takeLogin("st")).toEqual(login);
    expect(await store.takeLogin("st")).toBeNull();
    expect(await store.takeLogin("other")).toBeNull();
  });

  it("creates, reads, renews (capped at the absolute limit) and deletes a session", async () => {
    const store = make();
    await store.createSession(session());
    expect(await store.getSession("h1")).toEqual(session());
    await store.renewSession("h1", T + 50, T + 5000);
    expect(await store.getSession("h1")).toMatchObject({ renewedAt: T + 50, idleExpiresAt: T + 1000 });
    expect(await store.deleteSession("h1")).toMatchObject({ idHash: "h1", idToken: "header.payload.sig" });
    expect(await store.getSession("h1")).toBeNull();
    expect(await store.deleteSession("h1")).toBeNull();
  });

  it("keeps null fields null", async () => {
    const store = make();
    await store.createSession(session({ name: null, sid: null, idToken: null, authTime: null }));
    expect(await store.getSession("h1")).toEqual(session({ name: null, sid: null, idToken: null, authTime: null }));
  });

  it("deleteBy deletes rows by sid (and sub), or by sub, and counts them", async () => {
    const store = make();
    await store.createSession(session({ idHash: "a", sub: "s1", sid: "x" }));
    await store.createSession(session({ idHash: "b", sub: "s1", sid: "y" }));
    await store.createSession(session({ idHash: "c", sub: "s2", sid: "x" }));
    await store.createSession(session({ idHash: "d", sub: "s2", sid: "z" }));
    expect(await store.deleteBy({ sid: "x", sub: "s1" })).toBe(1);
    expect(await store.getSession("c")).not.toBeNull();
    expect(await store.deleteBy({ sid: "x" })).toBe(1);
    expect(await store.deleteBy({ sub: "s2" })).toBe(1);
    expect(await store.deleteBy({ sub: "s1" })).toBe(1);
    expect(await store.deleteBy({ sub: "s1" })).toBe(0);
    for (const id of ["a", "b", "c", "d"]) expect(await store.getSession(id)).toBeNull();
  });

  it("seenJti answers false the first time and true after", async () => {
    const store = make();
    expect(await store.seenJti("j1", T + 300)).toBe(false);
    expect(await store.seenJti("j1", T + 300)).toBe(true);
    expect(await store.seenJti("j2", T + 300)).toBe(false);
  });

  it("hit counts a fixed window per key", async () => {
    const store = make();
    const base = T - (T % 60);
    for (let i = 0; i < 3; i += 1) expect(await store.hit("k", 60, 3, base + i)).toBe(true);
    expect(await store.hit("k", 60, 3, base + 59)).toBe(false);
    expect(await store.hit("other", 60, 3, base + 59)).toBe(true);
    expect(await store.hit("k", 60, 3, base + 60)).toBe(true);
  });

  it("prune removes only what has expired", async () => {
    const store = make();
    await store.putLogin({ stateHash: "old", nonceHash: "n", verifier: "v", returnTo: "/", bindingHash: "b", expiresAt: T });
    await store.putLogin({ stateHash: "new", nonceHash: "n", verifier: "v", returnTo: "/", bindingHash: "b", expiresAt: T + 600 });
    await store.createSession(session({ idHash: "idle", idleExpiresAt: T }));
    await store.createSession(session({ idHash: "abs", idleExpiresAt: T + 50, absoluteExpiresAt: T }));
    await store.createSession(session({ idHash: "live" }));
    await store.seenJti("j-old", T);
    await store.seenJti("j-new", T + 300);
    await store.hit("k", 60, 10, T - 120);
    await store.hit("k", 60, 10, T);
    expect(await store.prune(T)).toEqual({ logins: 1, sessions: 2, jtis: 1, hits: 1 });
    expect(await store.takeLogin("new")).not.toBeNull();
    expect(await store.getSession("live")).not.toBeNull();
    expect(await store.seenJti("j-new", T + 300)).toBe(true);
  });
});

describe("the whole flow on the D1 store", () => {
  it("signs in, reads the session, logs out by back-channel and prunes", async () => {
    const { store } = d1Store();
    const h = await harness({}, store);
    const result = await h.signIn({ returnTo: "/device?user_code=WXYZ" });
    if (!result.ok) throw new Error(result.refused);
    expect(result.returnTo).toBe("/device?user_code=WXYZ");
    const cookie = cookiePair(result.setCookie[0]);
    expect(await h.signin.session(h.get("/", cookie))).toMatchObject({ sub: "acct_user_1" });

    const logout = await h.account.signLogoutToken();
    const post = () =>
      new Request("https://app.example.test/forspring/logout", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: logout }).toString(),
      });
    expect(await h.signin.backchannelLogout(post())).toMatchObject({ ok: true, ended: 1 });
    expect(await h.signin.backchannelLogout(post())).toMatchObject({ ok: false, refused: "replayed" });
    expect(await h.signin.session(h.get("/", cookie))).toBeNull();

    h.advance(86_400);
    expect(await h.signin.prune()).toEqual({ logins: 0, sessions: 0, jtis: 1, hits: 2 });
  });
});
