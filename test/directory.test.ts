import { describe, expect, it } from "vitest";

import { accountDirectory, AccountUnavailableError } from "../src/directory.js";
import { CLIENT_ID, CLIENT_SECRET, ISSUER } from "./fake-account.js";

function fakeDirectory(answer: (url: URL) => Response) {
  const calls: { url: URL; authorization: string | null }[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    calls.push({ url, authorization: new Headers(init?.headers).get("authorization") });
    return answer(url);
  };
  return { fetch, calls };
}

const orgsAnswer = () =>
  Response.json({
    ok: true,
    orgs: [
      { org: "cus_1", name: "Acme", role: "admin", product_on: true, org_suspended: false },
      { org: "cus_2", name: "Beta", role: "member", product_on: false },
      { org: "cus_3", name: "Odd", role: "superuser", product_on: true },
    ],
  });

describe("accountDirectory", () => {
  it("asks /api/products/access at the issuer's origin with the client as Basic auth", async () => {
    const d = fakeDirectory(orgsAnswer);
    const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: d.fetch });
    expect(await dir.orgsOf("acct_user_1")).toEqual([
      { id: "cus_1", name: "Acme", role: "admin", productOn: true, orgSuspended: false },
      { id: "cus_2", name: "Beta", role: "member", productOn: false, orgSuspended: false },
    ]);
    expect(d.calls[0]?.url.toString()).toBe("https://account.forspring.ai/api/products/access?sub=acct_user_1");
    expect(d.calls[0]?.authorization).toBe(`Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`);
  });

  it("does not cache by default: every call asks the account", async () => {
    const d = fakeDirectory(orgsAnswer);
    const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: d.fetch });
    await dir.orgsOf("acct_user_1");
    await dir.orgsOf("acct_user_1");
    expect(d.calls).toHaveLength(2);
  });

  it("caches for cacheS when a product asks for it", async () => {
    const d = fakeDirectory(orgsAnswer);
    let now = 1_000_000;
    const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: d.fetch, cacheS: 30, now: () => now });
    await dir.orgsOf("acct_user_1");
    now += 29_000;
    await dir.orgsOf("acct_user_1");
    expect(d.calls).toHaveLength(1);
    now += 2_000;
    await dir.orgsOf("acct_user_1");
    expect(d.calls).toHaveLength(2);
    expect(() => accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, cacheS: -1 })).toThrow(/cacheS/);
  });

  it("takes a service binding's fetch as transport", async () => {
    const binding = fakeDirectory(() => Response.json({ ok: true, role: "owner", product_on: true, org_suspended: false }));
    const ACCOUNT = { fetch: binding.fetch };
    const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: (i, init) => ACCOUNT.fetch(i, init) });
    expect(await dir.roleIn("acct_user_1", "cus_1")).toBe("owner");
    expect(binding.calls[0]?.url.searchParams.get("org")).toBe("cus_1");
  });

  it("roleIn is null unless the product is on and the org not suspended", async () => {
    const answers = [
      { ok: true, role: "admin", product_on: false },
      { ok: true, role: "admin", product_on: true, org_suspended: true },
      { ok: false, reason: "member_not_found" },
      { ok: true, role: "admin", product_on: true },
    ];
    const d = fakeDirectory(() => Response.json(answers.shift()));
    const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: d.fetch });
    expect(await dir.roleIn("s", "o")).toBeNull();
    expect(await dir.roleIn("s", "o")).toBeNull();
    expect(await dir.roleIn("s", "o")).toBeNull();
    expect(await dir.roleIn("s", "o")).toBe("admin");
  });

  it("throws AccountUnavailableError, never naming the secret, when the account cannot answer", async () => {
    for (const failing of [() => new Response("boom", { status: 503 }), () => new Response("no", { status: 401 }), () => new Response("not json")]) {
      const dir = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: fakeDirectory(failing).fetch });
      const error = await dir.orgsOf("s").catch((e: unknown) => e);
      expect(error).toBeInstanceOf(AccountUnavailableError);
      expect(String(error)).not.toContain(CLIENT_SECRET);
    }
    const down = accountDirectory({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: async () => Promise.reject(new Error(CLIENT_SECRET)) });
    const error = await down.orgsOf("s").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AccountUnavailableError);
    expect(String(error)).not.toContain(CLIENT_SECRET);
  });
});
