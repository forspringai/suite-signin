import { describe, expect, it } from "vitest";

import { safeReturnTo } from "../src/return-to.js";

const ORIGIN = "https://app.example.test";

describe("safeReturnTo", () => {
  it.each([
    ["/", "/"],
    ["/o/acme/", "/o/acme/"],
    ["/device?user_code=ABCD-EFGH", "/device?user_code=ABCD-EFGH"],
    ["/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fx&state=s", "/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fx&state=s"],
    ["/o/acme/approve/site-1/deploy-2", "/o/acme/approve/site-1/deploy-2"],
    ["/a/../b", "/b"],
    ["/café", "/caf%C3%A9"],
    ["/x#frag", "/x"],
  ])("keeps %j as %j", (raw, kept) => {
    expect(safeReturnTo(raw, ORIGIN)).toBe(kept);
  });

  it.each([
    null,
    undefined,
    "",
    "//evil.example",
    "//evil.example/path?q=1",
    "/\\evil.example",
    "/\\/evil.example",
    "\\\\evil.example",
    "https://evil.example/",
    "https://app.example.test/x",
    "javascript:alert(1)",
    "evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "/a\\b",
    "/a\u0000b",
    `/${"a".repeat(2048)}`,
  ])("refuses %j", (raw) => {
    expect(safeReturnTo(raw, ORIGIN)).toBeNull();
  });
});
