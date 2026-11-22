import { describe, expect, it } from "vitest";

import { rateLimitAddress } from "../src/rate-key.js";

describe("rateLimitAddress", () => {
  it.each([
    ["203.0.113.7", "203.0.113.7"],
    [" 203.0.113.7 ", "203.0.113.7"],
    ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
    ["2001:0DB8:0001:0002:0003:0004:0005:0006", "2001:db8:1:2::/64"],
    ["2001:db8::1", "2001:db8:0:0::/64"],
    ["::1", "0:0:0:0::/64"],
    ["fe80::", "fe80:0:0:0::/64"],
    ["::ffff:198.51.100.4", "198.51.100.4"],
    ["64:ff9b::192.0.2.33", "64:ff9b:0:0::/64"],
  ])("keys %j as %j", (raw, key) => {
    expect(rateLimitAddress(raw)).toBe(key);
  });

  it.each([null, "", "unknown", "256.1.1.1", "1.2.3", "1.2.3.4.5", "2001:db8::1::2", "2001:db8:1:2:3:4:5:6:7", "12345::", "g::1", "1.2.3.4, 5.6.7.8", "::ffff:999.1.1.1"])(
    "refuses %j",
    (raw) => {
      expect(rateLimitAddress(raw)).toBeNull();
    },
  );
});
