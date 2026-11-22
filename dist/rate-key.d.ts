/**
 * The address a rate-limit key is made of: an IPv4 address as it is, an IPv6 address by its /64
 * (one subscriber usually holds a whole /64, so keying the full address would give them 2^64
 * buckets). An IPv4-mapped IPv6 address counts as its IPv4. Anything that is not an address
 * answers null.
 */
export declare function rateLimitAddress(raw: string | null | undefined): string | null;
