/**
 * The address a rate-limit key is made of: an IPv4 address as it is, an IPv6 address by its /64
 * (one subscriber usually holds a whole /64, so keying the full address would give them 2^64
 * buckets). An IPv4-mapped IPv6 address counts as its IPv4. Anything that is not an address
 * answers null.
 */
export function rateLimitAddress(raw) {
    const value = (raw ?? "").trim().toLowerCase();
    if (value === "" || value.length > 45)
        return null;
    if (!value.includes(":"))
        return ipv4(value) === null ? null : value;
    if (!/^[0-9a-f:.]+$/.test(value))
        return null;
    let text = value;
    const tail = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
    if (tail) {
        const octets = ipv4(tail[2] ?? "");
        if (octets === null)
            return null;
        if (tail[1] === "::ffff:")
            return octets.join(".");
        const hi = ((octets[0] ?? 0) << 8) | (octets[1] ?? 0);
        const lo = ((octets[2] ?? 0) << 8) | (octets[3] ?? 0);
        text = `${tail[1]}${hi.toString(16)}:${lo.toString(16)}`;
    }
    const halves = text.split("::");
    if (halves.length > 2)
        return null;
    const head = halves[0] ? halves[0].split(":") : [];
    const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    let groups;
    if (halves.length === 1) {
        groups = head;
    }
    else {
        const missing = 8 - head.length - rest.length;
        if (missing < 1)
            return null;
        groups = [...head, ...Array(missing).fill("0"), ...rest];
    }
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g)))
        return null;
    return `${groups
        .slice(0, 4)
        .map((g) => Number.parseInt(g, 16).toString(16))
        .join(":")}::/64`;
}
function ipv4(value) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value))
        return null;
    const octets = value.split(".").map(Number);
    return octets.every((o) => o <= 255) ? octets : null;
}
