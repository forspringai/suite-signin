/**
 * `__Host-` cookies only: Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, so a browser takes
 * them only from this exact host over HTTPS and no sibling host (a customer site under the same
 * parent domain) can plant or read one. The names are checked when the package is configured.
 */
const COOKIE_NAME = /^__Host-[A-Za-z0-9_.-]{1,64}$/;
export function assertHostCookieName(name, field) {
    if (typeof name !== "string" || !name.startsWith("__Host-")) {
        throw new TypeError(`suite-signin: ${field} must start with "__Host-"`);
    }
    if (!COOKIE_NAME.test(name)) {
        throw new TypeError(`suite-signin: ${field} must be "__Host-" then 1 to 64 of [A-Za-z0-9_.-]`);
    }
}
/** The value of the first cookie with this name in the request, or null. */
export function readCookie(request, name) {
    const header = request.headers.get("cookie");
    if (!header)
        return null;
    for (const part of header.split(";")) {
        const eq = part.indexOf("=");
        if (eq === -1)
            continue;
        if (part.slice(0, eq).trim() !== name)
            continue;
        const value = part.slice(eq + 1).trim();
        return value === "" ? null : value;
    }
    return null;
}
export function setCookie(name, value, maxAgeS) {
    const maxAge = Math.max(0, Math.floor(maxAgeS));
    return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}
export function clearCookie(name) {
    return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
