/**
 * `__Host-` cookies only: Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, so a browser takes
 * them only from this exact host over HTTPS and no sibling host (a customer site under the same
 * parent domain) can plant or read one. The names are checked when the package is configured.
 */
export declare function assertHostCookieName(name: string, field: string): void;
/** The value of the first cookie with this name in the request, or null. */
export declare function readCookie(request: Request, name: string): string | null;
export declare function setCookie(name: string, value: string, maxAgeS: number): string;
export declare function clearCookie(name: string): string;
