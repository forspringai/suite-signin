/**
 * A same-origin path with its query string, for the redirect after sign-in, or null when the
 * candidate would leave the origin.
 *
 * Decided by resolving the candidate as a browser will, not by listing bytes alone: the URL parser
 * strips TAB, CR and LF and reads "\" as "/", so "//x", "/\x" and "/<TAB>/x" all leave the origin.
 * Control bytes and backslashes are refused outright, as is anything not starting with exactly one
 * "/" (an absolute URL, a scheme-relative "//host", a bare "host"). The answer is the resolved,
 * percent-encoded path and query, so whatever reaches a Location header is ASCII.
 */
export declare function safeReturnTo(raw: string | null | undefined, origin: string): string | null;
