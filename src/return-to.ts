const MAX_RETURN_TO = 2048;

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
export function safeReturnTo(raw: string | null | undefined, origin: string): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_RETURN_TO) return null;
  if (raw[0] !== "/" || raw[1] === "/" || raw[1] === "\\") return null;
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return null;

  let base: URL;
  let resolved: URL;
  try {
    base = new URL(origin);
    resolved = new URL(raw, base);
  } catch {
    return null;
  }
  const path = `${resolved.pathname}${resolved.search}`;
  if (resolved.origin !== base.origin || !path.startsWith("/") || path.startsWith("//")) return null;
  return path;
}
