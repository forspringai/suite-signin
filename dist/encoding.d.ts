export declare function base64Url(bytes: Uint8Array): string;
/** `byteLength` bytes from the platform CSPRNG, base64url without padding. Never fewer than 32. */
export declare function randomToken(byteLength?: number): string;
/** SHA-256 of the UTF-8 text, base64url without padding (43 characters). */
export declare function sha256(text: string): Promise<string>;
/** The PKCE S256 challenge for a verifier (RFC 7636 §4.2). */
export declare function codeChallengeS256(verifier: string): Promise<string>;
/**
 * Equality whose time does not depend on where the strings first differ. Both sides are short
 * hashes here, so their lengths are public; a length mismatch answers false at once.
 */
export declare function constantTimeEqual(a: string, b: string): boolean;
/** A 32-byte random value in base64url: 43 characters of [A-Za-z0-9_-]. */
export declare const RAW_TOKEN: RegExp;
/** HTTP Basic credentials as RFC 6749 §2.3.1 asks: each half form-url-encoded, then base64. */
export declare function basicAuth(clientId: string, clientSecret: string): string;
