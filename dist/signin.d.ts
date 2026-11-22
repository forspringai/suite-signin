import type { AccountEndpoints, SuiteSignIn, SuiteSignInConfig } from "./types.js";
/** The account's fixed endpoints, derived from the issuer with no discovery fetch. */
export declare function accountEndpoints(issuer: string): AccountEndpoints;
/**
 * Sign-in for a suite product's console, as an OIDC client of the Forspring account: authorization
 * code with PKCE S256, the id_token verified against the account's keys, a server-side session in
 * the product's store, single sign-out and OIDC Back-Channel Logout 1.0. Everything is checked
 * here, once, when the product configures it; a mistake throws a TypeError naming the field
 * (never its value).
 */
export declare function suiteSignIn(config: SuiteSignInConfig): SuiteSignIn;
/** A 302 to `location` carrying the Set-Cookie headers: what most products answer with. */
export declare function redirect(location: string, setCookies?: readonly string[], status?: 302 | 303): Response;
