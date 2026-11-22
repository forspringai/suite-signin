import type { FetchLike } from "./types.js";
/**
 * Optional: who is in which org, with what role, asked of the account's product directory
 * (GET /api/products/access, account D-33) with the product's OIDC client as Basic auth. A
 * product with its own directory (an RPC service binding, say) need not use this.
 *
 * No cache by default (`cacheS: 0`): no call inherits an earlier call's answer, so a person
 * removed at the account is refused on their next request. A product may opt into a short
 * in-memory cache; nothing is ever stored.
 */
export type OrgRole = "owner" | "admin" | "member" | "viewer";
export interface DirectoryOrg {
    /** The account's customer id for the org. */
    id: string;
    name: string;
    role: OrgRole;
    /** This product switched on for the person in this org. */
    productOn: boolean;
    /** Billing has stopped the org (suspended or cancelled at the account). */
    orgSuspended: boolean;
}
export interface OrgAccess {
    org: string;
    role: OrgRole;
    productOn: boolean;
    orgSuspended: boolean;
}
export interface AccountDirectory {
    /** Every org the person is in that has this product, switched on or not. */
    orgsOf(sub: string): Promise<DirectoryOrg[]>;
    /** The person's place in one org, or null when they are not in it. */
    access(sub: string, org: string): Promise<OrgAccess | null>;
    /** The person's role in the org when they may act there (product on, org not suspended), else null. */
    roleIn(sub: string, org: string): Promise<OrgRole | null>;
}
export interface AccountDirectoryOptions {
    /** The account's issuer; the directory is at its origin unless `baseUrl` says otherwise. */
    issuer: string;
    clientId: string;
    clientSecret: string;
    /** The account's origin for /api/products/*. Default the issuer's origin. */
    baseUrl?: string;
    /** Transport: a service binding's fetch, or the global fetch over HTTPS (the default). */
    fetch?: FetchLike;
    /** Seconds to keep an answer in this isolate's memory. Default 0: ask every time. */
    cacheS?: number;
    userAgent?: string;
    now?: () => number;
}
/** The account could not answer: a request that depends on a role must be refused, never guessed. */
export declare class AccountUnavailableError extends Error {
    constructor(note: string);
}
export declare function accountDirectory(options: AccountDirectoryOptions): AccountDirectory;
