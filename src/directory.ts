import { basicAuth } from "./encoding.js";
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
export class AccountUnavailableError extends Error {
  constructor(note: string) {
    super(`The Forspring account directory could not be reached: ${note}`);
    this.name = "AccountUnavailableError";
  }
}

const ROLES: readonly OrgRole[] = ["viewer", "member", "admin", "owner"];
const role = (value: unknown): OrgRole | null => (typeof value === "string" && (ROLES as readonly string[]).includes(value) ? (value as OrgRole) : null);

interface AccessBody {
  ok?: boolean;
  role?: unknown;
  product_on?: unknown;
  org_suspended?: unknown;
  orgs?: { org?: unknown; name?: unknown; role?: unknown; product_on?: unknown; org_suspended?: unknown }[];
}

export function accountDirectory(options: AccountDirectoryOptions): AccountDirectory {
  const issuer = new URL(options.issuer);
  const base = new URL(options.baseUrl ?? issuer.origin);
  if (base.protocol !== "https:") throw new TypeError("suite-signin: directory baseUrl must be https");
  if (!options.clientId || !options.clientSecret) throw new TypeError("suite-signin: directory needs clientId and clientSecret");
  const cacheS = options.cacheS ?? 0;
  if (!Number.isFinite(cacheS) || cacheS < 0) throw new TypeError("suite-signin: directory cacheS must be 0 or more");
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const authorization = basicAuth(options.clientId, options.clientSecret);
  const userAgent = options.userAgent ?? "Forspring suite-signin/0.1";
  const now = options.now ?? (() => Date.now());
  const cache = new Map<string, { at: number; body: AccessBody }>();

  async function ask(query: Record<string, string>): Promise<AccessBody> {
    const url = new URL("/api/products/access", base);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    const key = url.search;
    if (cacheS > 0) {
      const hit = cache.get(key);
      if (hit && now() - hit.at < cacheS * 1000) return hit.body;
    }
    let response: Response;
    try {
      response = await fetchImpl(url.toString(), {
        headers: { authorization, accept: "application/json", "user-agent": userAgent },
        redirect: "manual",
      });
    } catch {
      throw new AccountUnavailableError("no answer");
    }
    // A 404 is an answer (the person or org is not known: `ok: false`); any other non-2xx is not.
    if (!response.ok && response.status !== 404) {
      throw new AccountUnavailableError(`status ${response.status}`);
    }
    const body = (await response.json().catch(() => null)) as AccessBody | null;
    if (!body || typeof body !== "object") throw new AccountUnavailableError("unreadable answer");
    if (cacheS > 0) cache.set(key, { at: now(), body });
    return body;
  }

  const access = async (sub: string, org: string): Promise<OrgAccess | null> => {
    const body = await ask({ org, sub });
    const r = body.ok === true ? role(body.role) : null;
    if (r === null) return null;
    return { org, role: r, productOn: body.product_on === true, orgSuspended: body.org_suspended === true };
  };

  return {
    async orgsOf(sub) {
      const body = await ask({ sub });
      if (body.ok !== true || !Array.isArray(body.orgs)) return [];
      return body.orgs.flatMap((o) => {
        const r = role(o?.role);
        return r !== null && typeof o.org === "string" && typeof o.name === "string"
          ? [{ id: o.org, name: o.name, role: r, productOn: o.product_on === true, orgSuspended: o.org_suspended === true }]
          : [];
      });
    },
    access,
    async roleIn(sub, org) {
      const a = await access(sub, org);
      return a !== null && a.productOn && !a.orgSuspended ? a.role : null;
    },
  };
}
