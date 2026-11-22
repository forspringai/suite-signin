import { basicAuth } from "./encoding.js";
/** The account could not answer: a request that depends on a role must be refused, never guessed. */
export class AccountUnavailableError extends Error {
    constructor(note) {
        super(`The Forspring account directory could not be reached: ${note}`);
        this.name = "AccountUnavailableError";
    }
}
const ROLES = ["viewer", "member", "admin", "owner"];
const role = (value) => (typeof value === "string" && ROLES.includes(value) ? value : null);
export function accountDirectory(options) {
    const issuer = new URL(options.issuer);
    const base = new URL(options.baseUrl ?? issuer.origin);
    if (base.protocol !== "https:")
        throw new TypeError("suite-signin: directory baseUrl must be https");
    if (!options.clientId || !options.clientSecret)
        throw new TypeError("suite-signin: directory needs clientId and clientSecret");
    const cacheS = options.cacheS ?? 0;
    if (!Number.isFinite(cacheS) || cacheS < 0)
        throw new TypeError("suite-signin: directory cacheS must be 0 or more");
    const fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    const authorization = basicAuth(options.clientId, options.clientSecret);
    const userAgent = options.userAgent ?? "Forspring suite-signin/0.1";
    const now = options.now ?? (() => Date.now());
    const cache = new Map();
    async function ask(query) {
        const url = new URL("/api/products/access", base);
        for (const [k, v] of Object.entries(query))
            url.searchParams.set(k, v);
        const key = url.search;
        if (cacheS > 0) {
            const hit = cache.get(key);
            if (hit && now() - hit.at < cacheS * 1000)
                return hit.body;
        }
        let response;
        try {
            response = await fetchImpl(url.toString(), {
                headers: { authorization, accept: "application/json", "user-agent": userAgent },
                redirect: "manual",
            });
        }
        catch {
            throw new AccountUnavailableError("no answer");
        }
        // A 404 is an answer (the person or org is not known: `ok: false`); any other non-2xx is not.
        if (!response.ok && response.status !== 404) {
            throw new AccountUnavailableError(`status ${response.status}`);
        }
        const body = (await response.json().catch(() => null));
        if (!body || typeof body !== "object")
            throw new AccountUnavailableError("unreadable answer");
        if (cacheS > 0)
            cache.set(key, { at: now(), body });
        return body;
    }
    const access = async (sub, org) => {
        const body = await ask({ org, sub });
        const r = body.ok === true ? role(body.role) : null;
        if (r === null)
            return null;
        return { org, role: r, productOn: body.product_on === true, orgSuspended: body.org_suspended === true };
    };
    return {
        async orgsOf(sub) {
            const body = await ask({ sub });
            if (body.ok !== true || !Array.isArray(body.orgs))
                return [];
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
