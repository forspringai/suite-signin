import type { SignInStore } from "./types.js";
/**
 * The slice of Cloudflare's D1Database this store uses, declared here so the package needs no
 * Workers types at runtime. A real D1Database satisfies it.
 */
export interface D1Like {
    prepare(sql: string): D1StatementLike;
}
export interface D1StatementLike {
    bind(...values: unknown[]): D1StatementLike;
    first<T = Record<string, unknown>>(): Promise<T | null>;
    all<T = Record<string, unknown>>(): Promise<{
        results: T[];
    }>;
    run(): Promise<{
        meta?: {
            changes?: number;
        };
    }>;
}
/** The prefix goes into SQL, so it is held to [a-z_]{1,20}. */
export declare function assertPrefix(prefix: string): void;
/**
 * The migration for a prefix: what migrations/0001_suite_signin.sql holds for the default
 * `signin_`. A product copies that file into its own migrations (editing the prefix if it uses
 * another); this function is the same text, for tests and for products that generate theirs.
 */
export declare function migrationSql(prefix?: string): string;
/**
 * The SignInStore on D1, over the tables of `migrationSql(prefix)`. Every value is bound, never
 * spliced; only the validated prefix is part of the SQL text. Single use and replay checks are one
 * statement each (DELETE ... RETURNING, INSERT ... ON CONFLICT DO NOTHING RETURNING), so two
 * concurrent requests cannot both win.
 */
export declare function d1SignInStore(db: D1Like, options?: {
    prefix?: string;
}): SignInStore;
