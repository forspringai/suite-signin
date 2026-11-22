// A small D1 stand-in over Node's built-in SQLite (node:sqlite), in memory: enough of D1's
// prepare/bind/first/all/run to run the D1 store's real SQL against a real SQLite engine.
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

import type { D1Like, D1StatementLike } from "../src/d1.js";

export interface SqliteD1 extends D1Like {
  exec(sql: string): void;
  raw: DatabaseSync;
}

export function sqliteD1(): SqliteD1 {
  const raw = new DatabaseSync(":memory:");
  const statement = (sql: string, values: unknown[]): D1StatementLike => ({
    bind: (...next) => statement(sql, next),
    async first<T>() {
      const row = raw.prepare(sql).get(...(values as SQLInputValue[]));
      return (row ?? null) as T | null;
    },
    async all<T>() {
      return { results: raw.prepare(sql).all(...(values as SQLInputValue[])) as T[] };
    },
    async run() {
      const r = raw.prepare(sql).run(...(values as SQLInputValue[]));
      return { meta: { changes: Number(r.changes) } };
    },
  });
  return {
    raw,
    exec: (sql) => raw.exec(sql),
    prepare: (sql) => statement(sql, []),
  };
}
