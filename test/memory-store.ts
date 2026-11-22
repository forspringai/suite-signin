import type { LoginRow, SessionQuery, SessionRow, SignInStore } from "../src/types.js";

/** An in-memory SignInStore, with its maps open for the tests to look into. */
export interface MemoryStore extends SignInStore {
  logins: Map<string, LoginRow>;
  sessions: Map<string, SessionRow>;
  jtis: Map<string, number>;
  hits: Map<string, { count: number; expiresAt: number }>;
  renewals: number;
}

export function memoryStore(): MemoryStore {
  const store: MemoryStore = {
    logins: new Map(),
    sessions: new Map(),
    jtis: new Map(),
    hits: new Map(),
    renewals: 0,
    async putLogin(l) {
      store.logins.set(l.stateHash, { ...l });
    },
    async takeLogin(stateHash) {
      const row = store.logins.get(stateHash) ?? null;
      store.logins.delete(stateHash);
      return row;
    },
    async createSession(s) {
      store.sessions.set(s.idHash, { ...s });
    },
    async getSession(idHash) {
      const row = store.sessions.get(idHash);
      return row ? { ...row } : null;
    },
    async renewSession(idHash, renewedAt, idleExpiresAt) {
      const row = store.sessions.get(idHash);
      if (!row) return;
      store.renewals += 1;
      row.renewedAt = renewedAt;
      row.idleExpiresAt = Math.min(idleExpiresAt, row.absoluteExpiresAt);
    },
    async deleteSession(idHash) {
      const row = store.sessions.get(idHash) ?? null;
      store.sessions.delete(idHash);
      return row;
    },
    async deleteBy(q: SessionQuery) {
      let n = 0;
      for (const [k, row] of store.sessions) {
        const match = "sid" in q ? row.sid === q.sid && (q.sub === undefined || row.sub === q.sub) : row.sub === q.sub;
        if (match) {
          store.sessions.delete(k);
          n += 1;
        }
      }
      return n;
    },
    async seenJti(jti, expiresAt) {
      if (store.jtis.has(jti)) return true;
      store.jtis.set(jti, expiresAt);
      return false;
    },
    async hit(key, windowS, limit, now) {
      const start = now - (now % windowS);
      const k = `${key}@${start}`;
      const entry = store.hits.get(k) ?? { count: 0, expiresAt: start + windowS };
      entry.count += 1;
      store.hits.set(k, entry);
      return entry.count <= limit;
    },
    async prune(now) {
      const out = { logins: 0, sessions: 0, jtis: 0, hits: 0 };
      for (const [k, v] of store.logins) if (v.expiresAt <= now) (store.logins.delete(k), (out.logins += 1));
      for (const [k, v] of store.sessions) if (v.idleExpiresAt <= now || v.absoluteExpiresAt <= now) (store.sessions.delete(k), (out.sessions += 1));
      for (const [k, v] of store.jtis) if (v <= now) (store.jtis.delete(k), (out.jtis += 1));
      for (const [k, v] of store.hits) if (v.expiresAt <= now) (store.hits.delete(k), (out.hits += 1));
      return out;
    },
  };
  return store;
}
