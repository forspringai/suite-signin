# @forspring/suite-signin

The Forspring suite's shared console sign-in: an OIDC client of the Forspring account, with
sessions, single sign-out and OIDC Back-Channel Logout 1.0, for Cloudflare Workers. The contract is
README.md. The design came from lead-forspring's draft and lead-sitespring's review (coordinator
`areas/forspring/suite-signin-draft.md`).

```
pnpm install
pnpm check        # typecheck, tests, build, dist/ in step with src/
```

- Workers runtime: Web Crypto and fetch only, no Node APIs in `src/`. `tsconfig.build.json` builds
  with no Node types, so a Node global in `src/` fails the build. Tests may use Node (node:sqlite).
- The only runtime dependency is `jose`. Keep it that way.
- Nothing product-specific in `src/`: client ids, paths, scopes, cookie names are config.
- `dist/` is checked in: run `pnpm build` and commit it with every source change.
- `migrations/0001_suite_signin.sql` must equal `migrationSql("signin_")` (a test checks it). After
  changing the SQL, regenerate it from the build.
- Never log or put in an error a token, secret, code, state, nonce, verifier or raw session id. Logs
  are event names and reason codes. A test sweeps every path for this.
- Tests use the fake account in test/fake-account.ts (jose EdDSA key, injectable fetch) and the
  in-memory store in test/memory-store.ts; the D1 SQL runs on node:sqlite (test/sqlite-d1.ts).
- Release (after a security review): bump `package.json`, `pnpm check`, commit, tag `vX.Y.Z`, push
  the tag. Products pin the tag.
