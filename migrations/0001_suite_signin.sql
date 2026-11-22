-- @forspring/suite-signin: sign-in attempts, sessions, back-channel logout jtis and rate-limit
-- windows. Times are Unix seconds. Copy into the product's migrations; additive only.

-- One sign-in attempt, single use, 10 minutes. state and nonce are stored only as SHA-256.
CREATE TABLE IF NOT EXISTS signin_logins (
  state_hash TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL,
  verifier TEXT NOT NULL,
  return_to TEXT NOT NULL,
  binding_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signin_logins_expires_at ON signin_logins (expires_at);

-- One signed-in browser. id_hash is SHA-256 of the cookie; the raw value is never stored.
CREATE TABLE IF NOT EXISTS signin_sessions (
  id_hash TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  sid TEXT,
  id_token TEXT,
  auth_time INTEGER,
  created_at INTEGER NOT NULL,
  renewed_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signin_sessions_sub ON signin_sessions (sub);
CREATE INDEX IF NOT EXISTS signin_sessions_sid ON signin_sessions (sid);
CREATE INDEX IF NOT EXISTS signin_sessions_idle_expires_at ON signin_sessions (idle_expires_at);
CREATE INDEX IF NOT EXISTS signin_sessions_absolute_expires_at ON signin_sessions (absolute_expires_at);

-- Back-channel logout token ids already used, kept until the token could no longer be accepted.
CREATE TABLE IF NOT EXISTS signin_jtis (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signin_jtis_expires_at ON signin_jtis (expires_at);

-- Fixed-window rate-limit counts, per key (start:<ip>, callback:<ip>) and window.
CREATE TABLE IF NOT EXISTS signin_hits (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);
CREATE INDEX IF NOT EXISTS signin_hits_expires_at ON signin_hits (expires_at);
