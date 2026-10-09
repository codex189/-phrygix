CREATE TABLE IF NOT EXISTS secrets (
 id TEXT PRIMARY KEY,
 ciphertext TEXT NOT NULL,
 iv TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);
-- Run periodically (e.g. a scheduled Worker): DELETE FROM secrets WHERE expires_at <= unixepoch();
