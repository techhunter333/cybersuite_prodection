DROP TABLE IF EXISTS pastes;

CREATE TABLE pastes (
  id TEXT PRIMARY KEY,
  encrypted_content TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_expires_at ON pastes (expires_at);