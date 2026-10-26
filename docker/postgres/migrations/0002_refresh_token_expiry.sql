-- Expired refresh tokens are purged in batches (src/app/maintenance.inc).
CREATE INDEX refresh_tokens_expires_at ON refresh_tokens (expires_at);
