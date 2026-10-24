-- Schema for the example CRUD. Runs once, when the data volume is created.
-- Keys are UUIDv7 (PostgreSQL 18): time ordered, so inserts append to the
-- right edge of the B-tree instead of splitting random pages.

CREATE TABLE users (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    email          text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    password_hash  text        NOT NULL,            -- Argon2id, PHC string format
    session_epoch  integer     NOT NULL DEFAULT 0,  -- bumped to revoke every token
    created_at     timestamptz NOT NULL DEFAULT now()
);
-- The API lowercases emails before they reach the database.
CREATE UNIQUE INDEX users_email_key ON users (email);

CREATE TABLE refresh_tokens (
    token_hash   bytea       PRIMARY KEY CHECK (length(token_hash) = 32),  -- SHA-256 of the token
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id    uuid        NOT NULL,      -- one login; reuse of a rotated token revokes the family
    expires_at   timestamptz NOT NULL,
    rotated_at   timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_family_id ON refresh_tokens (family_id);

CREATE TABLE notes (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title       text        NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    body        text        NOT NULL DEFAULT '' CHECK (length(body) <= 4000),
    version     integer     NOT NULL DEFAULT 1,     -- optimistic concurrency (If-Match)
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
) WITH (fillfactor = 90);                           -- room for HOT updates
-- Keyset pagination: WHERE user_id = $1 AND id < $2 ORDER BY id DESC LIMIT n
CREATE INDEX notes_user_id_id ON notes (user_id, id DESC);
