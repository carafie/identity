CREATE TABLE IF NOT EXISTS refresh_tokens(
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (octet_length(email) >= 3 AND octet_length(email) <= 254),
    created_at TIMESTAMPTZ(0) NOT NULL,
    expires_at TIMESTAMPTZ(0) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
