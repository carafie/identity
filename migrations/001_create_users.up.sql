CREATE TABLE IF NOT EXISTS users(
    id UUID PRIMARY KEY,
    email TEXT NOT NULL CHECK (octet_length(email) >= 3 AND octet_length(email) <= 254),
    email_normalized TEXT NOT NULL CHECK (octet_length(email_normalized) >= 3 AND octet_length(email_normalized) <= 254)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_normalized ON users(email_normalized);
