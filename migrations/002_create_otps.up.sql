CREATE TABLE IF NOT EXISTS otps(
    id UUID PRIMARY KEY,
    email TEXT NOT NULL CHECK (octet_length(email) >= 3 AND octet_length(email) <= 254),
    code TEXT NOT NULL CHECK (octet_length(code) = 6),
    attempts INTEGER NOT NULL,
    created_at TIMESTAMPTZ(0) NOT NULL,
    expires_at TIMESTAMPTZ(0) NOT NULL
);
