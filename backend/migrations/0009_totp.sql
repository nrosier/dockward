-- Optional TOTP (RFC 6238) two-factor sign-in for local accounts (#341).
--
-- totp_secrets holds one row per local user who started enrolment. The secret is a `v1:`
-- AES-256-GCM ciphertext under the credentials key, with the AAD
-- `totp_secrets:secret_encrypted:<user_id>` (specs/security.md, Encryption and keys). A row with
-- enabled = 0 is a pending enrolment: sign-in ignores it until a valid code confirms it.
-- totp_last_step is the highest 30-second step a code was accepted for. A code for that step or
-- an earlier one is refused, so one code cannot be used twice (RFC 6238 section 5.2).
--
-- totp_recovery_codes holds the Argon2id PHC hash of each recovery code, never the code. A code
-- works once: used_at is set when it is accepted. Both tables go with the user row.

CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    totp_last_step INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    enabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user ON totp_recovery_codes (user_id);
