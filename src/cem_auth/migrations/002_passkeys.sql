-- Passkeys (WebAuthn): sign in with Face ID / Touch ID / a security key instead of password + code.
-- A person may hold several (phone, laptop). Reset deletes them; disable blocks them.
CREATE TABLE staff_passkey (
    id            bytea PRIMARY KEY,            -- the credential id the authenticator chose
    user_id       bigint NOT NULL REFERENCES staff_user (id),
    public_key    bytea NOT NULL,               -- COSE
    sign_count    bigint NOT NULL DEFAULT 0,
    transports    text[] NOT NULL DEFAULT '{}',
    name          text NOT NULL,                -- e.g. "iPhone, 7 Nov 2026"
    backed_up     boolean NOT NULL DEFAULT false,  -- synced (iCloud Keychain, Google Password Manager)
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX staff_passkey_user ON staff_passkey (user_id);

-- how the session was started, for the access token's amr claim: {pwd,otp} or {passkey}
ALTER TABLE staff_session ADD COLUMN amr text[] NOT NULL DEFAULT '{pwd,otp}';
