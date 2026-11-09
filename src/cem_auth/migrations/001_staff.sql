-- Staff sign-in (AUTH_MODE=local): accounts, roles with their scope, refresh sessions and the audit trail.
-- A database of its own (kia_core), so it outlives Receiving's switch from the scratch database to the live one.
CREATE TABLE schema_version (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE staff_user (
    id              bigserial PRIMARY KEY,
    username        text NOT NULL,              -- an email or a short name; compared case-insensitively
    name            text NOT NULL,
    pw_hash         text,                       -- scrypt$n$r$p$salt$hash; NULL until enrolled
    totp_secret     bytea,                      -- encrypted with TOTP_KEY; NULL until enrolled
    totp_last_step  bigint NOT NULL DEFAULT 0,  -- a code is accepted once
    active          boolean NOT NULL DEFAULT false,   -- true after enrolment (password + one code)
    disabled        boolean NOT NULL DEFAULT false,
    failed          int NOT NULL DEFAULT 0,     -- failures since the last good sign-in
    locked_until    timestamptz,                -- backoff: 1, 2, 4 ... up to 15 minutes after 5 failures
    enrol_hash      text,                       -- sha256 of the one-time enrolment token
    enrol_expires   timestamptz,
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX staff_user_username ON staff_user (lower(username));

-- one row per role a person holds; the scope limits writes (stored now, enforced in phase 2)
CREATE TABLE staff_role (
    user_id   bigint NOT NULL REFERENCES staff_user (id),
    role      text NOT NULL,
    line      text NOT NULL DEFAULT 'All' CHECK (line IN ('All', 'L1', 'L2', 'None')),
    material  text NOT NULL DEFAULT 'All' CHECK (material IN ('All', 'Coal', 'Non-coal', 'None')),
    port      boolean NOT NULL DEFAULT true,
    PRIMARY KEY (user_id, role)
);

-- a sign-in's refresh chain: the current token's hash, the one it replaced (good for a short grace, so one page's
-- parallel requests do not trip reuse detection), and its limits; an older token coming back revokes the chain
CREATE TABLE staff_session (
    id            uuid PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES staff_user (id),
    current_hash  text NOT NULL,
    prev_hash     text,
    rotated_at    timestamptz NOT NULL DEFAULT now(),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,         -- absolute limit
    mfa_at        timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoked_why   text,
    ip            text,
    agent         text
);
CREATE INDEX staff_session_current ON staff_session (current_hash);
CREATE INDEX staff_session_prev ON staff_session (prev_hash);

-- append-only: sign-ins, failures, lockouts, enrolments, revokes, role and account changes
CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    actor    text NOT NULL,                     -- username, "cli", or "anonymous"
    action   text NOT NULL,
    target   text,
    ip       text,
    detail   jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at);
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
