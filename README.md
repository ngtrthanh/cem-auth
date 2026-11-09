# cem-auth

Staff sign-in for cem-os apps (FastAPI + Postgres). Extracted from 8494 (cem-kia), where it runs in production at
`kia.plantops.org`.

## What it does

- **Accounts.** An Admin creates an account, on the `/users` page or with the CLI. The new person gets a one-time
  enrolment link: it works once, lasts 24 h, and only its sha256 is stored. On it they choose a password (12+
  characters, scrypt) and add the account to an authenticator app. The TOTP secret is stored encrypted with Fernet.
- **Sign-in.** Username and password, then a 6-digit code, which is accepted only once. A passkey can replace both
  (Face ID, Touch ID, Windows Hello or a security key). It is discoverable and needs user verification, is bound
  to `PASSKEY_RP_ID`, and only the `PUBLIC_URL` origin is accepted.
- **Sessions.**
  - A 15-minute EdDSA (Ed25519) access JWT in an httpOnly, Secure, SameSite=Lax cookie. Others can verify it with
    `/.well-known/jwks.json`.
  - A refresh token that rotates on every use. The token it replaced stays valid for 30 s, so a page's parallel
    requests still get through. If an older token comes back, the session is revoked as a stolen copy.
  - Sign-out, disable, reset or a role change ends the session within 30 s, even if its access token is still
    valid.
- **Guard.** Security headers on every response, including HSTS. A POST that carries cookies must come from an
  allowed origin (Origin, else Referer).
- **Brute force.** After 5 failures on an account, every further try waits 1, 2, 4 … up to 15 minutes. There is
  no hard lock, so nobody can lock an Admin out for good. The error message never says which part was wrong.
- **Audit.** `audit_log` is append-only, enforced by database rules: no UPDATE, no DELETE.
- **Users page.** Create, set roles (with optional line and material scope), reset, disable and enable accounts.
  It shows the enrolment link and its QR code once and is never cached. Changes need a sign-in within the last
  15 minutes. Nobody can disable or reset themselves, remove their own Admin role, or leave the app with no
  active Admin.
- **Guide.** A short Vietnamese sign-in guide with pictures, under the login form.

## Use it in an app

```python
import cem_auth
from cem_auth.web import User, require

cem_auth.configure(
    roles=("Viewer", "Planner", "Admin"),
    perms_of=lambda roles: my_permissions(roles),  # must give Admin "admin.users"
    issuer="CFC KIA",                              # the name in authenticator apps and passkey prompts
    render=my_render,                              # optional: render the package's pages in your own shell
)
app = FastAPI(**cem_auth.security.docs_urls())
cem_auth.install(app)            # session cookie, guard, routes, /auth-static, 303-to-login and 403 handlers
cem_auth.staff.migrate()         # at start-up: its tables in CORE_DATABASE_URL

@app.get("/report")
def report(u: User = Depends(require("read"))): ...
```

Settings come from the environment or `.env`, or are passed to `configure()`:

| Setting | |
|---|---|
| `SECRET_KEY` | 32+ characters; signs the session cookie |
| `TOTP_KEY` | Fernet key; encrypts the TOTP secrets |
| `JWT_KEY_FILE` | Ed25519 private key PEM, mode 0600 (`python -m cem_auth.users keygen <path>`) |
| `CORE_DATABASE_URL` | Postgres for its tables |
| `PUBLIC_URL`, `ALLOWED_ORIGINS` | the JWT issuer and the origins that may POST |
| `PASSKEY_RP_ID` | the domain passkeys are bound to; it can never change |
| `ACCESS_MIN`, `SESSION_IDLE_H`, `SESSION_MAX_DAYS`, `ENROL_LINK_HOURS` | lifetimes |
| `SERVICE_KEYS` | `{"name": "<sha256 of its bearer key>"}` for machine callers |

The app refuses to start without a real `SECRET_KEY`, a `TOTP_KEY`, and a key file that only its owner can read.

## CLI (the way back in when no Admin can sign in)

```
python -m cem_auth.users keygen /run/secrets/jwt_ed25519.pem
python -m cem_auth.users add <username> "<Name>" Admin
python -m cem_auth.users reset|disable|enable <username>
python -m cem_auth.users list
```

## Tests

```
CEM_AUTH_TEST_DB=postgresql+psycopg://user:pw@host:5432/cem_auth_test uv run pytest -q
```

17 tests cover:
- enrolment, sign-in and permissions;
- the CSRF origin check;
- refresh rotation, the grace period and reuse;
- backoff, and a code being used only once;
- sign-out ending a still-valid token;
- the start-up check;
- the QR code;
- the users page and its guards;
- passkeys: add, sign in, one-use challenge, wrong origin, disable and reset, whose key can be removed.

Passkeys are tested with a software authenticator. The database must be named `*_test`, because the tests
truncate its tables.

## Review, 9 Nov 2026

The design is sound, and pip-audit finds no known CVE in the dependencies. Gaps, from most to least important:

1. **No Content-Security-Policy.** The host pages use inline scripts; move them to files, or add a nonce.
2. **No per-IP throttle.** Backoff is per account only, so one IP can spray one password across many accounts.
3. **Not tested from outside.** No external pen test yet.
4. **The supplier portal is not included.** It is a separate account type (email + TOTP + passkeys) and stays in
   cem-kia for now.

## Status

- Version 0.1.0 is the first extraction.
- cem-kia still uses its own copy (`kia/core`). Switching it to this package is a separate step.
