"""Staff accounts: sign-in with username, password and a one-time code (TOTP), then a refresh
session that renews the short access JWT.

- An Admin creates an account (CLI for now) and hands over a one-time enrolment link (24 h). On it the person
  sets a password, scans the code and confirms one code; only then is the account active.
- Failures back off on the account: after 5, the next try waits 1, 2, 4 ... up to 15 minutes. Never a hard
  lock, so nobody can lock an Admin out for good. The message never says which part was wrong.
- A code is accepted once.
- Refresh tokens rotate on every use. The one just replaced stays good for GRACE (one page's parallel requests
  all present it); an older one coming back means a copy is in someone else's hands: the session ends.
- Everything that matters goes in the append-only audit log."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, text

from cem_auth import crypto, db
from cem_auth.config import HOST, settings

FREE_FAILS = 5
MAX_WAIT = timedelta(minutes=15)
GRACE = timedelta(seconds=30)
AMR_CODE, AMR_PASSKEY = ("pwd", "otp"), ("passkey",)  # how a session was started
GENERIC = "Username, password or code is not right, or too many tries: wait a minute and try again."


class StaffError(ValueError):
    pass


def engine():
    return db.engine_for(settings().core_database_url)


def migrate(eng=None) -> list[int]:
    return db.migrate(eng or engine())


def _now() -> datetime:
    return datetime.now(UTC)


def audit(c: Connection, actor: str, action: str, target: str | None = None, ip: str | None = None,
          **detail) -> None:  # fmt: skip
    import json

    c.execute(text("INSERT INTO audit_log (actor, action, target, ip, detail) VALUES (:a, :x, :t, :ip,"
                   " CAST(:d AS jsonb))"),
              {"a": actor, "x": action, "t": target, "ip": ip, "d": json.dumps(detail, default=str)})  # fmt: skip


# ---------------------------------------------------------------- accounts


def get(c: Connection, uid: int) -> dict | None:
    r = c.execute(text("SELECT * FROM staff_user WHERE id = :i"), {"i": uid}).mappings().first()
    return dict(r) if r else None


def by_username(c: Connection, username: str) -> dict | None:
    r = c.execute(text("SELECT * FROM staff_user WHERE lower(username) = lower(:u)"),
                  {"u": (username or "").strip()}).mappings().first()  # fmt: skip
    return dict(r) if r else None


def roles(c: Connection, uid: int) -> list[dict]:
    q = "SELECT role, line, material, port FROM staff_role WHERE user_id = :i ORDER BY role"
    return [dict(r) for r in c.execute(text(q), {"i": uid}).mappings()]


def _check_roles(rs: list[dict]) -> None:
    for r in rs:
        if r["role"] not in HOST.roles:
            raise StaffError(f"unknown role {r['role']!r}; roles: {', '.join(HOST.roles)}")
        if r.get("line", "All") not in HOST.lines or r.get("material", "All") not in HOST.materials:
            raise StaffError(f"scope must be line {HOST.lines} and material {HOST.materials}")


def set_roles(c: Connection, uid: int, rs: list[dict], by: str) -> None:
    _check_roles(rs)
    c.execute(text("DELETE FROM staff_role WHERE user_id = :i"), {"i": uid})
    for r in rs:
        c.execute(text("INSERT INTO staff_role (user_id, role, line, material, port) VALUES (:i, :r, :l, :m, :p)"),
                  {"i": uid, "r": r["role"], "l": r.get("line", "All"), "m": r.get("material", "All"),
                   "p": r.get("port", True)})  # fmt: skip
    revoke_all(c, uid, "roles changed")
    audit(c, by, "roles set", str(uid), roles=rs)


def create(c: Connection, username: str, name: str, rs: list[dict], by: str) -> tuple[int, str]:
    """A new account, not active yet; returns its id and the one-time enrolment token."""
    username, name = (username or "").strip(), (name or "").strip()
    if not username or not name:
        raise StaffError("username and name are needed")
    if by_username(c, username):
        raise StaffError(f"{username} exists")
    _check_roles(rs)
    tok, h = crypto.token()
    uid = c.execute(text("INSERT INTO staff_user (username, name, enrol_hash, enrol_expires, created_by)"
                         " VALUES (:u, :n, :h, :e, :b) RETURNING id"),
                    {"u": username, "n": name, "h": h, "b": by,
                     "e": _now() + timedelta(hours=settings().enrol_link_hours)}).scalar_one()  # fmt: skip
    audit(c, by, "user created", username)
    set_roles(c, uid, rs, by)
    return uid, tok


def reset(c: Connection, uid: int, by: str) -> str:
    """Start again: password and code cleared, every session ended, a new enrolment link."""
    tok, h = crypto.token()
    c.execute(text("UPDATE staff_user SET pw_hash = NULL, totp_secret = NULL, totp_last_step = 0, active = false,"
                   " failed = 0, locked_until = NULL, enrol_hash = :h, enrol_expires = :e WHERE id = :i"),
              {"h": h, "e": _now() + timedelta(hours=settings().enrol_link_hours), "i": uid})  # fmt: skip
    n = c.execute(text("DELETE FROM staff_passkey WHERE user_id = :i"), {"i": uid}).rowcount  # a lost phone: gone
    revoke_all(c, uid, "reset")
    audit(c, by, "user reset", str(uid), passkeys_removed=n)
    return tok


def disable(c: Connection, uid: int, by: str) -> None:
    c.execute(text("UPDATE staff_user SET disabled = true, enrol_hash = NULL WHERE id = :i"), {"i": uid})
    revoke_all(c, uid, "disabled")
    audit(c, by, "user disabled", str(uid))


def enable(c: Connection, uid: int, by: str) -> None:
    c.execute(text("UPDATE staff_user SET disabled = false WHERE id = :i"), {"i": uid})
    audit(c, by, "user enabled", str(uid))


def listing(c: Connection) -> list[dict]:
    q = ("SELECT id, username, name, active, disabled, failed, locked_until, created_at,"
         " (SELECT count(*) FROM staff_passkey p WHERE p.user_id = staff_user.id) AS passkeys FROM staff_user"
         " ORDER BY username")  # fmt: skip
    return [dict(r) | {"roles": roles(c, r["id"])} for r in c.execute(text(q)).mappings()]


# ---------------------------------------------------------------- enrolment


def by_enrol_token(c: Connection, tok: str) -> dict | None:
    r = c.execute(text("SELECT * FROM staff_user WHERE enrol_hash = :h AND enrol_expires > now() AND NOT disabled"),
                  {"h": crypto.sha256(tok or "")}).mappings().first()  # fmt: skip
    return dict(r) if r else None


def enrol_secret(c: Connection, u: dict) -> str:
    """The TOTP secret to show during enrolment (made once, kept encrypted)."""
    if u["totp_secret"]:
        return crypto.totp_secret(u["totp_secret"])
    clear, enc = crypto.new_totp_secret()
    c.execute(text("UPDATE staff_user SET totp_secret = :s WHERE id = :i"), {"s": enc, "i": u["id"]})
    return clear


def otpauth_uri(u: dict, secret: str) -> str:
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(name=u["username"], issuer_name=settings().issuer)


def finish_enrol(c: Connection, tok: str, pw: str, code: str, ip: str | None = None) -> dict:
    u = by_enrol_token(c, tok)
    if not u:
        raise StaffError("This enrolment link is not valid any more. Ask an Admin for a new one.")
    why = crypto.password_ok(pw or "")
    if why:
        raise StaffError(why)
    step = crypto.totp_step(u["totp_secret"], u["totp_last_step"], code)
    if step is None:
        raise StaffError("The code is not right. Check the time on your phone and try the next code.")
    c.execute(text("UPDATE staff_user SET pw_hash = :p, active = true, enrol_hash = NULL, enrol_expires = NULL,"
                   " totp_last_step = :s, failed = 0, locked_until = NULL WHERE id = :i"),
              {"p": crypto.hash_password(pw), "s": step, "i": u["id"]})  # fmt: skip
    audit(c, u["username"], "enrolled", u["username"], ip, mfa="totp")
    return get(c, u["id"])


# ---------------------------------------------------------------- sign-in


def _wait(failed: int) -> timedelta | None:
    """Backoff after the free tries: 1, 2, 4, 8, then 15 minutes."""
    if failed < FREE_FAILS:
        return None
    return min(timedelta(minutes=2 ** (failed - FREE_FAILS)), MAX_WAIT)


def _fail(c: Connection, u: dict | None, ip: str | None, step: str, username: str = "") -> None:
    if not u:
        audit(c, "anonymous", "sign-in failed", username[:80], ip, step=step, why="no such user")
        return
    failed = u["failed"] + 1
    wait = _wait(failed)
    c.execute(text("UPDATE staff_user SET failed = :f, locked_until = :l WHERE id = :i"),
              {"f": failed, "l": _now() + wait if wait else None, "i": u["id"]})  # fmt: skip
    audit(c, u["username"], "sign-in failed", u["username"], ip, step=step, failed=failed,
          wait_min=wait.total_seconds() / 60 if wait else 0)  # fmt: skip


def _usable(u: dict | None) -> bool:
    return bool(u and u["active"] and not u["disabled"] and not (u["locked_until"] and u["locked_until"] > _now()))


def password_step(c: Connection, username: str, pw: str, ip: str | None = None) -> dict:
    """Step 1. Raises StaffError(GENERIC) on any failure; a waiting account is not even checked."""
    u = by_username(c, username)
    if u and u["locked_until"] and u["locked_until"] > _now():
        audit(c, u["username"], "sign-in refused", u["username"], ip, why="waiting after failures")
        raise StaffError(GENERIC)
    ok = crypto.check_password(pw or "", u["pw_hash"] if u else None)
    if not ok or not _usable(u):
        _fail(c, u, ip, "password", username or "")
        raise StaffError(GENERIC)
    return u


def code_step(c: Connection, uid: int, code: str, ip: str | None = None) -> dict:
    """Step 2: the authenticator code. Raises StaffError(GENERIC) on any failure."""
    u = get(c, uid)
    step = crypto.totp_step(u["totp_secret"], u["totp_last_step"], code) if _usable(u) else None
    if step is None:
        _fail(c, u, ip, "code")
        raise StaffError(GENERIC)
    c.execute(text("UPDATE staff_user SET failed = 0, locked_until = NULL, totp_last_step = :s WHERE id = :i"),
              {"s": step, "i": uid})  # fmt: skip
    audit(c, u["username"], "signed in", u["username"], ip, mfa="totp")
    return get(c, uid)


# ---------------------------------------------------------------- sessions


def start(c: Connection, u: dict, ip: str | None, agent: str | None, amr: tuple[str, ...] = AMR_CODE
          ) -> tuple[str, str]:  # fmt: skip
    """A new refresh session after a full sign-in (password + code, or a passkey); returns (session id, token)."""
    sid = str(uuid.uuid4())
    tok, h = crypto.token()
    now = _now()
    c.execute(text("INSERT INTO staff_session (id, user_id, current_hash, expires_at, mfa_at, ip, agent, amr)"
                   " VALUES (:s, :u, :h, :e, :m, :ip, :a, :amr)"),
              {"s": sid, "u": u["id"], "h": h, "e": now + timedelta(days=settings().session_max_days), "m": now,
               "ip": ip, "a": (agent or "")[:200], "amr": list(amr)})  # fmt: skip
    return sid, tok


def refresh(c: Connection, tok: str, ip: str | None = None) -> tuple[str, dict | None, str | None]:
    """Use a refresh token. Returns (outcome, session row, new token):
    - "rotated": it was current; a new token replaces it.
    - "grace": it was the one just replaced (within GRACE): the session holds, the browser already has the new
      token from the parallel request, so no new one.
    - "reused": an older token came back: the session is revoked.
    - "invalid": unknown, expired, idle too long, revoked, or the account is not usable."""
    h = crypto.sha256(tok or "")
    s = c.execute(text("SELECT * FROM staff_session WHERE current_hash = :h OR prev_hash = :h FOR UPDATE"),
                  {"h": h}).mappings().first()  # fmt: skip
    if not s:
        return "invalid", None, None
    s = dict(s)
    now = _now()
    idle = timedelta(hours=settings().session_idle_h)
    u = get(c, s["user_id"])
    if s["revoked_at"] or s["expires_at"] <= now or s["last_seen"] + idle <= now or not u or not u["active"] \
            or u["disabled"]:  # fmt: skip
        return "invalid", None, None
    if s["current_hash"] != h:  # the previous token
        if now - s["rotated_at"] <= GRACE:
            c.execute(text("UPDATE staff_session SET last_seen = :n WHERE id = :i"), {"n": now, "i": s["id"]})
            return "grace", s, None
        revoke(c, s["id"], "refresh token reused")
        audit(c, u["username"], "session revoked", s["id"], ip, why="refresh token reused")
        return "reused", None, None
    new, nh = crypto.token()
    c.execute(text("UPDATE staff_session SET prev_hash = current_hash, current_hash = :h, rotated_at = :n,"
                   " last_seen = :n WHERE id = :i"), {"h": nh, "n": now, "i": s["id"]})  # fmt: skip
    return "rotated", s, new


def revoke(c: Connection, sid: str, why: str) -> None:
    c.execute(text("UPDATE staff_session SET revoked_at = now(), revoked_why = :w WHERE id = :i"
                   " AND revoked_at IS NULL"), {"w": why, "i": sid})  # fmt: skip
    from cem_auth import security

    security.forget_revoked()  # this process checks again at once; others within REVOKED_TTL_S


def revoke_all(c: Connection, uid: int, why: str) -> None:
    c.execute(text("UPDATE staff_session SET revoked_at = now(), revoked_why = :w WHERE user_id = :u"
                   " AND revoked_at IS NULL"), {"w": why, "u": uid})  # fmt: skip
    from cem_auth import security

    security.forget_revoked()  # this process checks again at once; others within REVOKED_TTL_S


def claims(c: Connection, u: dict, s: dict) -> dict:
    """The access token's claims: who, the roles and scopes, the session, when MFA was done."""
    rs = roles(c, u["id"])
    return {"sub": str(u["id"]), "name": u["name"], "usr": u["username"], "sid": str(s["id"]),
            "roles": [r["role"] for r in rs],
            "scope": [{k: r[k] for k in ("role", "line", "material", "port")} for r in rs],
            "amr": list(s.get("amr") or AMR_CODE), "mfa_at": int(s["mfa_at"].timestamp())}  # fmt: skip
