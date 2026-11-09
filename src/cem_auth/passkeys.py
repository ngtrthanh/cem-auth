"""Passkeys (WebAuthn) for staff: sign in with Face ID / Touch ID instead of password + code.

- Added by the person themself on /account, only within RECENT of a full sign-in (password + code, or a passkey).
- Discoverable credentials with user verification: sign-in needs no username, and the phone always asks for
  Face ID, so a passkey is both factors at once.
- Bound to the relying-party id `passkey_rp_id`; only PUBLIC_URL's origin is accepted.
- A challenge lives in the signed session cookie, is taken out before it is checked (one use) and lasts CHALLENGE_S.
- An account that is not active or is disabled cannot use one. The password backoff does not apply (nothing to
  guess) and a failed passkey does not count towards it. Reset deletes the person's passkeys."""

from __future__ import annotations

import time
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import Connection, text
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from cem_auth import staff
from cem_auth.config import settings

CHALLENGE_S = 300
RECENT = timedelta(minutes=15)  # adding a passkey needs a sign-in this recent
FAILED = "That passkey did not work. Try again, or sign in with your password and code."


def _origin() -> str:
    p = urlsplit(settings().public_url)
    return f"{p.scheme}://{p.netloc}".lower()


def _keep(session: dict, kind: str, challenge: bytes) -> None:
    session["webauthn"] = {"kind": kind, "c": challenge.hex(), "at": time.time()}


def _take(session: dict, kind: str) -> bytes:
    """The challenge handed out for this step, removed so it serves once."""
    w = session.pop("webauthn", None)
    if not w or w.get("kind") != kind or time.time() - w.get("at", 0) > CHALLENGE_S:
        raise staff.StaffError(FAILED)
    return bytes.fromhex(w["c"])


def of_user(c: Connection, uid: int) -> list[dict]:
    q = ("SELECT id, name, transports, backed_up, created_at, last_used_at FROM staff_passkey WHERE user_id = :u"
         " ORDER BY created_at")  # fmt: skip
    return [dict(r) for r in c.execute(text(q), {"u": uid}).mappings()]


# ---------------------------------------------------------------- adding one


def register_options(c: Connection, session: dict, u: dict) -> str:
    opts = generate_registration_options(
        rp_id=settings().passkey_rp_id, rp_name=settings().issuer, user_id=str(u["id"]).encode(),
        user_name=u["username"], user_display_name=u["name"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(p["id"])) for p in of_user(c, u["id"])],
    )  # fmt: skip
    _keep(session, "add", opts.challenge)
    return options_to_json(opts)


def register(c: Connection, session: dict, u: dict, credential: dict, name: str, ip: str | None) -> None:
    challenge = _take(session, "add")
    try:
        v = verify_registration_response(credential=credential, expected_challenge=challenge,
                                         expected_rp_id=settings().passkey_rp_id, expected_origin=_origin(),
                                         require_user_verification=True)  # fmt: skip
    except Exception as e:  # the library raises several kinds; the person only needs to know it failed
        staff.audit(c, u["username"], "passkey refused", u["username"], ip, step="add", why=str(e)[:200])
        raise staff.StaffError("The passkey could not be added. Try again.") from e
    transports = [t for t in (credential.get("response", {}).get("transports") or []) if isinstance(t, str)]
    name = (name or "").strip()[:60] or "Passkey"
    c.execute(text("INSERT INTO staff_passkey (id, user_id, public_key, sign_count, transports, name, backed_up)"
                   " VALUES (:i, :u, :k, :n, :t, :m, :b)"),
              {"i": v.credential_id, "u": u["id"], "k": v.credential_public_key, "n": v.sign_count,
               "t": transports[:8], "m": name, "b": bool(v.credential_backed_up)})  # fmt: skip
    staff.audit(c, u["username"], "passkey added", u["username"], ip, name=name)


def remove(c: Connection, u: dict, pid_hex: str, ip: str | None) -> bool:
    try:
        pid = bytes.fromhex(pid_hex)
    except ValueError:
        return False
    r = c.execute(text("DELETE FROM staff_passkey WHERE id = :i AND user_id = :u RETURNING name"),
                  {"i": pid, "u": u["id"]}).first()  # fmt: skip
    if r:
        staff.audit(c, u["username"], "passkey removed", u["username"], ip, name=r[0])
    return bool(r)


# ---------------------------------------------------------------- signing in


def login_options(session: dict) -> str:
    opts = generate_authentication_options(rp_id=settings().passkey_rp_id,
                                           user_verification=UserVerificationRequirement.REQUIRED)  # fmt: skip
    _keep(session, "login", opts.challenge)
    return options_to_json(opts)


def login(c: Connection, session: dict, credential: dict, ip: str | None) -> dict:
    """The person whose passkey this is, after checking it; raises StaffError(FAILED) on anything wrong."""
    challenge = _take(session, "login")
    try:
        pid = base64url_to_bytes(credential.get("rawId") or credential.get("id") or "")
    except Exception as e:
        raise staff.StaffError(FAILED) from e
    p = c.execute(text("SELECT * FROM staff_passkey WHERE id = :i FOR UPDATE"), {"i": pid}).mappings().first()
    u = staff.get(c, p["user_id"]) if p else None
    if not p or not u or not u["active"] or u["disabled"]:
        staff.audit(c, u["username"] if u else "anonymous", "sign-in failed", u["username"] if u else None, ip,
                    step="passkey", why="unknown passkey" if not p else "account not usable")  # fmt: skip
        raise staff.StaffError(FAILED)
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=challenge,
                                           expected_rp_id=settings().passkey_rp_id, expected_origin=_origin(),
                                           credential_public_key=bytes(p["public_key"]),
                                           credential_current_sign_count=p["sign_count"],
                                           require_user_verification=True)  # fmt: skip
    except Exception as e:
        staff.audit(c, u["username"], "sign-in failed", u["username"], ip, step="passkey", why=str(e)[:200])
        raise staff.StaffError(FAILED) from e
    c.execute(text("UPDATE staff_passkey SET sign_count = :n, last_used_at = now() WHERE id = :i"),
              {"n": v.new_sign_count, "i": pid})  # fmt: skip
    staff.audit(c, u["username"], "signed in", u["username"], ip, mfa="passkey", passkey=p["name"])
    return u
