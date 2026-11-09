"""Password hashing, TOTP secrets and codes, one-time tokens: shared by staff and supplier sign-in.
Passwords are scrypt hashes; TOTP secrets are stored encrypted with TOTP_KEY (Fernet), never in clear; a code
is accepted once (the caller keeps the last step used)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

import pyotp
from cryptography.fernet import Fernet

from cem_auth.config import settings

SCRYPT = (2**15, 8, 1)  # n, r, p


class KeyMissing(RuntimeError):
    pass


def fernet() -> Fernet:
    key = settings().totp_key
    if not key:
        raise KeyMissing("TOTP_KEY is not set")
    return Fernet(key.encode())


def hash_password(pw: str) -> str:
    n, r, p = SCRYPT
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=2**26, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def check_password(pw: str, stored: str | None) -> bool:
    if not stored:
        hashlib.scrypt(b"x", salt=b"0" * 16, n=SCRYPT[0], r=SCRYPT[1], p=SCRYPT[2], maxmem=2**26)  # same time
        return False
    _, n, r, p, salt, h = stored.split("$")
    got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), maxmem=2**26,
                         dklen=32)  # fmt: skip
    return hmac.compare_digest(got, base64.b64decode(h))


def password_ok(pw: str) -> str | None:
    """None if acceptable, else why not."""
    if len(pw) < 12:
        return "Use at least 12 characters"
    return None


def token() -> tuple[str, str]:
    """A one-time token and its sha256 (only the hash is stored)."""
    t = secrets.token_urlsafe(32)
    return t, sha256(t)


def sha256(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def new_totp_secret() -> tuple[str, bytes]:
    """A TOTP secret in clear (to show once as a QR code) and encrypted (to store)."""
    s = pyotp.random_base32()
    return s, fernet().encrypt(s.encode())


def qr_svg(uri: str) -> str:
    """An inline SVG QR code of `uri` that scales to whatever box CSS gives it (a viewBox, no fixed size: a fixed
    285 px code in a 200 px box was cut off and would not scan), with the standard 4-module quiet zone."""
    import io

    import segno

    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=1, border=4, dark="#13202b", light="#ffffff",
                                    omitsize=True, xmldecl=False, svgclass="qrcode")  # fmt: skip
    return buf.getvalue().decode()


def totp_secret(enc: bytes | memoryview) -> str:
    return fernet().decrypt(bytes(enc)).decode()


def totp_step(enc: bytes | memoryview | None, last_step: int, code: str, now: float | None = None) -> int | None:
    """The step of a valid code (one step of drift either way) not used before, else None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6 or not enc:
        return None
    totp = pyotp.TOTP(totp_secret(enc))
    cur = int(now if now is not None else time.time()) // 30
    for step in (cur - 1, cur, cur + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None
