"""The request guard: security headers on every response, and
- CSRF: a POST (or other unsafe method) carrying cookies must come from an allowed origin (Origin, else Referer);
  with neither header it is refused. Bearer requests (service keys) carry no cookie and are not checked.
- tokens: a valid access JWT (at) signs the request in; an expired one is renewed from the refresh token
  (rt), and both cookies are set again on the response.
And the start-up check: refuse to start without the keys."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool

from cem_auth.config import settings

AT, RT = "cem_at", "cem_rt"  # httpOnly, Secure, SameSite=Lax cookies
SAFE = {"GET", "HEAD", "OPTIONS"}
SKIP = ("/static/", "/auth-static/", "/healthz")
HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


REVOKED_TTL_S = 30
_revoked: dict = {"at": 0.0, "sids": frozenset()}


def docs_urls() -> dict:
    """FastAPI kwargs: no API docs or schema (the app is on the internet)."""
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}


def _revoked_sids() -> frozenset[str]:
    """Sessions ended in the last day (sign-out, disable, reset, role change, reuse): a still-valid access token
    of one of them is refused, so these take effect within REVOKED_TTL_S, not at the token's expiry."""
    import time

    if time.monotonic() - _revoked["at"] < REVOKED_TTL_S:
        return _revoked["sids"]
    from sqlalchemy import text

    from cem_auth import staff

    with staff.engine().connect() as c:
        rows = c.execute(text("SELECT id::text FROM staff_session WHERE revoked_at > now() - interval '1 day'"))
        _revoked.update(at=time.monotonic(), sids=frozenset(r[0] for r in rows))
    return _revoked["sids"]


def forget_revoked() -> None:
    _revoked["at"] = 0.0


def startup_check() -> None:
    """Local mode needs: a real SECRET_KEY, TOTP_KEY, and the Ed25519 key file (0600). Refuse to start otherwise."""
    cfg = settings()
    from cem_auth import tokens

    if not cfg.secret_key or cfg.secret_key == "change-me" or len(cfg.secret_key) < 32:
        raise RuntimeError("cem-auth needs SECRET_KEY (32+ characters, not the default)")
    if not cfg.totp_key:
        raise RuntimeError("cem-auth needs TOTP_KEY")
    tokens.check_key_file(cfg.jwt_key_file)


def _origins() -> set[str]:
    cfg = settings()
    return {_origin(o) for o in [cfg.public_url, *cfg.allowed_origins] if o}


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()


def origin_ok(request: Request) -> bool:
    o = request.headers.get("origin") or request.headers.get("referer")
    return bool(o) and _origin(o) in _origins()


def _cookie_args(max_age: int) -> dict:
    return {"max_age": max_age, "httponly": True, "secure": True, "samesite": "lax", "path": "/"}


def set_tokens(resp, at: str, rt: str | None) -> None:
    cfg = settings()
    resp.set_cookie(AT, at, **_cookie_args(cfg.access_min * 60))
    if rt:
        resp.set_cookie(RT, rt, **_cookie_args(cfg.session_max_days * 86400))


def clear_tokens(resp) -> None:
    for k in (AT, RT):
        resp.delete_cookie(k, path="/", secure=True, httponly=True, samesite="lax")


def _renew(rt: str, ip: str | None) -> tuple[str, dict | None, str | None, str | None]:
    """(outcome, claims, new access token, new refresh token) from a refresh token."""
    from cem_auth import staff, tokens

    with staff.engine().begin() as c:
        outcome, s, new_rt = staff.refresh(c, rt, ip)
        if outcome not in ("rotated", "grace"):
            return outcome, None, None, None
        u = staff.get(c, s["user_id"])
        claims = staff.claims(c, u, s)
    return outcome, claims, tokens.issue(claims), new_rt


async def guard(request: Request, call_next):
    path = request.url.path
    renewed = None
    if not path.startswith(SKIP):
        from cem_auth import tokens

        bearer = request.headers.get("authorization", "").startswith("Bearer ")
        if request.method not in SAFE and request.cookies and not bearer and not origin_ok(request):
            msg = "cross-site request refused"
            return JSONResponse({"detail": msg}, 403) if path.startswith("/api/") else PlainTextResponse(msg, 403)
        at, rt = request.cookies.get(AT), request.cookies.get(RT)
        claims = tokens.read(at) if at else None
        if claims and claims.get("sid") in await run_in_threadpool(_revoked_sids):
            claims, rt = None, None  # signed out, disabled or demoted: sign in again
            renewed = ("revoked", None, None)
        if claims is None and rt and not bearer:
            ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)
            outcome, claims, new_at, new_rt = await run_in_threadpool(_renew, rt, ip)
            renewed = (outcome, new_at, new_rt)
        if claims:
            request.state.staff = claims
    resp = await call_next(request)
    for k, v in HEADERS.items():
        resp.headers.setdefault(k, v)
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if renewed:
        outcome, new_at, new_rt = renewed
        if new_at:
            set_tokens(resp, new_at, new_rt)
        else:
            clear_tokens(resp)
    return resp
