"""The sign-in pages and the staff users page, as one FastAPI router; and the request dependencies.

    app.add_middleware(SessionMiddleware, secret_key=..., https_only=True, same_site="lax")
    app.middleware("http")(cem_auth.security.guard)
    app.include_router(cem_auth.web.router)
    app.mount("/auth-static", StaticFiles(packages=[("cem_auth", "static")]), name="auth-static")
    @app.exception_handler(cem_auth.web.NotSignedIn) ...  -> redirect to /login?next=...
    @app.exception_handler(cem_auth.web.Forbidden) ...   -> 403

Sign-in: username + password, then a 6-digit code (TOTP), or a passkey (Face ID / Touch ID / a security key).
Then a 15-minute EdDSA access JWT renewed by a rotating refresh token (security.py). Every change goes in the
append-only audit log."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Connection
from starlette.concurrency import run_in_threadpool

from cem_auth import crypto, passkeys, security, staff, tokens
from cem_auth.config import HOST, settings

PRE_S = 300  # a password step is good for the code step this long
router = APIRouter()
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.globals["static"] = lambda name: f"/auth-static/{name}"


@dataclass(frozen=True)
class User:
    id: str  # "staff:<username>" or "service:<name>"
    name: str
    roles: tuple[str, ...] = ()
    perms: frozenset[str] = field(default=frozenset())
    scope: tuple = ()  # ({role, line, material, port}, ...)
    sid: str | None = None

    def can(self, perm: str) -> bool:
        return perm in self.perms


class NotSignedIn(Exception):
    pass


class Forbidden(Exception):
    pass


def current_user(request: Request) -> User | None:
    c = getattr(request.state, "staff", None)
    if c:
        return User(id=f"staff:{c['usr']}", name=c["name"], roles=tuple(c["roles"]), perms=HOST.perms_of(c["roles"]),
                    scope=tuple(c.get("scope", ())), sid=c.get("sid"))  # fmt: skip
    return _service(request)


def _service(request: Request) -> User | None:
    """Another app with its bearer key (only its sha256 is configured)."""
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer ") or not settings().service_keys:
        return None
    got = hashlib.sha256(h[7:].strip().encode()).hexdigest()
    for name, want in settings().service_keys.items():
        if hmac.compare_digest(got, want):
            return User(id=f"service:{name}", name=name, roles=("service",), perms=HOST.perms_of(["service"]))
    return None


def require(perm: str):
    def dep(request: Request) -> User:
        u = current_user(request)
        if u is None:
            raise NotSignedIn()
        if not u.can(perm):
            raise Forbidden()
        return u

    dep.perm = perm
    return dep


def signed_in(request: Request) -> User:
    u = current_user(request)
    if u is None or not u.id.startswith("staff:"):
        raise NotSignedIn()
    return u


def page(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    if HOST.render:
        return HOST.render(request, name, status_code, **ctx)
    ctx = {"user": current_user(request), "cfg": settings(), "host_users_perm": HOST.users_perm} | ctx
    return TEMPLATES.TemplateResponse(request, name, ctx, status_code=status_code)


def _safe_next(n: str | None) -> str:
    return n if n and n.startswith("/") and not n.startswith("//") else "/"


def _ip(request: Request) -> str | None:
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)


def recent(request: Request) -> bool:
    """Signed in (password + code, or a passkey) within passkeys.RECENT: needed to add a passkey or change users."""
    return time.time() - request.state.staff.get("mfa_at", 0) < passkeys.RECENT.total_seconds()


def _me(c: Connection, request: Request) -> dict:
    u = staff.get(c, int(request.state.staff["sub"]))
    if not u or not u["active"] or u["disabled"]:
        raise Forbidden()
    return u


async def _json(request: Request) -> dict | None:
    try:
        body = await request.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


# ---------------------------------------------------------------- password + code


@router.get("/login")
def login(request: Request, next: str | None = None, err: str | None = None):
    if next is not None:
        request.session["next"] = _safe_next(next)
    pre = request.session.get("pre")
    step = "code" if pre and time.time() - pre["at"] < PRE_S else "password"
    return page(request, "login_local.html", step=step, err=err)


@router.post("/login")
def login_password(request: Request, username: str = Form(""), password: str = Form("")):
    nxt = request.session.get("next", "/")
    err = None
    with staff.engine().begin() as c:  # caught inside, so the failure and its backoff are committed
        try:
            u = staff.password_step(c, username, password, _ip(request))
        except staff.StaffError as e:
            err = str(e)
    if err:
        return RedirectResponse(f"/login?err={err}", 303)
    request.session.clear()
    request.session.update({"pre": {"uid": u["id"], "at": time.time()}, "next": nxt})
    return RedirectResponse("/login", 303)


@router.post("/login/code")
def login_code(request: Request, code: str = Form("")):
    pre = request.session.get("pre")
    if not pre or time.time() - pre["at"] >= PRE_S:
        request.session.pop("pre", None)
        return RedirectResponse("/login?err=Too slow: start again", 303)
    err = None
    with staff.engine().begin() as c:
        try:
            u = staff.code_step(c, pre["uid"], code, _ip(request))
            sid, rt = staff.start(c, u, _ip(request), request.headers.get("user-agent"))
            at = tokens.issue(staff.claims(c, u, {"id": sid, "mfa_at": staff._now(), "amr": staff.AMR_CODE}))
            has_passkey = bool(passkeys.of_user(c, u["id"]))
        except staff.StaffError as e:
            err = str(e)
    if err:
        return RedirectResponse(f"/login?err={err}", 303)
    nxt = _safe_next(request.session.get("next"))
    request.session.clear()
    # no passkey yet: offer one while the sign-in is fresh enough to add it
    resp = RedirectResponse(nxt if has_passkey else f"/account?next={quote(nxt)}", 303)
    security.set_tokens(resp, at, rt)
    return resp


@router.get("/enrol/{tok}")
def enrol(request: Request, tok: str, err: str | None = None):
    with staff.engine().begin() as c:
        u = staff.by_enrol_token(c, tok)
        if not u:
            return page(request, "enrol.html", status_code=404, u=None, err=None)
        secret = staff.enrol_secret(c, u)
    uri = staff.otpauth_uri(u, secret)
    return page(request, "enrol.html", u=u, tok=tok, qr=crypto.qr_svg(uri), secret=secret, uri=uri, err=err)


@router.post("/enrol/{tok}")
def enrol_post(request: Request, tok: str, password: str = Form(""), password2: str = Form(""),
               code: str = Form("")):  # fmt: skip
    if password != password2:
        return RedirectResponse(f"/enrol/{tok}?err=The passwords differ", 303)
    try:
        with staff.engine().begin() as c:
            staff.finish_enrol(c, tok, password, code, _ip(request))
    except staff.StaffError as e:
        return RedirectResponse(f"/enrol/{tok}?err={e}", 303)
    request.session.clear()
    return RedirectResponse("/login?msg=Enrolled. Sign in with your username, password and a code.", 303)


@router.post("/logout")
def logout(request: Request):
    u = current_user(request)
    if u and u.sid:
        with staff.engine().begin() as c:
            staff.revoke(c, u.sid, "signed out")
            staff.audit(c, u.id.removeprefix("staff:"), "signed out", u.sid, _ip(request))
    request.session.clear()
    resp = RedirectResponse("/login", 303)
    security.clear_tokens(resp)
    return resp


@router.get("/.well-known/jwks.json", include_in_schema=False)
def jwks():
    return JSONResponse(tokens.jwks())


# ---------------------------------------------------------------- passkeys

ADD_AGAIN = "For your safety, sign out and sign in again, then add the passkey."


@router.post("/login/passkey/options")
def passkey_login_options(request: Request):
    return JSONResponse(json.loads(passkeys.login_options(request.session)))


@router.post("/login/passkey")
async def passkey_login(request: Request):
    credential = await _json(request)
    if credential is None:
        return JSONResponse({"error": "bad request"}, 400)
    return await run_in_threadpool(_passkey_login, request, credential)


def _passkey_login(request: Request, credential: dict):
    err = None
    with staff.engine().begin() as c:
        try:
            u = passkeys.login(c, request.session, credential, _ip(request))
            sid, rt = staff.start(c, u, _ip(request), request.headers.get("user-agent"), staff.AMR_PASSKEY)
            at = tokens.issue(staff.claims(c, u, {"id": sid, "mfa_at": staff._now(), "amr": staff.AMR_PASSKEY}))
        except staff.StaffError as e:
            err = str(e)
    if err:
        return JSONResponse({"error": err}, 400)
    nxt = _safe_next(request.session.get("next"))
    request.session.clear()
    resp = JSONResponse({"next": nxt})
    security.set_tokens(resp, at, rt)
    return resp


@router.get("/account")
def account(request: Request, next: str | None = None, u: User = Depends(signed_in)):
    with staff.engine().begin() as c:
        me = _me(c, request)
        keys = passkeys.of_user(c, me["id"])
    tz = ZoneInfo(settings().timezone)
    for k in keys:
        k["created_at"] = k["created_at"].astimezone(tz)
        k["last_used_at"] = k["last_used_at"] and k["last_used_at"].astimezone(tz)
    agent = request.headers.get("user-agent", "")
    device = [d for d in ("iPhone", "iPad", "Android", "Mac", "Windows") if d in agent][:1] or ["This device"]
    return page(request, "account.html", me=me, keys=keys, recent=recent(request), device=device[0],
                next=_safe_next(next) if next else None)  # fmt: skip


@router.post("/account/passkeys/options")
def passkey_add_options(request: Request, u: User = Depends(signed_in)):
    if not recent(request):
        return JSONResponse({"error": ADD_AGAIN}, 403)
    with staff.engine().begin() as c:
        opts = passkeys.register_options(c, request.session, _me(c, request))
    return JSONResponse(json.loads(opts))


@router.post("/account/passkeys")
async def passkey_add(request: Request, u: User = Depends(signed_in)):
    body = await _json(request)
    if body is None or not isinstance(body.get("credential"), dict):
        return JSONResponse({"error": "bad request"}, 400)
    return await run_in_threadpool(_passkey_add, request, body)


def _passkey_add(request: Request, body: dict):
    if not recent(request):
        return JSONResponse({"error": ADD_AGAIN}, 403)
    err = None
    with staff.engine().begin() as c:
        try:
            passkeys.register(c, request.session, _me(c, request), body["credential"], str(body.get("name") or ""),
                              _ip(request))  # fmt: skip
        except staff.StaffError as e:
            err = str(e)
    return JSONResponse({"error": err}, 400) if err else JSONResponse({"ok": True})


@router.post("/account/passkeys/{pid}/delete")
def passkey_remove(request: Request, pid: str, u: User = Depends(signed_in)):
    with staff.engine().begin() as c:
        passkeys.remove(c, _me(c, request), pid, _ip(request))
    return RedirectResponse("/account?msg=Passkey removed", 303)
