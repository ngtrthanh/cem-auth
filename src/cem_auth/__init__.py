"""cem-auth: staff sign-in for cem-os apps. Username + password + TOTP, or a passkey; a 15-minute EdDSA JWT renewed
by a rotating refresh token with reuse detection; an origin check against cross-site POSTs; per-account backoff;
an append-only audit log; an Admin page for users. See README.md."""

from __future__ import annotations

from urllib.parse import quote

__version__ = "0.1.0"


def install(app, *, mount_static: bool = True, users_page: bool = True) -> None:
    """Wire cem-auth into a FastAPI app: session cookie, request guard, routes, static files, error pages.
    Call `cem_auth.configure(...)` first; run `cem_auth.staff.migrate()` at start-up."""
    from fastapi.responses import PlainTextResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from starlette.middleware.sessions import SessionMiddleware

    from cem_auth import security, users_web, web
    from cem_auth.config import settings

    security.startup_check()
    app.middleware("http")(security.guard)
    app.add_middleware(SessionMiddleware, secret_key=settings().secret_key, session_cookie="cem_session",
                       same_site="lax", https_only=True, max_age=12 * 3600)  # fmt: skip
    app.include_router(web.router)
    if users_page:
        app.include_router(users_web.router)
    if mount_static:
        app.mount("/auth-static", StaticFiles(packages=[("cem_auth", "static")]), name="auth-static")

    @app.exception_handler(web.NotSignedIn)
    async def _not_signed_in(request, _exc):
        return RedirectResponse(f"/login?next={quote(request.url.path)}", 303)

    @app.exception_handler(web.Forbidden)
    async def _forbidden(_request, _exc):
        return PlainTextResponse("Forbidden", 403)


from cem_auth.config import configure  # noqa: E402

__all__ = ["configure", "install", "__version__"]
