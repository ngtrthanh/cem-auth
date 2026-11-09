"""Staff users in the browser (/users), in place of `python -m cem_auth.users` over SSH. Needs HOST.users_perm
(default "admin.users"). The CLI still works and stays the way back in if no Admin can sign in.

- Every change needs a sign-in within passkeys.RECENT (15 min), as adding a passkey does: a session left open on a
  desk cannot hand out accounts.
- The one-time enrolment link (and a QR code of it, for the new person's phone) is shown once, on the response to
  the create or reset, never stored or put in a URL; the page is not cached.
- Nobody disables or resets themself, takes Admin off themself, or leaves the plant with no active Admin.
- Every change goes in the audit log under the Admin's username (staff.audit), as the CLI's go under "cli"."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import Connection, text

from cem_auth import crypto, staff
from cem_auth.config import HOST, settings
from cem_auth.web import Forbidden, User, page, recent, require

router = APIRouter()
LOG = (
    "SELECT at, actor, action, target FROM audit_log WHERE action LIKE 'user %' OR action IN ('roles set', 'enrolled')"
    " ORDER BY id DESC LIMIT 15"
)
AGAIN = "For safety, sign out and sign in again (within 15 minutes) before changing users."


def _link(tok: str) -> str:
    return f"{settings().public_url.rstrip('/')}/enrol/{tok}"


def _actor(c: Connection, request: Request) -> dict:
    me = staff.get(c, int(request.state.staff["sub"]))
    if not me:
        raise Forbidden()
    return me


def _roles_from(form) -> list[dict]:
    out = []
    for r in HOST.roles:
        if form.get(f"role:{r}"):
            line, mat = form.get(f"line:{r}") or "All", form.get(f"material:{r}") or "All"
            out.append({"role": r, "line": line, "material": mat, "port": bool(form.get(f"port:{r}"))})
    if not out:
        raise staff.StaffError("Pick at least one role")
    return out


def _admins_left(c: Connection, without: int, roles_after: list[dict] | None = None) -> int:
    """Active, enabled Admins once user `without` is disabled / reset (roles_after None) or given roles_after."""
    q = ("SELECT count(DISTINCT u.id) FROM staff_user u JOIN staff_role r ON r.user_id = u.id"
         " WHERE r.role = :a AND u.active AND NOT u.disabled AND u.id <> :i")  # fmt: skip
    n = c.execute(text(q), {"i": without, "a": HOST.admin_role}).scalar_one()
    u = staff.get(c, without)
    if roles_after is not None and u and u["active"] and not u["disabled"]:
        n += any(r["role"] == HOST.admin_role for r in roles_after)
    return n


def _view(request: Request, status: int = 200, **ctx):
    with staff.engine().connect() as c:
        rows = staff.listing(c)
        log = c.execute(text(LOG)).mappings().all()
    names = {str(r["id"]): r["username"] for r in rows}
    resp = page(request, "users.html", status, rows=rows, roles=list(HOST.roles), lines=HOST.lines,
                materials=HOST.materials, recent=recent(request), hours=settings().enrol_link_hours,
                 log=[dict(x) | {"who": names.get(str(x["target"]), x["target"])} for x in log], **ctx)  # fmt: skip
    resp.headers["Cache-Control"] = "no-store"  # the page may carry a one-time link
    return resp


def _need(request: Request) -> User:
    return require(HOST.users_perm)(request)


@router.get("/users")
def users_page(request: Request, user: User = Depends(_need)):
    return _view(request)


@router.post("/users")
async def users_post(request: Request, user: User = Depends(_need)):
    if not recent(request):
        return RedirectResponse(f"/users?err={AGAIN}", 303)
    f = await request.form()
    action = f.get("action")
    try:
        with staff.engine().begin() as c:
            me = _actor(c, request)
            by = me["username"]
            if action == "create":
                uid, tok = staff.create(c, f.get("username") or "", f.get("name") or "", _roles_from(f), by)
                u = staff.get(c, uid)
                shown = {"user": u, "link": _link(tok), "what": "created"}
            else:
                u = staff.get(c, int(f.get("id") or 0))
                if not u:
                    raise staff.StaffError("No such user")
                mine = u["id"] == me["id"]
                if action == "roles":
                    rs = _roles_from(f)
                    if mine and not any(r["role"] == HOST.admin_role for r in rs):
                        raise staff.StaffError(f"You cannot take {HOST.admin_role} off yourself")
                    if not _admins_left(c, u["id"], rs):
                        raise staff.StaffError("That would leave no active Admin")
                    staff.set_roles(c, u["id"], rs, by)
                    return RedirectResponse(f"/users?msg=Roles of {u['username']} set; their sessions ended", 303)
                if action in ("reset", "disable") and mine:
                    raise staff.StaffError(f"You cannot {action} your own account here")
                if action in ("reset", "disable") and not _admins_left(c, u["id"]):
                    raise staff.StaffError("That would leave no active Admin")
                if action == "reset":
                    tok = staff.reset(c, u["id"], by)
                    shown = {"user": u, "link": _link(tok), "what": "reset: sessions and passkeys ended"}
                elif action == "disable":
                    staff.disable(c, u["id"], by)
                    return RedirectResponse(f"/users?msg={u['username']} disabled; sessions ended", 303)
                elif action == "enable":
                    staff.enable(c, u["id"], by)
                    return RedirectResponse(f"/users?msg={u['username']} enabled", 303)
                else:
                    raise staff.StaffError("Unknown action")
    except staff.StaffError as e:
        return RedirectResponse(f"/users?err={e}", 303)
    return _view(request, shown=shown, qr=crypto.qr_svg(shown["link"]))
