"""A minimal host app: roles, what each may do, one page per permission level."""

from fastapi import Depends, FastAPI

from cem_auth.web import User, require

ROLES = ("Viewer", "Planner", "Admin")
PERMS = {"Viewer": {"read"}, "Planner": {"read", "write"}, "Admin": {"read", "write", "admin.users"}}


def perms_of(roles):
    return frozenset().union(*(PERMS.get(r, set()) for r in roles)) if roles else frozenset()


def make_app() -> FastAPI:
    import cem_auth

    cem_auth.configure(roles=ROLES, perms_of=perms_of, issuer="cem-auth test", lines=("All", "L1", "L2"),
                       materials=("All", "Coal"))  # fmt: skip
    app = FastAPI()
    cem_auth.install(app)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/")
    def home(u: User = Depends(require("read"))):
        return {"hello": u.name}

    @app.post("/write")
    def write(u: User = Depends(require("write"))):
        return {"ok": True}

    return app
