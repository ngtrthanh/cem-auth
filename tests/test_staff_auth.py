"""Staff sign-in and permissions: enrolment; password + code; JWT and
the rotating refresh token (grace for parallel requests, reuse revokes); CSRF origin check; backoff; a code used
once; the start-up check."""

import os

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from cem_auth import security, staff, tokens
from cem_auth.config import settings
from tests.demo_app import make_app

ORIGIN = "https://testserver"


@pytest.fixture
def local(monkeypatch, tmp_path):
    key = tmp_path / "jwt.pem"
    fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, tokens.new_key_pem())
    os.close(fd)
    monkeypatch.setenv("JWT_KEY_FILE", str(key))
    monkeypatch.setenv("PUBLIC_URL", ORIGIN)
    monkeypatch.setenv("ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("SECRET_KEY", "s" * 40)
    settings.cache_clear()
    tokens._private.cache_clear()
    e = staff.engine()
    staff.migrate(e)
    with e.begin() as c:
        c.execute(text("TRUNCATE staff_role, staff_session, staff_user, audit_log RESTART IDENTITY CASCADE"))
    security.forget_revoked()
    yield e
    monkeypatch.undo()
    settings.cache_clear()
    tokens._private.cache_clear()


def _enrol(e, username="ana", roles=("Admin",)):
    with e.begin() as c:
        uid, tok = staff.create(c, username, "Ana", [{"role": r} for r in roles], "test")
        secret = staff.enrol_secret(c, staff.get(c, uid))
    return uid, tok, pyotp.TOTP(secret)


def _client():
    return TestClient(make_app(), base_url=ORIGIN, headers={"Origin": ORIGIN})


def _sign_in(cl, totp, username="ana", step=1):
    import time

    r = cl.post("/login", data={"username": username, "password": "correct horse battery"}, follow_redirects=False)
    assert r.headers["location"] == "/login"
    code = totp.at(time.time() + 30 * step)  # a later step than the one used at enrolment
    return cl.post("/login/code", data={"code": code}, follow_redirects=False)


def _enrolled(e, cl, **kw):
    uid, tok, totp = _enrol(e, **kw)
    page = cl.get(f"/enrol/{tok}").text
    assert "Set up your account" in page
    # a password manager saves the new password under this username, with the code (iPhone Passwords)
    assert f'autocomplete="username" value="{kw.get("username", "ana")}"' in page
    r = cl.post(f"/enrol/{tok}", data={"password": "correct horse battery", "password2": "correct horse battery",
                                       "code": totp.now()}, follow_redirects=False)  # fmt: skip
    assert r.status_code == 303 and "Enrolled" in r.headers["location"]
    return uid, totp


def test_enrol_sign_in_and_permissions(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl, roles=("Viewer",))
        assert cl.get("/", follow_redirects=False).status_code == 303  # not signed in yet
        r = _sign_in(cl, totp)
        assert r.status_code == 303 and cl.cookies.get("cem_at") and cl.cookies.get("cem_rt")
        claims = tokens.read(cl.cookies.get("cem_at"))
        assert claims["roles"] == ["Viewer"] and claims["amr"] == ["pwd", "otp"]
        assert cl.get("/").status_code == 200  # every role reads
        assert cl.post("/write", data={}).status_code == 403  # a Viewer does not write
        assert cl.get("/.well-known/jwks.json").json()["keys"][0]["crv"] == "Ed25519"


def test_csrf_origin_check(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl)
        _sign_in(cl, totp)
        assert cl.post("/write", data={}, headers={"Origin": "https://evil.example"}).status_code == 403
        cl.headers.pop("Origin")
        assert cl.post("/write", data={}).status_code == 403  # neither Origin nor Referer
        r = cl.post("/write", data={}, headers={"Referer": ORIGIN + "/"})
        assert r.status_code != 403


def test_refresh_rotates_grace_then_reuse_revokes(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl)
        _sign_in(cl, totp)
        rt1 = cl.cookies.get("cem_rt")
        cl.cookies.delete("cem_at")  # the access token ran out
        assert cl.get("/").status_code == 200
        rt2 = cl.cookies.get("cem_rt")
        assert rt2 and rt2 != rt1 and cl.cookies.get("cem_at")
        with local.begin() as c:  # a parallel request of the same page presents the old token: grace
            assert staff.refresh(c, rt1)[0] == "grace"
            c.execute(text("UPDATE staff_session SET rotated_at = rotated_at - interval '1 minute'"))
            assert staff.refresh(c, rt1)[0] == "reused"  # later: a copy elsewhere, the session ends
            assert staff.refresh(c, rt2)[0] == "invalid"
            assert c.execute(text("SELECT count(*) FROM audit_log WHERE action = 'session revoked'")).scalar() == 1


def test_backoff_and_a_code_is_used_once(local):
    with _client() as cl:
        uid, totp = _enrolled(local, cl)
        for _ in range(staff.FREE_FAILS):
            cl.post("/login", data={"username": "ana", "password": "wrong"})
        r = cl.post("/login", data={"username": "ana", "password": "correct horse battery"}, follow_redirects=False)
        assert "err=" in r.headers["location"]  # waiting: even the right password is refused
        with local.begin() as c:
            assert staff.get(c, uid)["locked_until"] is not None
            c.execute(text("UPDATE staff_user SET locked_until = NULL, failed = 0"))
        assert _sign_in(cl, totp).status_code == 303
        r = _sign_in(cl, totp)  # the same code again
        assert "err=" in r.headers["location"]


def test_logout_revokes_the_session(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl)
        _sign_in(cl, totp)
        rt = cl.cookies.get("cem_rt")
        cl.post("/logout")
        with local.begin() as c:
            assert staff.refresh(c, rt)[0] == "invalid"


def test_startup_check_refuses_missing_or_open_keys(local, tmp_path, monkeypatch):
    security.startup_check()  # the fixture's set-up is complete
    bad = tmp_path / "open.pem"
    bad.write_bytes(tokens.new_key_pem())
    bad.chmod(0o644)
    monkeypatch.setenv("JWT_KEY_FILE", str(bad))
    settings.cache_clear()
    with pytest.raises(tokens.KeyProblem):
        security.startup_check()
    monkeypatch.setenv("JWT_KEY_FILE", str(tmp_path / "missing.pem"))
    settings.cache_clear()
    with pytest.raises(tokens.KeyProblem):
        security.startup_check()
    monkeypatch.setenv("SECRET_KEY", "change-me")
    settings.cache_clear()
    with pytest.raises(RuntimeError):
        security.startup_check()


def test_a_signed_out_access_token_is_refused_before_it_expires(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl)
        _sign_in(cl, totp)
        at = cl.cookies.get("cem_at")
        with _client() as ok:  # control: the same token, replayed before sign-out, works
            assert ok.get("/", headers={"Cookie": f"cem_at={at}"}, follow_redirects=False).status_code == 200
        cl.post("/logout")
    with _client() as cl2:  # the old access token, replayed
        assert cl2.get("/", headers={"Cookie": f"cem_at={at}"}, follow_redirects=False).status_code == 303


def test_qr_scales_to_its_box():
    """A fixed-size SVG in a smaller CSS box was cut off and did not scan: the code has a viewBox and no size."""
    import re

    from cem_auth import crypto

    svg = crypto.qr_svg("otpauth://totp/CFC%20KIA:someone?secret=JBSWY3DPEHPK3PXP&issuer=CFC%20KIA")
    head = svg[: svg.index(">")]
    assert svg.startswith("<svg") and "viewBox" in head
    assert not re.search(r'\swidth="', head) and not re.search(r'\sheight="', head)


def test_users_page_creates_resets_and_guards(local, monkeypatch):
    from urllib.parse import unquote

    with _client() as cl:
        admin_id, totp = _enrolled(local, cl, roles=("Admin",))
        _sign_in(cl, totp)
        page = cl.get("/users")
        assert page.status_code == 200 and "Staff users" in page.text and page.headers["cache-control"] == "no-store"
        r = cl.post("/users", data={"action": "create", "username": "binh", "name": "Binh Tran",
                                    "role:Planner": "on", "line:Planner": "L1",
                                    "material:Planner": "Coal", "port:Planner": "on"})  # fmt: skip
        assert r.status_code == 200 and f"{ORIGIN}/enrol/" in r.text and "<svg" in r.text
        tok = r.text.split(f"{ORIGIN}/enrol/")[1].split("<")[0].split('"')[0]
        assert "Set up your account" in cl.get(f"/enrol/{tok}").text  # the link shown works
        assert tok not in cl.get("/users").text  # and is shown once
        with local.begin() as c:
            b = staff.by_username(c, "binh")
            assert staff.roles(c, b["id"]) == [{"role": "Planner", "line": "L1", "material": "Coal", "port": True}]
            assert c.execute(text("SELECT actor FROM audit_log WHERE action = 'user created' AND target = 'binh'")
                             ).scalar() == "ana"  # fmt: skip
        # no locking yourself out
        assert "cannot" in cl.post("/users", data={"action": "disable", "id": admin_id},
                                   follow_redirects=False).headers["location"]  # fmt: skip
        r = cl.post("/users", data={"action": "roles", "id": admin_id, "role:Viewer": "on"}, follow_redirects=False)
        assert "Admin" in r.headers["location"]
        r = cl.post("/users", data={"action": "disable", "id": b["id"]}, follow_redirects=False)
        assert "disabled" in r.headers["location"]
        # an old sign-in may read the page but not change users
        monkeypatch.setattr("cem_auth.users_web.recent", lambda request: False)
        r = cl.post("/users", data={"action": "enable", "id": b["id"]}, follow_redirects=False)
        assert "sign in again" in unquote(r.headers["location"])


def test_users_page_is_admin_only(local):
    with _client() as cl:
        _, totp = _enrolled(local, cl, roles=("Planner",))
        _sign_in(cl, totp)
        assert cl.get("/users").status_code == 403
        assert cl.post("/users", data={"action": "create"}).status_code == 403
