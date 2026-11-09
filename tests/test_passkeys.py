"""Passkeys: added after a recent full sign-in, then sign-in with no username, password or code; a challenge serves
once; another origin, a disabled account and a reset all stop a passkey; the session's amr says passkey, also
after a refresh. A software authenticator (ES256, "none" attestation) stands in for the phone."""

import hashlib
import json
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from cem_auth import passkeys, security, staff, tokens
from cem_auth.config import settings
from tests.test_staff_auth import ORIGIN, _client, _enrolled, _sign_in

RP_ID = "testserver"


@pytest.fixture
def local(monkeypatch, tmp_path):
    key = tmp_path / "jwt.pem"
    fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, tokens.new_key_pem())
    os.close(fd)
    for k, v in {"JWT_KEY_FILE": str(key), "PUBLIC_URL": ORIGIN, "ALLOWED_ORIGINS": "[]",
                 "SECRET_KEY": "s" * 40, "PASSKEY_RP_ID": RP_ID}.items():  # fmt: skip
        monkeypatch.setenv(k, v)
    settings.cache_clear()
    tokens._private.cache_clear()
    e = staff.engine()
    staff.migrate(e)
    with e.begin() as c:
        c.execute(text("TRUNCATE staff_passkey, staff_role, staff_session, staff_user, audit_log RESTART IDENTITY"
                       " CASCADE"))  # fmt: skip
    security.forget_revoked()
    yield e
    monkeypatch.undo()
    settings.cache_clear()
    tokens._private.cache_clear()


class Phone:
    """A software authenticator: one ES256 key, user present and verified (Face ID)."""

    def __init__(self, origin=ORIGIN, rp_id=RP_ID):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.origin, self.rp_id, self.count, self.user = origin, rp_id, 0, None

    def _client_data(self, kind, challenge):
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}).encode()  # fmt: skip

    def create(self, opts):
        self.user = opts["user"]["id"]
        n = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big")
                + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)  # fmt: skip
        cd = self._client_data("webauthn.create", opts["challenge"])
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        cid = bytes_to_base64url(self.cred_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": bytes_to_base64url(cd), "attestationObject": bytes_to_base64url(att),
                             "transports": ["internal", "hybrid"]}}  # fmt: skip

    def get(self, opts):
        self.count += 1
        auth = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + self.count.to_bytes(4, "big")
        cd = self._client_data("webauthn.get", opts["challenge"])
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        cid = bytes_to_base64url(self.cred_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": bytes_to_base64url(cd), "authenticatorData": bytes_to_base64url(auth),
                             "signature": bytes_to_base64url(sig), "userHandle": self.user}}  # fmt: skip


def _add(e, phone, roles=("Planner",)):
    """Enrol, sign in with password + code, add the phone's passkey, sign out."""
    with _client() as cl:
        uid, totp = _enrolled(e, cl, roles=roles)
        r = _sign_in(cl, totp)
        assert r.headers["location"].startswith("/account?next=")  # no passkey yet: offered at once
        assert "Add a passkey on this device" in cl.get("/account").text
        opts = cl.post("/account/passkeys/options").json()
        assert opts["rp"]["id"] == RP_ID and opts["authenticatorSelection"]["userVerification"] == "required"
        r = cl.post("/account/passkeys", json={"credential": phone.create(opts), "name": "iPhone"})
        assert r.status_code == 200, r.text
        assert "iPhone" in cl.get("/account").text
        cl.post("/logout")
    return uid


def _passkey_sign_in(cl, phone):
    opts = cl.post("/login/passkey/options").json()
    assert opts.get("allowCredentials", []) == []  # discoverable: no username asked
    return cl.post("/login/passkey", json=phone.get(opts))


def test_add_then_sign_in_with_the_passkey_only(local):
    phone = Phone()
    _add(local, phone)
    with _client() as cl:
        r = _passkey_sign_in(cl, phone)
        assert r.status_code == 200 and r.json()["next"] == "/", r.text
        assert tokens.read(cl.cookies.get("cem_at"))["amr"] == ["passkey"]
        assert cl.get("/").status_code == 200
        cl.cookies.delete("cem_at")  # renewed from the refresh token: still a passkey session
        assert cl.get("/").status_code == 200
        assert tokens.read(cl.cookies.get("cem_at"))["amr"] == ["passkey"]
    with local.begin() as c:
        assert c.execute(text("SELECT count(*) FROM audit_log WHERE action = 'signed in'"
                              " AND detail->>'mfa' = 'passkey'")).scalar() == 1  # fmt: skip


def test_a_challenge_serves_once(local):
    phone = Phone()
    _add(local, phone)
    with _client() as cl:
        opts = cl.post("/login/passkey/options").json()
        assert cl.post("/login/passkey", json=phone.get(opts)).status_code == 200
        cl.post("/logout")
        assert cl.post("/login/passkey", json=phone.get(opts)).status_code == 400  # replayed


def test_another_origin_is_refused(local):
    phone = Phone()
    _add(local, phone)
    phone.origin = "https://other.example.org"
    with _client() as cl:
        assert _passkey_sign_in(cl, phone).status_code == 400
        assert not cl.cookies.get("cem_at")


def test_disable_blocks_and_reset_removes_passkeys(local):
    phone = Phone()
    uid = _add(local, phone)
    with local.begin() as c:
        staff.disable(c, uid, "test")
    with _client() as cl:
        assert _passkey_sign_in(cl, phone).status_code == 400
    with local.begin() as c:
        staff.enable(c, uid, "test")
        staff.reset(c, uid, "test")
        assert passkeys.of_user(c, uid) == []
    with _client() as cl:
        assert _passkey_sign_in(cl, phone).status_code == 400


def test_adding_needs_a_recent_sign_in(local, monkeypatch):
    from datetime import timedelta

    with _client() as cl:
        _, totp = _enrolled(local, cl)
        _sign_in(cl, totp)
        monkeypatch.setattr(passkeys, "RECENT", timedelta(0))
        assert "sign out and sign in again" in cl.get("/account").text
        assert cl.post("/account/passkeys/options").status_code == 403


def test_someone_elses_passkey_cannot_be_removed(local):
    phone = Phone()
    _add(local, phone)
    with _client() as cl:
        _, totp = _enrolled(local, cl, username="bob")
        _sign_in(cl, totp, username="bob")
        cl.post(f"/account/passkeys/{phone.cred_id.hex()}/delete")
    with local.begin() as c:
        assert c.execute(text("SELECT count(*) FROM staff_passkey")).scalar() == 1


def test_base64url_helper_round_trip():
    assert base64url_to_bytes(bytes_to_base64url(b"\x00\xff")) == b"\x00\xff"
