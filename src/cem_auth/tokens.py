"""Access tokens: JWT signed with Ed25519 (EdDSA). Only this app holds the private key (a mounted file, mode
0600, never in the image or the repo); other cem-os pieces check tokens with the public key from
/.well-known/jwks.json. An access token lives `access_min` minutes; the refresh token (staff.py) renews it."""

from __future__ import annotations

import base64
import hashlib
import stat
import time
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cem_auth.config import settings

AUDIENCE = "cem"


class KeyProblem(RuntimeError):
    pass


def check_key_file(path: Path) -> None:
    """Refuse a missing key, a key readable by others, or one that is not Ed25519."""
    if not path.is_file():
        raise KeyProblem(f"JWT key file {path} is missing")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyProblem(f"JWT key file {path} must be readable by its owner only (chmod 600)")
    if not isinstance(_load(path), Ed25519PrivateKey):
        raise KeyProblem(f"JWT key file {path} is not an Ed25519 private key")


def _load(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


@lru_cache
def _private() -> Ed25519PrivateKey:
    path = settings().jwt_key_file
    check_key_file(path)
    return _load(path)


def _public() -> Ed25519PublicKey:
    return _private().public_key()


def _raw_public() -> bytes:
    return _public().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid() -> str:
    return hashlib.sha256(_raw_public()).hexdigest()[:16]


def issue(claims: dict, minutes: int | None = None) -> str:
    now = int(time.time())
    body = {"iss": settings().public_url, "aud": AUDIENCE, "iat": now,
            "exp": now + 60 * (minutes or settings().access_min)} | claims  # fmt: skip
    return jwt.encode(body, _private(), algorithm="EdDSA", headers={"kid": kid()})


def read(token: str) -> dict | None:
    """The claims of a valid, unexpired token from this issuer, else None."""
    try:
        return jwt.decode(token, _public(), algorithms=["EdDSA"], audience=AUDIENCE, issuer=settings().public_url)
    except jwt.PyJWTError:
        return None


def jwks() -> dict:
    x = base64.urlsafe_b64encode(_raw_public()).rstrip(b"=").decode()
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid(), "x": x}]}


def new_key_pem() -> bytes:
    """A new Ed25519 private key as PEM (for the CLI's keygen)."""
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
