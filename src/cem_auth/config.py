"""Settings, from the environment (or a .env file) or set by the host app with `configure()`.

The host app owns: the role names and what each may do (`roles`, `perms_of`), how a page is rendered around the
package's templates (`render`, optional), its name in authenticator apps and passkey prompts (`issuer`)."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = "change-me"  # signs the session cookie (pre-sign-in step, passkey challenges)
    totp_key: str = ""  # Fernet key: encrypts the TOTP secrets at rest
    core_database_url: str = "postgresql+psycopg://auth:auth@127.0.0.1:5432/auth"
    jwt_key_file: Path = Path("/run/secrets/jwt_ed25519.pem")  # Ed25519 private key, mode 0600
    public_url: str = "https://app.example.org"  # the JWT issuer and the origin that may POST
    allowed_origins: list[str] = []  # more origins that may POST with a cookie
    passkey_rp_id: str = "example.org"  # passkeys are bound to it for good
    access_min: int = 15
    session_idle_h: int = 12
    session_max_days: int = 7
    enrol_link_hours: int = 24
    service_keys: dict[str, str] = {}  # {"name": "<sha256 of its bearer key>"}: read-only machine callers
    timezone: str = "UTC"  # times shown on the account page
    issuer: str = "cem-os"  # the name in authenticator apps and passkey prompts


@lru_cache
def settings() -> Settings:
    return Settings()


class _Host:
    roles: tuple[str, ...] = ("Viewer", "Admin")
    admin_role: str = "Admin"
    users_perm: str = "admin.users"  # may open /users
    lines: tuple[str, ...] = ("All",)  # optional scope fields on a role grant
    materials: tuple[str, ...] = ("All",)
    perms_of: Callable[[list[str]], frozenset[str]] = staticmethod(
        lambda roles: frozenset(roles) | ({"admin.users"} if "Admin" in roles else set())
    )
    render: Callable | None = None  # (request, template, status_code, **ctx) -> Response; None: the package's own


HOST = _Host()


def configure(**kw) -> None:
    """Set the host's roles and hooks; settings fields given here override the environment."""
    for k, v in kw.items():
        if hasattr(_Host, k):
            setattr(HOST, k, staticmethod(v) if k in ("perms_of", "render") and v else v)
        elif k in Settings.model_fields:
            setattr(settings(), k, v)
        else:
            raise TypeError(f"unknown setting {k!r}")
