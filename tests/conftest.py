"""Tests run against a *_test database (they truncate the tables) and a demo app built from cem-auth alone."""

import os

os.environ.update({
    "CORE_DATABASE_URL": os.environ.get("CEM_AUTH_TEST_DB",
                                        "postgresql+psycopg://auth:auth@127.0.0.1:5432/cem_auth_test"),
    "TOTP_KEY": "T3Bzr0dQ9t6xq2m1yQ4Wc7nVZp8aJk5LbH0sD2fG4hE=",
    "SECRET_KEY": "s" * 40,
})  # fmt: skip
assert os.environ["CORE_DATABASE_URL"].rsplit("/", 1)[-1].endswith("_test"), "tests need a *_test database"
