"""The package's own tables: one engine per URL, plain-SQL migrations applied in order under an advisory lock and
recorded in schema_version (the same scheme as the host app's, so the two share a database safely)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from sqlalchemy import Engine, create_engine, text

MIGRATIONS = Path(__file__).parent / "migrations"
LOCK = 4941


@lru_cache
def engine_for(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, future=True)


def migrate(eng: Engine, folder: Path = MIGRATIONS, lock: int = LOCK) -> list[int]:
    """Apply the migrations not applied yet; returns their numbers."""
    done: list[int] = []
    with eng.begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(:l)"), {"l": lock})
        have = c.execute(text("SELECT to_regclass('schema_version')")).scalar()
        applied = set(c.execute(text("SELECT version FROM schema_version")).scalars()) if have else set()
        for f in sorted(folder.glob("[0-9][0-9][0-9]_*.sql")):
            n = int(f.name[:3])
            if n in applied:
                continue
            c.exec_driver_sql(f.read_text())
            c.execute(text("INSERT INTO schema_version (version) VALUES (:v)"), {"v": n})
            done.append(n)
    return done
