"""Shared test support.

The database fake lives here because every model test needs one, and the lab
server must not be a requirement for the unit suite: sqlite in memory holds the
same seven tables (`models/base.py` makes the PostgreSQL-only pieces of the
schema dialect-conditional).
"""

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from models.base import BASE


class MemoryDatabase:
    """A Database stand-in backed by one shared in-memory sqlite connection."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def create_schema(self) -> None:
        """Build every table of the schema on the empty in-memory database."""
        BASE.metadata.create_all(self.engine)

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Yield a session, commit on success, always close.

        `expire_on_commit=False` matches `models/database.py`: the repositories
        hand back detached rows that callers read after the scope closed.
        """
        session = Session(bind=self.engine, expire_on_commit=False)
        try:
            yield session
            session.commit()
        finally:
            session.close()


@pytest.fixture
def database() -> MemoryDatabase:
    """An empty in-memory database with the whole schema already built on it."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    memory = MemoryDatabase(engine)
    memory.create_schema()
    return memory
