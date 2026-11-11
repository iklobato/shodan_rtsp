"""Shared test support.

The database fake lives here because every model test needs one, and the lab
server must not be a requirement for the unit suite: sqlite in memory holds the
same seven tables (`models/base.py` makes the PostgreSQL-only pieces of the
schema dialect-conditional).

The capture fake lives here for the same reason: the RTSP probe is tested for
what it logs and which URL it opens, and neither needs a camera or ffmpeg.
"""

from collections.abc import Iterator
from contextlib import contextmanager

import numpy as np
import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from models.base import BASE
from scanners import rtsp_probe

_FRAME_SHAPE: tuple[int, ...] = (2, 2, 3)


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


class FakeCapture:
    """Stands in for the cv2 capture: one frame per read, and the URL it opened.

    `readable` is set to False by a test that wants the camera which answers
    nothing, so the branch that logs and returns None is reachable without one.
    """

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.readable = True

    @contextmanager
    def __call__(self, url: str) -> Iterator["FakeCapture"]:
        """Install as `_opened_capture`: record the URL, then yield this capture."""
        self.urls.append(url)
        yield self

    def read(self) -> tuple[bool, np.ndarray | None]:
        """One frame, or nothing at all when the test asked for a silent camera."""
        if not self.readable:
            return False, None
        return True, np.zeros(_FRAME_SHAPE, dtype=np.uint8)


@pytest.fixture
def opened_frames(monkeypatch: pytest.MonkeyPatch) -> FakeCapture:
    """Replace the cv2 capture, so probing needs no camera and no ffmpeg."""
    capture = FakeCapture()
    monkeypatch.setattr(rtsp_probe, "_opened_capture", capture)
    return capture
