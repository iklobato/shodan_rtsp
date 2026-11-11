"""A device that never answers is a recorded reason and a closed run (FR-020).

Two real sockets, no fake transport: one port that refuses the connection
outright, and one that lets it in and then says nothing. The second is the case
the timeout exists for, so the test measures the clock as well.
"""

import socket
import time

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from models.camera import CameraStatus
from models.finding import CveOutcome
from scanners.cve.auth_bypass import HikvisionAuthBypass
from tests.conftest import CveLab, CveDeps, MemoryDatabase, RecordingProbe

_LOOPBACK = "127.0.0.1"
_TIMEOUT_SECONDS = 0.5
_CEILING_SECONDS = 10.0
_PORT_INDEX = 1
_BACKLOG = 1
_FIRST = 0
_SNAPSHOT_CVE = "CVE-2017-7921"
_SNAPSHOT_ONLY = (HikvisionAuthBypass,)


@pytest.fixture
def silent_port() -> Iterator[int]:
    """A loopback port that lets the connection in and then says nothing.

    The kernel completes the handshake from the listen backlog, so the client
    connects and waits for an answer that never comes: exactly the device the
    timeout is for. A refused port would fail at connect instead.
    """
    listening = socket.socket()
    listening.bind((_LOOPBACK, 0))
    listening.listen(_BACKLOG)
    try:
        yield listening.getsockname()[_PORT_INDEX]
    finally:
        listening.close()


@pytest.fixture
def refused_port() -> int:
    """A loopback port nothing listens on: bound to learn the number, then closed."""
    reservation = socket.socket()
    reservation.bind((_LOOPBACK, 0))
    port = reservation.getsockname()[_PORT_INDEX]
    reservation.close()
    return port


@dataclass(frozen=True)
class Case:
    """One camera, and the single read this file sends at it."""

    lab: CveLab
    deps: CveDeps

    @classmethod
    def at(cls, database: MemoryDatabase, root: Path, port: int) -> "Case":
        """A camera at one port, and the one class read with the short timeout."""
        lab = CveLab.at(database, root, port)
        return cls(
            lab,
            lab.deps(
                RecordingProbe((_SNAPSHOT_CVE,)),
                batch=_SNAPSHOT_ONLY,
                timeout=_TIMEOUT_SECONDS,
            ),
        )

    def elapsed_read(self) -> float:
        """Run the one read and return how long the whole run took."""
        started = time.monotonic()
        self.lab.read_batch(self.deps)
        return time.monotonic() - started


@pytest.fixture
def silent(database: MemoryDatabase, tmp_path: Path, silent_port: int) -> Case:
    """A camera at the port that holds the connection and never answers."""
    return Case.at(database, tmp_path, silent_port)


@pytest.fixture
def refused(database: MemoryDatabase, tmp_path: Path, refused_port: int) -> Case:
    """A camera at the port that refuses the connection outright."""
    return Case.at(database, tmp_path, refused_port)


def test_a_device_that_never_answers_ends_at_the_timeout(silent: Case) -> None:
    """FR-020: the read is bounded, and the bound is what ends it."""
    elapsed = silent.elapsed_read()
    assert _TIMEOUT_SECONDS <= elapsed < _CEILING_SECONDS
    assert silent.lab.outcomes() == [CveOutcome.no_frame]
    reason = silent.lab.findings()[_FIRST].failure_reason
    assert "unreachable" in reason
    assert str(silent.lab.camera.port) in reason


def test_a_port_that_refuses_the_connection_is_also_a_recorded_reason(
    refused: Case,
) -> None:
    """A refused port answers at once, and the reason says which port it was."""
    assert refused.elapsed_read() < _CEILING_SECONDS
    assert refused.lab.outcomes() == [CveOutcome.no_frame]
    assert "unreachable" in refused.lab.findings()[_FIRST].failure_reason


def test_a_run_that_never_got_a_frame_still_finished(silent: Case) -> None:
    """The camera keeps its status, no frame is stored, and the run is closed."""
    silent.elapsed_read()
    assert silent.lab.frame_rows() == []
    assert silent.lab.stored_camera().status is CameraStatus.responded
    assert silent.lab.last_run().finished_at is not None
