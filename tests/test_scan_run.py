"""A scan run keeps the record of what the run was allowed to reach."""

import pytest

from models.base import InvalidEntity
from models.managers import ScanRunRepository
from models.scan_run import ScanKind, ScanRun
from tests.conftest import MemoryDatabase

_TARGET_SET = "127.0.0.1/32"
_CAMERAS_FOUND = 3


def test_a_started_run_records_the_target_set_it_reached(
    database: MemoryDatabase,
) -> None:
    """The target set is the only answer, after the fact, to what the run reached."""
    ScanRunRepository(database=database).start(ScanKind.nmap, _TARGET_SET)
    with database.session_scope() as session:
        stored = session.query(ScanRun).one()
        assert (stored.kind, stored.target_set) == (ScanKind.nmap, _TARGET_SET)


def test_a_started_run_has_no_finish_and_no_cameras_yet(
    database: MemoryDatabase,
) -> None:
    run = ScanRunRepository(database=database).start(ScanKind.nmap, _TARGET_SET)
    assert (run.finished_at, run.camera_count) == (None, 0)


def test_finishing_a_run_keeps_the_camera_count(database: MemoryDatabase) -> None:
    runs = ScanRunRepository(database=database)
    run = runs.start(ScanKind.nmap, _TARGET_SET)
    runs.finish(run, _CAMERAS_FOUND)
    with database.session_scope() as session:
        stored = session.query(ScanRun).one()
        assert stored.camera_count == _CAMERAS_FOUND
        assert stored.finished_at is not None


def test_a_run_without_a_target_set_is_refused() -> None:
    with pytest.raises(InvalidEntity, match="target_set is required"):
        ScanRun(kind=ScanKind.nmap, target_set="   ")
