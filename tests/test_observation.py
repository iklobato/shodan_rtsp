"""One observation per camera per port per run, and never a second camera row."""

from models.camera import Camera, CameraStatus
from models.managers import (
    CameraObservationRepository,
    CameraRepository,
    ScanRunRepository,
)
from models.observation import CameraObservation
from models.scan_run import ScanKind
from tests.conftest import MemoryDatabase

_ADDRESS = "10.0.0.1"
_RTSP_PORT = 554
_TARGET_SET = "10.0.0.0/24"
_ONE_ROW = 1
_TWO_RUNS = 2


def test_one_scan_writes_one_observation_for_the_camera_port(
    database: MemoryDatabase,
) -> None:
    camera = CameraRepository(database=database).get_or_create(
        Camera(ip=_ADDRESS, port=_RTSP_PORT, status=CameraStatus.responded)
    )
    run = ScanRunRepository(database=database).start(ScanKind.nmap, _TARGET_SET)
    CameraObservationRepository(database=database).record(camera, run)
    with database.session_scope() as session:
        stored = session.query(CameraObservation).one()
        assert (stored.camera_id, stored.scan_run_id, stored.port) == (
            camera.id,
            run.id,
            _RTSP_PORT,
        )
        assert stored.status is CameraStatus.responded


def test_recording_the_same_camera_twice_in_one_run_writes_one_row(
    database: MemoryDatabase,
) -> None:
    """A run that sees one camera on one port twice still wrote one observation."""
    camera = CameraRepository(database=database).get_or_create(
        Camera(ip=_ADDRESS, port=_RTSP_PORT)
    )
    run = ScanRunRepository(database=database).start(ScanKind.nmap, _TARGET_SET)
    observations = CameraObservationRepository(database=database)
    first = observations.record(camera, run)
    second = observations.record(camera, run)
    assert second.id == first.id
    with database.session_scope() as session:
        assert session.query(CameraObservation).count() == _ONE_ROW


def test_a_repeated_scan_keeps_one_camera_and_one_observation_per_run(
    database: MemoryDatabase,
) -> None:
    """The second run adds its own observation and no second camera (FR-006)."""
    camera = CameraRepository(database=database).get_or_create(
        Camera(ip=_ADDRESS, port=_RTSP_PORT)
    )
    observations = CameraObservationRepository(database=database)
    runs = ScanRunRepository(database=database)
    observations.record(camera, runs.start(ScanKind.nmap, _TARGET_SET))
    observations.record(camera, runs.start(ScanKind.nmap, _TARGET_SET))
    with database.session_scope() as session:
        assert session.query(Camera).count() == _ONE_ROW
        assert session.query(CameraObservation).count() == _TWO_RUNS
