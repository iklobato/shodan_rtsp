"""The cve_finding invariants: one row per camera and CVE, and an honest outcome."""

from dataclasses import dataclass

import pytest
from sqlalchemy.exc import IntegrityError

from models.camera import Camera
from models.finding import CveClass, CveFinding, CveOutcome
from models.frame import FaceFrame, FrameSource
from models.managers import (
    CameraRepository,
    CveFindingRepository,
    FaceFrameRepository,
    ScanRunRepository,
)
from models.scan_run import ScanKind, ScanRun
from tests.conftest import MemoryDatabase

_ADDRESS = "10.0.0.1"
_PORT = 80
_CVE_ID = "CVE-2017-7921"
_OTHER_CVE = "CVE-2016-15055"
_MATCHED_RANGE = "<5.4.5"
_NEWER_RANGE = "<=5.4.4"
_CVSS = 9.8
_NEWER_CVSS = 7.5
_FRAME_WIDTH = 640
_FRAME_HEIGHT = 480
_LONG_REASON = 900
_COLUMN_WIDTH = 480
_ONE_ROW = 1
_TWO_ROWS = 2


@dataclass(frozen=True)
class Stage:
    """The database, the camera and the run one finding test writes against."""

    database: MemoryDatabase
    camera: Camera
    run: ScanRun

    def row(self, cve_id: str = _CVE_ID) -> CveFinding:
        """The finding of one CVE, as the task opens it before the attempt."""
        return CveFinding(
            camera_id=self.camera.id,
            scan_run_id=self.run.id,
            cve_id=cve_id,
            cve_class=CveClass.auth_bypass,
        )

    def stored(self, cve_id: str = _CVE_ID) -> CveFinding:
        """The row as the database holds it now."""
        with self.database.session_scope() as session:
            return session.query(CveFinding).filter(CveFinding.cve_id == cve_id).one()

    def rows(self) -> int:
        with self.database.session_scope() as session:
            return session.query(CveFinding).count()

    def frame_row(self) -> int:
        """A stored frame, which a finding may point at."""
        return FaceFrameRepository(database=self.database).record(
            FaceFrame(
                camera_id=self.camera.id,
                scan_run_id=self.run.id,
                path=f"{self.camera.id}/20260101T000000Z-cve.jpg",
                source=FrameSource.cve,
                width=_FRAME_WIDTH,
                height=_FRAME_HEIGHT,
            )
        ).id


@pytest.fixture
def stage(database: MemoryDatabase) -> Stage:
    """A camera a scan stored, and the CVE run that reads it."""
    camera = CameraRepository(database=database).get_or_create(
        Camera(ip=_ADDRESS, port=_PORT)
    )
    run = ScanRunRepository(database=database).start(ScanKind.cve, _ADDRESS)
    return Stage(database, camera, run)


def test_a_second_run_updates_the_row_instead_of_adding_one(stage: Stage) -> None:
    findings = CveFindingRepository(database=stage.database)
    first = findings.upsert(stage.row())
    second = findings.upsert(stage.row())
    assert second.id == first.id
    assert stage.rows() == _ONE_ROW


def test_a_second_match_keeps_the_row_and_refreshes_the_range(stage: Stage) -> None:
    """`first_seen_at` keeps the history, so a new range updates in place."""
    findings = CveFindingRepository(database=stage.database)
    findings.upsert(stage.row())
    newer = stage.row()
    newer.matched_range = _NEWER_RANGE
    newer.cvss = _NEWER_CVSS
    findings.upsert(newer)
    stored = stage.stored()
    assert (stored.cvss, stored.matched_range) == (_NEWER_CVSS, _NEWER_RANGE)


def test_two_cves_on_one_camera_are_two_rows(stage: Stage) -> None:
    """The pair (camera, CVE) is the identity, so a second CVE is a second row."""
    findings = CveFindingRepository(database=stage.database)
    findings.upsert(stage.row(_CVE_ID))
    findings.upsert(stage.row(_OTHER_CVE))
    assert stage.rows() == _TWO_ROWS


def test_a_frame_outcome_carries_the_frame_and_no_reason(stage: Stage) -> None:
    findings = CveFindingRepository(database=stage.database)
    frame_id = stage.frame_row()
    findings.record_frame(findings.upsert(stage.row()), frame_id)
    stored = stage.stored()
    assert stored.outcome is CveOutcome.frame_obtained
    assert (stored.frame_id, stored.failure_reason) == (frame_id, "")
    assert stored.last_attempt_at is not None


def test_an_attempt_that_yielded_no_frame_carries_its_reason(stage: Stage) -> None:
    findings = CveFindingRepository(database=stage.database)
    findings.record_failure(
        findings.upsert(stage.row()), "CVE-2017-7921: no image; 80 HTTP 404 0B"
    )
    stored = stage.stored()
    assert stored.outcome is CveOutcome.no_frame
    assert stored.failure_reason == "CVE-2017-7921: no image; 80 HTTP 404 0B"
    assert stored.frame_id is None


def test_a_long_reason_is_cut_to_the_width_of_the_column(stage: Stage) -> None:
    """A reason longer than the column loses its tail, never the whole write."""
    findings = CveFindingRepository(database=stage.database)
    findings.record_failure(findings.upsert(stage.row()), "x" * _LONG_REASON)
    assert len(stage.stored().failure_reason) == _COLUMN_WIDTH


def test_the_schema_refuses_a_frame_outcome_without_a_frame(stage: Stage) -> None:
    stored = stage.row()
    stored.outcome = CveOutcome.frame_obtained
    with pytest.raises(IntegrityError):
        with stage.database.session_scope() as session:
            session.add(stored)


def test_the_schema_refuses_a_no_frame_outcome_without_a_reason(stage: Stage) -> None:
    stored = stage.row()
    stored.outcome = CveOutcome.no_frame
    with pytest.raises(IntegrityError):
        with stage.database.session_scope() as session:
            session.add(stored)
