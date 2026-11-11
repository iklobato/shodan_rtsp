"""The batch runs in order, records every attempt, and stops at the first frame."""

from dataclasses import dataclass, replace
from pathlib import Path

import numpy as np
import pytest

from models.camera import Camera, CameraStatus
from models.finding import CveClass, CveFinding, CveOutcome
from models.frame import FaceFrame
from models.managers import CameraRepository
from models.scan_run import ScanRun
from scanners.config import FramesConfig, TargetsConfig, VulnConfig
from scanners.cve.base import AttemptResult, CveAttempt, CveTarget
from scanners.task import TargetOutsideScopeError
from scanners.vuln_probe import DeviceFingerprint
from scanners.vuln_task import CveDeps, CveTask
from tests.conftest import MemoryDatabase, RecordingProbe

_CAMERA_IP = "10.0.0.1"
_CAMERA_PORT = 554
_ALLOWED_CIDR = "10.0.0.0/24"
_OTHER_CIDR = "127.0.0.1/32"
_VENDOR = "hikvision"
_PRODUCT = "ip camera"
_VERSION = "5.4.5"
_STORED_CPE = "cpe:2.3:h:hikvision:ip_camera:5.4.5:*:*:*:*:*:*:*"
_FIRST_CVE = "CVE-2017-7921"
_SECOND_CVE = "CVE-2016-15055"
_THIRD_CVE = "CVE-2025-34022"
_CVSS = 9.8
_FRAME_SHAPE = (4, 4, 3)
_ONE_FRAME = 1
_NO_FRAME = 0
_TWO_ATTEMPTS = 2


@dataclass(frozen=True)
class Scripted:
    """One class of a fake batch: which CVE it proves, and what it answers."""

    cve_id: str
    cve_class: CveClass
    outcome: AttemptResult


class ScriptedAttempt(CveAttempt):
    """A batch class that records that it ran and answers what the test scripted."""

    def __init__(self, script: Scripted, calls: list[str]) -> None:
        self._script = script
        self._calls = calls

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return (self._script.cve_id,)

    @property
    def cve_class(self) -> CveClass:
        return self._script.cve_class

    def attempt(self, target: CveTarget) -> AttemptResult:
        self._calls.append(self._script.cve_id)
        return self._script.outcome


@dataclass(frozen=True)
class Harness:
    """A stored camera and the database a CVE run writes against."""

    database: MemoryDatabase
    camera: Camera
    root: Path

    def deps(self, attempts: tuple[CveAttempt, ...], probe: RecordingProbe) -> CveDeps:
        """The task's inputs, with the batch and the matcher the test named."""
        return CveDeps(
            config=VulnConfig(web_ports=[]),
            frames=FramesConfig(root_path=str(self.root)),
            targets=TargetsConfig(allowed_cidrs=[_ALLOWED_CIDR]),
            attempts=attempts,
            probe=probe,
        )

    def task(self, deps: CveDeps) -> CveTask:
        return CveTask(deps, database=self.database)

    def findings(self) -> list[CveFinding]:
        """The findings in the order the run opened them."""
        with self.database.session_scope() as session:
            return session.query(CveFinding).order_by(CveFinding.id).all()

    def outcomes(self) -> list[tuple[str, CveOutcome]]:
        """Each finding as (CVE, outcome), in CVE order."""
        return [(finding.cve_id, finding.outcome) for finding in self.findings()]

    def frames(self) -> int:
        with self.database.session_scope() as session:
            return session.query(FaceFrame).count()

    def stored_camera(self) -> Camera:
        """The camera as the database holds it now."""
        return CameraRepository(database=self.database).find_by_id(self.camera.id)

    def last_run(self) -> ScanRun:
        with self.database.session_scope() as session:
            return session.query(ScanRun).order_by(ScanRun.id.desc()).first()


@pytest.fixture
def harness(database: MemoryDatabase, tmp_path: Path) -> Harness:
    """A camera a scan stored with its identity, and where its frames land."""
    camera = CameraRepository(database=database).get_or_create(
        Camera(
            ip=_CAMERA_IP,
            port=_CAMERA_PORT,
            status=CameraStatus.responded,
            vendor=_VENDOR,
            product=_PRODUCT,
            version=_VERSION,
            raw_banner={"source": "nmap", "product": _PRODUCT, "cpe": _STORED_CPE},
        )
    )
    return Harness(database, camera, tmp_path)


def test_the_run_stops_at_the_first_class_that_yields_a_frame(harness: Harness) -> None:
    calls: list[str] = []
    frame = np.zeros(_FRAME_SHAPE, dtype=np.uint8)
    scripts = (
        Scripted(_FIRST_CVE, CveClass.auth_bypass, AttemptResult.recorded("no image")),
        Scripted(_SECOND_CVE, CveClass.unauth_read, AttemptResult.obtained(frame)),
        Scripted(_THIRD_CVE, CveClass.unauth_onvif, AttemptResult.obtained(frame)),
    )
    probe = RecordingProbe((_FIRST_CVE, _SECOND_CVE, _THIRD_CVE))
    attempts = tuple(ScriptedAttempt(script, calls) for script in scripts)
    harness.task(harness.deps(attempts, probe)).run()
    assert calls == [_FIRST_CVE, _SECOND_CVE]
    assert harness.outcomes() == [
        (_FIRST_CVE, CveOutcome.no_frame),
        (_SECOND_CVE, CveOutcome.frame_obtained),
    ]
    assert harness.stored_camera().status is CameraStatus.frame_by_cve
    assert harness.frames() == _ONE_FRAME


def test_a_run_that_yields_no_frame_records_every_reason(harness: Harness) -> None:
    calls: list[str] = []
    scripts = tuple(
        Scripted(cve_id, CveClass.unauth_read, AttemptResult.recorded("no image"))
        for cve_id in (_FIRST_CVE, _SECOND_CVE)
    )
    attempts = tuple(ScriptedAttempt(script, calls) for script in scripts)
    probe = RecordingProbe((_FIRST_CVE, _SECOND_CVE))
    harness.task(harness.deps(attempts, probe)).run()
    assert calls == [_FIRST_CVE, _SECOND_CVE]
    assert [finding.outcome for finding in harness.findings()] == [
        CveOutcome.no_frame
    ] * _TWO_ATTEMPTS
    assert all(finding.failure_reason for finding in harness.findings())
    assert harness.stored_camera().status is CameraStatus.responded
    assert harness.frames() == _NO_FRAME
    assert harness.last_run().finished_at is not None


def test_a_class_whose_cve_is_not_matched_never_runs(harness: Harness) -> None:
    calls: list[str] = []
    scripts = (
        Scripted(_FIRST_CVE, CveClass.auth_bypass, AttemptResult.recorded("no image")),
        Scripted(_SECOND_CVE, CveClass.unauth_read, AttemptResult.recorded("no image")),
    )
    attempts = tuple(ScriptedAttempt(script, calls) for script in scripts)
    probe = RecordingProbe((_SECOND_CVE,))
    harness.task(harness.deps(attempts, probe)).run()
    assert calls == [_SECOND_CVE]
    assert [finding.cve_id for finding in harness.findings()] == [_SECOND_CVE]


def test_the_match_reads_what_the_scan_stored(harness: Harness) -> None:
    """D30, FR-029: the fingerprint comes from the row, never from the XML."""
    probe = RecordingProbe(())
    harness.task(harness.deps((), probe)).run()
    assert probe.asked == [
        DeviceFingerprint(
            host=_CAMERA_IP,
            port=_CAMERA_PORT,
            vendor=_VENDOR,
            product=_PRODUCT,
            version=_VERSION,
            cpe=_STORED_CPE,
        )
    ]


def test_a_camera_outside_the_declared_ranges_is_refused_before_any_read(
    harness: Harness,
) -> None:
    probe = RecordingProbe((_FIRST_CVE,))
    deps = replace(
        harness.deps((), probe), targets=TargetsConfig(allowed_cidrs=[_OTHER_CIDR])
    )
    with pytest.raises(TargetOutsideScopeError):
        harness.task(deps).run()
    assert probe.asked == []
    assert harness.findings() == []
