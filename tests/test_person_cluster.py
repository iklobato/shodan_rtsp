"""One face seen twice is one person, and a camera is read the way it was read.

The scan reads the frames the pipeline already stored, so a camera whose only
frame came through a CVE class is scanned without a stream to open (D33). Only a
camera holding no frame is captured over RTSP.
"""

from dataclasses import replace
from datetime import datetime, timezone

import numpy as np
import pytest

from models.frame import FrameSource
from models.scan_run import ScanKind
from scanners.config import FaceConfig, TargetsConfig
from scanners.rtsp_probe import ProbeResult, RtspTarget
from scanners.task import TargetOutsideScopeError, UnknownCameraError
from tests.conftest import (
    FaceLab,
    FakeCapture,
    FakeDetector,
    FakeFace,
    Vectors,
)

_FIRST_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_SECOND_MOMENT = datetime(2026, 11, 11, 11, 2, 41, tzinfo=timezone.utc)
_CAMERA_IP = "10.0.0.1"
_CAMERA_URL = "rtsp://admin:lab@10.0.0.1:554/Streaming/Channels/1"
_OUTSIDE_CIDR = "127.0.0.1/32"
_UNKNOWN_CAMERA = 99
# The same person at a slightly different angle: a match at the lab threshold.
_SAME_FACE_DEGREES = 5.0
_ONE_PERSON = 1
_ONE_CAMERA = 1
_ONE_FRAME = 1
_ONE_FACE = 1
_TWO_FRAMES = 2
_THREE_FRAMES = 3
_FRAME_SHAPE: tuple[int, ...] = (2, 2, 3)


class WatchingProbe:
    """The lab stream, watched: it answers a frame and says what was stored then.

    `stored_at_capture` holds how many frame rows the run had already written
    when each capture started, so a test sees the order of capture and store
    without reading a clock.
    """

    def __init__(self, lab: FaceLab) -> None:
        self._lab = lab
        self.stored_at_capture: list[int] = []

    def probe(self, target: RtspTarget) -> ProbeResult:
        """One frame, and the count of rows the run holds at this instant."""
        self.stored_at_capture.append(len(self._lab.frames()))
        return ProbeResult(
            camera=self._lab.camera, frame=np.zeros(_FRAME_SHAPE, dtype=np.uint8)
        )


def test_each_frame_of_one_capture_is_stored_before_the_next_is_read(
    face_lab: FaceLab,
) -> None:
    """A run over a camera holding no frame keeps every frame it captured."""
    probe = WatchingProbe(face_lab)
    detector = FakeDetector([[FakeFace.of(Vectors.unit(0.0))]] * _THREE_FRAMES)
    deps = face_lab.deps(detector, probe)
    config = deps.config.model_copy(update={"frames_per_scan": _THREE_FRAMES})
    deps = replace(deps, config=config)

    face_lab.scan(deps)

    stored = face_lab.frames()
    assert len({frame.path for frame in stored}) == _THREE_FRAMES
    assert len(detector.seen) == _THREE_FRAMES
    assert probe.stored_at_capture == list(range(_THREE_FRAMES))


def test_the_same_face_in_two_frames_of_one_run_is_one_person(
    face_lab: FaceLab,
) -> None:
    """FR-022: the second sighting joins the person the first one opened."""
    first = face_lab.frame(_FIRST_MOMENT)
    second = face_lab.frame(_SECOND_MOMENT, FrameSource.cve)
    detector = FakeDetector(
        [
            [FakeFace.of(Vectors.unit(0.0))],
            [FakeFace.of(Vectors.unit(_SAME_FACE_DEGREES))],
        ]
    )

    face_lab.scan(face_lab.deps(detector))

    people = face_lab.people()
    assert len(people) == _ONE_PERSON
    assert [face.person_id for face in face_lab.faces()] == [people[0].id] * _TWO_FRAMES
    assert [face.frame_id for face in face_lab.faces()] == [first, second]
    assert len(detector.seen) == _TWO_FRAMES


def test_a_frame_that_came_by_cve_is_read_without_opening_a_stream(
    face_lab: FaceLab,
    opened_frames: FakeCapture,
) -> None:
    """D33: the frame the CVE class obtained is read at its own row."""
    stored = face_lab.frame(_FIRST_MOMENT, FrameSource.cve)

    face_lab.scan(face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(0.0))]])))

    assert opened_frames.urls == []
    assert [face.frame_id for face in face_lab.faces()] == [stored]
    assert len(face_lab.frames()) == _ONE_FRAME


def test_a_camera_holding_no_frame_is_captured_over_rtsp(
    face_lab: FaceLab,
    opened_frames: FakeCapture,
) -> None:
    """Only a camera the pipeline never obtained a frame for is opened."""
    face_lab.scan(face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(0.0))]])))

    assert opened_frames.urls == [_CAMERA_URL]
    assert [(frame.source, frame.camera_id) for frame in face_lab.frames()] == [
        (FrameSource.rtsp, face_lab.camera.id)
    ]
    assert len(face_lab.faces()) == _ONE_FACE


def test_the_run_is_recorded_as_a_face_run_and_closed(face_lab: FaceLab) -> None:
    face_lab.frame(_FIRST_MOMENT)

    face_lab.scan(face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(0.0))]])))

    run = face_lab.last_run()
    assert run.kind is ScanKind.faces
    assert run.target_set == _CAMERA_IP
    assert run.camera_count == _ONE_CAMERA
    assert run.finished_at is not None


def test_a_wide_run_over_an_address_outside_the_declared_ranges_is_refused(
    face_lab: FaceLab,
) -> None:
    """FR-001: the gate refuses before any packet leaves, and nothing is written."""
    deps = replace(
        face_lab.deps(FakeDetector([])),
        targets=TargetsConfig(allowed_cidrs=[_OUTSIDE_CIDR]),
    )

    with pytest.raises(TargetOutsideScopeError):
        face_lab.scan(deps)

    assert face_lab.people() == []
    assert face_lab.last_run() is None


def test_a_run_narrowed_to_one_camera_is_not_gated(face_lab: FaceLab) -> None:
    """D18: the address the operator typed is the authorization itself."""
    face_lab.frame(_FIRST_MOMENT)
    deps = replace(
        face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(0.0))]])),
        targets=TargetsConfig(allowed_cidrs=[_OUTSIDE_CIDR]),
        camera_id=face_lab.camera.id,
    )

    face_lab.scan(deps)

    assert len(face_lab.people()) == _ONE_PERSON


def test_a_run_narrowed_to_a_camera_that_is_not_stored_is_refused(
    face_lab: FaceLab,
) -> None:
    deps = replace(face_lab.deps(FakeDetector([])), camera_id=_UNKNOWN_CAMERA)

    with pytest.raises(UnknownCameraError, match=f"no camera with id {_UNKNOWN_CAMERA}"):
        face_lab.scan(deps)


def test_a_disabled_scan_reaches_no_camera(
    face_lab: FaceLab,
    opened_frames: FakeCapture,
) -> None:
    deps = replace(face_lab.deps(FakeDetector([])), config=FaceConfig(enabled=False))

    face_lab.scan(deps)

    assert opened_frames.urls == []
    assert face_lab.last_run() is None
