"""The batch only reads: what it sends, what it records, and what it never does.

The transport here is the real one, over a loopback server, so the assertion is
about the bytes that actually left the process. A class that starts writing, or
that reads a path nobody declared, fails this file.
"""

from pathlib import Path

import cv2
import numpy as np
import pytest

from models.camera import CameraStatus
from models.finding import CveOutcome
from models.frame import FrameSource
from scanners.cve.auth_bypass import HikvisionAuthBypass
from scanners.cve.base import ReadFailed, ReadMethod, ReadRequest
from tests.conftest import CveLab, MemoryDatabase, RecordingProbe, StubRoute, StubServer

_LOOPBACK = "127.0.0.1"
_READ_VERBS = ("GET", "POST")
_QUERY_SEPARATOR = "?"
_SNAPSHOT_PATH = "/onvif-http/snapshot"
_REDIRECTED_PATH = "/elsewhere"
_SNAPSHOT_CVE = "CVE-2017-7921"
_FIRST = 0
_BATCH_CLASSES = 4
_ONE_FRAME = 1
_FRAME_WIDTH = 64
_FRAME_HEIGHT = 48
_CHANNELS = 3
_JPEG_SUFFIX = ".jpg"
_OK_STATUS = 200
_REDIRECT_STATUS = 302
_JPEG_CONTENT_TYPE = "image/jpeg"

# Every read the batch of D9 sends, as (method, path without its query). The
# assertion is equality, so a class that adds a read or changes a path fails.
_DECLARED_READS: tuple[tuple[str, str], ...] = (
    ("GET", _SNAPSHOT_PATH),
    ("POST", "/cgi-bin/get_file.php"),
    ("GET", "/common/get_file.php"),
    ("GET", "/check.cgi"),
    ("POST", "/onvif/device_service"),
)
_ALL_CVES: tuple[str, ...] = (
    _SNAPSHOT_CVE,
    "CVE-2025-34022",
    "CVE-2016-15055",
    "CVE-2025-65856",
)
_SNAPSHOT_ONLY = (HikvisionAuthBypass,)


@pytest.fixture
def lab(
    database: MemoryDatabase, stub_server: StubServer, tmp_path: Path
) -> CveLab:
    """A camera at the stub server's port, with its frames under tmp_path."""
    return CveLab.at(database, tmp_path, stub_server.port)


@pytest.fixture
def jpeg() -> bytes:
    """A real encoded JPEG, so the decode under test is the real one."""
    frame = np.zeros((_FRAME_HEIGHT, _FRAME_WIDTH, _CHANNELS), dtype=np.uint8)
    encoded_ok, encoded = cv2.imencode(_JPEG_SUFFIX, frame)
    assert encoded_ok
    return encoded.tobytes()


def test_the_read_method_enum_holds_no_write_verb() -> None:
    """D5, FR-003: a write cannot be expressed here, so it cannot be sent."""
    assert [method.value for method in ReadMethod] == list(_READ_VERBS)


def test_a_read_without_a_url_is_refused() -> None:
    with pytest.raises(ReadFailed):
        ReadRequest(method=ReadMethod.get, url="")


def test_a_form_read_without_its_fields_is_refused() -> None:
    """A POST with no body is a write nobody scripted, so it never leaves."""
    with pytest.raises(ReadFailed):
        ReadRequest(method=ReadMethod.form_post, url=f"http://{_LOOPBACK}/read")


def test_the_whole_batch_only_sends_the_declared_reads(
    lab: CveLab, stub_server: StubServer
) -> None:
    """FR-003: the five declared reads, and nothing else, over a real socket."""
    lab.read_batch(lab.deps(probe=RecordingProbe(_ALL_CVES)))
    asked = {
        (method, path.partition(_QUERY_SEPARATOR)[0])
        for method, path in stub_server.asked
    }
    assert asked == set(_DECLARED_READS)
    assert lab.outcomes() == [CveOutcome.no_frame] * _BATCH_CLASSES
    assert lab.frame_rows() == []
    assert lab.stored_camera().status is CameraStatus.responded


def test_a_redirect_is_recorded_and_never_followed(
    lab: CveLab, stub_server: StubServer
) -> None:
    """FR-001: a 3xx is an answer to record, not an address to land on."""
    location = f"http://{_LOOPBACK}:{stub_server.port}{_REDIRECTED_PATH}"
    stub_server.routes[_SNAPSHOT_PATH] = StubRoute(
        status=_REDIRECT_STATUS, headers=(("Location", location),)
    )
    lab.read_batch(
        lab.deps(probe=RecordingProbe((_SNAPSHOT_CVE,)), batch=_SNAPSHOT_ONLY)
    )
    asked = [path.partition(_QUERY_SEPARATOR)[0] for _method, path in stub_server.asked]
    assert asked == [_SNAPSHOT_PATH]
    assert _REDIRECTED_PATH not in [path for _method, path in stub_server.asked]
    assert lab.outcomes() == [CveOutcome.no_frame]
    assert str(_REDIRECT_STATUS) in lab.findings()[_FIRST].failure_reason


def test_a_real_jpeg_becomes_one_stored_frame(
    lab: CveLab, stub_server: StubServer, jpeg: bytes
) -> None:
    """FR-017: the first class that yields a picture is the only one that runs."""
    stub_server.routes[_SNAPSHOT_PATH] = StubRoute(
        status=_OK_STATUS, body=jpeg, content_type=_JPEG_CONTENT_TYPE
    )
    lab.read_batch(lab.deps(probe=RecordingProbe(_ALL_CVES)))
    stored = lab.frame_rows()
    assert len(stored) == _ONE_FRAME
    assert (stored[_FIRST].width, stored[_FIRST].height) == (_FRAME_WIDTH, _FRAME_HEIGHT)
    assert stored[_FIRST].source is FrameSource.cve
    assert (lab.root / stored[_FIRST].path).is_file()
    assert lab.outcomes() == [CveOutcome.frame_obtained]
    assert lab.stored_camera().status is CameraStatus.frame_by_cve
