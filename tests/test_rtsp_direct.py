"""The direct RTSP path still works once the proxy is gone (T026).

D11 retires the residential proxy, so a probe reaches the camera straight from
the local IP and takes no proxy to do it. These are the guards that the probe
still opens the target URL unchanged, still reads a frame, and still hands back
the camera it reached: the three things the removal could quietly break.
"""

import pytest

from models.camera import CameraStatus
from scanners.rtsp_probe import RtspProbe, RtspTarget
from tests.conftest import FakeCapture

_USER = "admin"
_PASSWORD = "1234"
_URL_TEMPLATE = "rtsp://{}:{}@{}:{}/live"
_HOST = "10.0.0.5"
_PORT = 554
_FRAME_SHAPE = (2, 2, 3)


@pytest.fixture
def target() -> RtspTarget:
    """The lab endpoint the probe is asked to open, with its credentials."""
    return RtspTarget(
        host=_HOST,
        port=_PORT,
        user=_USER,
        password=_PASSWORD,
        url_template=_URL_TEMPLATE,
    )


def test_the_probe_opens_the_target_url_with_nothing_configured(
    opened_frames: FakeCapture, target: RtspTarget
) -> None:
    """No proxy, no tunnel: the camera is opened at its own address and port."""
    RtspProbe().probe(target)

    assert opened_frames.urls == [target.url], (
        f"expected the probe to open {target.url}, got {opened_frames.urls}"
    )


def test_the_probe_returns_the_camera_it_reached(
    opened_frames: FakeCapture, target: RtspTarget
) -> None:
    probe_result = RtspProbe().probe(target)

    assert probe_result is not None, "the capture answered, so the probe won"
    assert (probe_result.camera.ip, probe_result.camera.port) == (_HOST, _PORT)
    assert probe_result.camera.status is CameraStatus.stream_obtained


def test_the_probe_returns_the_frame_it_read(
    opened_frames: FakeCapture, target: RtspTarget
) -> None:
    probe_result = RtspProbe().probe(target)

    assert probe_result is not None, "the capture answered, so the probe won"
    assert probe_result.frame.shape == _FRAME_SHAPE, (
        f"expected the frame the capture read, got shape {probe_result.frame.shape}"
    )


def test_a_camera_that_never_answers_returns_nothing(
    opened_frames: FakeCapture, target: RtspTarget
) -> None:
    """A dead camera is a None, not an exception that ends the whole run."""
    opened_frames.readable = False

    assert RtspProbe().probe(target) is None
