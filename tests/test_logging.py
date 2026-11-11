"""No credential value reaches a log line, at any level (T025).

`RtspProbe` is the only place that holds a user and a password together, so it
is the only place that can leak one. It used to log both at INFO, and the URL it
logged at DEBUG carried them as well: a credential that only leaks under `-v` is
still a credential sitting in `logs/rtsp_scanner.log`.

Every level is checked, not just the one the leak was found at, because the next
line someone adds is the one that gets missed.
"""

import logging

import pytest

from scanners.rtsp_probe import RtspProbe, RtspTarget
from tests.conftest import FakeCapture

_USER = "leakeduser"
_PASSWORD = "leakedpassword"
_URL_TEMPLATE = "rtsp://{}:{}@{}:{}/live"
_HOST = "10.0.0.5"
_PORT = 554


@pytest.fixture
def target() -> RtspTarget:
    """The endpoint the probe is asked to open, with credentials it must not log."""
    return RtspTarget(
        host=_HOST,
        port=_PORT,
        user=_USER,
        password=_PASSWORD,
        url_template=_URL_TEMPLATE,
    )


def test_the_url_the_probe_opens_carries_both_credentials(target: RtspTarget) -> None:
    """The control: logging this URL would leak them, so the checks below bite."""
    assert _USER in target.url and _PASSWORD in target.url, (
        f"expected both credentials inside {target.url}, which is what makes a "
        "log of the URL a leak"
    )


def test_a_probe_that_grabs_a_frame_logs_no_credential(
    opened_frames: FakeCapture, target: RtspTarget, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    probe_result = RtspProbe().probe(target)

    assert probe_result is not None, "the capture answered, so the probe won"
    messages = [record.getMessage() for record in caplog.records]
    assert messages, "the probe logged nothing, so this test checks nothing"
    leaked = [
        message for message in messages if _USER in message or _PASSWORD in message
    ]
    assert leaked == [], f"a credential reached the log: {leaked}"


def test_a_camera_that_sends_no_frame_logs_no_credential(
    opened_frames: FakeCapture, target: RtspTarget, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    opened_frames.readable = False

    probe_result = RtspProbe().probe(target)

    assert probe_result is None, "the capture answered nothing, so the probe lost"
    messages = [record.getMessage() for record in caplog.records]
    assert messages, "the probe logged nothing, so this test checks nothing"
    leaked = [
        message for message in messages if _USER in message or _PASSWORD in message
    ]
    assert leaked == [], f"a credential reached the log: {leaked}"
