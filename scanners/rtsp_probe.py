"""Confirm an RTSP camera answers by grabbing one frame.

The probe opens the camera at its own address, straight from the local IP: D11
retired the residential proxy, so there is no tunnel left to relay through. Each
attempt is forced to RTSP over TCP and bounded at 8 s, so a camera that never
answers costs one timeout instead of holding the run.
"""

import logging
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Protocol

import cv2
import numpy as np

from models.camera import Camera, CameraStatus

# Force RTSP over TCP so control and media share one connection, and bound one
# attempt: stimeout is in microseconds, so a dead camera costs 8 s and no more.
_TCP_CAPTURE_OPTIONS = "rtsp_transport;tcp|stimeout;8000000"


@dataclass(frozen=True)
class RtspTarget:
    """A single RTSP endpoint to try, with the credentials and URL template."""

    host: str
    port: int
    user: str
    password: str
    url_template: str

    @property
    def url(self) -> str:
        return self.url_template.format(self.user, self.password, self.host, self.port)


@dataclass(frozen=True)
class ProbeResult:
    """What a probe that answered produced: the camera and one frame.

    The frame used to travel in a `Camera` column as hex text; the schema keeps
    frames as files now (D17), so it travels as the decoded array instead.
    """

    camera: Camera
    frame: np.ndarray


_capture_options_lock = threading.Lock()
_capture_options_depth = 0
_capture_options_previous = None


@contextmanager
def _ffmpeg_tcp_transport() -> Iterator[None]:
    """Force OpenCV/FFmpeg to RTSP-over-TCP for the duration, then restore.

    The option is a process-global env var, so under a CheckTask thread pool a
    per-call set/restore would race: one probe's restore could clear it while
    another is opening its capture. A depth counter keeps it set while any probe
    is active and restores the prior value only when the last one leaves.
    """
    global _capture_options_depth, _capture_options_previous
    with _capture_options_lock:
        if _capture_options_depth == 0:
            _capture_options_previous = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = _TCP_CAPTURE_OPTIONS
        _capture_options_depth += 1
    try:
        yield
    finally:
        with _capture_options_lock:
            _capture_options_depth -= 1
            if _capture_options_depth == 0:
                if _capture_options_previous is None:
                    os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
                else:
                    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = (
                        _capture_options_previous
                    )


@contextmanager
def _opened_capture(url: str) -> Iterator[cv2.VideoCapture]:
    capture = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
    try:
        yield capture
    finally:
        capture.release()


class Transport(Protocol):
    """Yields the URL OpenCV should open for a target."""

    def open(self, target: RtspTarget) -> "Iterator[str]": ...


class DirectTransport:
    """Open the camera at its own address, straight from the local IP."""

    @contextmanager
    def open(self, target: RtspTarget) -> Iterator[str]:
        with _ffmpeg_tcp_transport():
            yield target.url


class RtspProbe:
    """Opens an RTSP stream through a Transport and grabs one frame."""

    def __init__(self, transport: Transport = None):
        self._transport = transport

    def probe(self, target: RtspTarget) -> ProbeResult | None:
        with self._transport_or_default().open(target) as url:
            return self._grab(url, target)

    def _transport_or_default(self) -> Transport:
        """The injected transport, or the direct one when none was given."""
        return self._transport or DirectTransport()

    def _grab(self, url: str, target: RtspTarget) -> ProbeResult | None:
        """Log what was reached by address only: the URL carries the credentials."""
        logging.debug("Opening %s:%s", target.host, target.port)
        with _opened_capture(url) as capture:
            ok, frame = capture.read()
        if not ok:
            logging.debug("No frame from %s:%s", target.host, target.port)
            return None
        logging.info("[!] %s:%s answered", target.host, target.port)
        return ProbeResult(camera=self._to_camera(target), frame=frame)

    @staticmethod
    def _to_camera(target: RtspTarget) -> Camera:
        return Camera(
            ip=target.host,
            port=target.port,
            user=target.user,
            password=target.password,
            url=target.url,
            status=CameraStatus.stream_obtained,
        )
