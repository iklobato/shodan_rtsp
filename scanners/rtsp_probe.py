import logging
import os
import urllib.parse
from dataclasses import dataclass

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


class RtspProbe:
    """Opens an RTSP stream and grabs one frame to confirm the camera answers.

    With a proxy, the RTSP TCP connection is relayed through the residential
    exit (see ProxyTunnel) instead of leaving from the local IP, so the probe,
    the login attempt and the frame grab are all anonymised.
    """

    def __init__(self, proxy: TwoCaptchaProxy = None):
        self._proxy = proxy

    def probe(self, target: RtspTarget):
        if self._proxy is None:
            return self._grab(target.url, target)
        with ProxyTunnel(self._proxy.url(), target.host, target.port) as (host, port):
            local_url = _rewrite_netloc(target.url, host, port)
            return self._grab(local_url, target, force_tcp=True)

    def _grab(self, url: str, target: RtspTarget, force_tcp: bool = False):
        logging.debug(url)
        previous = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
        if force_tcp:
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = _TCP_CAPTURE_OPTIONS
        try:
            capture = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
            try:
                ok, frame = capture.read()
            finally:
                capture.release()
        finally:
            if force_tcp:
                if previous is None:
                    os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
                else:
                    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = previous

        if not ok:
            logging.debug(f"No frame for {target.url}")
            return None

        logging.info(
            f"[!] {target.url}, user: {target.user}, password: {target.password}"
        )
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
