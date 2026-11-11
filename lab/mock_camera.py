"""The lab device of Front 4, which is a mock and not vendor firmware.

D42 asked for FEMU or FirmAE running old Hikvision firmware. No machine this
repository is developed on can run either one: a Mac has no `/dev/kvm`, and the
Linux VM Docker Desktop runs has neither `/dev/kvm` nor the `vmx` flag in
`/proc/cpuinfo`. D42's own fallback is therefore what this is, and the first line
of `docs/front-4-rig.md` says so.

What it does: it answers the one request CVE-2017-7921 is proved with, on the
path and with the parameter the advisory publishes, and it answers 404 to every
other path. It sends `Server: Hikvision-Webs/DS-2CD2032-I`, so a real `nmap -sV`
identifies the brand and the model through `brands.yaml` and nothing about the
camera row is written by hand. `Hikvision-Webs` is what the series really sends;
the model is appended because the model is what `brands.yaml` needs to reach the
CVE, and this device is a mock with no other way to report one.

It is not vulnerable. It proves the client end to end: the request shape, the one
frame, the rows the run writes, and that nothing was written to the device. It
proves nothing about Hikvision's code.

Its stderr is the device state the run is compared on, because that is where the
standard library access log goes. Start it with `2> logs/mock_camera.log`.
"""

import argparse
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import cv2
import numpy as np

_LOOPBACK = "127.0.0.1"
_SERVER_NAME = "Hikvision-Webs/DS-2CD2032-I"
_SNAPSHOT_PATH = "/onvif-http/snapshot"
_AUTH_PARAM = "auth"
_OK_STATUS = 200
_NOT_FOUND_STATUS = 404
_CONTENT_TYPE = "image/jpeg"
_PLAIN_CONTENT_TYPE = "text/plain"
_WIDTH = 640
_HEIGHT = 480
_CHANNELS = 3
_GREY = 96
_EXTENSION = ".jpg"
_DEFAULT_PORT = 8000
_LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


class ImageNotEncoded(Exception):
    """cv2 refused to encode the image the lab serves."""


class SyntheticImage:
    """A real JPEG, made here so the lab needs no image file in the repository."""

    @classmethod
    def encode(cls) -> bytes:
        """One flat grey frame, encoded the way a camera would encode it."""
        frame = np.full((_HEIGHT, _WIDTH, _CHANNELS), _GREY, dtype=np.uint8)
        encoded_ok, encoded = cv2.imencode(_EXTENSION, frame)
        if not encoded_ok:
            raise ImageNotEncoded("cv2 could not encode the lab image")
        return encoded.tobytes()


class MockCamera(BaseHTTPRequestHandler):
    """The device: the vulnerable snapshot path, and a 404 for everything else.

    `server_version` with an empty `sys_version` is what puts exactly
    `Server: Hikvision-Webs/DS-2CD2032-I` on the wire, which is the line
    `nmap -sV` reads and `brands.yaml` matches on.
    """

    server_version = _SERVER_NAME
    sys_version = ""

    def do_GET(self) -> None:
        self._answer()

    def do_POST(self) -> None:
        self._answer()

    def _answer(self) -> None:
        parts = urlsplit(self.path)
        wanted = parts.path == _SNAPSHOT_PATH and _AUTH_PARAM in parse_qs(parts.query)
        body = self.server.image if wanted else b""
        self.send_response(_OK_STATUS if wanted else _NOT_FOUND_STATUS)
        self.send_header("Content-Type", _CONTENT_TYPE if wanted else _PLAIN_CONTENT_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CameraServer:
    """The loopback device: one port, and the image it serves on the one path."""

    def __init__(self, port: int, image: bytes) -> None:
        self._port = port
        self._image = image
        self._server: ThreadingHTTPServer | None = None

    def serve_forever(self) -> None:
        """Bind the port and answer until the process is stopped."""
        self._server = ThreadingHTTPServer((_LOOPBACK, self._port), MockCamera)
        self._server.image = self._image
        logging.info("mock camera on %s:%d", _LOOPBACK, self._port)
        self._server.serve_forever()


class MockRig:
    """The command line of the lab device."""

    @classmethod
    def main(cls) -> None:
        arguments = cls._parsed()
        logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
        CameraServer(arguments.port, SyntheticImage.encode()).serve_forever()

    @classmethod
    def _parsed(cls) -> argparse.Namespace:
        parser = argparse.ArgumentParser(description="The Front 4 lab camera (a mock)")
        parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
        return parser.parse_args()


if __name__ == "__main__":
    MockRig.main()
