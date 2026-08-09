import logging
from dataclasses import dataclass

import cv2

from models.camera import Camera


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


class RtspProbe:
    """Opens an RTSP stream and grabs one frame to confirm the camera answers."""

    def probe(self, target: RtspTarget):
        logging.debug(target.url)
        capture = cv2.VideoCapture(target.url)
        try:
            ok, frame = capture.read()
        finally:
            capture.release()

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
