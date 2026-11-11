"""Where a captured frame lives on disk (R8).

The database holds the path (D17), so the layout only has to stay readable by a
human and stable across runs: one directory per camera, and a file name that
sorts by time and says which path produced the frame.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import cv2
import numpy as np

from models.frame import FrameSource

_EXTENSION = ".jpg"
_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"


class FrameWriteFailed(Exception):
    """The frame never reached the disk, so no row may point at it."""


@dataclass(frozen=True)
class StoredFrame:
    """A frame on disk, with the instant its file name carries."""

    path: str
    captured_at: datetime


class FrameStore:
    """Writes frames under one root and returns the path relative to it."""

    def __init__(self, root: str) -> None:
        self._root = root

    def write(self, camera_id: int, source: FrameSource, frame: np.ndarray) -> StoredFrame:
        """Write one frame and return its path, relative to the root."""
        captured_at = datetime.now(timezone.utc)
        relative = self._relative_path(camera_id, source, captured_at)
        target = Path(self._root) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        encoded_ok, encoded = cv2.imencode(_EXTENSION, frame)
        if not encoded_ok:
            raise FrameWriteFailed(
                f"cv2 could not encode the frame of camera {camera_id}"
            )
        target.write_bytes(encoded.tobytes())
        return StoredFrame(path=str(relative), captured_at=captured_at)

    def _relative_path(
        self, camera_id: int, source: FrameSource, captured_at: datetime
    ) -> Path:
        # ponytail: the name resolves to the second, so two frames of one camera
        # inside the same second would collide on UNIQUE (path). The run shape
        # rules that out today (frames are frame_interval seconds apart, one scan
        # per camera at a time). Add a counter suffix if that stops holding.
        stamp = captured_at.strftime(_TIMESTAMP_FORMAT)
        return Path(str(camera_id)) / f"{stamp}-{source.value}{_EXTENSION}"
