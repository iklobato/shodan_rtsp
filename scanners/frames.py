"""Where a captured frame lives on disk (R8).

The database holds the path (D17), so the layout only has to stay readable by a
human and stable across runs: one directory per camera, and a file name that
sorts by time and says which path produced the frame.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from shutil import copyfile

import cv2
import numpy as np

from models.frame import FrameSource

_EXTENSION = ".jpg"
_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_REFERENCE_DIRECTORY = "targets"


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

    def write_reference(self, origin: str, target_id: int) -> str:
        """Copy a reference photo under the root and return its relative path.

        The file is copied, not re-encoded: the bytes the operator gave are the
        record of the target, and a second lossy pass would change what the
        detection was run on (R3, D57).
        """
        source = Path(origin)
        if not source.is_file():
            raise FrameWriteFailed(f"reference photo not found: {origin}")
        relative = self._free_reference_path(source, target_id)
        destination = Path(self._root) / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        copyfile(source, destination)
        return str(relative)

    def remove_reference(self, relative: str) -> bool:
        """Delete one reference photo, tolerating a file that is already gone."""
        path = Path(self._root) / relative
        if not path.is_file():
            return False
        path.unlink()
        return True

    def _free_reference_path(self, source: Path, target_id: int) -> Path:
        directory = Path(_REFERENCE_DIRECTORY) / str(target_id)
        relative = directory / source.name
        suffix = 1
        while (Path(self._root) / relative).exists():
            relative = directory / f"{source.stem}-{suffix}{source.suffix}"
            suffix += 1
        return relative

    def _relative_path(
        self, camera_id: int, source: FrameSource, captured_at: datetime
    ) -> Path:
        # The name resolves to the second, and one run may capture several frames
        # of one camera inside the same second (frame_interval can be 0), so a
        # name already on disk is not free to reuse: the UNIQUE (path) constraint
        # of the frame table refuses the second row. A counter keeps the plain
        # name for the first frame of a second and only lengthens a repeat.
        directory = Path(str(camera_id))
        name = f"{captured_at.strftime(_TIMESTAMP_FORMAT)}-{source.value}"
        relative = directory / f"{name}{_EXTENSION}"
        suffix = 1
        while (Path(self._root) / relative).exists():
            relative = directory / f"{name}-{suffix}{_EXTENSION}"
            suffix += 1
        return relative
