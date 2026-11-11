"""The entity package.

Importing it registers every table on `BASE.metadata`, which is the metadata
Alembic autogenerates from and the one the repository tests build.
"""

from models.base import BASE
from models.camera import Camera, CameraStatus
from models.face import Face
from models.finding import CveClass, CveFinding, CveOutcome
from models.frame import FaceFrame, FrameSource
from models.observation import CameraObservation
from models.person import Person
from models.scan_run import ScanKind, ScanRun

__all__ = [
    "BASE",
    "Camera",
    "CameraObservation",
    "CameraStatus",
    "CveClass",
    "CveFinding",
    "CveOutcome",
    "Face",
    "FaceFrame",
    "FrameSource",
    "Person",
    "ScanKind",
    "ScanRun",
]
