"""One stored frame: the file on disk and the path in the database.

Replaces the `face_frames` table, whose payload was the encoded image in a
column. With unlimited retention that was the most expensive of the options, so
the payload is a file and the row holds the path (D17).
"""

import enum

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import validates

from models.base import BASE, InvalidEntity


class FrameSource(enum.Enum):
    """Which path produced the frame."""

    rtsp = "rtsp"
    cve = "cve"


class FaceFrame(BASE):
    __tablename__ = "face_frame"
    __table_args__ = (
        UniqueConstraint("path"),
        Index("ix_face_frame_camera_id_captured_at", "camera_id", "captured_at"),
        Index("ix_face_frame_scan_run_id", "scan_run_id"),
    )

    id = Column(Integer, primary_key=True)
    camera_id = Column(Integer, ForeignKey("camera.id"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_run.id"), nullable=True)
    path = Column(String(512), nullable=False)
    source = Column(Enum(FrameSource, name="frame_source"), nullable=False)
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    captured_at = Column(DateTime(timezone=True), nullable=False, default=func.now())

    @validates("path")
    def _validate_path(self, _key: str, value: str) -> str:
        """The path is the only handle on the file, so it is never empty."""
        if not value or not value.strip():
            raise InvalidEntity("path is required")
        return value
