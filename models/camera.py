from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Face(Base):
    """A detected face: bounding box + 128-d embedding + source camera."""

    __tablename__ = "faces"
    __table_args__ = (Index("ix_faces_camera_id", "camera_id"),)

    id = Column(Integer, primary_key=True)
    camera_id = Column(Integer, nullable=False)
    frame_id = Column(Integer, nullable=True)  # optional link to face_frames
    embedding = Column(String)  # 128 floats comma-separated
    bbox_top = Column(Integer)
    bbox_left = Column(Integer)
    bbox_bottom = Column(Integer)
    bbox_right = Column(Integer)
    confidence = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class FaceFrame(Base):
    """A saved frame from an active camera (multi-frame capture)."""

    __tablename__ = "face_frames"

    id = Column(Integer, primary_key=True)
    camera_id = Column(Integer, nullable=False)
    image_b64 = Column(String)
    captured_at = Column(DateTime, default=datetime.utcnow)


class Camera(Base):
    __tablename__ = "cam"

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    port = Column(Integer)
    user = Column(String, default="")
    password = Column(String, default="")
    url = Column(String, default="")
    active = Column(Boolean, default=False)
    city = Column(String, default="")
    country_code = Column(String, default="")
    country_name = Column(String, default="")
    region_code = Column(String, default="")
    image_b64 = Column(String, default="")
    added_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Camera {self.ip}:{self.port} ({self.city}, {self.country_code}) - {self.active}>"
