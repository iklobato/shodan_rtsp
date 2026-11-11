"""What one camera looked like on one port in one run.

One row per camera per port per scan (FR-006, D19). This is the time series that
makes a firmware change, an uptime change or the first appearance of a CVE
visible.
"""

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

from models.base import BASE, JSON_OBJECT, InvalidEntity
from models.camera import MAX_PORT, CameraStatus


class CameraObservation(BASE):
    __tablename__ = "camera_observation"
    __table_args__ = (
        UniqueConstraint("camera_id", "scan_run_id", "port"),
        Index(
            "ix_camera_observation_camera_id_observed_at", "camera_id", "observed_at"
        ),
        Index("ix_camera_observation_scan_run_id", "scan_run_id"),
    )

    id = Column(Integer, primary_key=True)
    camera_id = Column(Integer, ForeignKey("camera.id"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_run.id"), nullable=False)
    port = Column(Integer, nullable=False)
    status = Column(
        Enum(CameraStatus, name="camera_status"),
        nullable=False,
        default=CameraStatus.unknown,
    )
    vendor = Column(String(128), nullable=False, default="")
    product = Column(String(128), nullable=False, default="")
    version = Column(String(64), nullable=False, default="")
    raw_banner = Column(JSON_OBJECT, nullable=True)
    observed_at = Column(DateTime(timezone=True), nullable=False, default=func.now())

    @validates("port")
    def _validate_port(self, _key: str, value: int) -> int:
        """A port is a whole number inside the range, or it is not a port."""
        if not isinstance(value, int) or not 1 <= value <= MAX_PORT:
            raise InvalidEntity(f"port out of range: {value}")
        return value
