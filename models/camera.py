"""The camera entity: one device at one address and port.

Replaces the `cam` table. The `active` boolean became a status, because the CVE
path never authenticates over RTSP and a boolean cannot say how a frame was
obtained (D33).

Timestamps default to `now()` in the database rather than a Python helper, so
every writer of a row stamps it from the same clock.
"""

import enum

from ipaddress import ip_address

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import validates

from models.base import BASE, JSON_OBJECT, InvalidEntity

MAX_PORT = 65535


class CameraStatus(enum.Enum):
    """How far the pipeline got with one camera."""

    unknown = "unknown"
    responded = "responded"
    stream_obtained = "stream_obtained"
    frame_by_cve = "frame_by_cve"
    offline = "offline"


class Camera(BASE):
    __tablename__ = "camera"
    __table_args__ = (
        UniqueConstraint("ip", "port"),
        Index("ix_camera_vendor_product", "vendor", "product"),
        Index("ix_camera_status", "status"),
    )

    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    user = Column(String(128), nullable=False, default="")
    password = Column(String(256), nullable=False, default="")
    url = Column(String(512), nullable=False, default="")
    status = Column(
        Enum(CameraStatus, name="camera_status"),
        nullable=False,
        default=CameraStatus.unknown,
    )
    vendor = Column(String(128), nullable=False, default="")
    product = Column(String(128), nullable=False, default="")
    version = Column(String(64), nullable=False, default="")
    raw_banner = Column(JSON_OBJECT, nullable=True)
    city = Column(String(128), nullable=False, default="")
    country_code = Column(String(8), nullable=False, default="")
    country_name = Column(String(128), nullable=False, default="")
    region_code = Column(String(32), nullable=False, default="")
    added_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    @validates("ip")
    def _validate_ip(self, _key: str, value: str) -> str:
        """Refuse an address that does not parse, before any network call."""
        if not value:
            raise InvalidEntity("ip is required")
        try:
            ip_address(value)
        except ValueError as unparsable:
            raise InvalidEntity(f"ip does not parse: {value}") from unparsable
        return value

    @validates("port")
    def _validate_port(self, _key: str, value: int) -> int:
        """A port is a whole number inside the range, or it is not a port."""
        if not isinstance(value, int) or not 1 <= value <= MAX_PORT:
            raise InvalidEntity(f"port out of range: {value}")
        return value

    @validates("raw_banner")
    def _validate_raw_banner(self, _key: str, value: dict | None) -> dict | None:
        if value is not None and not isinstance(value, dict):
            raise InvalidEntity("raw_banner must be a JSON object")
        return value
