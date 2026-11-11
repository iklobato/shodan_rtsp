"""A vulnerable product matched to a camera, plus what the attempt produced.

One row per camera and CVE, updated in place, so a repeated run does not add
rows and `first_seen_at` keeps the history. The outcome and the reason are both
recorded, because a match without a picture has to stay visible (D31, FR-018).
"""

import enum

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import validates

from models.base import BASE, InvalidEntity


class CveClass(enum.Enum):
    """The three classes of the batch, tried in this order (D9)."""

    auth_bypass = "auth_bypass"
    unauth_read = "unauth_read"
    unauth_onvif = "unauth_onvif"


class CveOutcome(enum.Enum):
    """What the attempt produced."""

    not_attempted = "not_attempted"
    frame_obtained = "frame_obtained"
    no_frame = "no_frame"


class CveFinding(BASE):
    __tablename__ = "cve_finding"
    __table_args__ = (
        UniqueConstraint("camera_id", "cve_id"),
        # A frame is recorded exactly when one was obtained.
        CheckConstraint(
            "(outcome = 'frame_obtained') = (frame_id IS NOT NULL)",
            name="frame_matches_outcome",
        ),
        # An attempted candidate that yielded no frame always carries the reason.
        # not_attempted is exempt: nothing was tried yet, so there is nothing to
        # report and the row has to exist before the attempt runs.
        CheckConstraint(
            "outcome = 'frame_obtained' OR outcome = 'not_attempted' "
            "OR failure_reason <> ''",
            name="failure_reason",
        ),
        Index("ix_cve_finding_cve_id", "cve_id"),
        Index("ix_cve_finding_camera_id", "camera_id"),
    )

    id = Column(Integer, primary_key=True)
    camera_id = Column(Integer, ForeignKey("camera.id"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_run.id"), nullable=True)
    cve_id = Column(String(32), nullable=False)
    cve_class = Column(Enum(CveClass, name="cve_class"), nullable=False)
    matched_range = Column(String(128), nullable=False, default="")
    cvss = Column(Float, nullable=True)
    outcome = Column(
        Enum(CveOutcome, name="cve_outcome"),
        nullable=False,
        default=CveOutcome.not_attempted,
    )
    failure_reason = Column(String(512), nullable=False, default="")
    frame_id = Column(Integer, ForeignKey("face_frame.id"), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)

    @validates("cve_id")
    def _validate_cve_id(self, _key: str, value: str) -> str:
        if not value or not value.startswith("CVE-"):
            raise InvalidEntity(f"cve_id must look like CVE-YYYY-NNNN: {value}")
        return value
