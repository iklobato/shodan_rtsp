"""One execution of one scan kind against one target set.

This is the row that makes a run tellable apart from a run against a different
range, which is the only record left when nothing gates the target (D6, FR-002).
"""

import enum

from sqlalchemy import Column, DateTime, Enum, Index, Integer, Text, func
from sqlalchemy.orm import validates

from models.base import BASE, InvalidEntity


class ScanKind(enum.Enum):
    """Which command produced the run."""

    nmap = "nmap"
    shodan = "shodan"
    check = "check"
    cve = "cve"
    faces = "faces"


class ScanRun(BASE):
    __tablename__ = "scan_run"
    __table_args__ = (Index("ix_scan_run_kind_started_at", "kind", "started_at"),)

    id = Column(Integer, primary_key=True)
    kind = Column(Enum(ScanKind, name="scan_kind"), nullable=False)
    target_set = Column(Text, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
    camera_count = Column(Integer, nullable=False, default=0)

    @validates("target_set")
    def _validate_target_set(self, _key: str, value: str) -> str:
        """A run that does not say what it reached is not a record."""
        if not value or not value.strip():
            raise InvalidEntity("target_set is required")
        return value
