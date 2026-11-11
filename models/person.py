"""A cluster of faces judged to be the same individual.

Anonymous by default: nothing in this batch labels a person automatically, and a
label is only ever set by hand (D28).
"""

from sqlalchemy import Column, DateTime, Index, Integer, String, func
from sqlalchemy.orm import validates

from models.base import BASE


class Person(BASE):
    __tablename__ = "person"
    __table_args__ = (Index("ix_person_label", "label"),)

    id = Column(Integer, primary_key=True)
    label = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    @validates("label")
    def _validate_label(self, _key: str, value: str | None) -> str | None:
        """An empty label and no label are the same thing, so they become one."""
        if value is None:
            return None
        return value.strip() or None
