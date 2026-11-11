"""One detected face in one frame, with the embedding that identifies it.

Replaces the `faces` table. The embedding is the raw 512-value vector from the
`buffalo_l` recognition model, stored unnormalized: the comparison normalizes at
match time, and a later change of metric stays recomputable from the original
measurement (D44).
"""

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    func,
)
from sqlalchemy.orm import validates

from models.base import BASE, EMBEDDING, InvalidEntity

# The recognition model emits 512 values. A vector of another length is a bug,
# not data, so it is refused at construction and again by a CHECK in the
# migration.
EMBEDDING_LENGTH = 512


class Face(BASE):
    __tablename__ = "face"
    __table_args__ = (
        # array_length is PostgreSQL only, so the constraint is emitted there and
        # skipped on the sqlite the repository tests run on.
        CheckConstraint(
            f"array_length(embedding, 1) = {EMBEDDING_LENGTH}",
            name="embedding_length",
        ).ddl_if(dialect="postgresql"),
        Index("ix_face_person_id", "person_id"),
        Index("ix_face_frame_id", "frame_id"),
    )

    id = Column(Integer, primary_key=True)
    frame_id = Column(Integer, ForeignKey("face_frame.id"), nullable=False)
    person_id = Column(Integer, ForeignKey("person.id"), nullable=True)
    embedding = Column(EMBEDDING, nullable=False)
    bbox_top = Column(Integer, nullable=False)
    bbox_left = Column(Integer, nullable=False)
    bbox_bottom = Column(Integer, nullable=False)
    bbox_right = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())

    @validates("embedding")
    def _validate_embedding(self, _key: str, value: list[float]) -> list[float]:
        length = 0 if value is None else len(value)
        if length != EMBEDDING_LENGTH:
            raise InvalidEntity(
                f"embedding must hold {EMBEDDING_LENGTH} values, got {length}"
            )
        return list(value)
