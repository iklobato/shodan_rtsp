"""A named person the operator wants to find, its reference photos, and its hits.

A target is operator-created data, not something the pipeline inferred: the name
is the identity key, and the reference photos are what the search compares
against (D49, D55, D57). A hit is the record that one target matched one stored
face (D53). None of these tables holds a frame or a face, so removing a target
never touches the retention of D10 (D54).
"""

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import validates

from models.base import BASE, EMBEDDING, InvalidEntity
from models.face import EMBEDDING_LENGTH

MAX_NAME_CHARS = 128
MIN_SCORE = -1.0
MAX_SCORE = 1.0


class Target(BASE):
    """One person the operator wants to find, identified by a unique name."""

    __tablename__ = "target"
    __table_args__ = (
        UniqueConstraint("name"),
        CheckConstraint("name <> ''", name="name_not_empty"),
    )

    id = Column(Integer, primary_key=True)
    name = Column(String(MAX_NAME_CHARS), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        """The name is the identity key, so an empty one is not data."""
        if value is None or not value.strip():
            raise InvalidEntity("target name is required")
        return value.strip()


class TargetPhoto(BASE):
    """One reference image of one target: the file on disk, the vector, the path."""

    __tablename__ = "target_photo"
    __table_args__ = (
        UniqueConstraint("path"),
        CheckConstraint(
            f"array_length(embedding, 1) = {EMBEDDING_LENGTH}",
            name="embedding_length",
        ).ddl_if(dialect="postgresql"),
        Index("ix_target_photo_target_id", "target_id"),
    )

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("target.id"), nullable=False)
    path = Column(String(512), nullable=False)
    embedding = Column(EMBEDDING, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())

    @validates("path")
    def _validate_path(self, _key: str, value: str) -> str:
        if not value or not value.strip():
            raise InvalidEntity("path is required")
        return value

    @validates("embedding")
    def _validate_embedding(self, _key: str, value: list[float]) -> list[float]:
        length = 0 if value is None else len(value)
        if length != EMBEDDING_LENGTH:
            raise InvalidEntity(
                f"embedding must hold {EMBEDDING_LENGTH} values, got {length}"
            )
        return list(value)


class TargetHit(BASE):
    """One target matched to one stored face, with the score of the match."""

    __tablename__ = "target_hit"
    __table_args__ = (
        UniqueConstraint("target_id", "face_id"),
        CheckConstraint(
            f"score >= {MIN_SCORE} AND score <= {MAX_SCORE}", name="score_range"
        ),
        Index("ix_target_hit_target_id_score", "target_id", "score"),
        Index("ix_target_hit_face_id", "face_id"),
    )

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("target.id"), nullable=False)
    face_id = Column(Integer, ForeignKey("face.id"), nullable=False)
    score = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())

    @validates("score")
    def _validate_score(self, _key: str, value: float) -> float:
        if value < MIN_SCORE or value > MAX_SCORE:
            raise InvalidEntity(
                f"a cosine score lies between {MIN_SCORE} and {MAX_SCORE}, got {value}"
            )
        return value
