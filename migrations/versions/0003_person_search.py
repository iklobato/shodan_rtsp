"""add target, target_photo and target_hit for the named person search

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-12 09:00:00.000000

A target is the person the operator wants to find: a unique name, and the
reference photos the search compares stored faces against (D49, D55, D57). A hit
records that one target matched one stored face, at most once per pair (D53,
D58).

Nothing here points at a frame or at an embedding of the pipeline: the photos
are files under `frames.root_path/targets/`, and `target_hit` only carries the
score. Removing a target therefore keeps every face and every frame, which is
what lets the removal of D54 coexist with the unlimited retention of D10.

The three tables are new and empty, so the upgrade needs no data step and the
downgrade drops them in dependency order: the hits first, the photos second, the
targets last. No other table is touched in either direction.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the three tables of the named person search."""
    op.create_table(
        "target",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("name <> ''", name=op.f("ck_target_name_not_empty")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target")),
        sa.UniqueConstraint("name", name=op.f("uq_target_name")),
    )
    op.create_table(
        "target_photo",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column(
            "embedding", postgresql.ARRAY(sa.DOUBLE_PRECISION()), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "array_length(embedding, 1) = 512",
            name=op.f("ck_target_photo_embedding_length"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["target.id"],
            name=op.f("fk_target_photo_target_id_target"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_photo")),
        sa.UniqueConstraint("path", name=op.f("uq_target_photo_path")),
    )
    op.create_index(
        "ix_target_photo_target_id", "target_photo", ["target_id"], unique=False
    )
    op.create_table(
        "target_hit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("face_id", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "score >= -1.0 AND score <= 1.0", name=op.f("ck_target_hit_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["face_id"], ["face.id"], name=op.f("fk_target_hit_face_id_face")
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["target.id"],
            name=op.f("fk_target_hit_target_id_target"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_hit")),
        sa.UniqueConstraint(
            "target_id", "face_id", name=op.f("uq_target_hit_target_id")
        ),
    )
    op.create_index(
        "ix_target_hit_target_id_score", "target_hit", ["target_id", "score"], unique=False
    )
    op.create_index("ix_target_hit_face_id", "target_hit", ["face_id"], unique=False)


def downgrade() -> None:
    """Drop them again, in dependency order: hits, photos, targets."""
    op.drop_index("ix_target_hit_face_id", table_name="target_hit")
    op.drop_index("ix_target_hit_target_id_score", table_name="target_hit")
    op.drop_table("target_hit")
    op.drop_index("ix_target_photo_target_id", table_name="target_photo")
    op.drop_table("target_photo")
    op.drop_table("target")
