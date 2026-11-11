"""The declarative base and the column types every entity shares.

The naming convention is passed to the MetaData constructor rather than assigned
afterwards, so a constraint carries a stable name before the first migration is
generated (research R2). It is written inline because a module-level dict would
be mutable global state.
"""

from sqlalchemy import JSON, MetaData
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import declarative_base


class InvalidEntity(ValueError):
    """A value that cannot be stored as given, refused before the database."""


# jsonb on PostgreSQL and plain JSON elsewhere, so the repository tests run on
# sqlite without a second mapping.
JSON_OBJECT = JSON().with_variant(postgresql.JSONB(), "postgresql")

# double precision[] on PostgreSQL, JSON elsewhere. The CHECK on the length is
# PostgreSQL only, so it lives in the migration.
EMBEDDING = postgresql.ARRAY(postgresql.DOUBLE_PRECISION).with_variant(JSON(), "sqlite")

# One base for the seven entities. Named in capitals because the module holds no
# other state.
BASE = declarative_base(
    metadata=MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )
)
