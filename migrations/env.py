"""Alembic's migration environment.

This file follows the shape Alembic's own template defines, because the
framework loads it as a script. The database URL comes from config.yaml and
never from alembic.ini, so the connection string has one source.
`transaction_per_migration` is on because a batch that fails halfway must not
leave the schema sitting between two revisions (research R3).
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from models import BASE
from scanners.config import get_config

# The lab database still carries the retired `cam` table with its rows. The new
# schema replaces it without deleting it, so autogenerate has to stop proposing
# a drop for it on every future revision.
LEGACY_TABLES = ("cam",)


def include_object(object_, name, type_, reflected, compare_to):
    """Keep the legacy tables out of the comparison, so no revision drops one."""
    return name not in LEGACY_TABLES


def database_url() -> str:
    """The URL the caller set on the config, or the one from config.yaml.

    alembic.ini ships with `sqlalchemy.url` empty, so a plain command falls
    through to config.yaml and the connection string keeps one source. The
    migration test sets the option to point a throwaway database here.
    """
    return context.config.get_main_option("sqlalchemy.url") or get_config().database.dsn


def run_migrations_offline() -> None:
    """Emit the SQL instead of running it, for a review before it touches a database."""
    context.configure(
        url=database_url(),
        target_metadata=BASE.metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        transaction_per_migration=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against the configured database."""
    config = context.config
    if config.config_file_name is not None:
        fileConfig(config.config_file_name)
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()
    engine = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=BASE.metadata,
            transaction_per_migration=True,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
