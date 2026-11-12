"""The migration is the only thing that builds the schema, so it is tested for real.

sqlite cannot stand in: the revision emits PostgreSQL-only DDL (the enum types,
`DOUBLE PRECISION[]`, `array_length`). Every test builds a throwaway database on
the lab server and drops it again, so the suite never touches the lab data.
When that server is down the tests skip and say why; `docker compose up -d
postgres` makes them run.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, Row, make_url
from sqlalchemy.exc import OperationalError

from models import BASE
from scanners.config import get_config

_SCRATCH_DATABASE = "shodan_migration_test"
_ADMIN_DATABASE = "postgres"
_VERSION_TABLE = "alembic_version"
_HEAD = "0003"
_BEFORE_PERSON_SEARCH = "0002"
_BEFORE_LEGACY = "0001"
_BASE = "base"
_ZERO = 0
_TWO = 2
_LEGACY_ACTIVE_PORT = 554
_LEGACY_IDLE_PORT = 8554
_ACTIVE_STATUS = "stream_obtained"
_INACTIVE_STATUS = "unknown"
_LEGACY_PREFIX = "unknown: imported from the legacy cam table"
_EXPECTED_ENUMS = frozenset(
    {"camera_status", "scan_kind", "frame_source", "cve_class", "cve_outcome"}
)
_PERSON_SEARCH_TABLES = frozenset({"target", "target_photo", "target_hit"})
_COUNT_PERSONS = "SELECT count(*) FROM person"
_INSERT_PERSON = "INSERT INTO person (created_at, updated_at) VALUES (now(), now())"
_COUNT_CAMERAS = "SELECT count(*) FROM camera"
_COUNT_OBSERVATIONS = "SELECT count(*) FROM camera_observation"
_COUNT_RUNS = "SELECT count(*) FROM scan_run"
_COUNT_LEGACY = "SELECT count(*) FROM cam"
_STATUSES_BY_PORT = "SELECT status FROM camera ORDER BY port"
_CITY_OF_FIRST = "SELECT city FROM camera ORDER BY port LIMIT 1"
_LEGACY_RUN = "SELECT target_set, camera_count FROM scan_run"

# The `cam` table as the pre-0001 code left it. Every column but id is nullable
# there, which is why the migration coalesces most of them.
_LEGACY_CAM_DDL = """
CREATE TABLE cam (
    id serial PRIMARY KEY,
    ip varchar,
    port integer,
    "user" varchar,
    password varchar,
    url varchar,
    active boolean,
    city varchar,
    country_code varchar,
    country_name varchar,
    region_code varchar,
    image_b64 varchar,
    added_at timestamp,
    updated_at timestamp
)
"""
_INSERT_LEGACY_ROW = """
INSERT INTO cam (ip, port, "user", active, city, country_code)
VALUES (:ip, :port, :user, :active, :city, :country_code)
"""


class _ScratchDatabase:
    """One throwaway database on the lab server, for the length of one test."""

    def __init__(self, name: str) -> None:
        self._name = name

    def skip_unless_reachable(self) -> None:
        """Skip the test when the lab is down, naming what to start."""
        try:
            with self._connection(_ADMIN_DATABASE) as connection:
                connection.execute(text('SELECT 1'))
        except FileNotFoundError:
            pytest.skip("no config.yaml here, so the lab database is unnamed")
        except OperationalError as unreachable:
            pytest.skip(f"lab postgres is down: {unreachable}")

    def create(self) -> None:
        with self._connection(_ADMIN_DATABASE) as connection:
            connection.execute(
                text(f'DROP DATABASE IF EXISTS "{self._name}" WITH (FORCE)')
            )
            connection.execute(text(f'CREATE DATABASE "{self._name}"'))

    def drop(self) -> None:
        with self._connection(_ADMIN_DATABASE) as connection:
            connection.execute(
                text(f'DROP DATABASE IF EXISTS "{self._name}" WITH (FORCE)')
            )

    def alembic(self) -> Config:
        """The alembic config pointed at this database instead of config.yaml."""
        config = Config(str(self._ini_path()))
        config.set_main_option("sqlalchemy.url", self.url())
        return config

    def url(self) -> str:
        return self._dsn(self._name)

    def tables(self) -> set[str]:
        with self._connection(self._name) as connection:
            return set(inspect(connection).get_table_names())

    def enum_types(self) -> set[str]:
        """The enum types the database holds, which the revision creates itself."""
        with self._connection(self._name) as connection:
            rows = connection.execute(
                text("SELECT typname FROM pg_type WHERE typtype = 'e'")
            )
            return {row.typname for row in rows}

    def revision(self) -> str | None:
        with self._connection(self._name) as connection:
            found = connection.execute(
                text(f"SELECT version_num FROM {_VERSION_TABLE}")
            ).scalar()
            return found

    def rows(self, statement: str) -> list[Row]:
        """Run one query against this database, for the assertions."""
        with self._connection(self._name) as connection:
            return list(connection.execute(text(statement)))

    def execute(self, statement: str) -> None:
        """Run one statement that returns no rows, for the setup of a test."""
        with self._connection(self._name) as connection:
            connection.execute(text(statement))

    def count(self, statement: str) -> int:
        """The single number a `count(*)` query returns."""
        return self.rows(statement)[0][0]

    def column(self, statement: str) -> list[object]:
        """The first column of every row, for the assertions."""
        return [row[0] for row in self.rows(statement)]

    def create_legacy_cam(self, rows: list[dict]) -> None:
        """Build the pre-0001 `cam` table and fill it, as the old code left it."""
        with self._connection(self._name) as connection:
            connection.execute(text(_LEGACY_CAM_DDL))
            connection.execute(text(_INSERT_LEGACY_ROW), rows)

    @contextmanager
    def _connection(self, database: str) -> Iterator[Connection]:
        engine = create_engine(self._dsn(database), isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as connection:
                yield connection
        finally:
            engine.dispose()

    def _dsn(self, database: str) -> str:
        dsn = make_url(get_config().database.dsn).set(database=database)
        return dsn.render_as_string(hide_password=False)

    def _ini_path(self) -> Path:
        return Path(__file__).resolve().parents[1] / "alembic.ini"


@pytest.fixture
def lab() -> Iterator[_ScratchDatabase]:
    """A throwaway database on the lab server, created before and dropped after."""
    server = _ScratchDatabase(_SCRATCH_DATABASE)
    server.skip_unless_reachable()
    server.create()
    try:
        yield server
    finally:
        server.drop()


@pytest.fixture
def legacy_rows() -> list[dict]:
    """Two `cam` rows as the old code left them: one active, one never reached.

    The second leaves city and country_code NULL, the path the migration coalesces.
    """
    found = {"ip": "10.9.9.1", "port": _LEGACY_ACTIVE_PORT, "user": "admin"}
    idle = {"ip": "10.9.9.2", "port": _LEGACY_IDLE_PORT, "user": "root"}
    found.update(active=True, city="Sao Paulo", country_code="BR")
    idle.update(active=False, city=None, country_code=None)
    return [found, idle]


def test_upgrade_from_zero_creates_every_table(lab: _ScratchDatabase) -> None:
    command.upgrade(lab.alembic(), _HEAD)
    assert lab.tables() == set(BASE.metadata.tables) | {_VERSION_TABLE}


def test_second_upgrade_changes_nothing(lab: _ScratchDatabase) -> None:
    command.upgrade(lab.alembic(), _HEAD)
    before = (lab.tables(), lab.revision())
    command.upgrade(lab.alembic(), _HEAD)
    assert (lab.tables(), lab.revision()) == before
    # Raises AutogenerateDiffsDetected if the models and the database disagree,
    # which is also what proves the legacy `cam` table is never proposed for a drop.
    command.check(lab.alembic())


def test_legacy_cam_rows_move_into_the_new_schema(
    lab: _ScratchDatabase, legacy_rows: list[dict]
) -> None:
    """The rows of the old table land as cameras, one observation each."""
    command.upgrade(lab.alembic(), _BEFORE_LEGACY)
    lab.create_legacy_cam(legacy_rows)
    command.upgrade(lab.alembic(), _HEAD)
    command.upgrade(lab.alembic(), _HEAD)  # a second run must add nothing
    assert lab.count(_COUNT_CAMERAS) == _TWO
    assert lab.count(_COUNT_OBSERVATIONS) == _TWO
    assert lab.column(_STATUSES_BY_PORT) == [_ACTIVE_STATUS, _INACTIVE_STATUS]
    target_set, camera_count = lab.rows(_LEGACY_RUN)[0]
    assert target_set.startswith(_LEGACY_PREFIX)
    assert camera_count == _TWO
    assert lab.column(_CITY_OF_FIRST)[0] == "Sao Paulo"


def test_legacy_migration_rolls_back_and_keeps_the_old_rows(
    lab: _ScratchDatabase, legacy_rows: list[dict]
) -> None:
    """The rollback takes the migrated rows out; `cam` still holds them."""
    command.upgrade(lab.alembic(), _BEFORE_LEGACY)
    lab.create_legacy_cam(legacy_rows)
    command.upgrade(lab.alembic(), _HEAD)
    command.downgrade(lab.alembic(), _BEFORE_LEGACY)
    assert lab.count(_COUNT_CAMERAS) == _ZERO
    assert lab.count(_COUNT_OBSERVATIONS) == _ZERO
    assert lab.count(_COUNT_RUNS) == _ZERO
    assert lab.count(_COUNT_LEGACY) == _TWO


def test_person_search_migration_round_trips_without_touching_people(
    lab: _ScratchDatabase,
) -> None:
    """0003 goes up and down again, and the rows it never owned stay put."""
    command.upgrade(lab.alembic(), _BEFORE_PERSON_SEARCH)
    lab.execute(_INSERT_PERSON)
    command.upgrade(lab.alembic(), _HEAD)
    assert _PERSON_SEARCH_TABLES <= lab.tables()
    assert lab.count(_COUNT_PERSONS) == 1
    command.downgrade(lab.alembic(), _BEFORE_PERSON_SEARCH)
    assert lab.tables().isdisjoint(_PERSON_SEARCH_TABLES)
    assert lab.count(_COUNT_PERSONS) == 1
    command.upgrade(lab.alembic(), _HEAD)
    assert _PERSON_SEARCH_TABLES <= lab.tables()


def test_downgrade_base_returns_to_zero_tables(lab: _ScratchDatabase) -> None:
    command.upgrade(lab.alembic(), _HEAD)
    command.downgrade(lab.alembic(), _BASE)
    assert lab.tables() == {_VERSION_TABLE}
    assert lab.enum_types() == set()
    # The round trip that used to die on `type "camera_status" already exists`.
    command.upgrade(lab.alembic(), _HEAD)
    assert lab.tables() == set(BASE.metadata.tables) | {_VERSION_TABLE}
    assert lab.enum_types() == _EXPECTED_ENUMS
