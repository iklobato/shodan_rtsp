from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanners.config import DatabaseConfig, get_config


class Database:
    """Owns the SQLAlchemy engine and hands out transactional sessions."""

    def __init__(self, config: DatabaseConfig = None):
        config = config or get_config().database
        self.engine = create_engine(config.dsn)
        self._session_factory = sessionmaker(bind=self.engine)

    @contextmanager
    def session_scope(self):
        """Yield a session, commit on success, roll back on error, always close.

        The rollback here is the one error path we keep on purpose: it prevents a
        half-written transaction from being committed on failure.
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


@lru_cache(maxsize=1)
def default_database() -> Database:
    """The process-wide Database (one engine), created on first use.

    A cached factory replaces the old Singleton metaclass: callers that want a
    different Database (tests) just inject one instead of fighting a global.
    """
    return Database()
