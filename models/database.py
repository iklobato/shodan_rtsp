from contextlib import contextmanager
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="POSTGRES_", extra="ignore"
    )

    user: str
    password: str
    host: str
    db: str

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}/{self.db}"


class Database:
    """Owns the SQLAlchemy engine and hands out transactional sessions."""

    def __init__(self, settings: DatabaseSettings = None):
        settings = settings or DatabaseSettings()
        self.engine = create_engine(settings.dsn)
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
