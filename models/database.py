from contextlib import contextmanager

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


class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class Database(metaclass=SingletonMeta):
    """Owns the SQLAlchemy engine and hands out transactional sessions."""

    def __init__(self, settings: DatabaseSettings = None):
        settings = settings or DatabaseSettings()
        self.engine = create_engine(settings.dsn)
        self._session_factory = sessionmaker(bind=self.engine)

    @contextmanager
    def session_scope(self):
        """Yield a session, commit on success, roll back on error, always close."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
