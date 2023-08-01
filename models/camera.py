import logging
import os
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

load_dotenv()


class DatabaseConnectionSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            logging.debug('Singleton call if')
            cls._instances[cls] = super(DatabaseConnectionSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class DatabaseConnection(metaclass=DatabaseConnectionSingleton):
    Base = declarative_base()

    def __init__(self):
        username = os.getenv('POSTGRES_USER')
        password = os.getenv('POSTGRES_PASSWORD')
        host = os.getenv('POSTGRES_HOST')
        database = os.getenv('POSTGRES_DB')
        connection_string = f'postgresql://{username}:{password}@{host}/{database}'
        self.engine = create_engine(connection_string)
        self.Session = None

    @property
    def session(self):
        if self.Session is None:
            self.Session = sessionmaker(bind=self.engine)
        return self.Session()

    @classmethod
    def base(cls):
        return cls.Base


class Camera(DatabaseConnection.base()):
    __tablename__ = 'cam'
    id = Column(Integer, primary_key=True)

    ip = Column(String)
    port = Column(Integer)
    user = Column(String, default='')
    password = Column(String, default='')
    url = Column(String, default='')
    active = Column(Boolean, default=False)
    city = Column(String, default='')
    country_code = Column(String, default='')
    country_name = Column(String, default='')
    region_code = Column(String, default='')
    image_b64 = Column(String, default='')
    added_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Camera {self.ip}:{self.port} ({self.city}, {self.country_code}) - {self.active}>'

