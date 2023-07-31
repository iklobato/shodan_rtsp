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
            logging.info('Singleton call if')
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
    user = Column(String)
    password = Column(String)
    url = Column(String)
    active = Column(Integer)
    city = Column(String)
    country_code = Column(String)
    country_name = Column(String)
    region_code = Column(String)
    added_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Camera {self.ip}:{self.port} ({self.city}, {self.country_code}) - {self.active}>'


if __name__ == '__main__':

    db_connection = DatabaseConnection()

    # with db_connection.session as session:
    #     new_camera = Camera(
    #         ip='192.168.0.3', port=8080, user='admin', password='password', url='rtsp://example.com/camera3', active=1,
    #         city='New City', country_code='CA', country_name='Canada', region_code='ON'
    #     )
    #     session.add(new_camera)
    #     session.commit()

    with db_connection.session as session:
        query_result = session.query(Camera).all()
        for camera in query_result:
            print(camera)
